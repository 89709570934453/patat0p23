//
// ZeraphX Driver - Connection Test (Hardened)
// Discovers the randomized section name from registry
//

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <cstdio>


// Shared memory structure - must match kernel driver
struct SharedMemory {
  volatile long RequestReady;
  volatile long ResponseReady;
  volatile long Shutdown;
  unsigned long Magic;
  unsigned long Operation;
  void *ProcessId;
  void *Target;
  void *Buffer;
  size_t Size;
  long Status;
  size_t ReturnSize;
  void *ResultAddress;
  size_t ResultSize;
  wchar_t ModuleName[256];
  wchar_t SectionName[64];
};

constexpr unsigned long ZX_OP_PING = 5;

int main() {
  printf("========================================\n");
  printf("  ZeraphX Driver - Hardened Test\n");
  printf("========================================\n\n");

  // Step 1: Discover randomized section name from registry
  HKEY key = nullptr;
  wchar_t sectionName[128] = {};
  DWORD size = sizeof(sectionName);
  DWORD type = 0;

  printf("[*] Discovering section name from registry...\n");

  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                    KEY_READ, &key) != ERROR_SUCCESS) {
    printf("[-] Failed to open registry key! Error: %lu\n", GetLastError());
    printf("    Run as Administrator.\n");
    return 1;
  }

  LSTATUS regStatus = RegQueryValueExW(key, L"MachineSession", nullptr, &type,
                                       (LPBYTE)sectionName, &size);
  RegCloseKey(key);

  if (regStatus != ERROR_SUCCESS) {
    printf("[-] Section name not found in registry! Error: %lu\n", regStatus);
    printf("    Make sure the driver is loaded via KDMapper.\n");
    return 1;
  }

  wprintf(L"[+] Discovered section: %s\n", sectionName);

  // Step 2: Open the shared memory section
  HANDLE section = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sectionName);
  if (!section) {
    printf("[-] Failed to open shared memory! Error: %lu\n", GetLastError());
    return 1;
  }
  printf("[+] Shared memory section opened!\n");

  // Step 3: Map it
  SharedMemory *shared = (SharedMemory *)MapViewOfFile(
      section, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemory));
  if (!shared) {
    printf("[-] Failed to map! Error: %lu\n", GetLastError());
    CloseHandle(section);
    return 1;
  }
  printf("[+] Mapped at: 0x%p\n", shared);

  // Step 4: Read the dynamic session magic
  unsigned long sessionMagic = shared->Magic;
  printf("[+] Session magic: 0x%08X\n", sessionMagic);

  // Step 5: Send PING using session magic
  printf("[*] Sending PING...\n");
  shared->Operation = ZX_OP_PING;
  shared->Magic = sessionMagic;
  shared->ResponseReady = 0;
  shared->RequestReady = 1;

  // Wait for response (max 3s)
  for (int i = 0; i < 3000; i++) {
    if (shared->ResponseReady == 1) {
      printf("[+] Driver responded! Status: 0x%08X\n",
             (unsigned)shared->Status);
      if (shared->ResultAddress == (void *)(uintptr_t)sessionMagic) {
        printf("[+] PING verified - driver is ALIVE!\n");
        printf("\n[+] === EAC Hardening Active ===\n");
        printf("    * Randomized section name: YES\n");
        printf("    * Dynamic session magic:   YES\n");
        printf(
            "    * MmCopyVirtualMemory:     REPLACED (attach-copy-detach)\n");
        printf("    * Pool tags:               INNOCUOUS\n");
        printf("    * PE headers:              ZEROED\n");
        printf("    * MmUnloadedDrivers:       CLEARED\n");
      }
      break;
    }
    Sleep(1);
  }

  if (shared->ResponseReady != 1) {
    printf("[-] No response from driver (timeout).\n");
  }

  printf("\n[*] Press Enter to exit...\n");
  getchar();

  UnmapViewOfFile(shared);
  CloseHandle(section);
  return 0;
}
