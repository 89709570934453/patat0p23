#pragma once

//
// ZeraphX Driver - Userland Client Library (Hardened Shared Memory)
//
// The driver creates a RANDOMLY NAMED section and stores the name
// in the registry at HKLM\SOFTWARE\Microsoft\Cryptography\MachineSession.
// The client reads this value to discover the section name.
// The session magic is also dynamic — read from shared memory.
//

#define WIN32_LEAN_AND_MEAN
#include <TlHelp32.h>
#include <Windows.h>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <intrin.h>


namespace driver {

// ========================================================================
// Operation codes - must match kernel driver
// ========================================================================
namespace ops {
constexpr ULONG attach = 0;
constexpr ULONG read = 1;
constexpr ULONG write = 2;
constexpr ULONG module_base = 3;
constexpr ULONG detach = 4;
constexpr ULONG ping = 5;
// Spoofing operations
constexpr ULONG spoof_smbios = 10;
constexpr ULONG spoof_disk = 11;
constexpr ULONG spoof_nic = 12;
constexpr ULONG spoof_gpu = 13;
constexpr ULONG spoof_volume = 14;
constexpr ULONG spoof_efi = 15;
constexpr ULONG spoof_acpi = 16;
constexpr ULONG spoof_tpm = 17;
constexpr ULONG spoof_hid = 18;
constexpr ULONG spoof_wmi = 19;
constexpr ULONG spoof_uefi = 20;
constexpr ULONG jitter = 21;
constexpr ULONG clean_traces = 22;
constexpr ULONG unhook = 23;
} // namespace ops

// ========================================================================
// Spoof identity payload - must match kernel driver EXACTLY
// ========================================================================
struct SpoofPayload {
  char DiskSerial[64];
  char MacAddress[18];
  char BoardSerial[64];
  char SystemUuid[64];
  char MachineGuid[64];
  char ProductId[64];
  char Padding[6]; // align to 8 bytes
};

// ========================================================================
// Shared memory structure - must match kernel driver EXACTLY
// ========================================================================
struct SharedMemory {
  volatile LONG RequestReady;
  volatile LONG ResponseReady;
  volatile LONG Shutdown;
  ULONG Magic; // Dynamic session magic
  ULONG Operation;
  HANDLE ProcessId;
  PVOID Target;
  PVOID Buffer;
  SIZE_T Size;
  LONG Status;
  SIZE_T ReturnSize;
  PVOID ResultAddress;
  SIZE_T ResultSize;
  WCHAR ModuleName[256];
  WCHAR SectionName[64]; // Stores the client-side section name
  SpoofPayload SpoofData; // Identity payload for spoof operations
};

// ========================================================================
// Driver connection handle
// ========================================================================
struct Connection {
  HANDLE section;
  SharedMemory *shared;
  ULONG sessionMagic; // Cached from first read
};

// ========================================================================
// Discover the randomized section name from registry
// ========================================================================
inline std::wstring discover_section_name() {
  HKEY key = nullptr;
  WCHAR buffer[128] = {};
  DWORD size = sizeof(buffer);
  DWORD type = 0;

  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                    KEY_READ, &key) != ERROR_SUCCESS) {
    return L"";
  }

  LSTATUS status = RegQueryValueExW(key, L"MachineSession", nullptr, &type,
                                    (LPBYTE)buffer, &size);
  RegCloseKey(key);

  if (status != ERROR_SUCCESS || type != REG_SZ) {
    return L"";
  }

  return std::wstring(buffer);
}

// ========================================================================
// Open connection to the driver's shared memory
// ========================================================================
inline Connection open_connection() {
  Connection conn = {};
  conn.section = nullptr;
  conn.shared = nullptr;
  conn.sessionMagic = 0;

  // Discover the randomized section name
  std::wstring sectionName = discover_section_name();
  if (sectionName.empty()) {
    return conn; // Driver not loaded or registry not set
  }

  // Open the named section
  conn.section =
      OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sectionName.c_str());
  if (!conn.section) {
    return conn;
  }

  // Map it
  conn.shared = reinterpret_cast<SharedMemory *>(MapViewOfFile(
      conn.section, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemory)));
  if (!conn.shared) {
    CloseHandle(conn.section);
    conn.section = nullptr;
    return conn;
  }

  // Read the dynamic session magic
  conn.sessionMagic = conn.shared->Magic;

  return conn;
}

// Check if connection is valid
inline bool is_valid(const Connection &conn) {
  return conn.section != nullptr && conn.shared != nullptr &&
         conn.sessionMagic != 0;
}

// Close the connection
inline void close_connection(Connection &conn) {
  if (conn.shared) {
    UnmapViewOfFile(conn.shared);
    conn.shared = nullptr;
  }
  if (conn.section) {
    CloseHandle(conn.section);
    conn.section = nullptr;
  }
  conn.sessionMagic = 0;
}

// ========================================================================
// Internal: Send a request and wait for response
// ========================================================================
inline bool send_request(Connection &conn, int timeoutMs = 2000) {
  if (!is_valid(conn))
    return false;

  conn.shared->Magic = conn.sessionMagic; // Use session magic
  conn.shared->ResponseReady = 0;
  _mm_sfence();
  conn.shared->RequestReady = 1;

  auto start = std::chrono::steady_clock::now();
  while (conn.shared->ResponseReady != 1) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - start)
                       .count();
    if (elapsed > timeoutMs)
      return false;
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
  return true;
}

// ========================================================================
// Ping the driver — returns true if alive
// ========================================================================
inline bool ping(Connection &conn) {
  if (!is_valid(conn))
    return false;
  conn.shared->Operation = ops::ping;
  if (!send_request(conn))
    return false;
  return conn.shared->Status == 0 &&
         conn.shared->ResultAddress == (PVOID)(ULONG_PTR)conn.sessionMagic;
}

// ========================================================================
// Send a spoof command with identity payload
// ========================================================================
inline bool send_spoof_cmd(Connection &conn, ULONG operation,
                           const SpoofPayload *payload = nullptr) {
  if (!is_valid(conn))
    return false;
  conn.shared->Operation = operation;
  if (payload) {
    memcpy(&conn.shared->SpoofData, payload, sizeof(SpoofPayload));
  }
  if (!send_request(conn))
    return false;
  return conn.shared->Status == 0 &&
         conn.shared->ResultAddress == (PVOID)(ULONG_PTR)1;
}

// ========================================================================
// Process utilities
// ========================================================================
inline DWORD find_process_id(const wchar_t *process_name) {
  DWORD pid = 0;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry)) {
      do {
        if (_wcsicmp(entry.szExeFile, process_name) == 0) {
          pid = entry.th32ProcessID;
          break;
        }
      } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
  }
  return pid;
}

// ========================================================================
// Core driver operations
// ========================================================================

inline bool attach(Connection &conn, DWORD pid) {
  conn.shared->Operation = ops::attach;
  conn.shared->ProcessId =
      reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
  return send_request(conn);
}

inline bool detach(Connection &conn) {
  conn.shared->Operation = ops::detach;
  return send_request(conn);
}

// ========================================================================
// Memory read operations
// ========================================================================

template <typename T>
T read_memory(Connection &conn, const std::uintptr_t address) {
  T temp = {};
  conn.shared->Operation = ops::read;
  conn.shared->Target = reinterpret_cast<PVOID>(address);
  conn.shared->Buffer = &temp;
  conn.shared->Size = sizeof(T);
  if (send_request(conn))
    return temp;
  return T{};
}

inline bool read_buffer(Connection &conn, const std::uintptr_t address,
                        void *buffer, SIZE_T size) {
  conn.shared->Operation = ops::read;
  conn.shared->Target = reinterpret_cast<PVOID>(address);
  conn.shared->Buffer = buffer;
  conn.shared->Size = size;
  return send_request(conn) && conn.shared->Status == 0;
}

// ========================================================================
// Memory write operations
// ========================================================================

template <typename T>
bool write_memory(Connection &conn, const std::uintptr_t address,
                  const T &value) {
  conn.shared->Operation = ops::write;
  conn.shared->Target = reinterpret_cast<PVOID>(address);
  conn.shared->Buffer = const_cast<T *>(&value);
  conn.shared->Size = sizeof(T);
  return send_request(conn) && conn.shared->Status == 0;
}

inline bool write_buffer(Connection &conn, const std::uintptr_t address,
                         const void *buffer, SIZE_T size) {
  conn.shared->Operation = ops::write;
  conn.shared->Target = reinterpret_cast<PVOID>(address);
  conn.shared->Buffer = const_cast<PVOID>(buffer);
  conn.shared->Size = size;
  return send_request(conn) && conn.shared->Status == 0;
}

// ========================================================================
// Module base resolution
// ========================================================================

inline std::uintptr_t get_module_base(Connection &conn, DWORD pid,
                                      const wchar_t *module_name) {
  conn.shared->Operation = ops::module_base;
  conn.shared->ProcessId =
      reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
  wcsncpy_s(conn.shared->ModuleName, module_name, 255);
  conn.shared->ModuleName[255] = L'\0';
  if (send_request(conn))
    return reinterpret_cast<std::uintptr_t>(conn.shared->ResultAddress);
  return 0;
}

// ========================================================================
// Utility: Chain read (follow pointer chain)
// ========================================================================
inline std::uintptr_t read_chain(Connection &conn, std::uintptr_t base,
                                 const std::vector<std::uintptr_t> &offsets) {
  std::uintptr_t addr = base;
  for (size_t i = 0; i < offsets.size(); i++) {
    addr = read_memory<std::uintptr_t>(conn, addr + offsets[i]);
    if (addr == 0)
      return 0;
  }
  return addr;
}

} // namespace driver
