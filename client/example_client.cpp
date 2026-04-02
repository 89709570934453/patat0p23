//
// ZeraphX Driver - Example Client (Shared Memory Communication)
// Demonstrates how to use the ZeraphX kernel driver for memory R/W
//

#include "zeraphx_driver.h"
#include <Windows.h>
#include <iostream>
#include <vector>


int main() {
  std::wcout << L"========================================" << std::endl;
  std::wcout << L"  ZeraphX Driver - Example Client" << std::endl;
  std::wcout << L"  (Shared Memory Communication)" << std::endl;
  std::wcout << L"========================================" << std::endl;
  std::wcout << std::endl;

  // Step 1: Open connection to the driver's shared memory
  auto conn = driver::open_connection();
  if (!driver::is_valid(conn)) {
    std::cerr << "[-] Failed to open shared memory!" << std::endl;
    std::cerr << "    Make sure the driver is loaded via KDMapper."
              << std::endl;
    std::cerr << "    Error code: " << GetLastError() << std::endl;
    return 1;
  }
  std::cout << "[+] Connected to driver via shared memory." << std::endl;

  // Step 2: Find target process
  const wchar_t *targetProcess = L"cs2.exe";
  DWORD pid = driver::find_process_id(targetProcess);

  if (pid == 0) {
    std::wcerr << L"[-] Could not find process: " << targetProcess << std::endl;
    driver::close_connection(conn);
    return 1;
  }
  std::wcout << L"[+] Found " << targetProcess << L" (PID: " << pid << L")"
             << std::endl;

  // Step 3: Attach to the process
  if (!driver::attach(conn, pid)) {
    std::cerr << "[-] Failed to attach to process!" << std::endl;
    driver::close_connection(conn);
    return 1;
  }
  std::cout << "[+] Attached to process." << std::endl;

  // Step 4: Get module base address
  std::uintptr_t clientBase = driver::get_module_base(conn, pid, L"client.dll");
  if (clientBase == 0) {
    std::cerr << "[-] Failed to get client.dll base address!" << std::endl;
    driver::detach(conn);
    driver::close_connection(conn);
    return 1;
  }
  std::cout << "[+] client.dll base: 0x" << std::hex << clientBase << std::dec
            << std::endl;

  // Step 5: Example memory read
  constexpr std::uintptr_t EXAMPLE_OFFSET = 0x100;
  int value = driver::read_memory<int>(conn, clientBase + EXAMPLE_OFFSET);
  std::cout << "[+] Value at client.dll + 0x" << std::hex << EXAMPLE_OFFSET
            << " = " << std::dec << value << std::endl;

  // Step 6: Example pointer chain read
  // std::vector<std::uintptr_t> offsets = { 0x10, 0x20, 0x30 };
  // std::uintptr_t finalAddr = driver::read_chain(conn, clientBase + 0x50,
  // offsets);

  // Step 7: Example memory write
  // driver::write_memory<int>(conn, clientBase + SOME_OFFSET, 1337);

  std::cout << std::endl;
  std::cout << "[+] All operations completed successfully!" << std::endl;
  std::cout << "[*] Press Enter to detach and exit..." << std::endl;
  std::cin.get();

  // Cleanup
  driver::detach(conn);
  driver::close_connection(conn);

  return 0;
}
