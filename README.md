# ZeraphX Kernel Driver — Spoofing Edition

## Overview
KDMapper-compatible kernel driver that provides process memory R/W and full HWID spoofing via shared memory communication. Designed to work with the HoMely Spoofer GUI.

## Features

### Core Operations
| Op Code | Name | Description |
|---------|------|-------------|
| 0 | ATTACH | Attach to a target process by PID |
| 1 | READ | Read memory from attached process |
| 2 | WRITE | Write memory to attached process |
| 3 | MODULE_BASE | Get module base address by name |
| 4 | DETACH | Detach from target process |
| 5 | PING | Check driver is alive (returns session magic) |

### Spoofing Operations
| Op Code | Name | Description |
|---------|------|-------------|
| 10 | SPOOF_SMBIOS | Patch SMBIOS registry entries (serial, UUID, baseboard) |
| 11 | SPOOF_DISK | Patch disk serial in SCSI device registry |
| 12 | SPOOF_NIC | Write new MAC to NIC registry entries |
| 13 | SPOOF_GPU | Randomize GPU adapter string |
| 14 | SPOOF_VOLUME | Randomize volume identifiers |
| 15 | SPOOF_EFI | Mask EFI/BIOS version strings |
| 16 | SPOOF_ACPI | Patch ACPI table descriptions |
| 17 | SPOOF_TPM | Disable TPM device visibility |
| 18 | SPOOF_HID | Ghost HID peripheral identifiers |
| 19 | SPOOF_WMI | Invalidate WMI hardware cache |
| 20 | SPOOF_UEFI | Mask UEFI/SecureBoot variables |
| 21 | JITTER | Randomize boot timestamps |
| 22 | CLEAN_TRACES | Erase driver artifacts from kernel |
| 23 | UNHOOK | Remove hooks and go dormant |

## Anti-Detection
- Randomized section name (`\\BaseNamedObjects\\SMxxxxxxxx`)
- Dynamic session magic from kernel entropy
- PE header zeroing after mapping
- MmUnloadedDrivers clearing
- Innocuous pool tags (`FMfn`, `bSmM`)
- Attach-Copy-Detach (no MmCopyVirtualMemory)

## Communication Protocol
1. Driver creates a named section with random name
2. Section name stored in `HKLM\SOFTWARE\Microsoft\Cryptography\MachineSession`
3. Client reads registry → opens section → maps shared memory
4. Requests via `RequestReady`/`ResponseReady` flags with `_mm_sfence()`

## Building
Requires Windows Driver Kit (WDK). Build as kernel driver (Release x64).

## Deploying
Map with KDMapper or DigiMapper:
```
DigiMapper.exe ZeraphX.sys
```

## Files
- `driver/driver.c` — Main driver implementation (all operations)
- `driver/driver_codes.h` — IOCTL definitions
- `driver/driver_config.h` — Pool tags and constants
- `driver/stealth.h` — Anti-forensic trace clearing
- `client/zeraphx_driver.h` — Userland client library
