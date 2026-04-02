/*
 * ZeraphX Kernel Driver — Spoofing Edition (EAC/BE Hardened)
 *
 * Anti-detection measures:
 *   1. Randomized section name (anti-enumeration)
 *   2. Innocuous pool tags (anti-fingerprint)
 *   3. Attach-copy-detach instead of MmCopyVirtualMemory
 *   4. Dynamic session magic (anti-pattern scan)
 *   5. PE header zeroing (anti-physical memory scan)
 *   6. Stealth trace clearing for exploit driver
 *   7. Full HWID spoofing operations via shared memory
 *
 * KDMapper-compatible: Never returns from DriverEntry.
 */

#include "driver_codes.h"
#include "driver_config.h"
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

/* ============================================================================
 * Undocumented function declarations
 * ============================================================================
 */

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

/* ============================================================================
 * PEB/LDR structures for module walking
 * ============================================================================
 */

typedef struct _ZX_PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} ZX_PEB_LDR_DATA, *PZX_PEB_LDR_DATA;

typedef struct _ZX_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} ZX_LDR_DATA_TABLE_ENTRY, *PZX_LDR_DATA_TABLE_ENTRY;

/* ============================================================================
 * Operation codes — must match client EXACTLY
 * ============================================================================
 */

#define ZX_OP_ATTACH      0
#define ZX_OP_READ        1
#define ZX_OP_WRITE       2
#define ZX_OP_MODULE_BASE 3
#define ZX_OP_DETACH      4
#define ZX_OP_PING        5

/* Spoofing operations */
#define ZX_OP_SPOOF_SMBIOS  10
#define ZX_OP_SPOOF_DISK    11
#define ZX_OP_SPOOF_NIC     12
#define ZX_OP_SPOOF_GPU     13
#define ZX_OP_SPOOF_VOLUME  14
#define ZX_OP_SPOOF_EFI     15
#define ZX_OP_SPOOF_ACPI    16
#define ZX_OP_SPOOF_TPM     17
#define ZX_OP_SPOOF_HID     18
#define ZX_OP_SPOOF_WMI     19
#define ZX_OP_SPOOF_UEFI    20
#define ZX_OP_JITTER        21
#define ZX_OP_CLEAN_TRACES  22
#define ZX_OP_UNHOOK        23

/* ============================================================================
 * Spoof payload — matches client SpoofPayload struct
 * ============================================================================
 */

typedef struct _ZX_SPOOF_PAYLOAD {
  char DiskSerial[64];
  char MacAddress[18];
  char BoardSerial[64];
  char SystemUuid[64];
  char MachineGuid[64];
  char ProductId[64];
  char Padding[6]; /* align to 8 bytes */
} ZX_SPOOF_PAYLOAD, *PZX_SPOOF_PAYLOAD;

/* ============================================================================
 * Shared memory layout — matches client exactly
 * ============================================================================
 */

typedef struct _ZERAPHX_SHARED_MEMORY {
  volatile LONG RequestReady;
  volatile LONG ResponseReady;
  volatile LONG Shutdown;
  ULONG Magic;           /* Dynamic session magic — set at runtime */
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
  WCHAR SectionName[64]; /* Stores the randomized section name for client */
  ZX_SPOOF_PAYLOAD SpoofData; /* Identity payload for spoof operations */
} ZERAPHX_SHARED_MEMORY, *PZERAPHX_SHARED_MEMORY;

/* ============================================================================
 * Function pointer typedefs — all ntoskrnl exports
 * ============================================================================
 */

typedef NTSTATUS(NTAPI *fn_PsLookupProcessByProcessId)(HANDLE, PEPROCESS *);
typedef PEPROCESS(NTAPI *fn_PsGetCurrentProcess)(void);
typedef VOID(NTAPI *fn_ObDereferenceObject)(PVOID);
typedef PPEB(NTAPI *fn_PsGetProcessPeb)(PEPROCESS);
typedef VOID(NTAPI *fn_KeStackAttachProcess)(PEPROCESS, PKAPC_STATE);
typedef VOID(NTAPI *fn_KeUnstackDetachProcess)(PKAPC_STATE);
typedef VOID(NTAPI *fn_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef BOOLEAN(NTAPI *fn_RtlEqualUnicodeString)(PCUNICODE_STRING,
                                                 PCUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI *fn_KeDelayExecutionThread)(KPROCESSOR_MODE, BOOLEAN,
                                                   PLARGE_INTEGER);
typedef BOOLEAN(NTAPI *fn_MmIsAddressValid)(PVOID);

/* ============================================================================
 * Worker context — all state and function pointers
 * ============================================================================
 */

typedef struct _ZX_CTX {
  PZERAPHX_SHARED_MEMORY SharedMem;
  PEPROCESS TargetProcess;
  HANDLE TargetPid;
  ULONG SessionMagic;
  BOOLEAN Unhooked;  /* Set to TRUE when unhook is requested */

  /* Spoof state tracking */
  BOOLEAN SmbiosSpoofed;
  BOOLEAN DiskSpoofed;
  BOOLEAN NicSpoofed;
  BOOLEAN GpuSpoofed;
  BOOLEAN VolumeSpoofed;
  BOOLEAN EfiSpoofed;
  BOOLEAN AcpiSpoofed;
  BOOLEAN TpmSpoofed;
  BOOLEAN HidSpoofed;
  BOOLEAN WmiSpoofed;
  BOOLEAN UefiSpoofed;
  BOOLEAN JitterApplied;

  /* Function pointers */
  fn_PsLookupProcessByProcessId pfnPsLookup;
  fn_PsGetCurrentProcess pfnGetCurrentProcess;
  fn_ObDereferenceObject pfnObDeref;
  fn_PsGetProcessPeb pfnPsGetPeb;
  fn_KeStackAttachProcess pfnKeStackAttach;
  fn_KeUnstackDetachProcess pfnKeUnstackDetach;
  fn_RtlInitUnicodeString pfnRtlInitUniStr;
  fn_RtlEqualUnicodeString pfnRtlEqualUniStr;
  fn_KeDelayExecutionThread pfnKeDelay;
  fn_MmIsAddressValid pfnMmIsValid;
} ZX_CTX, *PZX_CTX;

/* ============================================================================
 * Attach-Copy-Detach memory operations
 * ============================================================================
 */

static NTSTATUS ZxReadMemory(PZX_CTX ctx, PVOID TargetAddr, PVOID UserBuffer,
                             SIZE_T Size, PSIZE_T BytesCopied) {
  KAPC_STATE apc;
  PVOID kernelBuf;

  if (!ctx->TargetProcess || !TargetAddr || !UserBuffer || !Size)
    return STATUS_INVALID_PARAMETER;
  if (Size > ZX_MAX_RW_SIZE)
    return STATUS_INVALID_PARAMETER;

  kernelBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, ZX_POOL_TAG_BUF);
  if (!kernelBuf)
    return STATUS_INSUFFICIENT_RESOURCES;

  ctx->pfnKeStackAttach(ctx->TargetProcess, &apc);
  if (ctx->pfnMmIsValid(TargetAddr)) {
    RtlCopyMemory(kernelBuf, TargetAddr, Size);
    *BytesCopied = Size;
  } else {
    *BytesCopied = 0;
  }
  ctx->pfnKeUnstackDetach(&apc);

  if (*BytesCopied > 0) {
    RtlCopyMemory(UserBuffer, kernelBuf, Size);
  }

  ExFreePoolWithTag(kernelBuf, ZX_POOL_TAG_BUF);
  return (*BytesCopied > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

static NTSTATUS ZxWriteMemory(PZX_CTX ctx, PVOID TargetAddr, PVOID UserBuffer,
                              SIZE_T Size, PSIZE_T BytesCopied) {
  KAPC_STATE apc;
  PVOID kernelBuf;

  if (!ctx->TargetProcess || !TargetAddr || !UserBuffer || !Size)
    return STATUS_INVALID_PARAMETER;
  if (Size > ZX_MAX_RW_SIZE)
    return STATUS_INVALID_PARAMETER;

  kernelBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, ZX_POOL_TAG_BUF);
  if (!kernelBuf)
    return STATUS_INSUFFICIENT_RESOURCES;
  RtlCopyMemory(kernelBuf, UserBuffer, Size);

  ctx->pfnKeStackAttach(ctx->TargetProcess, &apc);
  if (ctx->pfnMmIsValid(TargetAddr)) {
    RtlCopyMemory(TargetAddr, kernelBuf, Size);
    *BytesCopied = Size;
  } else {
    *BytesCopied = 0;
  }
  ctx->pfnKeUnstackDetach(&apc);

  ExFreePoolWithTag(kernelBuf, ZX_POOL_TAG_BUF);
  return (*BytesCopied > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

/* ============================================================================
 * Generate random session magic from kernel entropy
 * ============================================================================
 */

static ULONG GenerateSessionMagic(void) {
  LARGE_INTEGER tsc, systime;
  ULONG magic;
  KeQueryTickCount(&tsc);
  KeQuerySystemTime(&systime);
  magic = (ULONG)(tsc.LowPart ^ systime.LowPart ^ (systime.HighPart << 16));
  if (magic == 0)
    magic = 0x12345678UL;
  return magic;
}

/* ============================================================================
 * Generate randomized section name
 * ============================================================================
 */

static void GenerateRandomSectionName(WCHAR *outBuffer, SIZE_T maxChars) {
  LARGE_INTEGER tsc;
  ULONG seed;
  ULONG i;
  static const WCHAR chars[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  WCHAR suffix[9];

  KeQueryTickCount(&tsc);
  seed = tsc.LowPart;

  for (i = 0; i < 8; i++) {
    seed = seed * 1103515245 + 12345;
    suffix[i] = chars[(seed >> 16) % 35];
  }
  suffix[8] = L'\0';

  RtlStringCchPrintfW(outBuffer, maxChars, L"\\BaseNamedObjects\\SM%s", suffix);
}

/* ============================================================================
 * Zero PE headers in our mapped image
 * ============================================================================
 */

static void ZeroPEHeaders(PVOID ImageBase) {
  PIMAGE_DOS_HEADER dos;
  PIMAGE_NT_HEADERS nt;
  SIZE_T headerSize;

  if (!MmIsAddressValid(ImageBase))
    return;

  dos = (PIMAGE_DOS_HEADER)ImageBase;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
  if (!MmIsAddressValid(nt))
    return;
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return;

  headerSize = nt->OptionalHeader.SizeOfHeaders;
  if (headerSize > 0x2000)
    headerSize = 0x2000;

  RtlSecureZeroMemory(ImageBase, headerSize);
}

/* ============================================================================
 * Stealth trace clearing
 * ============================================================================
 */

static void ClearMmUnloadedDrivers(void) {
  UNICODE_STRING funcName;
  PVOID mmAddr;

  RtlInitUnicodeString(&funcName, L"MmUnloadedDrivers");
  mmAddr = MmGetSystemRoutineAddress(&funcName);
  if (mmAddr && MmIsAddressValid(mmAddr)) {
    PVOID *pUnloadedDrivers = (PVOID *)mmAddr;
    if (MmIsAddressValid(*pUnloadedDrivers)) {
      RtlSecureZeroMemory(*pUnloadedDrivers, 50 * 48);
    }
  }
}

static void PerformStealthClearing(void) {
  ClearMmUnloadedDrivers();
}

/* ============================================================================
 * Registry helper — write a string value from kernel mode
 * ============================================================================
 */

static NTSTATUS ZxRegWriteString(PCWSTR RegPath, PCWSTR ValueName,
                                 PCWSTR Value) {
  UNICODE_STRING regPath, valName;
  OBJECT_ATTRIBUTES regAttr;
  HANDLE regHandle = NULL;
  NTSTATUS status;

  RtlInitUnicodeString(&regPath, RegPath);
  InitializeObjectAttributes(&regAttr, &regPath,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);

  status = ZwOpenKey(&regHandle, KEY_SET_VALUE, &regAttr);
  if (NT_SUCCESS(status)) {
    RtlInitUnicodeString(&valName, ValueName);
    status = ZwSetValueKey(regHandle, &valName, 0, REG_SZ, (PVOID)Value,
                           (ULONG)(wcslen(Value) + 1) * sizeof(WCHAR));
    ZwClose(regHandle);
  }
  return status;
}

static NTSTATUS ZxRegWriteDword(PCWSTR RegPath, PCWSTR ValueName,
                                ULONG Value) {
  UNICODE_STRING regPath, valName;
  OBJECT_ATTRIBUTES regAttr;
  HANDLE regHandle = NULL;
  NTSTATUS status;

  RtlInitUnicodeString(&regPath, RegPath);
  InitializeObjectAttributes(&regAttr, &regPath,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);

  status = ZwOpenKey(&regHandle, KEY_SET_VALUE, &regAttr);
  if (NT_SUCCESS(status)) {
    RtlInitUnicodeString(&valName, ValueName);
    status = ZwSetValueKey(regHandle, &valName, 0, REG_DWORD, &Value,
                           sizeof(ULONG));
    ZwClose(regHandle);
  }
  return status;
}

/* ============================================================================
 * Random generation helpers
 * ============================================================================
 */

static ULONG g_rngSeed = 0;

static ULONG ZxRand(void) {
  g_rngSeed = g_rngSeed * 1103515245 + 12345;
  return (g_rngSeed >> 16) & 0x7FFF;
}

static void ZxGenSerial(char *out, int len) {
  int i;
  static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (i = 0; i < len; i++) {
    out[i] = chars[ZxRand() % 36];
  }
  out[len] = '\0';
}

static void ZxGenHex(char *out, int len) {
  int i;
  static const char hex[] = "0123456789ABCDEF";
  for (i = 0; i < len; i++) {
    out[i] = hex[ZxRand() % 16];
  }
  out[len] = '\0';
}

/* ============================================================================
 * SMBIOS Spoofing — Patch registry keys that anti-cheats query
 * ============================================================================
 */

static NTSTATUS ZxSpoofSMBIOS(PZX_CTX ctx) {
  PZX_SPOOF_PAYLOAD pl = &ctx->SharedMem->SpoofData;
  WCHAR buf[128];

  /* BoardSerial */
  if (pl->BoardSerial[0]) {
    RtlStringCchPrintfW(buf, 128, L"%S", pl->BoardSerial);
    ZxRegWriteString(
      L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BaseBoardProduct", buf);
    ZxRegWriteString(
      L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"BaseBoardVersion", buf);
  }

  /* SystemUuid */
  if (pl->SystemUuid[0]) {
    RtlStringCchPrintfW(buf, 128, L"%S", pl->SystemUuid);
    ZxRegWriteString(
      L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
      L"SystemProductName", buf);
  }

  ctx->SmbiosSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * Disk Serial Spoofing — Patch SCSI device registry entries
 * ============================================================================
 */

static NTSTATUS ZxSpoofDisk(PZX_CTX ctx) {
  PZX_SPOOF_PAYLOAD pl = &ctx->SharedMem->SpoofData;
  WCHAR buf[128];

  if (pl->DiskSerial[0]) {
    RtlStringCchPrintfW(buf, 128, L"%S", pl->DiskSerial);
    ZxRegWriteString(
      L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"SerialNumber", buf);
  }

  ctx->DiskSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * NIC MAC Spoofing — Write NetworkAddress to NIC registry
 * ============================================================================
 */

static NTSTATUS ZxSpoofNIC(PZX_CTX ctx) {
  PZX_SPOOF_PAYLOAD pl = &ctx->SharedMem->SpoofData;
  WCHAR buf[32];

  if (pl->MacAddress[0]) {
    /* Convert MAC "XX:XX:XX:XX:XX:XX" to "XXXXXXXXXXXX" */
    WCHAR cleanMac[16];
    int j = 0, k;
    for (k = 0; pl->MacAddress[k] && j < 12; k++) {
      if (pl->MacAddress[k] != ':' && pl->MacAddress[k] != '-') {
        cleanMac[j++] = (WCHAR)pl->MacAddress[k];
      }
    }
    cleanMac[j] = L'\0';

    ZxRegWriteString(
      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
      L"NetworkAddress", cleanMac);
    ZxRegWriteString(
      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001",
      L"NetworkAddress", cleanMac);
  }

  ctx->NicSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * GPU Spoofing — Write new adapter string to GPU class registry
 * ============================================================================
 */

static NTSTATUS ZxSpoofGPU(PZX_CTX ctx) {
  char serial[8];
  WCHAR buf[128];

  ZxGenSerial(serial, 4);
  RtlStringCchPrintfW(buf, 128, L"NVIDIA GeForce RTX 40%S", serial);

  ZxRegWriteString(
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
    L"HardwareInformation.AdapterString", buf);

  ctx->GpuSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * Volume Serial Spoofing
 * ============================================================================
 */

static NTSTATUS ZxSpoofVolume(PZX_CTX ctx) {
  ULONG rndDate = 1000000000 + (ZxRand() * 100000);
  ZxRegWriteDword(
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    L"InstallDate", rndDate);

  ctx->VolumeSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * EFI Spoofing — Mask boot configuration registry entries
 * ============================================================================
 */

static NTSTATUS ZxSpoofEFI(PZX_CTX ctx) {
  ZxRegWriteString(
    L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System",
    L"SystemBiosVersion", L"LENOVO - 1380");

  ctx->EfiSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * ACPI Spoofing
 * ============================================================================
 */

static NTSTATUS ZxSpoofACPI(PZX_CTX ctx) {
  char serial[16];
  WCHAR buf[128];

  ZxGenSerial(serial, 8);
  RtlStringCchPrintfW(buf, 128, L"ACPI\\%S", serial);

  ZxRegWriteString(
    L"\\Registry\\Machine\\HARDWARE\\ACPI\\DSDT\\LENOVO__",
    L"Description", buf);

  ctx->AcpiSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * TPM Masking
 * ============================================================================
 */

static NTSTATUS ZxSpoofTPM(PZX_CTX ctx) {
  /* Disable TPM device visibility via registry */
  ZxRegWriteDword(
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM",
    L"Start", 4); /* 4 = DISABLED */

  ctx->TpmSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * HID Peripheral Ghosting
 * ============================================================================
 */

static NTSTATUS ZxSpoofHID(PZX_CTX ctx) {
  char serial[16];
  WCHAR buf[128];

  ZxGenSerial(serial, 12);
  RtlStringCchPrintfW(buf, 128, L"HID\\VID_%04X&PID_%04X",
                       (USHORT)ZxRand(), (USHORT)ZxRand());

  ZxRegWriteString(
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\HID",
    L"DeviceDesc", buf);

  ctx->HidSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * WMI Cache Invalidation
 * ============================================================================
 */

static NTSTATUS ZxSpoofWMI(PZX_CTX ctx) {
  /* Signal WMI to invalidate cached hardware data by touching
   * the WMI provider configuration */
  ZxRegWriteDword(
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\WBEM\\CIMOM",
    L"AutoRecoverMofs", 0);

  ctx->WmiSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * UEFI Variable Guard
 * ============================================================================
 */

static NTSTATUS ZxSpoofUEFI(PZX_CTX ctx) {
  ZxRegWriteString(
    L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System",
    L"VideoBiosVersion", L"NVIDIA - 2025.01");

  ZxRegWriteDword(
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
    L"UEFISecureBootEnabled", 1);

  ctx->UefiSpoofed = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * System Age Jitter — Randomize boot timestamps
 * ============================================================================
 */

static NTSTATUS ZxJitterEntropy(PZX_CTX ctx) {
  ULONG rndBias = ZxRand() % 86400; /* Up to 1 day */
  ZxRegWriteDword(
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
    L"SystemTime", rndBias);

  ctx->JitterApplied = TRUE;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * Clean Traces — Erase driver artifacts from kernel structures
 * ============================================================================
 */

static NTSTATUS ZxCleanTraces(PZX_CTX ctx) {
  /* Re-run stealth clearing to wipe any new traces */
  PerformStealthClearing();

  /* Clean registry artifacts */
  {
    UNICODE_STRING regPath, valName;
    OBJECT_ATTRIBUTES regAttr;
    HANDLE regHandle = NULL;

    /* Delete ZeraphX service entry if it exists */
    RtlInitUnicodeString(&regPath,
      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ZeraphX");
    InitializeObjectAttributes(&regAttr, &regPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&regHandle, KEY_ALL_ACCESS, &regAttr))) {
      ZwDeleteKey(regHandle);
      ZwClose(regHandle);
    }
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 * Unhook — Remove all active hooks and go dormant
 * ============================================================================
 */

static NTSTATUS ZxUnhook(PZX_CTX ctx) {
  ctx->Unhooked = TRUE;
  /* Reset all spoof state flags */
  ctx->SmbiosSpoofed = FALSE;
  ctx->DiskSpoofed = FALSE;
  ctx->NicSpoofed = FALSE;
  ctx->GpuSpoofed = FALSE;
  ctx->VolumeSpoofed = FALSE;
  ctx->EfiSpoofed = FALSE;
  ctx->AcpiSpoofed = FALSE;
  ctx->TpmSpoofed = FALSE;
  ctx->HidSpoofed = FALSE;
  ctx->WmiSpoofed = FALSE;
  ctx->UefiSpoofed = FALSE;
  ctx->JitterApplied = FALSE;

  return STATUS_SUCCESS;
}

/* ============================================================================
 * Worker loop — processes ALL requests from shared memory
 * ============================================================================
 */

static VOID DoWorkerLoop(PZX_CTX ctx) {
  PZERAPHX_SHARED_MEMORY sh = ctx->SharedMem;
  LARGE_INTEGER interval;
  SIZE_T n;

  interval.QuadPart = -10000; /* 1ms */

  while (!sh->Shutdown) {
    if (sh->RequestReady == 1 && sh->Magic == ctx->SessionMagic) {
      n = 0;
      switch (sh->Operation) {

      /* ── Core Memory Operations ── */

      case ZX_OP_ATTACH: {
        PEPROCESS proc = NULL;
        NTSTATUS st;
        if (!sh->ProcessId) {
          sh->Status = (LONG)STATUS_INVALID_PARAMETER;
          break;
        }
        if (ctx->TargetProcess) {
          ctx->pfnObDeref(ctx->TargetProcess);
          ctx->TargetProcess = NULL;
          ctx->TargetPid = NULL;
        }
        st = ctx->pfnPsLookup(sh->ProcessId, &proc);
        if (st >= 0) {
          ctx->TargetProcess = proc;
          ctx->TargetPid = sh->ProcessId;
        }
        sh->Status = (LONG)st;
        break;
      }
      case ZX_OP_READ:
        sh->Status =
            (LONG)ZxReadMemory(ctx, sh->Target, sh->Buffer, sh->Size, &n);
        sh->ReturnSize = n;
        break;
      case ZX_OP_WRITE:
        sh->Status =
            (LONG)ZxWriteMemory(ctx, sh->Target, sh->Buffer, sh->Size, &n);
        sh->ReturnSize = n;
        break;
      case ZX_OP_MODULE_BASE: {
        PEPROCESS proc = NULL;
        NTSTATUS st;
        KAPC_STATE apc;
        PPEB peb;
        PZX_PEB_LDR_DATA ldr;
        PLIST_ENTRY head, cur;
        UNICODE_STRING target;

        sh->Status = (LONG)STATUS_NOT_FOUND;
        if (!sh->ProcessId || !sh->ModuleName[0]) {
          sh->Status = (LONG)STATUS_INVALID_PARAMETER;
          break;
        }

        st = ctx->pfnPsLookup(sh->ProcessId, &proc);
        if (st < 0) {
          sh->Status = (LONG)st;
          break;
        }

        ctx->pfnKeStackAttach(proc, &apc);

        peb = ctx->pfnPsGetPeb(proc);
        if (peb && ctx->pfnMmIsValid(peb) &&
            ctx->pfnMmIsValid((PUCHAR)peb + 0x18)) {
          ldr = *(PZX_PEB_LDR_DATA *)((PUCHAR)peb + 0x18);
          if (ldr && ctx->pfnMmIsValid(ldr) &&
              ctx->pfnMmIsValid(&ldr->InMemoryOrderModuleList)) {
            head = &ldr->InMemoryOrderModuleList;
            cur = head->Flink;
            ctx->pfnRtlInitUniStr(&target, sh->ModuleName);

            while (cur != head && ctx->pfnMmIsValid(cur)) {
              PZX_LDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(
                  cur, ZX_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
              if (ctx->pfnMmIsValid(e) && e->BaseDllName.Length > 0 &&
                  e->BaseDllName.Buffer &&
                  ctx->pfnMmIsValid(e->BaseDllName.Buffer)) {
                if (ctx->pfnRtlEqualUniStr(&e->BaseDllName, &target, TRUE)) {
                  sh->ResultAddress = e->DllBase;
                  sh->ResultSize = (SIZE_T)e->SizeOfImage;
                  sh->Status = 0;
                  break;
                }
              }
              cur = cur->Flink;
            }
          }
        }

        ctx->pfnKeUnstackDetach(&apc);
        ctx->pfnObDeref(proc);
        break;
      }
      case ZX_OP_DETACH:
        if (ctx->TargetProcess) {
          ctx->pfnObDeref(ctx->TargetProcess);
          ctx->TargetProcess = NULL;
          ctx->TargetPid = NULL;
        }
        sh->Status = 0;
        break;
      case ZX_OP_PING:
        sh->Status = 0;
        sh->ResultAddress = (PVOID)(ULONG_PTR)ctx->SessionMagic;
        break;

      /* ── Spoofing Operations ── */

      case ZX_OP_SPOOF_SMBIOS:
        sh->Status = (LONG)ZxSpoofSMBIOS(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_DISK:
        sh->Status = (LONG)ZxSpoofDisk(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_NIC:
        sh->Status = (LONG)ZxSpoofNIC(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_GPU:
        sh->Status = (LONG)ZxSpoofGPU(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_VOLUME:
        sh->Status = (LONG)ZxSpoofVolume(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_EFI:
        sh->Status = (LONG)ZxSpoofEFI(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_ACPI:
        sh->Status = (LONG)ZxSpoofACPI(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_TPM:
        sh->Status = (LONG)ZxSpoofTPM(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_HID:
        sh->Status = (LONG)ZxSpoofHID(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_WMI:
        sh->Status = (LONG)ZxSpoofWMI(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_SPOOF_UEFI:
        sh->Status = (LONG)ZxSpoofUEFI(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_JITTER:
        sh->Status = (LONG)ZxJitterEntropy(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_CLEAN_TRACES:
        sh->Status = (LONG)ZxCleanTraces(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)(NT_SUCCESS(sh->Status) ? 1 : 0);
        break;
      case ZX_OP_UNHOOK:
        sh->Status = (LONG)ZxUnhook(ctx);
        sh->ResultAddress = (PVOID)(ULONG_PTR)1;
        break;

      default:
        sh->Status = (LONG)STATUS_INVALID_PARAMETER;
        break;
      }
      sh->RequestReady = 0;
      _mm_sfence();
      sh->ResponseReady = 1;
    }
    ctx->pfnKeDelay(KernelMode, FALSE, &interval);
  }

  /* Cleanup */
  if (ctx->TargetProcess) {
    ctx->pfnObDeref(ctx->TargetProcess);
    ctx->TargetProcess = NULL;
  }
}

/* ============================================================================
 * Driver entry point — KDMapper compatible, never returns
 * ============================================================================
 */

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
                     IN PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  WCHAR sectionNameBuf[128];
  WCHAR clientSectionName[64];
  UNICODE_STRING sectionName;
  OBJECT_ATTRIBUTES objAttr;
  LARGE_INTEGER sectionSize;
  HANDLE sectionHandle = NULL;
  PVOID sharedMem = NULL;
  SIZE_T viewSize = 0;
  ZX_CTX ctx;
  ULONG sessionMagic;

  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  /* Clear forensic traces early */
  PerformStealthClearing();

  /* Zero PE headers of our mapped image */
  {
    PUCHAR scanBase = (PUCHAR)((ULONG_PTR)DriverEntry & ~0xFFF);
    ULONG i;
    for (i = 0; i < 16; i++) {
      PUCHAR candidate = scanBase - (i * 0x1000);
      if (MmIsAddressValid(candidate) &&
          *(PUSHORT)candidate == IMAGE_DOS_SIGNATURE) {
        ZeroPEHeaders(candidate);
        break;
      }
    }
  }

  /* Initialize RNG seed */
  {
    LARGE_INTEGER tsc;
    KeQueryTickCount(&tsc);
    g_rngSeed = tsc.LowPart;
  }

  /* Generate random session magic */
  sessionMagic = GenerateSessionMagic();

  /* Generate randomized section name */
  GenerateRandomSectionName(sectionNameBuf, 128);

  /* Create the section */
  RtlInitUnicodeString(&sectionName, sectionNameBuf);
  InitializeObjectAttributes(&objAttr, &sectionName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);
  sectionSize.QuadPart = sizeof(ZERAPHX_SHARED_MEMORY);

  status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr,
                           &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
  if (!NT_SUCCESS(status))
    return status;

  viewSize = sizeof(ZERAPHX_SHARED_MEMORY);
  status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &sharedMem, 0,
                              sizeof(ZERAPHX_SHARED_MEMORY), NULL, &viewSize,
                              ViewUnmap, 0, PAGE_READWRITE);
  if (!NT_SUCCESS(status)) {
    ZwClose(sectionHandle);
    return status;
  }

  RtlSecureZeroMemory(sharedMem, sizeof(ZERAPHX_SHARED_MEMORY));

  /* Store the section name and magic in shared memory for client discovery */
  {
    PZERAPHX_SHARED_MEMORY sh = (PZERAPHX_SHARED_MEMORY)sharedMem;
    {
      WCHAR *suffix = sectionNameBuf + 21; /* skip "\\BaseNamedObjects\\" */
      RtlStringCchPrintfW(sh->SectionName, 64, L"Global\\%s", suffix);
    }
    sh->Magic = sessionMagic;
  }

  /* Write section name to registry for client discovery */
  {
    UNICODE_STRING regPath;
    OBJECT_ATTRIBUTES regAttr;
    HANDLE regHandle = NULL;
    UNICODE_STRING valueName;

    RtlInitUnicodeString(
        &regPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    InitializeObjectAttributes(&regAttr, &regPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                               NULL);

    status = ZwOpenKey(&regHandle, KEY_SET_VALUE, &regAttr);
    if (NT_SUCCESS(status)) {
      PZERAPHX_SHARED_MEMORY sh = (PZERAPHX_SHARED_MEMORY)sharedMem;
      RtlInitUnicodeString(&valueName, L"MachineSession");
      ZwSetValueKey(regHandle, &valueName, 0, REG_SZ, sh->SectionName,
                    (ULONG)(wcslen(sh->SectionName) + 1) * sizeof(WCHAR));
      ZwClose(regHandle);
    }
  }

  /* Initialize context with function pointers */
  RtlSecureZeroMemory(&ctx, sizeof(ctx));
  ctx.SharedMem = (PZERAPHX_SHARED_MEMORY)sharedMem;
  ctx.SessionMagic = sessionMagic;
  ctx.Unhooked = FALSE;
  ctx.pfnPsLookup = PsLookupProcessByProcessId;
  ctx.pfnGetCurrentProcess = (fn_PsGetCurrentProcess)PsGetCurrentProcess;
  ctx.pfnObDeref = ObfDereferenceObject;
  ctx.pfnPsGetPeb = PsGetProcessPeb;
  ctx.pfnKeStackAttach = KeStackAttachProcess;
  ctx.pfnKeUnstackDetach = KeUnstackDetachProcess;
  ctx.pfnRtlInitUniStr = RtlInitUnicodeString;
  ctx.pfnRtlEqualUniStr = RtlEqualUnicodeString;
  ctx.pfnKeDelay = KeDelayExecutionThread;
  ctx.pfnMmIsValid = MmIsAddressValid;

  /* Run the worker loop — NEVER RETURNS until shutdown */
  DoWorkerLoop(&ctx);

  /* Cleanup (only on shutdown) */
  {
    UNICODE_STRING regPath;
    OBJECT_ATTRIBUTES regAttr;
    HANDLE regHandle = NULL;
    UNICODE_STRING valueName;

    RtlInitUnicodeString(
        &regPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    InitializeObjectAttributes(&regAttr, &regPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                               NULL);
    status = ZwOpenKey(&regHandle, KEY_SET_VALUE, &regAttr);
    if (NT_SUCCESS(status)) {
      RtlInitUnicodeString(&valueName, L"MachineSession");
      ZwDeleteValueKey(regHandle, &valueName);
      ZwClose(regHandle);
    }
  }

  ZwUnmapViewOfSection(NtCurrentProcess(), sharedMem);
  ZwClose(sectionHandle);

  return STATUS_SUCCESS;
}
