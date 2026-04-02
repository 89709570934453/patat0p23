#pragma once

/*
 * ZeraphX Stealth Module
 * Clears driver traces from kernel structures to evade anti-cheat detection
 */

#include <ntifs.h>
#include <ntimage.h>

/*
 * Undocumented structures for trace clearing
 */

typedef struct _MM_UNLOADED_DRIVER {
  UNICODE_STRING Name;
  PVOID ModuleStart;
  PVOID ModuleEnd;
  LARGE_INTEGER UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

typedef struct _PIDDB_CACHE_ENTRY {
  LIST_ENTRY List;
  UNICODE_STRING DriverName;
  ULONG TimeDateStamp;
  NTSTATUS LoadStatus;
  CHAR _pad[16];
} PIDDB_CACHE_ENTRY, *PPIDDB_CACHE_ENTRY;

typedef struct _HASH_BUCKET_ENTRY {
  struct _HASH_BUCKET_ENTRY *Next;
  UNICODE_STRING DriverName;
  ULONG CertHash[5];
} HASH_BUCKET_ENTRY, *PHASH_BUCKET_ENTRY;

/* Forward declaration for ZwQuerySystemInformation */
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass,
                                                 PVOID SystemInformation,
                                                 ULONG SystemInformationLength,
                                                 PULONG ReturnLength);

/*
 * Pattern scanning in kernel memory
 */
static PVOID FindPattern(PVOID BaseAddress, SIZE_T Size, const UCHAR *Pattern,
                         const CHAR *Mask, SIZE_T PatternSize) {
  SIZE_T i, j;
  for (i = 0; i < Size - PatternSize; i++) {
    BOOLEAN found = TRUE;
    for (j = 0; j < PatternSize; j++) {
      if (Mask[j] == 'x' && ((PUCHAR)BaseAddress)[i + j] != Pattern[j]) {
        found = FALSE;
        break;
      }
    }
    if (found) {
      return (PVOID)((PUCHAR)BaseAddress + i);
    }
  }
  return NULL;
}

/*
 * Get ntoskrnl.exe base address and size
 */
static PVOID GetKernelBase(PULONG pSize) {
  NTSTATUS status;
  ULONG bytes = 0;
  PVOID kernelBase = NULL;
  PVOID buffer;

  typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
  } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

  typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
  } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

  /* Query required buffer size */
  status = ZwQuerySystemInformation(11 /* SystemModuleInformation */, NULL, 0,
                                    &bytes);
  if (bytes == 0)
    return NULL;

  buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'xprZ');
  if (!buffer)
    return NULL;

  status = ZwQuerySystemInformation(11, buffer, bytes, &bytes);
  if (NT_SUCCESS(status)) {
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer;
    if (modules->NumberOfModules > 0) {
      kernelBase = modules->Modules[0].ImageBase;
      if (pSize)
        *pSize = modules->Modules[0].ImageSize;
    }
  }

  ExFreePoolWithTag(buffer, 'xprZ');
  return kernelBase;
}

/*
 * Clear MmUnloadedDrivers - removes traces of previously unloaded drivers
 */
static NTSTATUS ClearMmUnloadedDrivers(PUNICODE_STRING DriverName) {
  ULONG kernelSize = 0;
  PVOID kernelBase = GetKernelBase(&kernelSize);
  UCHAR pattern[] = {0x4C, 0x8B, 0x15};
  CHAR mask[] = "xxx";
  PVOID found;
  LONG offset;
  PMM_UNLOADED_DRIVER *pMmUnloadedDrivers;
  PMM_UNLOADED_DRIVER drivers;
  BOOLEAN modified = FALSE;
  ULONG i;

  if (!kernelBase)
    return STATUS_NOT_FOUND;

  found =
      FindPattern(kernelBase, kernelSize, pattern, mask, sizeof(pattern) - 1);
  if (!found)
    return STATUS_NOT_FOUND;

  offset = *(PLONG)((PUCHAR)found + 3);
  pMmUnloadedDrivers = (PMM_UNLOADED_DRIVER *)((PUCHAR)found + 7 + offset);
  drivers = *pMmUnloadedDrivers;

  if (!drivers)
    return STATUS_NOT_FOUND;

  for (i = 0; i < 50; i++) {
    if (drivers[i].Name.Length == 0)
      continue;
    if (RtlEqualUnicodeString(&drivers[i].Name, DriverName, TRUE)) {
      if (drivers[i].Name.Buffer) {
        RtlSecureZeroMemory(drivers[i].Name.Buffer,
                            drivers[i].Name.MaximumLength);
      }
      RtlSecureZeroMemory(&drivers[i], sizeof(MM_UNLOADED_DRIVER));
      modified = TRUE;
    }
  }

  return modified ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * Clear PiDDBCacheTable - removes driver load history
 */
static NTSTATUS ClearPiDDBCacheEntry(PUNICODE_STRING DriverName) {
  ULONG kernelSize = 0;
  PVOID kernelBase = GetKernelBase(&kernelSize);
  UCHAR pattern[] = {0x48, 0x8D, 0x0D};
  CHAR mask[] = "xxx";
  PVOID found;
  LONG offset;
  PRTL_AVL_TABLE PiDDBCacheTable;
  PVOID entry;

  if (!kernelBase)
    return STATUS_NOT_FOUND;

  found =
      FindPattern(kernelBase, kernelSize, pattern, mask, sizeof(pattern) - 1);
  if (!found)
    return STATUS_NOT_FOUND;

  offset = *(PLONG)((PUCHAR)found + 3);
  PiDDBCacheTable = (PRTL_AVL_TABLE)((PUCHAR)found + 7 + offset);

  entry = RtlEnumerateGenericTableAvl(PiDDBCacheTable, TRUE);
  while (entry) {
    PPIDDB_CACHE_ENTRY cacheEntry = (PPIDDB_CACHE_ENTRY)entry;
    if (RtlEqualUnicodeString(&cacheEntry->DriverName, DriverName, TRUE)) {
      RtlDeleteElementGenericTableAvl(PiDDBCacheTable, entry);
      return STATUS_SUCCESS;
    }
    entry = RtlEnumerateGenericTableAvl(PiDDBCacheTable, FALSE);
  }

  return STATUS_NOT_FOUND;
}

/*
 * Clear g_KernelHashBucketList - removes driver hash verification entries
 */
static NTSTATUS ClearKernelHashBucketList(PUNICODE_STRING DriverName) {
  ULONG kernelSize = 0;
  PVOID kernelBase = GetKernelBase(&kernelSize);
  UCHAR pattern[] = {0x48, 0x8B, 0x1D};
  CHAR mask[] = "xxx";
  PVOID found;
  LONG relOffset;
  PHASH_BUCKET_ENTRY *pHashBucketList;
  PHASH_BUCKET_ENTRY prevEntry;
  PHASH_BUCKET_ENTRY currentEntry;

  if (!kernelBase)
    return STATUS_NOT_FOUND;

  found =
      FindPattern(kernelBase, kernelSize, pattern, mask, sizeof(pattern) - 1);
  if (!found)
    return STATUS_NOT_FOUND;

  relOffset = *(PLONG)((PUCHAR)found + 3);
  pHashBucketList = (PHASH_BUCKET_ENTRY *)((PUCHAR)found + 7 + relOffset);
  prevEntry = NULL;
  currentEntry = *pHashBucketList;

  while (currentEntry) {
    if (RtlEqualUnicodeString(&currentEntry->DriverName, DriverName, TRUE)) {
      if (prevEntry) {
        prevEntry->Next = currentEntry->Next;
      } else {
        *pHashBucketList = currentEntry->Next;
      }
      ExFreePool(currentEntry);
      return STATUS_SUCCESS;
    }
    prevEntry = currentEntry;
    currentEntry = currentEntry->Next;
  }

  return STATUS_NOT_FOUND;
}

/*
 * Master trace clearing function - call during driver initialization
 */
static NTSTATUS ClearAllDriverTraces(PUNICODE_STRING DriverName) {
  /* 1. Clear MmUnloadedDrivers */
  ClearMmUnloadedDrivers(DriverName);

  /* 2. Clear PiDDBCacheTable */
  ClearPiDDBCacheEntry(DriverName);

  /* 3. Clear g_KernelHashBucketList */
  ClearKernelHashBucketList(DriverName);

  return STATUS_SUCCESS;
}
