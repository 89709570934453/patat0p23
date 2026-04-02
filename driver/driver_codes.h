#pragma once
#include "driver_config.h"
#include <ntifs.h>

/*
 * Device type for driver
 */
#ifndef DRIVER_DEVICE_TYPE
#define DRIVER_DEVICE_TYPE 0x22 /* FILE_DEVICE_UNKNOWN */
#endif

/*
 * IOCTL Control Codes (kept for compatibility, not used in shared-memory mode)
 */
#define IOCTL_ZERAPHX_ATTACH                                                   \
  ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED,                 \
                   FILE_SPECIAL_ACCESS))
#define IOCTL_ZERAPHX_READ                                                     \
  ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED,                 \
                   FILE_SPECIAL_ACCESS))
#define IOCTL_ZERAPHX_WRITE                                                    \
  ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x802, METHOD_BUFFERED,                 \
                   FILE_SPECIAL_ACCESS))
#define IOCTL_ZERAPHX_MODULE_BASE                                              \
  ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x803, METHOD_BUFFERED,                 \
                   FILE_SPECIAL_ACCESS))
#define IOCTL_ZERAPHX_DETACH                                                   \
  ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 0x804, METHOD_BUFFERED,                 \
                   FILE_SPECIAL_ACCESS))

/*
 * Memory read/write request structure
 */
typedef struct _ZERAPHX_REQUEST {
  ULONG Magic;       /* Must be ZERAPHX_MAGIC for validation */
  HANDLE ProcessId;  /* Target process ID (for attach) */
  PVOID Target;      /* Target address in the remote process */
  PVOID Buffer;      /* Local buffer address */
  SIZE_T Size;       /* Size of the operation */
  SIZE_T ReturnSize; /* Bytes actually copied (output) */
} ZERAPHX_REQUEST, *PZERAPHX_REQUEST;

/*
 * Module base request structure
 */
typedef struct _ZERAPHX_MODULE_REQUEST {
  ULONG Magic;           /* Must be ZERAPHX_MAGIC */
  HANDLE ProcessId;      /* Target process ID */
  WCHAR ModuleName[256]; /* Module name to find */
  PVOID BaseAddress;     /* Output: module base address */
  SIZE_T ModuleSize;     /* Output: module size */
} ZERAPHX_MODULE_REQUEST, *PZERAPHX_MODULE_REQUEST;
