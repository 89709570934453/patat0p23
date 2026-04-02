#pragma once

/*
 * ZeraphX Driver Configuration
 * HARDENED: No identifiable strings, dynamic magic, innocuous tags
 */

/* Pool tags - use innocuous system-like tags to blend in */
#define ZX_POOL_TAG_CTX 'FMfn' /* Looks like a File Manager tag */
#define ZX_POOL_TAG_BUF 'bSmM' /* Looks like MmSb (memory manager) */

/* Session magic - generated at runtime, stored in shared memory offset 0 */
/* Client reads this dynamically. No hardcoded magic. */

/* Section name prefix - driver appends random suffix at runtime */
#define ZX_SECTION_PREFIX L"\\BaseNamedObjects\\SM"

/* Legacy constants (kept for non-shared-memory code paths) */
#define ZERAPHX_XOR_KEY 0xDEAD1337CAFE4269ULL
#define ZERAPHX_MAGIC 0x5A455241UL

/* Max read/write size to prevent abuse */
#define ZX_MAX_RW_SIZE (16 * 1024 * 1024) /* 16MB */
