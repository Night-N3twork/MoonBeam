#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stddef.h>

#define LWIP_NO_STDINT_H 1
#define LWIP_NO_LIMITS_H 1
#define LWIP_NO_UNISTD_H 1

#define INT_MAX   2147483647
#define SHRT_MAX  32767
#define CHAR_BIT  8
#define SSIZE_MAX __PTRDIFF_MAX__

#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_CTYPE_H 1
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#define LWIP_DBG_TYPES_ON               0
#define LWIP_PLATFORM_ASSERT(x) do {} while(0)
#define LWIP_PLATFORM_DIAG(x)           do {} while(0)
#define LWIP_STATS                      0
#define LWIP_STATS_DISPLAY              0
#define LWIP_PERF_LOGGING               0
#define LWIP_DEBUG         0

/* ssize_t / mem_ptr_t must track the target pointer width, not a fixed 64-bit
 * size: this port builds for wasm32, where pointers are 4 bytes. Hardcoding
 * 64-bit here makes bindgen reject the mismatch against the target. */
typedef __PTRDIFF_TYPE__ ssize_t;

typedef __UINT8_TYPE__   uint8_t;
typedef __INT8_TYPE__    int8_t;
typedef __UINT16_TYPE__  uint16_t;
typedef __INT16_TYPE__   int16_t;
typedef __UINT32_TYPE__  uint32_t;
typedef __INT32_TYPE__   int32_t;
typedef __UINT64_TYPE__  uint64_t;
typedef __INT64_TYPE__   int64_t;

typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
typedef __UINTPTR_TYPE__ mem_ptr_t;

#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"



#endif