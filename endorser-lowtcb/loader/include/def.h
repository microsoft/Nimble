#pragma once

#include <stdint.h>

#define _In_
#define _In_Opt_
#define _Out_
#define _Out_Opt_
#define _In_Out_

typedef void *              PVOID;
typedef unsigned char       UCHAR;
typedef char*               PCHAR;
typedef unsigned char *     PUCHAR;
typedef unsigned long       ULONG;
typedef unsigned long *     PULONG;
typedef unsigned short      USHORT;
typedef unsigned short *    PUSHORT;
typedef uint64_t *          PU64;
typedef uint32_t *          PU32;
typedef int64_t *           P64;
typedef int32_t *           P32;

#define ROUND_UP(p, align)   ((decltype(p)) (((p) + (align) - 1) & (-(align))))
#define ROUND_DOWN(p, align) ((decltype(p)) ((p) & (-(align))))
#define POINTER_TO_U64(A) ((__u64)((uintptr_t)(A)))

