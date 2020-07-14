#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#ifdef _x86_64_
    typedef unsigned long long u64;
#else
    typedef uint64_t u64;
#endif

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifdef MIN
    #define MIN(a,b) ((a) > (b)) ? (b) : (a)
    #define MAX(a,b) ((a) > (b)) ? (a) : (b)
#endif

#define SWAP16(x)({\
    u16 ret=(x);\
    (u16)((ret << 8)|(ret >> 8));\
})

#define SWAP32(x) ({ \
    u32 ret=(x);\
    (u32)((ret << 24 | ret >> 24) | \
    (((ret << 8 ) & 0x00FF0000) | ((ret >> 8) & 0x0000FF00)));\
})

#ifdef AFL_LLVM_PASS
    #define AFL_R(x) (random() % (x) )
#else
    #define R(x) (random() % (x))
#endif

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define MEM_BARRIER() \
    asm volatile("" ::: "memmory")

#define likely(x) __builtin_expect(!!(x),1)
#define unlikely(x) __builtin_expect(!!(x),0)


#endif