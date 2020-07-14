#ifndef _CONFIG_H
#define _CONFIG_H

#include "types.h"

#define VERSION "copy by wei"
#define USE_COLOR
#define FANCY_BOXES
#define EXEC_TIMEOUT 1000
#define EXEC_TM_ROUND 20

#ifndef _x86_64_
    #define MEM_LIMIT 25
#else
    #define MEM_LIMIT 50
#endif

#define MEM_LIMIT_QEMU 200
#define CAL_CYCLES 8
#define CAL_CYCLES_LONG 40

#define TMOUT_LIMIT 250

#define KEEP_UNIQUE_HANG 500
#define KEEP_UNIQUE_CRASH 5000

#define HAVOC_CYCLES 256
#define HAVOC_CYCLES_INIT 1024

#define HAVOC_MAX_MULT 16

#define HAVOC_MIN 16

#define HAVOC_STACK_POW2 7

#define HAVOC_BLK_SMALL 32
#define HAVOC_BLK MEDIUM 128
#define HAVOC_BLK_LAGE 1500

#define HAVOC_BLK_XL 32768

#define SKIP_TO_NEW_PROB 99
#define SKIP_NFAV_OLD_PROB 95
#define SKIP_NFAV_NEW_PROB 75

#define SPLICE_CYCLES       15

#define SPLICE_HAVOC        32

#define ARITH_MAX           35


#define TRIM_MIN_BYTES      4
#define TRIM_START_STEPS    16
#define TRIM_END_STEPS      1024

#define MAX_FILE            (1 * 1024 * 1024)


#define TMIN_MAX_FILE       (10 * 1024 * 1024)
#define TMIN_SET_MIN_SIZE   4
#define TMIN_SET_STEPS      128

#define MAX_DICT_FILE       128

#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32

#define MAX_DET_EXTRAS      200

#define USE_AUTO_EXTRAS     50
#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)

#define EFF_MAP_SCALE2      3

#define EFF_MIN_LEN         128

#define EFF_MAX_PERC        90

#define UI_TARGET_HZ        5

#define STATS_UPDATE_SEC    60
#define PLOT_UPDATE_SEC     5

#define AVG_SMOOTHING       16

#define SYNC_INTERVAL       5

#define OUTPUT_GRACE        25

#define INTERESTING_8 \
    -128,\
    -1,\
    0,\
    1,\
    16,\
    32,\
    64,\
    100,\
    127
#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */
#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

/***********************************************************
 *                                                         *
 *  Really exotic stuff you probably don't want to touch:  *
 *                                                         *
 ***********************************************************/

/* Call count interval between reseeding the libc PRNG from /dev/urandom: */

#define RESEED_RNG          10000

/* Maximum line length passed from GCC to 'as' and used for parsing
   configuration files: */

#define MAX_LINE            8192

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Other less interesting, internal-only variables. */

#define CLANG_ENV_VAR       "__AFL_CLANG_MODE"
#define AS_LOOP_ENV_VAR     "__AFL_AS_LOOPCHECK"
#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"

/* In-code signatures for deferred and persistent mode. */

#define PERSIST_SIG         "##SIG_AFL_PERSISTENT##"
#define DEFER_SIG           "##SIG_AFL_DEFER_FORKSRV##"

/* Distinctive bitmap signature used to indicate failed execution: */

#define EXEC_FAIL_SIG       0xfee1dead

/* Distinctive exit code used to indicate MSAN trip condition: */

#define MSAN_ERROR          86

/* Designated file descriptors for forkserver commands (the application will
   use FORKSRV_FD and FORKSRV_FD + 1): */

#define FORKSRV_FD          198

/* Fork server init timeout multiplier: we'll wait the user-selected
   timeout plus this much for the fork server to spin up. */

#define FORK_WAIT_MULT      10

/* Calibration timeout adjustments, to be a bit more generous when resuming
   fuzzing sessions or trying to calibrate already-added internal finds.
   The first value is a percentage, the other is in milliseconds: */

#define CAL_TMOUT_PERC      125
#define CAL_TMOUT_ADD       50

/* Number of chances to calibrate a case before giving up: */

#define CAL_CHANCES         3

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
   2; you probably want to keep it under 18 or so for performance reasons
   (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
   problems with complex programs). You need to recompile the target binary
   after changing this - otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

/* Maximum allocator request size (keep well under INT_MAX): */

#define MAX_ALLOC           0x40000000

/* A made-up hashing seed: */

#define HASH_CONST          0xa5b35705

/* Constants for afl-gotcpu to control busy loop timing: */

#define  CTEST_TARGET_MS    5000
#define  CTEST_CORE_TRG_MS  1000
#define  CTEST_BUSY_CYCLES  (10 * 1000 * 1000)

/* Uncomment this to use inferior block-coverage-based instrumentation. Note
   that you need to recompile the target binary for this to have any effect: */

// #define COVERAGE_ONLY

/* Uncomment this to ignore hit counts and output just one bit per tuple.
   As with the previous setting, you will need to recompile the target
   binary: */

// #define SKIP_COUNTS

/* Uncomment this to use instrumentation data to record newly discovered paths,
   but do not use them as seeds for fuzzing. This is useful for conveniently
   measuring coverage that could be attained by a "dumb" fuzzing algorithm: */

// #define IGNORE_FINDS

#endif /* ! _HAVE_CONFIG_H */
