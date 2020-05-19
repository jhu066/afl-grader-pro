/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#include <sys/socket.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif
/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

int sync_times = 0;
int sync_count = 0;
int sync_count_crashes = 0;

int sync_max_seeds_per = 20;



static u8 //*in_dir,                    /* Input directory with test cases  */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          // *local_out_dir,
          // *remote_out_dir,
          *sync_dir,                  /* Synchronization directory        */
          *sync_id,                   /* Fuzzer ID                        */
          *use_banner,                /* Display banner                   */
          *in_bitmap,                 /* Input bitmap                     */
          *doc_path,                  /* Path to documentation dir        */
          *target_path,               /* Path to target binary            */
          *orig_cmdline;              /* Original command line            */


static u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u64 mem_limit = MEM_LIMIT;     /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

static u8  skip_deterministic,        /* Skip deterministic stages?       */
           force_deterministic,       /* Force deterministic stages?      */
           use_splicing,              /* Recombine input files?           */
           dumb_mode,                 /* Run in non-instrumented mode?    */
           score_changed,             /* Scoring for favorites changed?   */
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming an older fuzzing job?   */
           timeout_given,             /* Specific timeout given?          */
           not_on_tty,                /* stdout is not a tty              */
           uses_asan,                 /* Target uses ASAN?                */
           no_forkserver,             /* Disable forkserver?              */
           crash_mode,                /* Crash mode! Yeah!                */
           in_place_resume = 0,           /* Attempt in-place resume?         */

           no_cpu_meter_red,          /* Feng shui on the status screen   */
           no_var_check,              /* Don't detect variable behavior   */
           bitmap_changed = 1,        /* Time to update bitmap?           */
           qemu_mode,                 /* Running in QEMU mode?            */
           skip_requested,            /* Skip request, via SIGUSR1        */
           run_over10m;               /* Run time over 10 minutes?        */

static s32 out_fd,                    /* Persistent fd for out_file       */
           out_cb_info_fd,            /* Persistent fd for cur_code_block_info file */
           dev_urandom_fd,            /* Persistent fd for /dev/urandom   */
           dev_null_fd;               /* Persistent fd for /dev/null      */

static s32 qemu_log_fd;                    /*Persistent fd for /tmp/afl_log*/

static s32 fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1;            /* PID of the fuzzed program        */



static u8 is_qemu_log = 0;
static u8 is_trim_case = 0;

static u8* trace_bits;                /* SHM with instrumentation bitmap - now serve for N2/4/8 coverage */
// static u8* trace_bits_N4;             /* serve for N4 coverage */
// static u8* trace_bits_N8;             /* serve for N8 coverage */

// static uint64_t *new_n2_num,
//                 *new_n4_num,
//                 *new_n8_num;

static int overall_bits[MAP_SIZE * 2];     /* 2 global bitmap, one for global max-hit, the other for accumulative hitcount  */
static int *accu_bits;

static u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
           virgin_hang[MAP_SIZE],     /* Bits we haven't seen in hangs    */
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen = 1,  /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

static u32 queued_paths,              /* Total number of queued testcases */
           queued_variable,           /* Testcases with variable behavior */
           //queued_at_start,           /* Total number of initial inputs   */
           queued_discovered,         /* Items discovered during this run */
           queued_imported,           /* Items imported via -S            */
           queued_favored,            /* Paths deemed favorable           */
           queued_with_cov,           /* Paths with new coverage bytes    */
           pending_not_fuzzed,        /* Queued but not done yet          */
           pending_favored,           /* Pending favored paths            */
           cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */
           useless_at_start,          /* Number of useless starting paths */
           current_entry,             /* Current queue entry ID           */
           havoc_div = 1;             /* Cycle count divisor for havoc    */

static u64 total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_hangs,               /* Total number of hangs            */
           unique_hangs,              /* Hangs with unique signatures     */
           total_execs,               /* Total execve() calls             */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           first_crash_time = 0,      /* Add for cgc                      */
           last_crash_time = 0,       /* Time for most recent crash (ms)  */
           last_hang_time,            /* Time for most recent hang (ms)   */
           queue_cycle,               /* Queue round counter              */
           cycles_wo_finds,           /* Cycles without any new paths     */
           trim_execs,                /* Execs done to trim input files   */
           bytes_trim_in,             /* Bytes coming into the trimmer    */
           bytes_trim_out,            /* Bytes coming outa the trimmer    */
           blocks_eff_total,          /* Blocks subject to effector maps  */
           blocks_eff_select;         /* Blocks selected as fuzzable      */



static u8 *stage_name = "init",       /* Name of the current fuzz stage   */
          *stage_short,               /* Short stage name                 */
          *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
           stage_cur_val;             /* Value used for stage op          */

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32],           /* Patterns found per fuzz stage    */
           stage_cycles[32];          /* Execs per fuzz stage             */

static u32 rand_cnt = RESEED_RNG;     /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
           total_bitmap_entries;      /* Number of bitmaps counted        */

static u32 cpu_core_count;            /* CPU core count                   */

static FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      // was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant,                  /* Marked as redundant in the fs?   */
      fs_favored;

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      fuzz_level,                     /* Number of fuzzing iterations     */      
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */
  u32 tc_prev_ref;                    /* Trace bytes prevous ref count    */

  struct queue_entry *next;           /* Next element, if any             */
                     // *next_100;       /* 100 elements ahead               */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top; /* Top of the list                  */
                          // *q_prev100; /* Previous 100 marker              */

static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */







/* Fuzzing stages */

enum {
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum {
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_HANG,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

#include "khash.h"
KHASH_MAP_INIT_INT(32,u32)
khash_t(32) *cksum2paths;

KHASH_SET_INIT_INT64(p64)
khash_t(p64) *hash_value_set;

static u32 getPaths(u32 key_cksum){
  khiter_t k = kh_get(32, cksum2paths, key_cksum);
  if (k != kh_end(cksum2paths)){
    return kh_value(cksum2paths, k);
  } else {
    return 0;
  }
}


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

  if (!rand_cnt--) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}





/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single 
   static buffer. */

static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.995) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


/* Describe integer as memory size. */

static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}




/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry* q) {

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}


/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);


  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


static void mark_as_favored(struct queue_entry* q, u8 state)
{
  u8* fn;
  s32 fd;

  // printf("%s,%d,%d,%d,%d\n",q->fname, state, q->fs_favored, q->tc_prev_ref, q->tc_ref);

  if (state == q->fs_favored)  return;

  q->fs_favored = state;

  fn = strrchr(q->fname, '/');


  if (state) {
    fn = alloc_printf("%s/queue/.state/favored_edges/%s,ref:%d", out_dir, fn + 1, q->tc_ref);
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    q->tc_prev_ref = q->tc_ref;
    close(fd);

  } else {
    fn = alloc_printf("%s/queue/.state/favored_edges/%s,ref:%d", out_dir, fn + 1, q->tc_prev_ref);
    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}

// extract covered blocks of an explored path
static void extra_blocks(u32 path_id, int q_or_c)
{
  u8 *fn ;

  if (q_or_c == 0) 
    fn = alloc_printf("%s/queue/blocks,id:%08u", out_dir, path_id);
  else
    fn = alloc_printf("%s/crashes/blocks,id:%08u", out_dir, path_id);

  
  s32 fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  struct stat st;

  if (fstat(out_cb_info_fd, &st)) PFATAL("fstat() for '%s' failed", fn);

  if(st.st_size)
  {
    // fprintf(stderr, "st_size: %d\n", st.st_size);
    u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, out_cb_info_fd, 0);

    if(mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", fn);

    lseek(fd, 0, SEEK_SET);

    ck_write(fd, mem, st.st_size, fn);
  }

  close(fd);

}
/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else { //q_prev100 = 
      queue = queue_top = q;
  }
  queued_paths++;
  pending_not_fuzzed++;

  // if (!(queued_paths % 100)) {

  //   q_prev100->next_100 = q;
  //   q_prev100 = q;

  // }

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

static void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

static void write_bitmap(void) {

  u8* fname;
  s32 fd;

  if (!bitmap_changed) return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);
  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */

static void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

#define FFL(_b) (0xffULL << ((_b) << 3))
#define FF(_b)  (0xff << ((_b) << 3))

static inline u8 has_new_bits(u8* virgin_map) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

#ifdef __x86_64__

    u64 cur = *current;
    u64 vir = *virgin;

#else

    u32 cur = *current;
    u32 vir = *virgin;

#endif /* ^__x86_64__ */

    /* Optimize for *current == ~*virgin, since this will almost always be the
       case. */

    if (cur & vir) {

      if (ret < 2) {

        /* This trace did not have any new bytes yet; see if there's any
           current[] byte that is non-zero when virgin[] is 0xff. */

#ifdef __x86_64__

        if (((cur & FFL(0)) && (vir & FFL(0)) == FFL(0)) ||
            ((cur & FFL(1)) && (vir & FFL(1)) == FFL(1)) ||
            ((cur & FFL(2)) && (vir & FFL(2)) == FFL(2)) ||
            ((cur & FFL(3)) && (vir & FFL(3)) == FFL(3)) ||
            ((cur & FFL(4)) && (vir & FFL(4)) == FFL(4)) ||
            ((cur & FFL(5)) && (vir & FFL(5)) == FFL(5)) ||
            ((cur & FFL(6)) && (vir & FFL(6)) == FFL(6)) ||
            ((cur & FFL(7)) && (vir & FFL(7)) == FFL(7))) ret = 2;
        else ret = 1;

#else

        if (((cur & FF(0)) && (vir & FF(0)) == FF(0)) ||
            ((cur & FF(1)) && (vir & FF(1)) == FF(1)) ||
            ((cur & FF(2)) && (vir & FF(2)) == FF(2)) ||
            ((cur & FF(3)) && (vir & FF(3)) == FF(3))) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin = vir & ~cur;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}


/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}



/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or hang, should be
   reasonably fast. */

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static u8 simplify_lookup[256] = { 
  /*    4 */ 1, 128, 128, 128,
  /*   +4 */ AREP4(128),
  /*   +8 */ AREP8(128),
  /*  +16 */ AREP16(128),
  /*  +32 */ AREP32(128),
  /*  +64 */ AREP64(128),
  /* +128 */ AREP128(128)
};

#ifdef __x86_64__

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;

    mem++;
  }

}

#endif /* ^__x86_64__ */

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];
      mem8[4] = count_class_lookup[mem8[4]];
      mem8[5] = count_class_lookup[mem8[5]];
      mem8[6] = count_class_lookup[mem8[6]];
      mem8[7] = count_class_lookup[mem8[7]];

    }

    mem++;

  }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry* q) {
  u32 i;
  u32 fuzz_level = q->fuzz_level;
  u32 paths = getPaths(q->exec_cksum);
  u64 fav_factor = q->exec_us * q->len;
  
  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

      if (top_rated[i]) {
         u32 top_rated_fuzz_level = top_rated[i]->fuzz_level;
         u32 top_rated_paths = getPaths(top_rated[i]->exec_cksum);
         u64 top_rated_fav_factor = top_rated[i]->exec_us * top_rated[i]->len;
         
         if (fuzz_level > top_rated_fuzz_level) continue;
         else if (fuzz_level == top_rated_fuzz_level) {
           if (paths > top_rated_paths) continue;
           else if ( paths == top_rated_paths) {
             if (fav_factor > top_rated_fav_factor) continue;
           }
         }
         //if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len ) continue;
         
         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         // ACTF("minimizing...");
         minimize_bits(q->trace_mini, trace_bits);
       }

       score_changed = 1;

     }

}


/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;


  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      //if (!top_rated[i]->was_fuzzed) pending_favored++;
      if (!top_rated[i]->fuzz_level == 0) pending_favored++;
    }

    q = queue;
    while (q) {
      mark_as_favored(q, q->favored);
      mark_as_redundant(q, !q->favored);
      q = q->next;
    }

}


/* Configure shared memory and virgin_bits. This is called at startup. */

static void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_hang, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);
  memset(overall_bits, 0, 2 * MAP_SIZE * sizeof(int));

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600); //J.H. only one map is enough 

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (dumb_mode != 1)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);  
  if (!trace_bits) PFATAL("trace_bits shmat() failed");

  // new_n2_num = (uint64_t *)(trace_bits + MAP_SIZE);
  // new_n4_num = (uint64_t *)(trace_bits + 2 * MAP_SIZE + 8);
  // new_n8_num = (uint64_t *)(trace_bits + 3 * MAP_SIZE + 16);
  // trace_bits_N4 = (u8 *)(trace_bits + MAP_SIZE + 8);
  // trace_bits_N8 = (u8 *)(trace_bits_N4 + MAP_SIZE + 8);
  accu_bits = overall_bits + MAP_SIZE;
  // overall_bits = shmat(shm_id, NULL, 0);
  // if (!overall_bits) PFATAL("overall_bits shmat() failed");


    ACTF("shm_id: %i", (int)shm_id);
#ifdef __x86_64__
    ACTF("trace_bits@ 0x%016lx", (unsigned long)trace_bits);
    ACTF("overall_bits@ 0x%016lx", (unsigned long)overall_bits);
    ACTF("virgin_bits@ 0x%016lx", (unsigned long)virgin_bits);
    ACTF("virgin_hang@ 0x%016lx", (unsigned long)virgin_hang);
    ACTF("virgin_crash@ 0x%016lx", (unsigned long)virgin_crash);
#else
    ACTF("trace_bits@ 0x%08x", (unsigned int)trace_bits);
    ACTF("overall_bits@ 0x%08x", (unsigned int)overall_bits);
    ACTF("virgin_bits@ 0x%08x", (unsigned int)virgin_bits);
    ACTF("virgin_hang@ 0x%08x", (unsigned int)virgin_hang);
    ACTF("virgin_crash@ 0x%08x", (unsigned int)virgin_crash);
#endif /* ^__x86_64__ */
  
}










/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}


/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

static void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server ");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
      soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    
    if(!is_qemu_log)
      dup2(dev_null_fd, 2);
    else
      dup2(qemu_log_fd, 2);

    if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

    }
    dup2(out_cb_info_fd, CODE_BLOCK_INFO_FD);
    close(out_cb_info_fd);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD ) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));
    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];


  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
    // continue;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, WUNTRACED) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
          "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
          "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use ppvm (http://jwilk.net/software/ppvm) to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else if (!mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are two probable explanations:\n\n"

         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
        "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
        "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

        "      Tip: you can use ppvm (http://jwilk.net/software/ppvm) to quickly\n"
        "      estimate the required amount of virtual memory for the binary.\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
        "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
        DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv) {

  static struct itimerval it;
  int status = 0;
  u32 tb4;

  
  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE); // J.H. refresh the bitmap for new seed coming 
  // new_n2_num[0] = 0;
  // new_n4_num[0] = 0;
  // new_n8_num[0] = 0;
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver) {

    child_pid= fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      close(dev_null_fd);

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }
  

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server");

    }

  }
 
  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;
  

    /* Any subsequent operations on trace_bits must not be moved by the
       compiler above this point. Past this location, trace_bits[] behave
       very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

// #ifdef __x86_64__
//   classify_counts((u64*)trace_bits);
// #else
//   classify_counts((u32*)trace_bits);
// #endif /* ^__x86_64__ */
  
  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

/* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
   must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) { //J.H. why need modified data to file for testing though?

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}





/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

} 



/* Actually minimize! */

static u32 minimize_case(char** argv, u8* in_data, u32 orig_len, u32 orig_cksum, u8* fname) {

  u8* old_sn = stage_name;
  stage_name = "minimize";

  // static u32 alpha_map[256];


  u32 in_len = orig_len, stage_o_len;
  u8* tmp_buf = ck_alloc_nozero(in_len);
  
  u32 del_len, del_pos, /*i, alpha_size,*/ cur_pass = 0;
  // u32 syms_removed, alpha_del1, alpha_del2, alpha_d_total = 0;
  u8  changed_any;

  u8 fault = 0;
  ACTF(cYEL "--- " cBRI "minimizing %s" cYEL " ---", fname);

next_pass:

  ACTF(cYEL "--- " cBRI "Pass #%u" cYEL " ---", ++cur_pass);
  changed_any = 0;

  /******************
   * BLOCK DELETION *
   ******************/

  del_len = next_p2(in_len / TRIM_START_STEPS);
  stage_o_len = in_len;

  // ACTF(cBRI "Stage #1: " cNOR " Removing blocks of data...");

next_del_blksize:

  if (!del_len) del_len = 1;
  del_pos = 0;

  // SAYF(cGRA "    Block length = %u, remaining size = %u\n" cNOR,
  //      del_len, in_len);

  while (del_pos < in_len) {

    s32 tail_len;

    /* Head */
    memcpy(tmp_buf, in_data, del_pos);

    tail_len = in_len - del_pos - del_len;
    if (tail_len < 0) tail_len = 0;

    /* Tail */
    memcpy(tmp_buf + del_pos, in_data + del_pos + del_len, tail_len);

    write_to_testcase(tmp_buf, del_pos + tail_len);
    fault = run_target(argv);

    if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

    /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

    u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (cksum == orig_cksum) {

      // ACTF("in_data[%d]<-[%d]", orig_len, del_pos + tail_len);
      in_data[0] = tmp_buf[0];

      memcpy(in_data, tmp_buf, del_pos + tail_len);

      in_len = del_pos + tail_len;
      changed_any = 1;

    } else del_pos += del_len;

  }

  if (del_len > 1 && in_len >= 1) {

    del_len /= 2;
    goto next_del_blksize;

  }

  // OKF("Block removal complete, %u bytes deleted.", stage_o_len - in_len);

  if (!in_len && changed_any)
    WARNF(cLRD "Down to zero bytes - check the command line and mem limit!" cRST);

  if (cur_pass > 1 && !changed_any) goto finalize_all;

  // /*************************
  //  * ALPHABET MINIMIZATION *
  //  *************************/

  // alpha_size   = 0;
  // alpha_del1   = 0;
  // syms_removed = 0;

  // memset(alpha_map, 0, 256);

  // for (i = 0; i < in_len; i++) {
  //   if (!alpha_map[in_data[i]]) alpha_size++;
  //   alpha_map[in_data[i]]++;
  // }

  // // ACTF(cBRI "Stage #2: " cNOR "Minimizing symbols (%u code point%s)...",
  //      // alpha_size, alpha_size == 1 ? "" : "s");

  // for (i = 0; i < 256; i++) {

  //   u32 r;

  //   if (i == '0' || !alpha_map[i]) continue;

  //   memcpy(tmp_buf, in_data, in_len);

  //   for (r = 0; r < in_len; r++)
  //     if (tmp_buf[r] == i) tmp_buf[r] = '0'; 

  //   write_to_testcase(tmp_buf, in_len);
  //   fault = run_target(argv);

  //   if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

  //   u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  //   if (cksum == orig_cksum) {

  //     memcpy(in_data, tmp_buf, in_len);
  //     syms_removed++;
  //     alpha_del1 += alpha_map[i];
  //     changed_any = 1;

  //   }

  // }

  // alpha_d_total += alpha_del1;

  // // OKF("Symbol minimization finished, %u symbol%s (%u byte%s) replaced.",
  // //     syms_removed, syms_removed == 1 ? "" : "s",
  // //     alpha_del1, alpha_del1 == 1 ? "" : "s");

  // /**************************
  //  * CHARACTER MINIMIZATION *
  //  **************************/

  // alpha_del2 = 0;

  // // ACTF(cBRI "Stage #3: " cNOR "Character minimization...");

  // for (i = 0; i < in_len; i++) {

  //   if (tmp_buf[i] == '0') continue;

  //   memcpy(tmp_buf, in_data, in_len);

  //   tmp_buf[i] = '0';

  //   write_to_testcase(tmp_buf, in_len);
  //   fault = run_target(argv);

  //   if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

  //   u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  //   if (cksum == orig_cksum) {

  //     memcpy(in_data, tmp_buf, in_len);
  //     alpha_del2++;
  //     changed_any = 1;

  //   }

  // }

  // alpha_d_total += alpha_del2;

  // // OKF("Character minimization done, %u byte%s replaced.",
  // //     alpha_del2, alpha_del2 == 1 ? "" : "s");

  if (changed_any) goto next_pass;

finalize_all:

  // re-run the final minimized in_data
  write_to_testcase(in_data, in_len);
  fault = run_target(argv);
 
  if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

  // SAYF("\n"
  //      cGRA "     File size reduced by : " cNOR "%0.02f%% (to %u byte%s)\n"
  //      cGRA "    Characters simplified : " cNOR "%0.02f%%\n"
  //      cGRA "     Number of execs done : " cNOR "%u\n"
  //      cGRA "          Fruitless execs : " cNOR "path=%u crash=%u hang=%s%u\n\n",
  //      100 - ((double)in_len) * 100 / orig_len, in_len, in_len == 1 ? "" : "s",
  //      ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1),
  //      total_execs, missed_paths, missed_crashes, missed_hangs ? cLRD : "",
  //      missed_hangs);

  // if (total_execs > 50 && missed_hangs * 10 > total_execs)
  //   WARNF(cLRD "Frequent timeouts - results may be skewed." cRST);

  SAYF("\n"
     cGRA "     File size reduced by : " cNOR "%0.02f%% (%u to %u byte%s)\n",
     // cGRA "    Characters simplified : " cNOR "%0.02f%%\n\n",
     100 - ((double)in_len) * 100 / orig_len, orig_len, in_len, in_len == 1 ? "" : "s");
     // ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1));

abort_trimming:
  stage_name = old_sn;
  
  if(fault == FAULT_ERROR)
    FATAL("Unable to execute target application");
    
  return in_len;

}



static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  u8  fault = 0, new_bits = 0, var_detected = 0, first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max, old_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    exec_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                     exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = no_var_check ? CAL_CYCLES_NO_VAR : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!dumb_mode && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);
  // while(1);
  start_us = get_cur_time_us();
  // ACTF("stage_max: %d", stage_max);

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);
    // ACTF("run_target() 1 at staget_cur: %d", stage_cur);
    fault = run_target(argv);
    
    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
    // ACTF("cksum: %u @%d", cksum, stage_cur);
    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (!no_var_check && q->exec_cksum) {

        var_detected = 1;
        stage_max    = CAL_CYCLES_LONG;

      } else q->exec_cksum = cksum;

    }

  }
  
  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;
  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */
  
  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected && !q->var_behavior) {
    mark_as_variable(q);
    queued_variable++;
  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;
  exec_tmout = old_tmout;
  if (!first_run) show_stats();

  return fault;

}














#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%08u", syncing_party, syncing_case);

  } else {

    sprintf(ret, "src:%08u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%08u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);

}


/* check if the execution triggers unique path (identified by unique path hash value) => queue folder
                       or triggers unique crashes (trigger crash and unique path hash) => crash folder*/
static u8 save_if_interesting_JH(char** argv, void* mem, u32 len, u8 fault,  u8* path, int level) {
  u8 *fn = "";
  u8  hnb;
  int ifnew;
  s32 fd;
  u8  keeping = 0, res;
  int seedlevel;
  float seedscore;
  float covscore = 0.0;
  float rareness = 0.0;

  //FILE *fptr = fopen("/home/jie/projects/hybrid-root1/bitmap_real.log", "a+");

  int bit_i = 0;
  int diff = 0;
  // validate and update two global bitmap using trace_bits!
  for(bit_i = 0; bit_i < MAP_SIZE; bit_i ++) {
    if(trace_bits[bit_i] == 0) continue;
    // here is non-zero bits
    if(trace_bits[bit_i] > overall_bits[bit_i]) { // new max-hit at N2 level
    //if(overall_bits[bit_i] == 0) { // new flip
      diff = trace_bits[bit_i] - overall_bits[bit_i];
      covscore = covscore + 1.0 * diff / trace_bits[bit_i];
      overall_bits[bit_i] = trace_bits[bit_i];
    }

    // now update the accumulative hitcount bitmap
    if(accu_bits[bit_i] >= 1024) continue;
    
    // not hitting threshold yet, update! 
    accu_bits[bit_i] += trace_bits[bit_i];
    if(!covscore) { // if covscore valid, no need to calculate rareness anymore.
      rareness += 1.0 * trace_bits[bit_i] / accu_bits[bit_i];
    }
  }
  
  // decide if this seed is new-cov N2 seed or rare-rank no-cov seed
  if(covscore > 0) {
    seedlevel = 2;
    seedscore = covscore;
  }
  else {
    seedlevel = 9; // means no new coverage, compatible to old setting
    seedscore = rareness;
  }

  // for(bit_i = 0; bit_i < MAP_SIZE; bit_i ++) { // here i have access to the current bitmap and overall bitmap!
  //   if(trace_bits[bit_i] != 0) {
  //     if(overall_bits[bit_i] < trace_bits[bit_i]) { // new max hit!
  //       overall_bits[bit_i] = trace_bits[bit_i];
  //       rareness[0] += (1.0 / overall_bits[bit_i]);        
  //     }
  //   }

  //   if(trace_bits_N4[bit_i] != 0) {
  //     if(overall_bits[bit_i + MAP_SIZE] < trace_bits_N4[bit_i]) { // new max hit at N4
  //       overall_bits[bit_i + MAP_SIZE] = trace_bits_N4[bit_i];
  //       rareness[1] += (1.0 / overall_bits[bit_i + MAP_SIZE]);
  //     }
  //   }

  //   if(trace_bits_N8[bit_i] != 0) {
  //     if(overall_bits[bit_i + 2*MAP_SIZE] < trace_bits_N8[bit_i]) { // new max hit at N8
  //       overall_bits[bit_i + 2*MAP_SIZE] = trace_bits_N8[bit_i];
  //       rareness[2] += (1.0 / overall_bits[bit_i + 2*MAP_SIZE]);        
  //     }
  //   }
  // }
  
  // if(rareness[0]) {
  //   seedlevel  = 2;
  //   covscore = rareness[0];
  // }
  // else if(rareness[1]) {
  //   seedlevel  = 4;
  //   covscore = rareness[1];
  // }
  // else if(rareness[2]) {
  //   seedlevel  = 8;
  //   covscore = rareness[2];
  // }
  // else {
  //   seedlevel = 9;
  //   covscore = 0;
  // }

  // fprintf(fptr, "[afl-fuzz]: level: %d ~ %d-%d-%d--%f-%f-%f\n", seedlevel, score[0], score[1], score[2], rareness[0], rareness[1], rareness[2]);
  // fclose(fptr);

  // if(new_n2_num[0] > 0) {
  //   seedscore = new_n2_num[0];
  //   seedlevel = 2;
  // }
  // else if(new_n4_num[0] > 0) {
  //   seedscore = new_n4_num[0];
  //   seedlevel = 4;
  // }
  // else if(new_n8_num[0] > 0) {
  //   seedscore = new_n8_num[0];
  //   seedlevel = 8;
  // }
  // else {  // basically only executed when starved. 
  //   seedscore = 0;
  //   // calculate the rareness score of 3 level ngram bitmap

  //   seedlevel = 9;
  // }
  

  // this is my real path validation
  //uint64_t* afl_trace_p = (uint64_t*)(trace_bits + MAP_SIZE);
  // kh_put(p64, hash_value_set, afl_trace_p[0], &ifnew);

  // printout the real content of this bitmap now:
 /*  FILE *fptr = fopen("/home/jie/projects/hybrid-root/path-hash/bitmap_real.log", "a+");
  // fprintf(fptr, "[afl-fuzz]: %s - %lu\n", path, afl_trace_p[0]);
  // fclose(fptr);
 int bit_i = 0;
  double rareness = 0.0;
  for(bit_i = 0; bit_i < MAP_SIZE; bit_i ++) { // here i have access to the current bitmap and overall bitmap!
    // optimized for frequent cases: no hit
    if (trace_bits[bit_i] == 0)
      continue;
    // fprintf(fptr, "bitmap[%d]: %d\n", bit_i, trace_bits[bit_i], trace_bits[bit_i]);
    overall_bits[bit_i] += trace_bits[bit_i]; // count the new hit count as well! next calculate the rareness score
    rareness += (1.0 / overall_bits[bit_i]);
  }
  fprintf(fptr, "path: %s, rareness score being: %.5f\n", path, rareness);
  fclose(fptr);
*/
  //Update path freq. No change to semantics
  khiter_t k;
  int ret;
  u32 key_cksum = (u32)seedscore;//afl_trace_p[0];//hash32(trace_bits, MAP_SIZE, HASH_CONST);
  k = kh_get(32, cksum2paths, key_cksum);
  if (k == kh_end(cksum2paths)){
      k = kh_put(32, cksum2paths, key_cksum, &ret);
      kh_value(cksum2paths, k) = 1;
  }
  //if (k != kh_end(cksum2paths)){
  else {
    ++kh_value(cksum2paths, k);
  } 
  
  
  // for debug log 
  // FILE *fptr = fopen("/home/jie/projects/hybrid-root/path-hash/grader.log", "a+");
  // fprintf(fptr, "[afl-fuzz]: %s - %lu - uniq=%d, count=%d\n", path, afl_trace_p[0], ifnew, kh_value(cksum2paths, k));
  // fclose(fptr);
  // for debug log 

  if (fault == crash_mode) { // basically always gonna keep the testcase and mark it with rareness score. 

    fn = alloc_printf("%s/queue/id:%06u_%.5f_%d", out_dir, queued_paths, seedscore, seedlevel);
    

    // if (is_trim_case && (len <= 10*1024)) {
    //   len = minimize_case(argv, mem, len, key_cksum, fn);
    // }
    // extra_blocks(queued_paths, 0);
    add_to_queue(fn, len, 0);

    //if(ifnew) {
    if(seedscore) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }
    queue_top->exec_cksum = key_cksum;  
    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1; // set keeping to 1 because it is unique path  
  }

  switch(fault) {
    case FAULT_HANG:
      /* Hangs are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */
      total_hangs++;

      // if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;
#ifndef SIMPLE_FILES
      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));
#else
      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);
#endif /* ^!SIMPLE_FILES */
      unique_hangs++;

      last_hang_time = get_cur_time();

      break;
    case FAULT_CRASH:
      /* This is handled in a manner roughly similar to hangs,
         except for slightly different limits. */
      total_crashes++;

      // if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!unique_crashes) write_crash_readme();

// #ifndef SIMPLE_FILES
//       fn = alloc_printf("%s-crashes/queue/id:%06llu,sig:%02u,%s", out_dir,
//                         unique_crashes, kill_signal, describe_op(0));
// #else
//       fn = alloc_printf("%s-crashes/queue/id_%06llu_%02u", out_dir, unique_crashes,
//                         kill_signal);
// #endif /* ^!SIMPLE_FILES */

      fn = alloc_printf("%s-crashes/queue/id:%06llu_%.5f_%d", out_dir, unique_crashes, seedscore, seedlevel);

      if(unique_crashes == 0)
      {
        first_crash_time = get_cur_time();
      }

      // extra_blocks(unique_crashes, 1);

      unique_crashes++;

      last_crash_time = get_cur_time();

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }
  /* If we're here, we apparently want to save the crash or hang
     test case, too. */
  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);
  return keeping;
}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */
static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault,  u8* path) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  // J.H. reading the whole path hash value, testing code
  uint64_t* afl_trace_p = (uint64_t*)(trace_bits + MAP_SIZE);
  // FILE *fptr = fopen("/home/jie/projects/hybrid-root/path-hash/debug.log", "a+");
  // fprintf(fptr, "[afl-fuzz]: %s - %lu\n", path, afl_trace_p[0]);
  // fclose(fptr);

  //Update path freq. No change to semantics
  khiter_t k;
  u32 key_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  k = kh_get(32, cksum2paths, key_cksum);
  if (k != kh_end(cksum2paths)){
    ++kh_value(cksum2paths, k);
  }

  if (fault == crash_mode) {
    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) total_crashes++;
      return 0;
    }    
#ifndef SIMPLE_FILES
    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));
#else
    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);
#endif /* ^!SIMPLE_FILES */
    if (is_trim_case && (len <= 10*1024))
    {
      len = minimize_case(argv, mem, len, key_cksum, fn);
    }

    extra_blocks(queued_paths, 0);
    add_to_queue(fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = key_cksum; //hash32(trace_bits, MAP_SIZE, HASH_CONST);
    int ret;
    if (k == kh_end(cksum2paths)){
      k = kh_put(32, cksum2paths, key_cksum, &ret);
      kh_value(cksum2paths, k) = 1;
    } 
    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    // ACTF("calibrating");
    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_HANG:

      /* Hangs are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_hangs++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_hang)) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

      /* This is handled in a manner roughly similar to hangs,
         except for slightly different limits. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();



#ifndef SIMPLE_FILES

      fn = alloc_printf("%s-crashes/queue/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s-crashes/queue/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      if(unique_crashes == 0)
      {
        first_crash_time = get_cur_time();
      }

      extra_blocks(unique_crashes, 1);

      unique_crashes++;

      last_crash_time = get_cur_time();

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


// /* When resuming, try to find the queue position to start from. This makes sense
//    only when resuming, and when we can find the original fuzzer_stats. */

// static u32 find_start_position(void) {

//   static u8 tmp[4096]; /* Ought to be enough for anybody. */

//   u8  *fn, *off;
//   s32 fd, i;
//   u32 ret;

//   if (!resuming_fuzz) return 0;

//   if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
//   else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

//   // fn = alloc_printf("%s/fuzzer_stats", remote_out_dir);

//   fd = open(fn, O_RDONLY);
//   ck_free(fn);

//   if (fd < 0) return 0;

//   i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
//   close(fd);

//   off = strstr(tmp, "cur_path       : ");
//   if (!off) return 0;

//   ret = atoi(off + 17);
//   if (ret >= queued_paths) ret = 0;
//   return ret;

// }


/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double eps) {

  static double last_bcvg, last_eps;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  // u8* fn = alloc_printf("%s/fuzzer_stats", remote_out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !eps) {
    bitmap_cvg = last_bcvg;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_eps  = eps;
  }

  fprintf(f, "start_time            : %llu\n"
             "last_update           : %llu\n"
             "fuzzer_pid            : %u\n"
             "first_crash_time      : %llu\n"
             "last_crash_time       : %llu\n"
             "cycles_done           : %llu\n"
             "execs_done            : %llu\n"
             "execs_per_sec         : %0.02f\n"
             "paths_total           : %u\n"
             "paths_found           : %u\n"
             "paths_imported        : %u\n"
             "max_depth             : %u\n"
             "cur_path              : %u\n"
             "pending_favs          : %u\n"
             "pending_total         : %u\n"
             "variable_paths        : %u\n"
             "bitmap_cvg            : %0.02f%%\n"
             "unique_crashes        : %llu\n"
             "unique_hangs          : %llu\n"
             "imported_paths        : %u\n"
             "checked_paths         : %i\n"
             "checked_crashes       : %i\n"
             "sync_times            : %i\n"
             "afl_banner            : %s\n"
             "afl_version           : " VERSION "\n"
             "command_line          : %s\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             first_crash_time / 1000, last_crash_time /1000,
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_discovered, queued_imported, max_depth,
             current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, bitmap_cvg, unique_crashes, unique_hangs,
             queued_imported, sync_count, sync_count_crashes, sync_times,
             use_banner, orig_cmdline); /* ignore errors */

  fclose(f);

}


/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;

  prev_qp  = queued_paths;
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* ignore errors */

  fflush(plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' && (!prefix ||
        !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}




/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);
  // u8* fn = alloc_printf("%s/fuzzer_stats", remote_out_dir);

  static s32 out_dir_fd;

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir);

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);

  }

  close(out_dir_fd);

  f = fopen(fn, "r");

  if (f) {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in in '%s'", out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume) {

    // u8* orig_q = alloc_printf("%s/queue", out_dir);

    // in_dir = alloc_printf("%s/_resume", out_dir);

    // rename(orig_q, in_dir); /* Ignore errors */

    // OKF("Output directory exists, will attempt session resume.");

    // ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  fn = alloc_printf("%s/.synced", out_dir);
  if (delete_files(fn, NULL)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/favored_edges", out_dir);
  if(delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  // if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  if (delete_files(fn, CASE_PREFIX) && delete_files(fn, "blocks,id:")) 
  {
    // erro_n = 1;
    goto dir_cleanup_failed;
  }
  ck_free(fn);



  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  fn = alloc_printf("%s/crashes/README.txt", out_dir);
  unlink(fn); /* Ignore errors */
  ck_free(fn);

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  // if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  if (delete_files(fn, CASE_PREFIX) && delete_files(fn, "blocks,id:")) 
  {
    // erro_n = 1;
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/.cur_code_block_info", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) {
    fn  = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;


  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, avg_exec);

    write_bitmap();

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
 
  }

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

  }

  SAYF(TERM_HOME);

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cNOR);

  } else {

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (cycles_wo_finds < 3) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 20 && !pending_not_fuzzed) strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cNOR "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
      in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cNOR "%-34s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cNOR 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cNOR "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cNOR "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cNOR "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cNOR,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cNOR "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cNOR "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny becuse we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  // sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
  //         queue_cur->favored ? "" : "*",
  //         ((double)current_entry * 100) / queued_paths);
  sprintf(tmp, "%s%s%d (%0.02f%%)", DI(current_entry),
        queue_cur && !queue_cur->favored ? "*" : ".",
        queue_cur?queue_cur->fuzz_level:-1,
        ((double)current_entry * 100) / queued_paths);


  SAYF(bV bSTOP "  now processing : " cNOR "%-17s " bSTG bV bSTOP, tmp);


  sprintf(tmp, "%s (%0.02f%%)", DI(t_bytes), t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cNOR), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cNOR "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cNOR "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cNOR "%-21s " bSTG bV bSTOP 
       " favored paths : " cNOR "%-22s " bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cNOR "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cNOR "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cNOR "%-21s " bSTG bV bSTOP
         "   new crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cNOR, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cNOR "%-21s " bSTG bV bSTOP
         " total crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cNOR, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cNOR "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_hangs), DI(unique_hangs),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "   total hangs : " cNOR "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cNOR "%-37s " bSTG bV bSTOP "    levels : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cNOR "%-37s " bSTG bV bSTOP "   pending : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cNOR "%-37s " bSTG bV bSTOP "  pend fav : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cNOR "%-37s " bSTG bV bSTOP " own finds : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  u8 _tmp[256];
  memset(_tmp, ' ', banner_pad);
  if(sync_id)
    sprintf(_tmp, "%s|%s[%s]", DI(queued_imported), DI(sync_count), DI(sync_times));
  else
    sprintf(_tmp, "%s", (u8*)"n/a");

  // SAYF(bV bSTOP "  dictionary : " cNOR "%-37s " bSTG bV bSTOP
  //      "  imported : " cNOR "%-10s " bSTG bV "\n", tmp,
  //      sync_id ? DI(queued_imported) : (u8*)"n/a");
  SAYF(bV bSTOP "  dictionary : " cNOR "%-37s " bSTG bV bSTOP
       "  imported : " cNOR "%-10s " bSTG bV "\n", tmp, _tmp);
  
  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cNOR "%-37s " bSTG bV bSTOP 
       "  variable : %s%-10s " bSTG bV "\n", tmp, queued_variable ? cLRD : cNOR,
      no_var_check ? (u8*)"n/a" : DI(queued_variable));

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
            blocks_eff_total);

    strcat(tmp, tmp2);

  }

  SAYF(bV bSTOP "        trim : " cNOR "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
       bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, cur_utilization < 999 ? cur_utilization : 999);

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}


static void show_stats__()
{
  return;
}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000)) 
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000) havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cNOR "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cNOR "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cNOR "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
    else exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  }

  OKF("All set and ready to roll!");

}







static int startswith(const char *str, const char *prefix)
{
    return strncmp(prefix, str, strlen(prefix)) == 0;
}

/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char** argv) {

  sync_times++;

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */
  // J.H.: here make syncing process follow the order of N2/N4/N8! 
  while ((sd_ent = readdir(sd))) {

    int num_checked_seeds = 0;

    static u8 stage_tmp[128];

    // DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u8 *deletetscs;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory, and not fuzz dir. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name) || !startswith(sd_ent->d_name, "Kirenenko")) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */
    // ACTF("target_sync_dir: %s", sd_ent->d_name);

    // here check if the current syncing directory is N2/N4/N8
    //int del; // for path-prefix, will be 9, for n-gram: 2,4,8
    // if (sscanf(sd_ent->d_name, "Kirenenko-N%d", &level) != 1) {
    //   PFATAL("Invalid Kirenenko-NX directory!\n");
    // }
    // if(!strcmp(sd_ent->d_name, "Kirenenko-novel")) del = 1;  // means ce seeds
    // if(!strcmp(sd_ent->d_name, "Kirenenko-fuzz")) del = 0;   // means fuzz seeds
    

    int i;
    char* q_or_c[2] = {"queue", "crashes"};
    for(i=0; i<1; i++) // here is when the iteration over queue directory happens. 
    {
      min_accept = 0;
      // qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);
      qd_path = alloc_printf("%s/%s/%s", sync_dir, sd_ent->d_name, q_or_c[i]);

      // if (!(qd = opendir(qd_path))) {
      //   ck_free(qd_path);
      //   continue;
      // }

      /* Retrieve the ID of the last seen test case. */

      // qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);
      qd_synced_path = alloc_printf("%s/.synced/%s_%s", out_dir, sd_ent->d_name, q_or_c[i]);

      id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

      if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

      if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
        lseek(id_fd, 0, SEEK_SET);

      next_min_accept = min_accept;

      /* Show stats */    

      sprintf(stage_tmp, "sync(%s) %u", q_or_c[i], ++sync_cnt);
      stage_name = stage_tmp;
      stage_cur  = 0;
      stage_max  = 0;

      /* For every file queued by this fuzzer, parse ID and see if we have looked at
         it before; exec a test case if not. */

      struct dirent ** namelist;
      int dir_n = scandir(qd_path, &namelist, 0, alphasort);
      if(dir_n < 0) {
        ck_free(qd_path);
        close(id_fd); // J.H.
        continue;    
      } 
      // while ((qd_ent = readdir(qd))) {
      int dir_i;
      for(dir_i = 0; dir_i < dir_n; dir_i++){  
        qd_ent = namelist[dir_i];
        u8* path;
        s32 fd;
        struct stat st;

        if (qd_ent->d_name[0] == '.' ||
            sscanf(qd_ent->d_name, CASE_PREFIX "%08u", &syncing_case) != 1 || 
            syncing_case < min_accept) {
            // delete the ones below min_accept!
            if(qd_ent->d_name[0] != '.' && syncing_case < min_accept) {//&& del) { // meaning ce seeds, feel free to delete this copy
              deletetscs = alloc_printf("%s/%s", qd_path, qd_ent->d_name);
              if(unlink(deletetscs)) 
                PFATAL("Unable to remove '%s', syncing_case/min_accept: %d/%d", deletetscs, syncing_case, min_accept);
            }            
            continue; // if the tscs has been executed before, skip it. 
        }

        if(i == 0 && num_checked_seeds == sync_max_seeds_per)
          break;

        /* OK, sounds like a new one. Let's give it a try. */

        if (syncing_case >= next_min_accept)
          next_min_accept = syncing_case + 1;        

        path = alloc_printf("%s/%s", qd_path, qd_ent->d_name); // the new tscs's path! 

        fd = open(path, O_RDONLY);
        if (fd < 0) PFATAL("Unable to open '%s'", path);

        if (fstat(fd, &st)) PFATAL("fstat() failed");

        /* Ignore zero-sized or oversized files. */ // J.H.: maybe skip the unfinished file here as well! 

        if (st.st_size && st.st_size <= MAX_FILE) {

          if(i == 0) 
          {
            sync_count++;
            num_checked_seeds++;
          }
          else
          {
            sync_count_crashes++;
          }
          u8  fault;
          u8* mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

          if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

          /* See what happens. We rely on save_if_interesting() to catch major
             errors and save the test case. */

          write_to_testcase(mem, st.st_size); // so for some reason, firstly modify the file for testing, then execute...
          // ACTF("run_target() 4");
          fault = run_target(argv); // here the file is finally executed!

          if (stop_soon) return;

          syncing_party = sd_ent->d_name;
          queued_imported += save_if_interesting_JH(argv, mem, st.st_size, fault, path, 0); // if the file is interesting, where the validation of file happens! 
          syncing_party = 0;

          munmap(mem, st.st_size);

          if (!(stage_cur++ % stats_update_freq)) show_stats();
        }
        ck_free(path);
        close(fd);

      }

      for(dir_i = 0; dir_i < dir_n; dir_i++)
      {
        free(namelist[dir_i]);
      }
      free(namelist);

      ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

      close(id_fd);
      // closedir(qd);
      ck_free(qd_path);
      ck_free(qd_synced_path);
    }
  }  
  closedir(sd);
}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}



/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  skip_requested = 1;

}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1; 
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1; 
    kill(forksrv_pid, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

static void check_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary: %s...", fname);

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

  if (getenv("AFL_SKIP_BIN_CHECK")) return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);

  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");

  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");

  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) uses_asan = 1;

  if (munmap(f_data, f_len)) PFATAL("unmap() failed");

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {

    if (sync_id) {

      use_banner = sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) use_banner = name; else use_banner = trim + 1;

    }

  }

  if (strlen(use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}


/* Check terminal dimensions. */

static void check_terminal(void) {

  struct winsize ws;

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

  if (ws.ws_row < 25 || ws.ws_col < 80) {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, your terminal window seems to be smaller than 80 x 25 characters.\n"
         "    That's not enough for afl-fuzz to correctly draw its fancy ANSI UI!\n\n"

         "    Depending on the terminal software you are using, you should be able to\n"
         "    resize the window by dragging its edges, or to adjust the dimensions in\n"
         "    the settings menu.\n");

    FATAL("Please resize terminal to 80x25 or more");

  }

}



/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -s dir        - sync directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n" 
       "  -L            - maintain logs under QEMU mode\n\n"   
 
       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Prepare output fds for qemu_log*/
static void setup_qemu_log_fd(void)
{
  if(!qemu_mode) FATAL("qemu_log only supported under qemu_mode");

  u8* tmp = alloc_printf("%s/qemu_log", out_dir);
  qemu_log_fd = open(tmp, O_RDWR|O_CREAT, 0600);
  if(qemu_log_fd < 0) PFATAL("unalbe to open %s", tmp);
  ck_free(tmp);

}


/* Prepare output directories and fds. */

static void setup_dirs_fds(void) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
      PFATAL("Unable to create '%s'", sync_dir);

  // if (mkdir(local_out_dir, 0700) && errno != EEXIST)
  //     PFATAL("Unable to create '%s'", local_out_dir);

  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  } else {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);


  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Favored queue directory for any starting & discovered paths. */
  tmp = alloc_printf("%s/queue/.state/favored_edges", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);


  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id) {

    tmp = alloc_printf("%s/.synced/", out_dir);
    if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */

}


/* Setup the output file for fuzzed data, if not using -f. */

static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}

static void setup_cb_info_file(void){
  /* setup fd for communicating covered code block info */

  u8* fn = alloc_printf("%s/.cur_code_block_info", out_dir);

  unlink(fn);

  out_cb_info_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if(out_cb_info_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void) {

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of 
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */
  
  if (system("launchctl bslist 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as hangs, please run the\n" 
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues due to an extended delay\n"
         "    between the fuzzed binary malfunctioning and this information being\n"
         "    eventually relayed to the fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as hangs, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    FATAL("Pipe at the beginning of 'core_pattern'");

  }
 
  close(fd);

#endif /* ^__APPLE__ */

}


/* Check CPU governor. */

static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

  /* On Linux, a simple way is to look at /proc/stat, especially since we'd
     be parsing it anyway for other reasons later on. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

  fclose(f);
  
#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU cores and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if (cur_runnable + 1 <= cpu_core_count) {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
  
      }

    }

  } else WARNF("Unable to figure out the number of CPU cores.");

}


/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void) {

  u8* x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");

  }

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }

  if (strlen(sync_id) > 64) FATAL("Fuzzer ID too long");

  

  if(!sync_dir)
  {
    sync_dir = out_dir;
  }

  x = alloc_printf("%s/%s", out_dir, sync_id);
  out_dir  = x;

  // x = alloc_printf("%s/%s", local_out_dir, sync_id);
  // local_out_dir = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  clear_screen = 1;
}


/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x && !strstr(x, "abort_on_error=1"))
    FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

  x = getenv("MSAN_OPTIONS");

  if (x && !strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
    FATAL("Custom MSAN_OPTIONS set without exit_code="
          STRINGIFY(MSAN_ERROR) " - please fix!");

} 


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
      {
        out_file = alloc_printf("%s/.cur_input", out_dir);
        // out_file = alloc_printf("%s/.cur_input", local_out_dir);
      }

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(AFL_PATH "/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = ck_strdup(AFL_PATH "/afl-qemu-trace");
    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}


/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char** argv) {

  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;
  
  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}

// void backup_stat(char** stat_vector, int cnt)
// {
//   char filepath[] = "/home/vagrant/cc_server/afl_fuzz_stat.txt";
//   FILE* pFile = fopen(filepath, "w+");
//   if(pFile != NULL) 
//   {
//     int i;
//     for(i = 0; i < cnt; i++ )
//     {
//       fprintf(pFile, "%s\n", stat_vector[i]);
//     }
//     fclose(pFile);
//   }
// }

/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  // u64 prev_queued = 0;
  // u32 sync_interval_cnt = 0; 

  u8  mem_limit_given = 0;
  // Allocate memory for hashmaps
  cksum2paths = kh_init(32); 
  hash_value_set = kh_init(p64);

  char** use_argv;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  

  while ((opt = getopt(argc, argv, "+o:f:m:t:T:dnCB:S:M:QLs:r")) > 0)
  {
    // ACTF("opt: %c", opt);
    switch (opt) {

      // case 'i':

      //   if (in_dir) FATAL("Multiple -i options not supported");
      //   in_dir = optarg;

      //   if (!strcmp(in_dir, "-")) in_place_resume = 1;

      //   break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;

        break;

      case 'M':

        force_deterministic = 1;
        /* Fall through */

      case 'S': /* sync ID */

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = optarg;
        break;

      case 's':
        if (sync_dir) FATAL("Multiple -s options not supported");
        sync_dir = optarg;
        break;

      // case 'l':
      //   if(local_out_dir) FATAL("Multiple -l options not supported");
      //   local_out_dir = optarg;
      //   break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;


      case 't': {

          u8 suffix = 0;

          if (timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1)
            FATAL("Bad syntax used for -t");

          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }

      case 'm': {

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1)
            FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 'd':

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B':

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C':

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'n':

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2 ; else dumb_mode = 1;

        break;

      case 'T':

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q':

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'L':

        if(is_qemu_log) FATAL("Multiple -L options not supported");
        is_qemu_log = 1;
        break;

      case 'r':
        if(is_trim_case) FATAL("Multiple -r options not supported");
        OKF("seed minimization turned on");
        is_trim_case = 1;
        break;


      default:

        usage(argv[0]);

    }
  }
  

  if (optind == argc || /*!in_dir ||*/ !out_dir) usage(argv[0]);

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id) fix_up_sync();

  // if (!strcmp(in_dir, out_dir))
  //   FATAL("Input and output directories can't be the same");

  if (dumb_mode) {

    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }

  if (getenv("AFL_NO_FORKSRV"))   no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))   no_cpu_meter_red = 1;
  if (getenv("AFL_NO_VAR_CHECK")) no_var_check     = 1;

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_terminal();

  get_core_count();
  check_crash_handling();
  check_cpu_governor();

  setup_shm();

  setup_dirs_fds();

  if(is_qemu_log)
    setup_qemu_log_fd();



  detect_file_args(argv + optind + 1);

  if (!out_file) setup_stdio_file();
  setup_cb_info_file();
    
  check_binary(argv[optind]);
  start_time = get_cur_time();
 
  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  int _j;
  for(_j=0; _j<3; _j++)
    ACTF("use_argv[%i]: %s", _j , use_argv[_j]);

  ACTF("target_path_: %s", target_path);

  ACTF("sync_dir: %s", sync_dir);
  ACTF("out_dir: %s", out_dir);

  // perform_dry_run(use_argv);
  if (!dumb_mode && !no_forkserver && !forksrv_pid)
    init_forkserver(use_argv);

  


  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  while (1) {


      queue_cycle++;

      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

    sync_fuzzers(use_argv);
    write_stats_file(0,0);
    show_stats();

    cull_queue();

    if (stop_soon) break;


  }

  // if (queue_cur) show_stats();
  show_stats();

  write_bitmap();
  write_stats_file(0, 0);


stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted by user +++\n" cRST);

  /* Running for more than 30 minutes but still doing first cycle? */

  // if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

  //   SAYF("\n" cYEL "[!] " cRST
  //          "Stopped during the first cycle, results may be incomplete.\n"
  //          "    (For info on resuming, see %s/README.)\n", doc_path);

  // }

  fclose(plot_file);
  destroy_queue();

  ck_free(target_path);
  
  // De-allocate memory for hashmaps
  kh_destroy(32, cksum2paths);

  alloc_report();

  show_stats();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}
