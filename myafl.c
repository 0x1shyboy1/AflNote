#define AFL_FUCK
#define MESSAGES_TO_STDOUT

#define _GUN_SOURCE
#define _FILE_OFFSET_BITS 64

#define MIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include <stdio.h>
#include <fcntl.h>

#define RESEED_RNG 1000
#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif /* ^AFL_LIB */
EXP_ST u8 *in_dir,                    /* Input directory with test cases  */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *sync_dir,                  /* Synchronization directory        */
          *sync_id,                   /* Fuzzer ID                        */
          *use_banner,                /* Display banner                   */
          *in_bitmap,                 /* Input bitmap                     */
          *doc_path,                  /* Path to documentation dir        */
          *target_path,               /* Path to target binary            */
          *orig_cmdline;              /* Original command line            */
static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */


static u32 rand_cnt;

struct queue_entry
{
    u8 *fname;
    u32 len;

    u8 cal_failed,
        trim_done,
        was_fuzzed,
        passed_det,
        has_new_cov,
        var_behavior,
        favored,
        fs_redundant;

    u32 bitmap_size,
        exec_cksum;

    u64 exec_us,
        handicap,
        depth;

    u8 *trace_mini;

    u32 tc_ref;

    struct queue_entry *next,
                        *next_100;
    
};


void init(){
    dev_urandom_fd=open("/dev/urandom",O_RDONLY);
}

static inline u32 UR(u32 limit){
    if(unlikely(!rand_cnt--)){
        u32 seed[2];
        ck_read(dev_urandom_fd,&seed,sizeof(seed),"/dev/urandom");
        srandom(seed[1]);
        rand_cnt=(RESEED_RNG/2)+(seed[1]%RESEED_RNG);
    }
    return random() % limit;
}
//bits change
static void shuffle_ptrs(void **ptrs,u32 cnt){
    u32 i;
    for(i=0;i<cnt-2;i++){
        u32 j=i+UR(cnt-i);
        void *s=ptrs[i];
        ptrs[i]=ptrs[j];
        ptrs[j]=s;
    }
}

#ifdef HAVE_AFINITY
static void bind_to_free_cpu(){
    dir 
}
#endif

#ifdef IGNORE_FINDS
static void locate_diffs(u8 *ptr1,u8 *ptr2,u32 len,s32 *first,s32 last){
    s32 f_loc = -1;
    s32 l_loc = -1;
    u32 pos;
    for(pos = 0;pos < len;pos++){
        if(*(ptr1++)!=*(ptr2++)){
            if(f_loc==-1) f_loc=pos;
            l_loc = pos;
        }
    }
    *first = f_loc;
    *last = l_loc;

    return;
}
#endif
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

static void mark_as_det_done(struct queue_entry *q){
    u8 *fn=strstr(q->fname,'/');
    s32 fd;
    fn = alloc_printf("%s/queue/.state/deterministic_done/%s",out_dir,fn+1);
    fd=open(fn,O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0) PFATAL ("Unable to create '%s'",fn);
    close(fd);

    ck_free(fn);

    q->passed_det=1;
}

static void mark_as_variable(struct queue_entry *q){
    u8 *fn = strstr(q->fname,'/')+1,*ldest;
    ldest = alloc_printf("../../%s",fn);

    fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

    if(symlink(ldest,fn)){
        s32 fd = open(fn,O_WRONLY|O_CREAT|O_EXCL,0600);
        if(fd<0) PFATAL ("Unable to create '%s'",fn);
        close(fd);
    }
    ck_free(ldest);
    ck_free(fn);
    q->var_behavior=1;
}

int main(){
    init();
    printf("MIN=%d\n",MIN(5,2));
    printf("MAX=%d\n",MAX(5,2));
    printf("SWAP16=%x\n",SWAP16(1023));
    printf("SWAP32=%x\n",SWAP32(0x12345678));
    for(int i=0;i<20;i++){
        printf("UR=0x%x\n",UR(16));
    }
    printf("UR=0x%x\n",UR(16));
    return 0;
}