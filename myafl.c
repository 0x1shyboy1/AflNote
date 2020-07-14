#define AFL_FUCK
#define MESSAGES_TO_STDOUT

#define _GUN_SOURCE
#define _FILE_OFFSET_BITS 64

#define MIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include <stdio.h>

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */


static u32 rand_cnt;
static inline u32 UR(u32 limit){
    if(unlikely(!rand_cnt--)){
        u32 seed[2];
        ck_read(dev_urandom_fd,&seed,sizeof(seed),"/dev/urandom");
    }
    return random() % limit;
}

int main(){
    printf("MIN=%d\n",MIN(5,2));
    printf("MAX=%d\n",MAX(5,2));
    printf("SWAP16=%x\n",SWAP16(1023));
    printf("SWAP32=%x\n",SWAP32(0x12345678));
    printf("UR=%x\n",UR(16));
    return 0;
}