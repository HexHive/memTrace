#include <asm/ldt.h>
#include <time.h>
#include "syscalls.h"

#define CSIGNAL         0x000000ff      /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if  info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000      /* Same thread group? */
#define CLONE_NEWNS     0x00020000      /* New namespace group? */
#define CLONE_SYSVSEM   0x00040000      /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS    0x00080000      /* create a new TLS for the child */
#define CLONE_PARENT_SETTID     0x00100000      /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID    0x00200000      /* clear the TID in the child */
#define CLONE_DETACHED          0x00400000      /* Unused, ignored */
#define CLONE_UNTRACED          0x00800000      /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID      0x01000000      /* set the TID in the child */
#define CLONE_STOPPED           0x02000000      /* Start in stopped state */
#define CLONE_NEWUTS            0x04000000      /* New utsname group? */
#define CLONE_NEWIPC            0x08000000      /* New ipcs */
#define CLONE_NEWUSER           0x10000000      /* New user namespace */
#define CLONE_NEWPID            0x20000000      /* New pid namespace */
#define CLONE_NEWNET            0x40000000      /* New network namespace */
#define CLONE_IO                0x80000000      /* Clone io context */

#define SYS_nanosleep      162

struct user_desc u2;

int ekrclone(int (*fn)(void *), void *child_stack,
             int flags, pid_t *ptid, struct user_desc *tls, pid_t *ctid);

void ekrprint(int fd, unsigned n)
{
  char bb[8];
  char bbrev[9];
  int i;
  for (i=0; i<8; i++){
    bb[i]='0';
  }
  int bbs = 0;
  while (n){
    unsigned tmp = (n%16);
    if (tmp < 10){
      bb[bbs] = (unsigned char)((unsigned int)'0' + tmp);
    } else {
      bb[bbs] = (unsigned char)((unsigned int)'a' + tmp - 10);
    }
    n /= 16;
    bbs++;
  }

  for (i=0; i<8; i++){
    bbrev[i]=bb[7-i];
  }
  bbrev[8] = '\n';

  int rs;
  _syscall3(write, 2, bbrev, 9, rs);
}

void* memory[0x100000];

void* thestack[0x100000];

unsigned thetid = 0;

void threadfun()
{
  int r;
  _syscall3(write, 2, "thfn\n", 5, r);
  ekrprint(2, thetid);

  //asm ("movw %w0, %%gs" :: "q" (u2.entry_number * 8 + 3));
  int i;
  for (i=0; i<10; i++){
    struct timespec re;
    re.tv_sec = 1;
    re.tv_nsec = 0;
    _syscall2(nanosleep, &re, NULL, r);

    int m;
    asm("movl %%gs:0x0, %0": "=r"(m));
    _syscall3(write, 2, "m\n", 2, r);
    ekrprint(2, m);
  }

  _syscall1(exit, 0, r);
}

int _start(int ac, char **av)
{
  int i;
  for (i=0; i<0x100000; i++)
    memory[i]=0;

  int r;
  int result;

  struct user_desc u_info;
  u_info.entry_number = -1;
  u_info.base_addr = &memory[0x10000];
  u_info.limit = 0xffff;
  u_info.seg_32bit = 1;
  u_info.contents = 0;
  u_info.read_exec_only = 0;
  u_info.limit_in_pages = 1;
  u_info.seg_not_present = 0;
  u_info.useable = 1;

  u2.entry_number = -1;
  u2.base_addr = &memory[0x10000];
  u2.limit = 0xffff;
  u2.seg_32bit = 1;
  u2.contents = 0;
  u2.read_exec_only = 0;
  u2.limit_in_pages = 1;
  u2.seg_not_present = 0;
  u2.useable = 1;

  _syscall1(set_thread_area, &u_info, result);

  ekrprint(2, u_info.entry_number);
  if(result < 0)
    {
      _syscall3(write, 2, "fail\n", 5, r);
      _syscall1(exit, 0, r);
    }
  _syscall3(write, 2, "win!\n", 5, r);

  // set gs to right value
  asm ("movw %w0, %%gs" :: "q" (u_info.entry_number * 8 + 3));

  unsigned flags = CLONE_VM|CLONE_FS|CLONE_FILES
                    |CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM
                    |CLONE_PARENT_SETTID
                    |CLONE_CHILD_CLEARTID
                    |CLONE_SETTLS
                    ;
  ekrclone(threadfun,&thestack[0x100000-10],flags,&thetid,&u2,&thetid);

  struct timespec req;
  req.tv_sec = 1;
  req.tv_nsec = 500000;
  //struct timespec rem;

  _syscall3(write, 2, "wait\n", 5, r);
  _syscall2(nanosleep, &req, NULL, r);
  _syscall3(write, 2, "tiaw\n", 5, r);

  ekrprint(2, thetid);

  asm("movl $0xdadadada, %gs:0x0");

  for (i=0; i<0x100000; i++){
    if (memory[i]){
      _syscall3(write, 2, "nonn\n", 5, r);
      ekrprint(2, memory[i]);
    } 
  }

  for (i=0; i<10; i++){
    struct timespec re;
    re.tv_sec = 1;
    re.tv_nsec = 30000;
    _syscall2(nanosleep, &re, NULL, r);

    int q;
    asm("movl %%gs:0x0, %0": "=r"(q));
    _syscall3(write, 2, "q\n", 2, r);
    ekrprint(2, q);
  }

  _syscall1(exit, 0, r);
}

