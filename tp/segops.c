#include <asm/ldt.h>
#include <time.h>
#include "syscalls.h"

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

void** memory[0x10000];
void** thestack[0x10000];

unsigned thetid = 0;
unsigned far;

int sayhi()
{
  int r;
  far = 88;
  _syscall3(write, 2, "hi!!\n", 5, r);
  return 17;
}

int main(int ac, char **av)
{
  int i;
  for (i=0; i<0x10000; i++)
    memory[i]=0;

  int r;
  int result;

  struct user_desc u_info;
  u_info.entry_number = -1;
  u_info.base_addr = &memory[0x0];
  u_info.limit = 0xffff;
  u_info.seg_32bit = 1;
  u_info.contents = 0;
  u_info.read_exec_only = 0;
  u_info.limit_in_pages = 1;
  u_info.seg_not_present = 0;
  u_info.useable = 1;

  _syscall1(set_thread_area, &u_info, result);

  if(result < 0) {
    _syscall3(write, 2, "fail\n", 5, r);
    _syscall1(exit, 0, r);
  } else {
    _syscall3(write, 2, "win!\n", 5, r);
    ekrprint(2, u_info.entry_number);
  }

  // set gs to right value
  asm ("movw %w0, %%gs" :: "q" (u_info.entry_number * 8 + 3));

  ekrprint(2, thetid);

  asm("movl $0xdadadada, %gs:0x0");
  ekrprint(2, memory[0x0]);

  asm("mov $0x10, %%eax; movl $0xdfdfdfdf, %%gs:(,%%eax,4)": : : "eax");
  ekrprint(2, memory[0x10]);

  unsigned kk;
  asm("leal %%gs:(,%%eax,4), %0": "=g"(kk));
  ekrprint(2, kk);

  unsigned tt = 0;
  int d = 0;
  asm(//"int3;"
      "mov $0x10, %%eax;"
      "movl $0xdeffadee, %%gs:(,%%eax,4);"
      "mov %%esp, %1;"
      "push %%gs:(,%%eax,4);"
      "sub %%esp, %1;"
      "pop %0"
        : "=g"(tt), "=g"(d)
        :
        : "eax", "esp", "memory");
  ekrprint(2, tt);
  ekrprint(2, d);

  memory[0x0] = &sayhi;
  int qr;
  asm("mov %%esp, %%gs:0x50; call *%%gs:0x0; cmp %%esp, %%gs:0x50; je ok; hlt; ok:"
         : "=eax"(qr)
         :
         : "memory");
  ekrprint(2, qr);


  _syscall1(exit, d+qr, r);
}

