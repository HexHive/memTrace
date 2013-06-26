#include "fbt_translate.h"
#include "fbt_libc.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"
#include "fbt_llio.h"

#include <unistd.h>
#include <stdio.h>
#include <asm-generic/mman.h>

// Here we include the code that we would like to test
//#include "sdbg_insert_lea.h"
enum translation_state action_copy(struct translate *ts);

int check_action_pop(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct translate ts;
  struct thread_local_data tld;
  ts.tld = &tld;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld->transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = action_pop(&ts);

  if (ts.tld->transl_instr-&trans[0] != len){
      error = 1;
  }
  int i;
  for (i=0; i<len; i++){
     if (xpect[i] != trans[i]){
         error = 1;
         //assert(0);
     }
  }
  if (error){
    printf("ERROR\n");
    printf("expected: ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)xpect[i]);
    }
    printf("\n");
    printf("got:      ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)trans[i]);
    }
    printf("\n");
  } else {
    printf("test successful\n");
  }
  return error;
}


int check_action_push(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct translate ts;
  struct thread_local_data tld;
  ts.tld = &tld;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld->transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = action_push(&ts);

  if (ts.tld->transl_instr-&trans[0] != len){
      error = 1;
  }
  int i;
  for (i=0; i<len; i++){
     if (xpect[i] != trans[i]){
         error = 1;
         //assert(0);
     }
  }
  if (error){
    printf("ERROR\n");
    printf("expected: ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)xpect[i]);
    }
    printf("\n");
    printf("got:      ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)trans[i]);
    }
    printf("\n");
  } else {
    printf("test successful\n");
  }
  return error;
}

uchar* buf1;
uchar* buf2;

int check_buffers(uchar* pa, uchar* pb){
  int er = check_action_push(buf1, buf2, (int)(pb-buf2));
  if (er) { 
      printf("orig:     ");
      uchar* i;
      for (i = buf1; i!=pa; i++){ 
	printf("%02x ", (unsigned)*i); 
      } 
      printf("\n");
      return 0;
   } else {
      return 1;
   }
}

int check_buffers_pop(uchar* pa, uchar* pb){
  int er = check_action_pop(buf1, buf2, (int)(pb-buf2));
  if (er) { 
      printf("orig:     ");
      uchar* i;
      for (i = buf1; i!=pa; i++){ 
	printf("%02x ", (unsigned)*i); 
      } 
      printf("\n");
      return 0;
   } else {
      return 1;
   }
}
int test0(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl %ebx
  END_ASM
  BEGIN_ASM(pb)
    movl %ebx, -4(%esp)
    leal -4(%rsp), %esp
  END_ASM
  check_buffers(pa,pb);
}

int test0bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    popl %ebx
  END_ASM
  BEGIN_ASM(pb)
    leal 4(%rsp), %esp
    movl -4(%esp), %ebx
  END_ASM
  check_buffers_pop(pa,pb);
}

int test0c(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    popl %ebp
  END_ASM
  BEGIN_ASM(pb)
    leal 4(%rsp), %esp
    movl -4(%esp), %ebp
  END_ASM
  check_buffers_pop(pa,pb);
}

int test1(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl 0xdeadfee(%eax, %ebx, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee(%eax, %ebx, 4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test1b(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl 0x05(%eax, %ebx, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x05(%eax, %ebx, 4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test1c(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl (%eax, %ebx, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl (%eax, %ebx, 4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test2(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl 0xdeadfee
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee, %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test3(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl  0x1c(%ebp)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x1c(%ebp), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test3bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl  0x4(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x4(%ebx), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test3bis1(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl (%ecx)
  END_ASM
  BEGIN_ASM(pb)
    movl (%ecx), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test3bis2(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl  0x4bcabba(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x4bcabba(%ebx), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test3bis3(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl  0x4bcabba(%edx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x4bcabba(%edx), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}


int test4a(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl $0xdeadfee
  END_ASM
  BEGIN_ASM(pb)
    leal -4(%rsp), %esp
    movl $0xdeadfee, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4b(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl $0xffffffff
  END_ASM
  BEGIN_ASM(pb)
    leal -4(%rsp), %esp
    movl $0xffffffff, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4c(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl $0xff
  END_ASM
  BEGIN_ASM(pb)
    leal -4(%rsp), %esp
    movl $0xff, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4d(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl $0x22
  END_ASM
  BEGIN_ASM(pb)
    leal -4(%rsp), %esp
    movl $0x22, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4e(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    pushl %gs:(%eax)
  END_ASM
  BEGIN_ASM(pb)
    movl %gs:(%eax), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4f(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  push %gs:(,%eax,4);
  END_ASM
  BEGIN_ASM(pb)
    movl %gs:(,%eax,4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4g(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  push (,%eax,4);
  END_ASM
  BEGIN_ASM(pb)
    movl (,%eax,4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4h(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  push (,%ecx,4);
  END_ASM
  BEGIN_ASM(pb)
    movl (,%ecx,4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}

int test4i(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  push (,%ebp,4);
  END_ASM
  BEGIN_ASM(pb)
    movl (,%ebp,4), %r8d
    leal -4(%rsp), %esp
    movl %r8d, (%esp)
  END_ASM
  check_buffers(pa,pb);
}


int main(){
  // Generates buffers for 32 bit instructions. 
  // We use mmap since they need to be addressable with 32 bit pointers

  buf1 = fbt_mmap((void*)0x90000, 5 * PAGESIZE, PROT_READ|PROT_WRITE,
					 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0,
					 "fail!!\nn");
  buf2 = fbt_mmap((void*)0x180000, 5 * PAGESIZE, PROT_READ|PROT_WRITE,
					 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0,
					 "fail!!!\n");
  int nsuccess = 0;
  int ntests = 0;

  nsuccess += test0();
  ntests++;

  nsuccess += test0bis();
  ntests++;

  nsuccess += test0c();
  ntests++;

  nsuccess += test1();
  ntests++;

  nsuccess += test1b();
  ntests++;

  nsuccess += test1c();
  ntests++;

  nsuccess += test2();
  ntests++;

  nsuccess += test3();
  ntests++;

  nsuccess += test3bis();
  ntests++;

  nsuccess += test3bis1();
  ntests++;

  nsuccess += test3bis2();
  ntests++;

  nsuccess += test3bis3();
  ntests++;

  nsuccess += test4a();
  ntests++;

  nsuccess += test4b();
  ntests++;

  nsuccess += test4c();
  ntests++;

  nsuccess += test4d();
  ntests++;

  nsuccess += test4e();
  ntests++;

  nsuccess += test4f();
  ntests++;

  nsuccess += test4g();
  ntests++;

  nsuccess += test4h();
  ntests++;

  nsuccess += test4i();
  ntests++;

  printf("\n\n%d of %d tests successful\n\n", nsuccess, ntests);

  if (nsuccess == ntests){
    return 0;
  } else {
    return -1;
  }
}










