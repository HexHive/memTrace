#include "fbt_translate.h"
#include "fbt_libc.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"
#include "fbt_llio.h"

#include <unistd.h>
#include <stdio.h>
#include <asm-generic/mman.h>

int check(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct thread_local_data tld;
  struct translate ts;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld = &tld;
  ts.tld->transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = transform_instruction_to_leal_if_appropriate(&ts);

  if (ts.tld->transl_instr-&trans[0] != len){
      error = 1;
  }
  int i;
  for (i=0; i<len; i++){
     if (xpect[i] != trans[i]){
         error = 1;
     }
  }
  if (error){
    printf("ERROR\n");
    printf("xpected len %d but got %d\n",len,ts.tld->transl_instr-&trans[0]);
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

int checkret(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct translate ts;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld->transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = transform_instruction_to_leal_if_appropriate(&ts);

  if (ret){
    printf("ERROR\n");
  } else {
    printf("test successful\n");
  }
}

uchar* buf1;
uchar* buf2;

int check_returned(uchar* pa, uchar* pb){
  checkret(buf1, buf2, (int)(pb-buf2));
}

int check_buffers(uchar* pa, uchar* pb){
  int er = check(buf1, buf2, (int)(pb-buf2));
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
    mov 0xdeadbee, %eax
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test1(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    mov %eax, 0xdeadbee
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test2(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    mov %al, 0x55
  END_ASM
  BEGIN_ASM(pb)
    lea 0x55, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test3(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    mov 0x55, %al
  END_ASM
  BEGIN_ASM(pb)
    lea 0x55, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test4(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl 0xdeadbee, %ecx
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test5(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl %ecx, 0xdeadbee
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}

int test6(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl 0xdeadbee, %ecx
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test7(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ecx, 0xdeadbee
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test8(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl 0xdeadbee, %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test9(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl %ebx, 0xdeadbee
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}

int test10(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl 0xdeadbee, %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}
int test11(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, 0xdeadbee
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee, %r8
  END_ASM
  check_buffers(pa,pb);
}

int test12(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl 0xdeadbee(%eax, %ebx, 4), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee(%eax, %ebx, 4), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test13(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, 0xdeadbee(%eax, %ebx, 4)
  END_ASM
  BEGIN_ASM(pb)
    lea 0xdeadbee(%eax, %ebx, 4), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test14(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl 0x123456(%edx, %ecx, 1), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea 0x123456(%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test15(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, 0x123456(%edx, %ecx, 1)
  END_ASM
  BEGIN_ASM(pb)
    lea 0x123456(%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test16(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl 0x12(%edx, %ecx, 1), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea 0x12(%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test17(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, 0x12(%edx, %ecx, 1)
  END_ASM
  BEGIN_ASM(pb)
    lea 0x12(%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}


int test18(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl (%edx, %ecx, 1), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea (%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test19(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, (%edx, %ecx, 1)
  END_ASM
  BEGIN_ASM(pb)
    lea (%edx, %ecx, 1), %r8
  END_ASM
  check_buffers(pa,pb);
}


int test20(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl (%edx, %ecx), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea (%edx, %ecx), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test21(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, (%edx, %ecx)
  END_ASM
  BEGIN_ASM(pb)
    lea (%edx, %ecx), %r8
  END_ASM
  check_buffers(pa,pb);
}


int test22(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl (%ebx), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea (%ebx), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test23(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, (%ebx)
  END_ASM
  BEGIN_ASM(pb)
    lea (%ebx), %r8
  END_ASM
  check_buffers(pa,pb);
}


int test24(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl (,%ebx,8), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea (,%ebx,8), %r8
  END_ASM
  check_buffers(pa,pb);
}
int test25(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    addl %ebx, (,%ebx,8)
  END_ASM
  BEGIN_ASM(pb)
    lea (,%ebx,8), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test26(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    add %esp,-0x7d(%edi)
  END_ASM
  BEGIN_ASM(pb)
    lea -0x7d(%edi), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test27(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    cmpb $0x0,(%edx,%eax,1)
  END_ASM
  BEGIN_ASM(pb)
    lea (%edx,%eax,1), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test28(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl   $0xdeadbee,0x55dada
  END_ASM
  BEGIN_ASM(pb)
    lea 0x55dada, %r8
  END_ASM
  check_buffers(pa,pb);
}


int test29(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl   $0xdeadbee,0x55dada(%eax, %ebx, 4)
  END_ASM
  BEGIN_ASM(pb)
    lea 0x55dada(%eax, %ebx, 4), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test30(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl   $0xdeadbee,%eax
  END_ASM
  BEGIN_ASM(pb)
  END_ASM
  check_buffers(pa,pb);
}

int test31(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    movl $0xdeadbee,%eax
  END_ASM
  BEGIN_ASM(pb)
  END_ASM
  check_buffers(pa,pb);
}

int test32(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    cmpl $0x0,%gs:0xc
  END_ASM
  BEGIN_ASM(pb)
  END_ASM
  check_buffers(pa,pb);
}

int test33(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    cmp %dl,(%eax)
  END_ASM
  BEGIN_ASM(pb)
    lea (%eax), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test34(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    mov (%esp), %ebx
  END_ASM
  BEGIN_ASM(pb)
    lea (%esp), %r8
  END_ASM
  check_buffers(pa,pb);
}

int test35(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    imul 0x70(%ebp), %ebp
  END_ASM
  BEGIN_ASM(pb)
    lea 0x70(%ebp), %r8
  END_ASM
  check_buffers(pa,pb);
}

void cls(){
  int i;
  for (i=0; i<100; i++){buf1[i]=0;buf2[i]=0;}
}

#define TST(nr) cls();  nsuccess += test##nr();  ntests++;

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

  TST(0);
  TST(1);
  TST(2);
  TST(3);
  
  TST(4);
  TST(5);

  TST(6);
  TST(7);

  TST(8);
  TST(9);

  TST(10);
  TST(11);

  TST(12);
  TST(13);

  TST(14);
  TST(15);

  TST(16);
  TST(17);

  TST(18);
  TST(19);

  TST(20);
  TST(21);

  TST(22);
  TST(23);

  TST(24);
  TST(25);

  TST(26);

  TST(27);

  TST(28);
  TST(29);

  TST(30);

  TST(31);

  TST(32);

  TST(33);

  TST(34);

  TST(35);

  printf("\n\n%d of %d tests successful\n\n", nsuccess, ntests);

  if (nsuccess == ntests){
    return 0;
  } else {
    return -1;
  }
}










