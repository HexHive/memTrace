#include "fbt_translate.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"

#include <unistd.h>
#include <stdio.h>
#include <asm-generic/mman.h>

// Here we include the code that we would like to test
//#include "sdbg_insert_lea.h"
enum translation_state action_copy(struct translate *ts);

int check_action_indjmp(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct translate ts;
  struct thread_local_data tld;
  ts.tld = &tld;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld->transl_instr = &trans[0];
  unsigned char* transl_addr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = jump_target_into_r8(&ts, &transl_addr);

  if (transl_addr-&trans[0] != len){
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
  int er = check_action_indjmp(buf1, buf2, (int)(pb-buf2));
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
    jmp *(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl (%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test0_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl (%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test0bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *(%edi)
  END_ASM
  BEGIN_ASM(pb)
    movl (%edi), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test0bis_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *(%edi)
  END_ASM
  BEGIN_ASM(pb)
    movl (%edi), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test0bis2(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *(%eax)
  END_ASM
  BEGIN_ASM(pb)
    movl (%eax), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test0bis2_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *(%eax)
  END_ASM
  BEGIN_ASM(pb)
    movl (%eax), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test1(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *0xdeadfee
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test1_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0xdeadfee
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test2(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *0xdeadfee(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee(%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test2_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0xdeadfee(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee(%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test2bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *0xdeadfee(%ebp)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee(%ebp), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test2bis_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0xdeadfee(%ebp)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadfee(%ebp), %r8d
  END_ASM
  check_buffers(pa,pb);
}


int test3(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  jmp *0x0a(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test3_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  call *0x0a(%ebx)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebx), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test3bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  jmp *0x0a(%ebp)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebp), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test3bis_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
  call *0x0a(%ebp)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebp), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4mm(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl (%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4mm_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl (%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *0x0a(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}
int test4_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0x0a(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x0a(%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bis(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *0xdeadbee(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadbee(%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}
int test4bis_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0xdeadbee(%ebx, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0xdeadbee(%ebx, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}


int test4bisb(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  *pa++ = 0xff;
  *pa++ = 0x24;
  *pa++ = 0x85;
  *pa++ = 0xbc;
  *pa++ = 0x53;
  *pa++ = 0x06;
  *pa++ = 0x08;
  BEGIN_ASM(pb)
    movl 0x80653bc(, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bis_callb(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0x80653bc(, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x80653bc(, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bisc(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_ASM(pa)
    jmp *0x80(%ebp, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x80(%ebp, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bis_callc(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0x80(%ebp, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x80(%ebp, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bisd(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_ASM(pa)
    jmp *0x80dada(%ebp, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x80dada(%ebp, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test4bis_calld(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *0x80653bc(%ebp, %eax, 4)
  END_ASM
  BEGIN_ASM(pb)
    movl 0x80653bc(%ebp, %eax, 4), %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test5(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *%eax
  END_ASM
  BEGIN_ASM(pb)
    movl %eax, %r8d
  END_ASM
  check_buffers(pa,pb);
}
int test5_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *%eax
  END_ASM
  BEGIN_ASM(pb)
    movl %eax, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test5b(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *%edi
  END_ASM
  BEGIN_ASM(pb)
    movl %edi, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test5b_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *%edi
  END_ASM
  BEGIN_ASM(pb)
    movl %edi, %r8d
  END_ASM
  check_buffers(pa,pb);
}


int test6(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *%esp
  END_ASM
  BEGIN_ASM(pb)
    movl %esp, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test6_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *%esp
  END_ASM
  BEGIN_ASM(pb)
    movl %esp, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test6b(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *%ebp
  END_ASM
  BEGIN_ASM(pb)
    movl %ebp, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test6b_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *%ebp
  END_ASM
  BEGIN_ASM(pb)
    movl %ebp, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test6c(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    jmp *%esi
  END_ASM
  BEGIN_ASM(pb)
    movl %esi, %r8d
  END_ASM
  check_buffers(pa,pb);
}

int test6c_call(){
  uchar* pa = buf1;
  uchar* pb = buf2;
  BEGIN_32ASM(pa)
    call *%esi
  END_ASM
  BEGIN_ASM(pb)
    movl %esi, %r8d
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
  nsuccess += test0_call();
  ntests++;

  nsuccess += test0bis();
  ntests++;
  nsuccess += test0bis_call();
  ntests++;

  nsuccess += test0bis2();
  ntests++;
  nsuccess += test0bis2_call();
  ntests++;

  nsuccess += test1();
  ntests++;
  nsuccess += test1_call();
  ntests++;

  nsuccess += test2();
  ntests++;
  nsuccess += test2_call();
  ntests++;

  nsuccess += test2bis();
  ntests++;
  nsuccess += test2bis_call();
  ntests++;

  nsuccess += test3();
  ntests++;
  nsuccess += test3_call();
  ntests++;

  nsuccess += test3bis();
  ntests++;
  nsuccess += test3bis_call();
  ntests++;

  nsuccess += test4mm();
  ntests++;
  nsuccess += test4mm_call();
  ntests++;

  nsuccess += test4();
  ntests++;
  nsuccess += test4_call();
  ntests++;

  nsuccess += test4bis();
  ntests++;
  nsuccess += test4bis_call();
  ntests++;

  nsuccess += test4bisb();
  ntests++;
  nsuccess += test4bis_callb();
  ntests++;

  nsuccess += test4bisc();  // nota
  ntests++;
  nsuccess += test4bis_callc();
  ntests++;

  printf("test4bisd\n");
  nsuccess += test4bisd();
  ntests++;
  nsuccess += test4bis_calld();
  ntests++;

  nsuccess += test5();
  ntests++;
  nsuccess += test5_call();
  ntests++;

  nsuccess += test5b();
  ntests++;
  nsuccess += test5b_call();
  ntests++;


  nsuccess += test6();
  ntests++;
  nsuccess += test6_call();
  ntests++;

  nsuccess += test6b();
  ntests++;
  nsuccess += test6b_call();
  ntests++;

  nsuccess += test6c();
  ntests++;
  nsuccess += test6c_call();
  ntests++;

  printf("\n\n%d of %d tests successful\n\n", nsuccess, ntests);

  if (nsuccess == ntests){
    return 0;
  } else {
    return -1;
  }
}










