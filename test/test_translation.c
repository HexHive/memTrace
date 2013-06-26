#include "fbt_sdbg.h"

#include <unistd.h>
#include <asm-generic/fcntl.h>
#include <asm-generic/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "fbt_llio.h"
#include "fbt_libc.h"
#include "fbt_debug.h"
#include "fbt_syscalls_impl.h"
#include "fbt_mem_mgmt.h"
#include "fbt_asm_macros.h"
#include "fbt_code_cache.h"
#include "libfastbt.h"
#include "fbt_translate.h"
#include "fbt_x86_opcode.h"


#include "sdbg_insert_lea.h"

void check_lea(unsigned char* orig, unsigned char* xpect, int len){
  int error = 0;

  struct translate ts;
  unsigned char trans[16];

  ts.cur_instr = &orig[0];
  ts.next_instr = ts.cur_instr;
  ts.transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  unsigned char* trans_instr = ts.transl_instr;
  sdbg_insert_leal(&ts, &trans_instr);

  if (trans_instr-&trans[0] != len){
      error = 1;
  }
  int i;
  for (i=0; i<len; i++){
     if (xpect[i] != trans[i]){
         error = 1;
         //assert(0);
     }
  }
  if (error)
    printf("ERROR\n");
  else
    printf("test successful\n");
}

/*
 This function can be used to see the machine code by doing
 objdump -d tstlea | grep -A30 to_disas
 to develop new tests
 */
int to_disas()
{
  asm("movl %edx,0x80496c0(,%eax,4)");
  asm("lea 0x80496c0(,%eax,4),%eax");
  asm("nop");
  asm("movl $0x0,0x1c(%esp)");
  asm("lea 0x1c(%esp),%eax");
  asm("nop");
  asm("mov (%eax,%esi,1), %eax");
  asm("lea (%eax,%esi,1), %eax");
  asm("nop");
  asm("mov 5(%eax,%esi,1), %eax");
  asm("lea 5(%eax,%esi,1), %eax");
  asm("nop");
  asm("movl 0x80496c0(,%ecx,4), %edx");
  asm("leal 0x80496c0(,%ecx,4), %eax");
  asm("add 0x80496c0(,%ecx,4), %eax");
  asm("cmp 0x80496c0(,%ecx,4), %eax");
  asm("nop");
  asm("movl (,%ecx,4), %edx");
  asm("nop");
  asm("nop");
  asm("mov    %edx,0x8049620(,%eax,4)");
  asm("lea    0x8049620(,%eax,4), %eax");
//	89 14 85 20 96 04 08 	mov    %edx,0x8049620(,%eax,4)

}

void test1(){
  printf("test 1\n");
/* using to_disas we get
   8048357:       89 14 85 c0 96 04 08    mov    %edx,0x80496c0(,%eax,4)
   804835e:       8d 04 85 c0 96 04 08    lea    0x80496c0(,%eax,4),%eax
*/
  unsigned char orig[16] = {0x89, 0x14, 0x85, 0xc0, 0x96, 0x04, 0x08};
  unsigned char xpect[16] = {0x8d, 0x04, 0x85, 0xc0, 0x96, 0x04, 0x08};
  check_lea(orig, xpect, 7);
}

void test2(){
  printf("test 2\n");
  unsigned char orig[16] = {0xc7, 0x44, 0x24, 0x1c, 0x00, 0x00, 0x00, 0x00};
  unsigned char xpect[16] = {0x8d, 0x44, 0x24, 0x1c};
  check_lea(orig, xpect,4);
}

void test3(){
  printf("test 3\n");
  unsigned char orig[16] = {0x8b, 0x04, 0x30};
  unsigned char xpect[16] = {0x8d, 0x04, 0x30};
  check_lea(orig, xpect,3);
}

void test4(){
  printf("test 4\n");
  unsigned char orig[16] = {0x8b, 0x44, 0x30, 0x05};
  unsigned char xpect[16] = {0x8d, 0x44, 0x30, 0x05};
  check_lea(orig, xpect,4);
}
void test5(){
/*
 8048a82:	89 14 85 20 96 04 08 	mov    %edx,0x8049620(,%eax,4)
 8048a89:	8d 04 85 20 96 04 08 	lea    0x8049620(,%eax,4),%eax
*/
  printf("test 5\n");
  unsigned char orig[16] = {0x89, 0x14, 0x85, 0x20, 0x96, 0x04, 0x08};
  unsigned char xpect[16] = {0x8d, 0x04, 0x85, 0x20, 0x96, 0x04, 0x08};
  check_lea(orig, xpect,7);
}
int main(){
  test1();
  test2();
  test3();
  test4();
  test5();
}


