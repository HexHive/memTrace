#define _GNU_SOURCE             /* See feature_test_macros(7) */

#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/ldt.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MMAP_FLAGS (MAP_PRIVATE | MAP_ANONYMOUS)
#define SIZE (1024UL * 1024UL * 1024UL * 2UL)

void* thestack[0x100000];

//uint16_t selector, oldSelector;

int populateDescriptor(uint16_t selector, uint32_t base, uint32_t size, int type)
{
  struct user_desc descriptor = { 0 };

  descriptor.entry_number = selector >> 3;
  descriptor.base_addr = base;
  descriptor.limit = (size - 1) / sysconf(_SC_PAGESIZE) + 1;
  descriptor.seg_32bit = 1;
  descriptor.contents = (int) type;
  descriptor.read_exec_only = 0;
  descriptor.limit_in_pages = 1;
  descriptor.seg_not_present = 0;
  descriptor.useable = 1;

  if(syscall(SYS_modify_ldt, 1, &descriptor, sizeof(descriptor)) < 0)
    {
      perror(__PRETTY_FUNCTION__);
      return 0;
    }

  return 1;
}

uint16_t allocateDescriptor()
{
  static uint16_t index = 0;

  return ((++index << 3) | 7);
}

void** mm[1000];
void clonefn()
{
  printf("cld\n");

  int cgs;
  asm("xor %0,%0;movw %%gs, %w0" : "=r" (cgs) );
  printf("cgs = %x\n", cgs);
  asm("movl %%gs:0x0, %d0" : "=r" (cgs) );
  printf("(c) has value = %x\n", cgs);

  mm[0] = 0xbeeff00d;

/*  if(!populateDescriptor(selector, &mm[0], 0xffff, MODIFY_LDT_CONTENTS_DATA))
      return -1;
  asm("mov %0, %%gs" : : "r" (selector) ); */
  syscall(SYS_arch_prctl, ARCH_SET_GS, &mm[0]);

  asm("xor %0,%0;movw %%gs, %w0" : "=r" (cgs) );
  printf("cgs = %x\n", cgs);

  asm("movl %%gs:0x0, %d0" : "=r" (cgs) );
  printf("child has value = %x\n", cgs);
  sleep(1);
  asm("movl %%gs:0x0, %d0" : "=r" (cgs) );
  printf("child has value = %x\n", cgs);
  sleep(1);
  asm("movl %%gs:0x0, %d0" : "=r" (cgs) );
  printf("child has value = %x\n", cgs);
  sleep(1);
}

int ekrclone64(int (*fun)(void*),
                void* childstack,
                int flags,
                void* parameter,
                void* parenttidptr,
                void* childtidptr,
                void* tlsptr);


int main(int argc, char * argv[])
{
  void ** result = mmap((void *) 0xfffff000, 0x1000, PROT_NONE, MMAP_FLAGS, -1, 0);

  if(result != MAP_FAILED)
    printf("Successfully reserved %lx bytes of memory, starting at %p.\n", SIZE, result);
  else
    {
      perror("Failed to reserve memory");
      return -1;
    }

  if(mprotect(result, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE) < 0)
    {
      perror("Failed to protect first page");
      return -1;
    }

//  selector = allocateDescriptor();
  uint32_t value=0xdead;

//  if(!populateDescriptor(selector, (uint32_t) (size_t) result, SIZE, MODIFY_LDT_CONTENTS_DATA))
//    return -1;

  memset(result, 'A', 1024);
  result[0] = 0xbeeb00;

  /*asm("mov %%gs, %0" : "=r" (oldSelector) );
  asm("mov %0, %%gs" : : "r" (selector) );
  asm("movl %%gs:0, %0" : "=r" (value) ); */
  //asm("mov %0, %%gs" : : "r" (oldSelector) );

  syscall(SYS_arch_prctl, ARCH_SET_GS, result);

  printf("! %08x\n", value);

  int pregs;
  asm("xor %0,%0;movw %%gs, %w0" : "=r" (pregs) );
  printf("gs = %x\n", pregs);
  asm("xor %0,%0;movw %%fs, %w0" : "=r" (pregs) );
  printf("fs = %x\n", pregs);
  asm("movl %%gs:0x0, %d0" : "=r" (pregs) );
  printf("has value = %x\n", pregs);

  unsigned flags = CLONE_VM|CLONE_FS|CLONE_FILES
                    |CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM
                    //|CLONE_PARENT_SETTID
                    //|CLONE_CHILD_CLEARTID
                    //|CLONE_SETTLS
                    ;

  int retval = ekrclone64(clonefn,&thestack[0x10000-10],flags,0,0,0,0);

/*  if (clone(clonefn, &thestack[0x10000], CLONE_VM, 0) < 0){
    printf("faaaa\n");
    exit(1);
  }*/

  int pargs;
  asm("xor %0,%0;movw %%gs, %w0" : "=r" (pargs) );
  printf("pargs = %x\n", pargs);
  asm("movl %%gs:0x0, %d0" : "=r" (pregs) );
  printf("has value = %x\n", pregs);

  sleep(1);
  asm("movl %%gs:0x0, %d0" : "=r" (pregs) );
  printf("parent has value = %x\n", pregs);

  sleep(1);
  asm("movl %%gs:0x0, %d0" : "=r" (pregs) );
  printf("parent has value = %x\n", pregs);

  sleep(1);
  asm("movl %%gs:0x0, %d0" : "=r" (pregs) );
  printf("parent has value = %x\n", pregs);


  while(1);

  return 0;                       
}              
