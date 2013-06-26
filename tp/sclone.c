#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h> 
#include <sys/syscall.h> 
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

/* Macros to load from and store into segment registers.  We can use
   the 32-bit instructions.  */
#define TLS_GET_GS() \
  ({ int __seg; __asm ("movl %%gs, %0" : "=q" (__seg)); __seg; })
#define TLS_SET_GS(val) \
  __asm ("movl %0, %%gs" :: "q" (val))

int ekrclone(int (*fun)(void*), 
             void* childstack,
             int flags);

int variable, fd;

int do_something() {
   variable = 42;
   return 3;
}

int main(int argc, char *argv[]) {
   void **child_stack;
   char tempch;

   variable = 9;
   child_stack = (void **) malloc(16384);
   printf("The variable was %d\n", variable);
  
   int gs = TLS_GET_GS();
   printf("gs = %x\n", gs);
   
   ekrclone(do_something, ((char*)child_stack)+10000, CLONE_VM|CLONE_FILES);

   sleep(1);

   printf("The variable is now %d\n", variable);
   return variable;
}

