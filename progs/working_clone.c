#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main(){
     char* newstk = malloc(1000000);
     newstk += 1000000;
     newstk = (char*)((unsigned)newstk & 0xfffffff0);



     int cloneflags = SIGCHLD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM;

     printf("GONNA CLONE WITH %x %x\n", (unsigned)newstk, cloneflags);

	asm("movl $120, %%eax;" // clone
	    "movl %0, %%ebx;"   // 
	    "movl %1, %%ecx;"   // 
            "int $0x80;"
		:
		: "m"(cloneflags), "m"(newstk)
		: "memory", "eax", "ebx", "ecx", "edx", "esi");
puts("Bye\n");
  exit(0);	
}
