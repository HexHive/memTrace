#define _GNU_SOURCE

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

#include "fbt_syscalls_64.h"

void catchsignal(int signo) 
{
   char handmsg[] = "You cannot \"Ctrl-C\" me!\n";
   int msglen = sizeof(handmsg);
   write(STDERR_FILENO, handmsg, msglen);
}

struct kernel_sigaction {
  uint64_t k_sa_handler;
  uint64_t sa_flags;
  uint64_t restorer;
  uint64_t sa_mask;
};

#define SA_RESTORER 0x04000000

void restorefun();

int main() 
{
   printf("starting main\n");
#if 0
   struct sigaction act;
   act.sa_handler = catchsignal;
   act.sa_flags = 0;
   sigemptyset(&act.sa_mask);
   sigaction(SIGINT, &act, NULL);
#else
   struct kernel_sigaction ka;
   ka.k_sa_handler = catchsignal;
   ka.sa_mask = 0;
   ka.sa_flags = SA_RESTORER;
   ka.restorer = restorefun;
   fbt_syscall4(SYS64_rt_sigaction, SIGINT, &ka, NULL, 8);
#endif
   printf("spinning a bit, try ctrl c ing me!\n"); 
   while(1){
	sleep(1);
   }
}

