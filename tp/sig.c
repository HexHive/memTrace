#define _GNU_SOURCE

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

void catchsignal(int signo) 
{
   char handmsg[] = "You cannot \"Ctrl-C\" me!\n";
   int msglen = sizeof(handmsg);
   write(STDERR_FILENO, handmsg, msglen);
   int q;
   asm("mov %%esp, %%eax": "=a" (q));
   printf("stkinsig = %x\n", q);
}

int main() 
{
   printf("starting main\n");
   struct sigaction act;
   act.sa_handler = catchsignal;
   act.sa_flags = 0;
   sigemptyset(&act.sa_mask);
   sigaction(SIGINT, &act, NULL);
   printf("spinning a bit, try ctrl c ing me!\n"); 
   while(1){
     int q;
     asm("mov %%esp, %%eax": "=a" (q));
     printf("stack = %x\n", q);
	 sleep(1);
   }
}

