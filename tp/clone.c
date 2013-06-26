#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h> 
#include <sys/syscall.h> 
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

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
   
   clone(do_something, ((char*)child_stack)+10000, CLONE_VM|CLONE_FILES, NULL);
   sleep(1);

   printf("The variable is now %d\n", variable);
   return variable;
}

