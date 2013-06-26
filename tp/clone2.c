#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h> 
#include <sys/syscall.h> 
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int variable, fd;

int myparenttid;
int mychildtid;

int do_something() {
   sleep(4);
   variable = 42;
   printf("pt %d\n",  myparenttid);
   sleep(1);
   printf("ct %d\n",  mychildtid);
   return 3;
}

int foo[50000];

int main(int argc, char *argv[]) {
   void **child_stack;
   char tempch;

   variable = 9;
   child_stack = (void **) malloc(16384);
   int flags = CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|
               CLONE_THREAD|CLONE_SYSVSEM
               |CLONE_CHILD_SETTID
               |CLONE_SETTLS
               |CLONE_PARENT_SETTID
               ;

   //flags = CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;

   printf("The variable was %d\n", variable);
   printf("stack %x\n", child_stack+10000);
   printf("flags %x\n",  flags);
   printf("parenttid addr %x\n",  &myparenttid);
   printf("childtid addr %x\n",  &mychildtid);
   int r = clone(do_something, ((char*)child_stack)+10000, 
                    flags,
                    &myparenttid,0,&mychildtid);
   printf("parenttid %d\n",  myparenttid);
   printf("childtid %d\n",  mychildtid);
   sleep(10);
   printf("parenttid %d\n",  myparenttid);
   printf("childtid %d\n",  mychildtid);
 
   printf("The variable is now %d\n", variable);
   while(1){sleep(1);}
   return variable;
}

