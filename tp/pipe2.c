/* second pipe example from Haviland */
#include <unistd.h>
#include <stdio.h>

#define MSGSIZE 32

char *msg1 = "hello #1";
char *msg2 = "hello #2";
char *msg3 = "hello #3";

main()
{  char inbuf[MSGSIZE];

   int p[2], j, pid;

   /* open pipe */

   if(pipe(p) == -1)
   {    perror("pipe call error");
        exit(1);
   }

   switch(pid = fork()){
   case -1: perror("error: fork call");
            exit(2);

   case 0:  /* if child then write down pipe */
         close(p[0]);  /* first close the read end of the pipe */
	 /*write(p[1], msg1, MSGSIZE);
	 write(p[1], msg2, MSGSIZE);
	 write(p[1], msg3, MSGSIZE); */
         break;
   default:   /* parent reads pipe */
         close(p[1]);  /* first close the write end of the pipe */
/*	 for(j=0; j<3; j++)
	 {   read(p[0], inbuf, MSGSIZE);
	     printf("Parent: %s\n", inbuf);
	 } */
         wait(NULL);
   }

   exit(0);
}


