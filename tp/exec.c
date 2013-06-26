#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
    
int main(int argc, char *argv[])
{
int status;
int pid[2];
int pipe_fd[2];

char *prog1_argv[4];
char *prog2_argv[2];

/* 
* Build argument list
*/

prog1_argv[0] = "/usr/local/bin/ls";
prog1_argv[1] = "-l";
prog1_argv[2] = "/";
prog1_argv[3] = NULL;


prog2_argv[0] = "/usr/ucb/more";
prog2_argv[1] = NULL;

/*
* Create the pipe
*/
if (pipe(pipe_fd) < 0)
{
perror ("pipe failed");
exit (errno);
}

/*
* Create a process space for the ls  
*/
if ((pid[0]=fork()) < 0)
{
perror ("Fork failed");
exit(errno);
}

if (!pid[0])
{
  /*
   * Set stdout to pipe     
   */
  close (pipe_fd[0]);
  dup2 (pipe_fd[1], 1);
  close (pipe_fd[1]);

/* Execute the ls */ 
execvp (prog1_argv[0], prog1_argv);
}

if (pid[0])
{
/* 
 * We're in the parent 
 */

/*
 * Create a process space for the more
 */
if ((pid[1]=fork()) < 0)
{
  perror ("Fork failed");
  exit(errno);
}

if (!pid[1])
{
  /*
   * We're in the child
   */

  /*
   * Set stdin to pipe     
   */
  close (pipe_fd[1]);
  dup2 (pipe_fd[0], 0);
  close (pipe_fd[0]);

  /* Execute the more */ 
  execvp (prog2_argv[0], prog2_argv);
}

/* This is the parent */
close(pipe_fd[0]);
close(pipe_fd[1]);

waitpid (pid[1], &status, 0);
printf ("Done waiting for more.\n");

}

}

