/*
 * pipe-example.c - an example of creating a pipeline between two processes.
 * Alan J Rosenthal, September 2000.
 *
 * This program arranges the execution of the command "ls | tr e f".
 *
 * This program outputs some stuff before and after to show that the main
 * program persists, as one would like a shell to persist after executing
 * a command.  If I were writing this normally, I wouldn't bother to keep the
 * main program around, I'd make it exec tr directly without forking first.
 * But if we were writing a shell, it would have to loop around at that
 * point to print another prompt.
 *
 * Actually we wouldn't write the following at all.  We'd normally just write
 * system("ls | tr e f").  This does the initial fork and then execs sh, the
 * shell, to parse that command-line and do the other forking and pipe
 * creation and execing and stuff.  But of course someone has to write
 * *that* code, in the shell, and in CSC 209 we learn how it works.
 * So here is how it works.
 *
 * There are man pages for all of the kernel calls below, and the man pages
 * are highly recommended.  In the "Unix Programmer's Manual" (man pages),
 * volume 2 is kernel calls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main()
{
  int pid, status;
  extern void docommand();

  printf("Executing 'ls | tr e f'\n");
  fflush(stdout);  /* important, otherwise the stdout buffer would be
		    * present in both processes after the fork()!
		    * It could be printed twice...  Or never printed,
		    * because of the exec overwriting this whole process.
		    * It depends on how it's being buffered.  When doing
		    * a fork or exec, we are careful to empty our stdio
		    * buffers first.  */

  switch ((pid = fork())) {
  case -1:
    perror("fork");
    break;
  case 0:
    /* child */
    docommand();
    break;  /* not reached */
  default:
    /* parent; fork() return value is child pid */
    /* These two pids output below will be the same: the process we
     * forked will be the one which satisfies the wait().  This mightn't
     * be the case in a more complex situation, e.g. a shell which has
     * started several "background" processes. */
    printf("fork() returns child pid of %d\n", pid);
    pid = wait(&status);
    printf("wait() returns child pid of %d\n", pid);
    printf("Child exit status was %d\n", status >> 8);
    /* status is a two-byte value; the upper byte is the exit
     * status, i.e. return value from main() or the value passed
     * to exit(). */
  }

  return(0);
}


void docommand()  /* does not return, under any circumstances */
{
  int pipefd[2];

  /* get a pipe (buffer and fd pair) from the OS */
  if (pipe(pipefd)) {
    perror("pipe");
    exit(127);
  }

  /* We are the child process, but since we have TWO commands to exec we
   * need to have two disposable processes, so fork again */
  switch (fork()) {
  case -1:
    perror("fork");
    exit(127);
  case 0:
    /* child */
    /* do redirections and close the wrong side of the pipe */
    close(pipefd[0]);  /* the other side of the pipe */
    dup2(pipefd[1], 1);  /* automatically closes previous fd 1 */
    close(pipefd[1]);  /* cleanup */
    /* exec ls */
    execl("/bin/ls", "ls", (char *)NULL);
    /* return value from execl() can be ignored because if execl returns
     * at all, the return value must have been -1, meaning error; and the
     * reason for the error is stashed in errno */
    perror("/bin/ls");
    exit(126);
  default:
    /* parent */
    /*
     * It is important that the last command in the pipeline is execd
     * by the parent, because that is the process we want the shell to
     * wait on.  That is, the shell should not loop and print the next
     * prompt, etc, until the LAST process in the pipeline terminates.
     * Normally this will mean that the other ones have terminated as
     * well, because otherwise their sides of the pipes won't be closed
     * so the later-on processes will be waiting for more input still.
     */
    /* do redirections and close the wrong side of the pipe */
    close(pipefd[1]);  /* the other side of the pipe */
    dup2(pipefd[0], 0);  /* automatically closes previous fd 0 */
    close(pipefd[0]);  /* cleanup */
    /* exec tr */
    execl("/usr/bin/tr", "tr", "e", "f", (char *)NULL);
    perror("/usr/bin/tr");
    exit(125);
  }

  /*
   * When the exec'd processes exit, all of their file descriptors are closed.
   * Thus the "ls" command's side of the pipe will be closed, and thus the
   * "tr" command will get eof on stdin.  But if we didn't have the
   * close(pipefd[1]) for 'tr' (in the default: case), the incoming side
   * of the pipe would NOT be closed (fully), the "tr" command would still
   * have it open, and so tr itself would not get eof!  Try it!
   */
}
