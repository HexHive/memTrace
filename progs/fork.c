#include <malloc.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>

int main()
{
  printf("Hello...\n" );
  int val = fork();
  printf("World!, %d\n", val);
  return 0;
}

