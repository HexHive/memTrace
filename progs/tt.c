#include  <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>

char xx[15];

void* thread_function(void* arg)
{
  int i;
  for (i=0; i<5; i++){
    printf("i is %d\n", i);
  }
  pthread_exit(NULL);
}

void bar()
{
  int i;
  for (i=0; i<5; i++){
    printf("q is %d\n", i);
  }
  pthread_exit(NULL);
}

int main(int argc, char** argv)
{
  long ar;

  xx[0] = 15;
  xx[1] = 13;
  xx[2] = 14;
  xx[3] = xx[0];

  pthread_t thrd;
  pthread_create(&thrd, NULL, thread_function, (void*)ar);

  bar();

  pthread_exit(NULL);
  return 0;
}

