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
volatile int g;

void ekrpr(int fd, unsigned n)
{
  char bb[8];
  char bbrev[9];
  int i;
  for (i=0; i<8; i++){
    bb[i]='0';
  }
  int bbs = 0;
  while (n){
    unsigned tmp = (n%16);
    if (tmp < 10){
      bb[bbs] = (unsigned char)((unsigned int)'0' + tmp);
    } else {
      bb[bbs] = (unsigned char)((unsigned int)'a' + tmp - 10);
    }
    n /= 16;
    bbs++;
  }

  for (i=0; i<8; i++){
    bbrev[i]=bb[7-i];
  }
  bbrev[8] = '\n';

  int rs = write(fd, bbrev, 9);
}


void* thread_function(void* arg)
{
  g = (int)arg*(int)arg;
  /*{
  int slf;
  __asm__ __volatile__ ("nop;movl %%gs:0,%0" : "=r" (slf));
  ekrpr(2, 0xeddefaa);
  ekrpr(2, slf);
  }
  {
  int slf;
  __asm__ __volatile__ ("nop;movl %%gs:0,%0" : "=r" (slf));
  ekrpr(2, 0xeddefbb);
  ekrpr(2, slf);
  }
  */

  /*while(1){
   int slf;
   __asm__ __volatile__ ("nop;movl %%gs:0,%0" : "=r" (slf));
   //ekrpr(2, 0xfff);
   ekrpr(2, slf);
   } */

  //__asm__("int3");

  g += errno;

  int i;
  for (i=0; i<5000; i++){
    printf("i is %d\n", i);
  }

  pthread_exit(NULL);
}

void bar()
{
  int i;
  for (i=0; i<5000; i++){
    printf("q is %d\n", i);
  }
}

int main(int argc, char** argv)
{
  long ar;

  xx[0] = 15;
  xx[1] = 13;
  xx[2] = 14;
  xx[3] = xx[0];

  printf("About to create a thread of %x\n", &thread_function);

  pthread_t thrd;
  pthread_create(&thrd, NULL, thread_function, (void*)ar);

/*  while(1){
  int slf;
  __asm__ __volatile__ ("nop;movl %%gs:0,%0" : "=r" (slf));
  //ekrpr(2, 0xfff);
  ekrpr(2, slf);
  }


  while(1); */

  bar();

  //while(1);

  pthread_join(thrd, NULL);

  printf("bye\n");
  pthread_exit(0);
  //return 0;
}

