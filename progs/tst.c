#include  <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>

int addition(int a, int b){
	printf("adding\n");
	int c = a + b;
	printf("done\n");
	return a+b;
}

int main(int argc, char** argv)
{
  printf("primo\n");
  printf("secondo\n");
  printf("terzo\n");
  addition(3, 99);
  printf("quarto\n");
  printf("quinto\n");
  printf("sesto\n");
  printf("settimo\n");
  return 0;
}

