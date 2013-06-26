#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main()
{
  printf("first\n");
  int r = fork();
  if (r==0) {
    printf("second\n");
    return 0;
  } else {
    sleep(1);
    printf("third\n");
    return 3;
  }
}

