#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main()
{
  printf("start\n");
  int r = fork();
  if (r==0) {
    for (int i=0; i<5; i++){
      printf("child\n");
      sleep(1);
    }
    return 0;
  } else {
    sleep(1);
    printf("parent waiting\n");
    int status;
    wait(&status);
    printf("parent waited, got status %d\n", status);
    return 3;
  }
}

