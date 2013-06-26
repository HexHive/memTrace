#include <unistd.h>
#include <stdio.h>

#include "../lmempath.h"

/* int execve(const char *filename, char *const argv[],
                  char *const envp[]); */

int main(int argc, char** argv, char** envp)
{
  printf("robustness check\n");
  int res = execve(LMEMPATH "/tp/doesnotexist", argv, envp);
  if (res != -1){
    printf("FAIL!!!\n");
    return 39;
  }
  printf("starting a program:\n");
  int ret = execve(LMEMPATH "/tp/hi", argv, envp);
  printf("never reached: %d\n", ret);
  return 0;
}

