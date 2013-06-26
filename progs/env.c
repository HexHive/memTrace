#include <stdio.h>

int main(int argc, char** argv, char** env)
{
  while (*env){
    printf("en '%s'\n", *env);
    env++;
  }
  return 0;
}
