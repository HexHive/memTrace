#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char* mystrcpy(char* dest, const char* src){
  while (*src){
    *dest = *src;
    src++;
    dest++;
  } 
}

int main(){
  printf("start. It should print hello and then segfault: \n");
  void* a = malloc(10);
  void* b = calloc(1,100);
  strcpy(a, "hello\n");
  printf(a);
  fflush(stdout);
//  strcpy(a, "hellostupidworldhaha\n");
  mystrcpy(a, "hellostupidworldhaha\n");
  printf(a);
  free(a);
  free(b);
  printf("end\n");
}
