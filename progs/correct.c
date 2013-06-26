#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(){
  printf("start.\n");
  void* a = malloc(10);
  void* b = calloc(1,100);
  strcpy(a, "hello\n");
  printf(a);
  fflush(stdout);
  strcpy(a, "again\n");
  printf(a);
  free(a);
  free(b);
  printf("end\n");
}
