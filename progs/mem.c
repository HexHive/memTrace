#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>

int main(){
  printf("start\n");
  setlocale(LC_ALL, "");
  void* a = malloc(10);
  strcpy(a, "hello\n");
  printf(a);
  free(a);
  printf("end\n");
}
