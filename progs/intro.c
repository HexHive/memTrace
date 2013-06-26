#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(){
  printf("start\n");
  int a = 0;
  asm("movl %%esp, %%eax": "=a"(a) : );
  printf("a = %x\n", a);
  int* p = (int*)a;
  while (1){
    printf("%x: %x\n", (unsigned)p, (unsigned)*p);
    p++;
  }
  printf("end\n");
}
