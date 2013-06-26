#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(){
  int ps=7;
  //asm("mov %%gs:-56, %%eax": "=a"(ps));
  asm("mov %%gs:-56, %%eax;"
      "mov $-56, %%edx;"
      ".byte 0x65;"
      ".byte 0x8b;"
      ".byte 0x02;"
      : "=a"(ps): : "edx");
  printf("%d", 3);
  //ps = errno;
  //ps = getpagesize();
  //printf("pagesize: %d\n", ps);
  //printf("pagesize: %d\n", ps);
  /*int i;
  for (i=16; i<2000; i+=3){
    char* gu = malloc(i);
    strcpy(gu, "haha!");
    free(gu);
  }*/
  return (ps & 0xF);
}
