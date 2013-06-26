#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(){
  printf("start\n");
  float x = 10.0;
  float y = 0.2345;
  int res = 0;
  while (x > y){
    x *= 0.98;
    y += 0.01;
    res++;
  }
  printf("end, res=%d\n", res);
}
