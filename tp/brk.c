/**
 Unittest for test.sh. Do not change
*/

#include <stdio.h>
#include <unistd.h>

int main(){
  
  char* a = sbrk(0);
  //printf("a=%p\n", a);
  char* b = sbrk(0x1000);
  //printf("b=%p\n", b);
  char* q;
  for (q = a; q != b+0x1000; q++){
    *q = 15;
  } 
  return *(a+89); 
  return 12;
}
