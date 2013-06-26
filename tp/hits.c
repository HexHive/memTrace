#include "fbt_lmem_api.h"

int hell;

int main()
{
  int i;

  lmem_protect(&hell);
  printf("hell:\n");
  printf("%d\n", hell);

  char* foo = malloc(100);
  printf("foo = %p\n\n", foo);
  lmem_protect(foo+20);
  printf("foo+20 = %p\n\n", (foo+20));
  char a = 0;
  printf("first\n");
  a += *(foo+10);  
  printf("second\n");
  //asm("int3");
  a += *(foo+20);  
  printf("third\n");
  for (i=0; i<100; i++){
    a += foo[i];
  }
  printf("last\n");
  return (int)a;
}

