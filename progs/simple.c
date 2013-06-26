#include <stdio.h>
#include <string.h>

int addition(int a, int b){
	printf("adding\n");
	int c = a + b;
	printf("done\n");
	return a+b;
}

int a;
int q[10];
int k = 4;

int main(int argc, char** argv)
{
  int i;
  printf("ok\n");
  addition(3, 99);
  if (argc>2){
      k=3;
  }
  i = k;
  a = k;
  memset(&q, 0xFF, sizeof(q));
  printf("q[6] = %d\n", q[6]);
  memset(&q, 0, sizeof(q));
  printf("q[6] = %d\n", q[6]);
  a = argc;
  q[0] = a;
  for (i=1; i<10; i++){
    q[i] = 2*q[i-1]*a;
  }
  printf("q[7] = %d\n", q[7]);
  return 0;
}

