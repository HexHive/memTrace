#include <stdio.h>
#include <stdlib.h>

#define true 1
#define false 0

#define MAXENT 100
#define MAXSIZ 10000000

char* pointers[MAXENT];
int sizes[MAXENT];
char patterns[MAXENT];

void all(int i){
  int s = rand() % MAXSIZ + 1;
  unsigned char c = rand() % 256;
  sizes[i] = s;
  patterns[i] = c;
  pointers[i] = (char*) malloc(s);
  for (int k=0; k<s; k++){
    pointers[i][k] = c;
  }
}

void deall(int i){
  int s = sizes[i];
  char* p = pointers[i];
  char c = patterns[i];
  for (int k=0; k<s; k++){
    if (p[k] != c){
      printf("fail\n");
      exit(1);
    }
  }
  free(p);
}

int main(){
  for (int i=0; i<MAXENT; i++){
    all(i);
  }
  while (true){
    int idx = rand() % MAXENT;
    deall(idx);
    all(idx);
    printf("idx %d\n", idx);
  }
  printf("success\n");
  return 0;
}

