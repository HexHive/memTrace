#include <stdlib.h>
#include <string.h>

int main(){
  char* gu = malloc(16);
  strcpy(gu, "haha!");
  free(gu);

  gu = malloc(100000);
  gu = realloc(gu, 300000);
  free(gu);

  gu = malloc(1000000);
  gu = realloc(gu, 3000000);
  free(gu);

  while (1){
	  gu = malloc(100000000);
	  gu = realloc(gu, 300000000);

	  int i;
	  for (i=0; i<300000000; i++){
	    gu[i] = i%45;
	  }

	  free(gu);
  }

  return 0;
}
