#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>

//int n = 1000;
#define n 1000

int some_ints[n];

int main(){
	int i,j;
	int res;

	//some_ints = (int*)malloc(n * sizeof(int));

	printf("begin\n");

	for (i=0; i<n; i++){
		some_ints[i] = i;
	}

	printf("done initializing\n");

	for (i=0; i<n; i++){
		for (j=0; j<10; j++){
			some_ints[i] += i+j;
		}
		if (i%100 == 0){
			printf("i = %d\n", i);
		}
	}

	printf("computing result\n");

	res = 0;
	for (i=0; i<n; i++){
		res += some_ints[i]%2;
	}

	printf("done %d\n", res); 
}


