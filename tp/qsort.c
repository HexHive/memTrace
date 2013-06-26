/*

Unittest used by test.sh

Do not modify (or if you do, alter test.sh accordingly)

*/


#include <stdio.h>
#include <stdlib.h>

int comp(const int * a,const int * b)
{
  if (*a==*b)
    return 0;
  else
    if (*a < *b)
        return -1;
     else
      return 1;
}

int main(int argc, char* argv[])
{
   int numbers[14]={1892,45, 37, 42, 1, 43, 200,-98,4087,5,-12345,1087,88,-100000};
   int i;

  /* Sort the array */
  qsort(numbers,14,sizeof(int),comp) ;
/*  for (i=0;i<9;i++)
    printf("Number = %d\n",numbers[ i ]) ; */
  printf("returning %d\n", (int)numbers[5]);
  return numbers[5];
}

