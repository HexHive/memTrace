#include <stdio.h>
#include <string.h>

int a;
int k = 4;

int main(int argc, char** argv)
{
q:
  a = k;
  goto q;
  return 0;
}

