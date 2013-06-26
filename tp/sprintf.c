/**
 * Regression, manifestating a bug found when running some
 * perlbench tests (SPEC CPU2006)
 */

#include <string.h>
#include <stdio.h>

#define BIT_DIGITS(N)   (((N)*146)/485 + 1)  /* log2(10) =~ 146/485 */
#define TYPE_DIGITS(T)  BIT_DIGITS(sizeof(T) * 8)

char tbuf[100000];

int main()
{
  //char tbuf[TYPE_DIGITS(long) + 12 + 10];
  char*  tmpbuf = tbuf;
  //asm("int3");
  sprintf(tmpbuf, "%.10s", "re");
  printf("buf is %s\n", tmpbuf);

  if (strcmp(tmpbuf, "re") == 0)
    { return 42; }

  return -1;
}

