#include <stdio.h>
#include <sys/time.h>

#define NUM_ITER 1000000000

static int jmpindirect(int nriter) {
  int i;
  int loc;
  for (i = 0; i < nriter; ++i) {
    asm("movl $.out, %%eax\n"
        "movl %%eax, %0\n"
        "jmp *%0\n"
        ".out: nop\n" : : "m"(loc) : "eax", "memory");
  }
  return 0;
}

static int callindirect(int nriter) {
  int i;
  int loc;
  for (i = 0; i < nriter; ++i) {
    asm("movl $.ciout, %%eax\n"
        "movl %%eax, %0\n"
        "call *%0\n"
        ".ciout: leal 4(%%esp), %%esp\n" : : "m"(loc) : "eax", "memory");
  }
  return 0;
}

static int call(int nriter) {
  int i;
  for (i = 0; i < nriter; ++i) {
    asm("call .cout\n"
        ".cout: leal 4(%%esp), %%esp\n" : : : "memory");
  }
  return 0;
}

static int ret(int nriter) {
  int i;
  for (i = 0; i < nriter; ++i) {
    asm("pushl $.rout\n"
        "ret\n"
        ".rout: nop\n" : : : "memory");
  }
  return 0;
}

static int jcc(int nriter) {
  int i;
  int ret = 0;
  for (i = 0; i < nriter; ++i) {
    if ((i%2) == 0) ret+=3; else ret-=2;
  }
  return ret;
}

static int jump(int nriter) {
  int i;
  for (i = 0; i < nriter; ++i) {
    asm("jmp .jout\n"
        "nop\n"
        ".jout: nop");
  }
  return 0;
}

static void measure(int (*fctptr)(int), char *name)
{
  struct timeval start, stop;
  double total;
  gettimeofday(&start, 0);
  fctptr(NUM_ITER);
  gettimeofday(&stop, 0);
  total = stop.tv_sec - start.tv_sec;
  if (stop.tv_usec - start.tv_usec < 0) total++;
  total *= 1000*1000;
  total += stop.tv_usec - start.tv_usec;
  total /= (NUM_ITER/1000);
  printf("%s %10f ns\n", name, total);

  gettimeofday(&start, 0);
  fctptr(NUM_ITER);
  gettimeofday(&stop, 0);

  total = stop.tv_sec - start.tv_sec;
  if (stop.tv_usec - start.tv_usec < 0) total++;
  total *= 1000*1000;
  total += stop.tv_usec - start.tv_usec;
  total /= (NUM_ITER/1000);
  printf("%s %10f ns\n", name, total);
}

int main() {
  printf("Starting microbenchmark...\n");

  measure(&jmpindirect, "jmpindirect");
  measure(&callindirect, "callindirect");
  measure(&jcc, "jcc");
  measure(&call, "call");
  measure(&jump, "jump");
  measure(&ret, "ret");

  return 0;
}
