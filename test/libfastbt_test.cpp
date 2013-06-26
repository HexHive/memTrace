/**
 * Unit tests for the memory management unit
 *
 * Copyright (c) 2010 ETH Zurich
 *   Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */
#include <sys/mman.h>

#include "gtest/gtest.h"

#include "libfastbt.h"

/* max nr of mispredictions */
#define MAX_NR_MISPRED 100

TEST(LibfastbtTest, BasicTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  int foo = 256;
  for (int i=1; i<12; i++) {
    foo = foo*i;
  }
  fbt_commit_transaction();
  fbt_exit(tld);
  EXPECT_EQ(foo, 1628766208);
}

TEST(LibfastbtTest, LoopTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  int foo = 256;
  int bar = 12;
  for (int i=1; i<12; i++) {
    foo = foo*i;
    if (i%2==0) {
      bar*=foo;
    } else {
      bar+=5;
    }
  }
  fbt_commit_transaction();
  EXPECT_EQ(foo, 1628766208);
  EXPECT_EQ(bar, -1797586939);
  fbt_exit(tld);
}

static __attribute__ ((noinline)) int foobar()
{
  return 4;
}

TEST(LibfastbtTest, SwitchTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  int foo = foobar(); /* no constant propagation please */
  fbt_start_transaction(tld, fbt_commit_transaction);
  int bar = 0;
  switch (foo) {
  case 1: bar = 12*foo + 14;
  case 2: bar = 13*foo + 15; break;
  case 3: bar = 14*foo + 16;
  case 4: bar += 15*foo + 17;
  case 5: bar += 16*foo + 18;
  case 6: bar = 17*foo + 19; break;
  case 7: bar = 18*foo + 125;
  }
  if (foo == bar) {
    bar = 12;
  }
  fbt_commit_transaction();
  EXPECT_EQ(foo, 4);
  EXPECT_EQ(bar, 87);
  fbt_exit(tld);
}

TEST(LibfastbtTest, MultiSwitchTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  int foo = foobar(); /* no constant propagation please */
  fbt_start_transaction(tld, fbt_commit_transaction);
  int bar = 0;
  for (; foo < MAX_NR_MISPRED; ++foo) {
    switch (foo % 7) {
    case 1: bar = 12*foo + 14;
    case 2: bar = 13*foo + 15; break;
    case 3: bar = 14*foo + 16;
    case 4: bar += 15*foo + 17;
    case 5: bar += 16*foo + 18;
    case 6: bar = 17*foo + 19; break;
    case 7: bar = 18*foo + 125;
    }
    if (foo == bar) {
      bar = 12;
    }
  }
  fbt_commit_transaction();
  EXPECT_EQ(foo, 100);
  EXPECT_EQ(bar, 1302);
  fbt_exit(tld);
}

static __attribute__ ((noinline)) int fac(int n)
{
  if (n == 1 || n == 0) return 1;

  return fac(n-1) + fac(n-2);
}

static __attribute__ ((noinline)) int calltest(int foo, int bar)
{
  int temp;
  temp = fac(foo);
  temp = temp << 4;
  temp ^= bar;
  return temp*bar;
}

static __attribute__ ((noinline)) int calltest_alt(int foo, int bar)
{
  int temp;
  temp = fac(foo);
  temp = temp << 2;
  temp ^= bar;
  return temp*bar;
}

TEST(LibfastbtTest, SimpleCallTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  int foo = foobar();
  fbt_commit_transaction();
  EXPECT_EQ(foo, 4);
  fbt_exit(tld);
}

TEST(LibfastbtTest, RecursiveCallTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  int foo = foobar();
  int bar = fac(15);
  bar = calltest(foo, bar);
  fbt_commit_transaction();
  EXPECT_EQ(foo, 4);
  EXPECT_EQ(bar, 895209);
  fbt_exit(tld);
}

TEST(LibfastbtTest, IndirectCallTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  int (*foo)(int, int) = &calltest;
  int bar;
  fbt_start_transaction(tld, fbt_commit_transaction);
  bar = foo(5, 43);
  fbt_commit_transaction();
  EXPECT_EQ(bar, 7353);
  fbt_exit(tld);
}

TEST(LibfastbtTest, MultiIndirectCallTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  int (*fct)(int, int) = &calltest;
  int foo, bar;
  fbt_start_transaction(tld, fbt_commit_transaction);
  for (foo = 0; foo < MAX_NR_MISPRED; ++foo) {
    fct = (foo % 3 == 0) ? &calltest : &calltest_alt;
    bar = fct(foo % 10, 43);
  }
  fbt_commit_transaction();
  EXPECT_EQ(bar, 36937);
  fbt_exit(tld);
}

TEST(LibfastbtTest, LibCTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  int foo = foobar();
  int bar = fac(15);
  bar = calltest(foo, bar);
  printf("Printing inside a transaction (simple).\n");
  printf("Printing inside a transaction. Foo=%d, bar=%d\n", foo, bar);
  printf("Printing inside a transaction. Foo=%d, bar=%d\n", foo*bar, bar/foo);
  char foob[20];
  sprintf(foob, "string test");
  strncat(foob, " blabla", 19);
  printf("Using string routines: '%s'\n", foob);
  fbt_commit_transaction();
  EXPECT_EQ(foo, 4);
  EXPECT_EQ(bar, 895209);
  fbt_exit(tld);
}

TEST(LibfastbtTest, LibCIOTest)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);
  FILE *fp;
  fp = fopen("test.data", "r");
  EXPECT_TRUE(fp != NULL);
  char data[128];
  int read = 0, ret = 0;
  if (fp != NULL) {
    read = fread(data, 1, 128, fp);
    data[read]=0x0;
    ret = fclose(fp);
    printf("Read data: %s", data);
  } else {
    printf("Could not open test.data for read\n");
  }
  fbt_commit_transaction();
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(read, 9);
  fbt_exit(tld);
}

TEST(LibfastbtDeathTest, IllegalSystemCallMPROTECT)
{
#if defined(AUTHORIZE_SYSCALLS)
#define PAGESIZE (1<<12)
  ASSERT_EXIT({
      struct thread_local_data *tld = fbt_init(NULL);
      char *page = (char*)tld;
      page = (char*)((long)page & (~(PAGESIZE-1)));
      printf("Trying to remap thread local data as executable %p\n", tld);
      fbt_start_transaction(tld, fbt_commit_transaction);
      int ret = mprotect(page, 4096, PROT_EXEC);
      printf("Return value from mprotect %d\n", ret);
      fbt_exit(tld);
#if defined(DEBUG)
    }, ::testing::ExitedWithCode(255), "");
#else
    }, ::testing::KilledBySignal(11), "");
#endif  /* DEBUG */
#else  /*AUTHORIZE_SYSCALLS */
  printf("Not using system call authorization, bailing out of this test\n");
#endif  /* AUTHORIZE_SYSCALLS */
}
