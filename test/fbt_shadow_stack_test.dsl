/**
 * Unit tests related to the shadow stack
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

#include "gtest/gtest.h"

#define fllwrite(x,y) printf(y)

#if defined(SHADOWSTACK) && defined(DEBUG) && defined(SHADOWSTACK_TERMINATE_ON_FAILURE)

#include "libfastbt.h"
#include "fbt_debug.h"
#include "fbt_mem_mgmt.h"
#include "fbt_syscall.h"
#include "fbt_restart_transaction.h"

#include <sys/mman.h>

#include <pthread.h>
#include <semaphore.h>

typedef void (*void_func)(void);

void evil_function() {
  printf("evil_function should never be called!\n");
  ASSERT_TRUE(0);
}

TEST(ShadowStack, SimpleCall) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      pushl %ebp
      movl %esp, %ebp

      pushl %eax
      popl %eax

      popl %ebp
      ret
  END_ASM  

  void_func g = (void_func)target;
  BEGIN_ASM(target)
    call_abs {f}
    ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    g();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(0), "");  
}

TEST(ShadowStack, SimpleCallViolation) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      movl ${&evil_function}, (%esp)
      ret
  END_ASM  

  void_func g = (void_func)target;
  BEGIN_ASM(target)
    call_abs {f}
    ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    g();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(255), "");  
  
  fbt_exit(tld);
}

TEST(ShadowStack, SimpleIndirectCall) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      pushl %ebp
      movl %esp, %ebp

      pushl %eax
      popl %eax

      popl %ebp
      ret
  END_ASM  

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    f();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(0), "");  
}

TEST(ShadowStack, SimpleIndirectCallViolation) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      movl ${&evil_function}, (%esp)
      ret
  END_ASM  

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    f();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(255), "");  
  
  fbt_exit(tld);
}

TEST(ShadowStack, RemoveBytes) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      pushl %ebp
      movl %esp, %ebp

      pushl %eax
      popl %eax

      popl %ebp
      ret $12
  END_ASM  

  void_func g = (void_func)target;
  BEGIN_ASM(target)
    pushl $1000
    pushl $2000
    pushl $3000
    call_abs {f}
    ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    g();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(0), "");  
}

TEST(ShadowStack, RemoveBytesViolation) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;

  BEGIN_ASM(target)
    L1:
      movl ${&evil_function}, (%esp)

      pushl %ebp
      movl %esp, %ebp

      pushl %eax
      popl %eax

      popl %ebp

      ret $12
  END_ASM  

  void_func g = (void_func)target;
  BEGIN_ASM(target)
    pushl $1000
    pushl $2000
    pushl $3000
    call_abs {f}
    ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    g();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(255), "");  
}

/** This test builds an artificial call stack and then returns, which should cause libdetox to access
  * the boundary entry (all 0) */
TEST(ShadowStack, PopWholeStack) {
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void_func f = (void_func)target;
  BEGIN_ASM(target)
    ret
  END_ASM  

  void_func g = (void_func)target;
  BEGIN_ASM(target)
    pushl ${f}
    pushl ${f}
    pushl ${f}
    ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);

  ASSERT_EXIT({
    fbt_start_transaction(tld, &fbt_commit_transaction);
    g();
    fbt_commit_transaction();
    fbt_exit(tld);
    exit(0);
  }, ::testing::ExitedWithCode(0), "");  
}

#else /* SHADOWSTACK && DEBUG && SHADOWSTACK_TERMINATE_ON_FAILURE */

TEST(ShadowStack, Define)
{
  printf("*** Not testing, SHADOWSTACK, SHADOWSTACK_TERMINATE_ON_FAILURE or DEBUG not set.\n");
}
#endif /* TRACK_CFTX */
