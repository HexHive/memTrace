/**
 * Unit tests for the assembly generation DSL
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

#include "libfastbt.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_debug.h"
#include "fbt_mem_mgmt.h"

#include <sys/mman.h>

typedef void (*void_func)();
typedef long (*unary_func)(long);

TEST(AssemblyGeneration, Simple)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();

  char *target = (char *)fbt_lalloc(tld, 1, MT_CODE_CACHE);
  long result = 0;
  
  void_func f = (void_func)target;
  
  BEGIN_ASM(target)
    movl $1000, {&result}
    ret
  END_ASM

  f();

  ASSERT_EQ(result, 1000);

  fbt_mem_free(tld);
  DEBUG_END();
}

TEST(AssemblyGeneration, IndirectJump)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();

  char *target = (char *)fbt_lalloc(tld, 1, MT_CODE_CACHE);
  long result = 0;
  
  void_func a = (void_func)target;
  BEGIN_ASM(target)
    movl $1000, {&result}
    ret
  END_ASM

  void_func b = (void_func)target;
  BEGIN_ASM(target)
    jmp *{&a}
  END_ASM

  b();

  ASSERT_EQ(result, 1000);

  fbt_mem_free(tld);
  DEBUG_END();  
}

TEST(AssemblyGeneration, GenerationInLoop)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();

  char *target = (char *)fbt_lalloc(tld, 1, MT_CODE_CACHE);
  long arg = 20;
  long num_increments = 10;
  long expected = arg + num_increments;
  
  unary_func f = (unary_func)target; {
    BEGIN_ASM(target)
      movl 4(%esp), %eax
    END_ASM

    for (long i = 0; i < num_increments; ++i) {
      BEGIN_ASM(target)
        incl %eax
      END_ASM
    }

    BEGIN_ASM(target)
      ret
    END_ASM
  }

  ASSERT_EQ(f(arg), expected);

  fbt_mem_free(tld);
  DEBUG_END();  
}

long my_function(long a) {
  return a * a;
}

/**
 Test the call_abs DSL macro, which allows the generation of calls to code
 outside of the current code snippet by translating them to relative jumps
 at runtime
*/
TEST(AssemblyGeneration, AbsoluteJump)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();

  char *target = (char *)fbt_lalloc(tld, 1, MT_CODE_CACHE);
  long result = 5;
  
  void_func f = (void_func)target; {
    BEGIN_ASM(target)
      pushl ${result}      
      call_abs {my_function}
      movl %eax, {&result}
      addl $4, %esp
      ret
    END_ASM
  }

  f();

  ASSERT_EQ(result, 25);

  fbt_mem_free(tld);
  DEBUG_END();  
}

/** Regression test for bug fixed in r907:
 *
 * In cases where we mmap right after fbt_init and use the memory
 * starting exactly at the first byte to generate machine code, it will fail
 * when executed in a transaction because of an off-by-one error which will lead
 * libdetox to believe that the first byte still belongs to libdetox's memory.
 */
TEST(AssemblyGeneration, RegressionCodeGenerationAfterInit)
{
  DEBUG_START();
  
  struct thread_local_data *tld = fbt_init(NULL);

  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  
  void_func f = (void_func)target;
  
  BEGIN_ASM(target)
    ret
  END_ASM

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();  
    
  fbt_exit(tld);
  
  munmap(target, 1024);
  
  DEBUG_END();
}


