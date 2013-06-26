/**
 * Unit tests for some hairy assembly cases
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
#include "fbt_debug.h"
#include "fbt_mem_mgmt.h"

#include <pthread.h>

#include "test_util.h"

TEST(AsmGenerationTest, Call1BEsp)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);

  asm(" pushl $.CallEsp1BCall\n"
      " pushl $0x12345678\n"
      " call *0x04(%esp)\n"
      " addl $0x08, %esp\n"
      " jmp .CallEsp1BJump\n"
      ".CallEsp1BCall:\n"
      " ret\n"
      ".CallEsp1BJump:\n");
     
  fbt_commit_transaction();
  fbt_exit(tld);
}


TEST(AsmGenerationTest, Call4BEsp)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);

  asm(" pushl $.CallEsp4BCall\n"
      " subl $0x100, %esp\n"
      " call *0x100(%esp)\n"
      " addl $0x104, %esp\n"
      " jmp .CallEsp4BJump\n"
      ".CallEsp4BCall:\n"
      " ret\n"
      ".CallEsp4BJump:\n");
     
  fbt_commit_transaction();
  fbt_exit(tld);
}

TEST(AsmGenerationTest, Call0BEsp)
{
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_start_transaction(tld, fbt_commit_transaction);

  asm(" pushl $.CallEsp0BCall\n"
      " call *(%esp)\n"
      " addl $0x04, %esp\n"
      " jmp .CallEsp0BJump\n"
      ".CallEsp0BCall:\n"
      " ret\n"
      ".CallEsp0BJump:\n");
     
  fbt_commit_transaction();
  fbt_exit(tld);
}
