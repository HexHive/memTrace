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

#include "gtest/gtest.h"

#include "libfastbt.h"
#include "fbt_debug.h"
#include "fbt_mem_mgmt.h"
#include "fbt_mem_pool.h"

#include <sys/mman.h>

TEST(MemMgmtTest, InitTLS)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();
  EXPECT_EQ(tld->trans.tld, tld);
  EXPECT_NE(tld->chunk, (void*)0);
  EXPECT_NE(tld->chunk->size, 0);
  EXPECT_NE(tld->stack, (void*)0);
  EXPECT_NE(tld->mappingtable, (void*)0);
  fbt_mem_free(tld);
  DEBUG_END();
}

TEST(MemMgmtTest, AllocateNewTrampolines)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();
  int count = 0;
  struct trampoline *trampo = tld->trans.trampos;
  while (trampo != 0) {
    count++;
    trampo = trampo->next;
  }
  EXPECT_EQ(count, 0);
  fbt_allocate_new_trampolines(tld);
  /* reset and count again */
  count = 0;
  trampo = tld->trans.trampos;
  while (trampo != 0) {
    count++;
    trampo = trampo->next;
  }
  EXPECT_EQ(count, 1024); /* nr alloc trampos */
  fbt_mem_free(tld);  
  DEBUG_END();
}

TEST(MemMgmtTest, AllocateNewCodeCache)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();
  void *transl_instr = tld->trans.transl_instr;
  EXPECT_NE(tld->trans.transl_instr, (void*)0);
  fbt_allocate_new_code_cache(tld);
  EXPECT_NE(tld->trans.transl_instr, (void*)0);
  EXPECT_NE(tld->trans.transl_instr, transl_instr);
  fbt_mem_free(tld);  
  DEBUG_END();
}

TEST(MemMgmtTest, StressTest)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();
  /* allocates about 2GB memory */
  for (int i=0; i<128; ++i) {
    fbt_allocate_new_code_cache(tld);
    fbt_allocate_new_trampolines(tld);
  }
  fbt_mem_free(tld);
  DEBUG_END();
}

TEST(MemMgmtTest, ExhaustSmalloc) 
{
  /* This is a regression test for a bug where
   fbt_smalloc failed to allocate new pages when it
   ran out of memory. */
  
  DEBUG_START();

  struct thread_local_data *tld = fbt_init_tls();

  long bytes = PAGESIZE;
  long chunk_size = SMALLOC_MAX;
  assert(bytes % chunk_size == 0);

  long smalloc_size;

  // Allocate enough memory so we run out of smalloc memory
  for (long bytes_allocated = 0; bytes_allocated < bytes; bytes_allocated += chunk_size) {
    smalloc_size = tld->smalloc_size;
    void *ptr = fbt_smalloc(tld, chunk_size);
    EXPECT_NE(ptr, (void*)0);
    EXPECT_EQ(smalloc_size - chunk_size, tld->smalloc_size);
  }

  // ... and allocate some more!
  smalloc_size = tld->smalloc_size;
  void *ptr = fbt_smalloc(tld, chunk_size);
  EXPECT_NE(ptr, (void*)0);
  EXPECT_EQ(smalloc_size - chunk_size, tld->smalloc_size);

  DEBUG_END();
}

TEST(MemMgmtTest, ReInitTld)
{
  DEBUG_START();
  struct thread_local_data *tld = fbt_init_tls();
  EXPECT_EQ(tld->trans.tld, tld);
  EXPECT_NE(tld->chunk, (void*)0);
  EXPECT_NE(tld->chunk->size, 0);
  EXPECT_NE(tld->stack, (void*)0);
  EXPECT_NE(tld->mappingtable, (void*)0);
  struct thread_local_data *old_tld = tld;
  tld = fbt_reinit_tls(tld);
  EXPECT_EQ(tld, old_tld);
  EXPECT_EQ(tld->trans.tld, tld);
  EXPECT_NE(tld->chunk, (void*)0);
  EXPECT_NE(tld->chunk->size, 0);
  EXPECT_NE(tld->stack, (void*)0);
  EXPECT_NE(tld->mappingtable, (void*)0);
  fbt_mem_free(tld);
  DEBUG_END();
}

TEST(MemMgmtTest, MemPoolInitExternal)
{
  DEBUG_START();

  struct mem_pool pool;
  pool.allocation_size = 1024;
  pool.flags = PROT_READ | PROT_WRITE;
  fbt_mem_pool_init(&pool);
  
  fbt_mem_pool_free(&pool);  

  DEBUG_END();
}

TEST(MemMgmtTest, MemPoolInitInternal)
{
  DEBUG_START();

  /* Initialize map pool */
  struct mem_pool init_pool;
  init_pool.allocation_size = 1024;
  init_pool.flags = PROT_READ | PROT_WRITE;
  fbt_mem_pool_init(&init_pool);
  
  /* Now move the mem_pool struct into the pool memory */
  struct mem_pool *pool = (struct mem_pool *)fbt_mem_pool_allocate(&init_pool, sizeof(struct mem_pool));
  *pool = init_pool;
  /* Starting from this point, we do not need the local copy anymore */

  /* Allocate some more memory */
  fbt_mem_pool_allocate(pool, 1025);
  fbt_mem_pool_allocate(pool, 1000);
  fbt_mem_pool_allocate(pool, 10);
  fbt_mem_pool_allocate(pool, 100);
  fbt_mem_pool_allocate(pool, 1000);

  fbt_mem_pool_free(pool);  

  DEBUG_END();
}

