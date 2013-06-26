/**
 * Unit tests for the code cache
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
#include "fbt_code_cache.h"

TEST(CodeCacheTest, CodeCacheSimpleAddEntry)
{
  struct thread_local_data *tld = fbt_init(NULL);
  EXPECT_EQ(fbt_ccache_find(tld, (void*)0xdeadbeef), (void*)0);
  fbt_ccache_add_entry(tld, (void*)0xdeadbeef, (void*)0xc0ffee);
  EXPECT_EQ(fbt_ccache_find(tld, (void*)0xdeadbeef), (void*)0xc0ffee);
  fbt_exit(tld);
}

TEST(CodeCacheTest, CodeCacheMultipleEntries)
{
  struct thread_local_data *tld = fbt_init(NULL);
  /* add */
  for (unsigned int i=0x800000; i<0x800400; i+=4) {
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)0);
    fbt_ccache_add_entry(tld, (void*)i, (void*)(i+4096));
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)(i+4096));
  }
  /* add with clash */
  for (unsigned int i=0x800001; i<0x800400; i+=4) {
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)0);
    fbt_ccache_add_entry(tld, (void*)i, (void*)(i+4096));
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)(i+4096));
  }
  /* add with clash */
  for (unsigned int i=0x800002; i<0x800400; i+=4) {
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)0);
    fbt_ccache_add_entry(tld, (void*)i, (void*)(i+4096));
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)(i+4096));
  }
  /* add with clash */
  for (unsigned int i=0x800003; i<0x800400; i+=4) {
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)0);
    fbt_ccache_add_entry(tld, (void*)i, (void*)(i+4096));
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)(i+4096));
  }
  /* duplicate add, but test */
  for (unsigned int i=0x800000; i<0x800100; ++i) {
    EXPECT_NE(fbt_ccache_find(tld, (void*)i), (void*)0);
    /* this add should not overwrite the existing entry! */
    fbt_ccache_add_entry(tld, (void*)i, (void*)(i+2048));
    EXPECT_EQ(fbt_ccache_find(tld, (void*)i), (void*)(i+4096));
  }
  fbt_exit(tld);
}

TEST(CodeCacheTest, CodeCacheCreateTrampoline)
{
  struct thread_local_data *tld = fbt_init(NULL);
  struct trampoline *trampo = fbt_create_trampoline(tld, (void*)0xdead,
                                                    (void*)0xbeef,
                                                    ORIGIN_RELATIVE);
  EXPECT_NE(trampo, (void*)0);
  fbt_exit(tld);
}

TEST(CodeCacheTest, CodeCacheFlush)
{
  struct thread_local_data *tld = fbt_init(NULL);

  EXPECT_EQ(fbt_ccache_find(tld, (void*)0xdeadbeef), (void*)0);
  fbt_ccache_add_entry(tld, (void*)0xdeadbeef, (void*)0xc0ffee);
  EXPECT_EQ(fbt_ccache_find(tld, (void*)0xdeadbeef), (void*)0xc0ffee);

  fbt_ccache_flush(tld);

  EXPECT_EQ(fbt_ccache_find(tld, (void*)0xdeadbeef), (void*)0);

  fbt_exit(tld);
}
