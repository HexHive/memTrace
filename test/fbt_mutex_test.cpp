/**
 * Unit tests for the mutex implementation
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

#include <pthread.h>

#include "fbt_mutex.h"

fbt_mutex_t lock;

void *increment10000(void *p) {
  int *counter = (int *)p;

  int i;
  for(i = 0; i < 10000; ++i) {
    fbt_mutex_lock(&lock);
    (*counter) += 1;
    fbt_mutex_unlock(&lock);
  }
  
  return NULL;
}

TEST(MutexTest, Init)
{
  ASSERT_EQ(0, fbt_mutex_init(&lock));
  ASSERT_EQ(0, fbt_mutex_lock(&lock));
  ASSERT_EQ(0, fbt_mutex_unlock(&lock));  
  ASSERT_EQ(0, fbt_mutex_cleanup(&lock));  
}

TEST(MutexTest, Addition)
{
  fbt_mutex_init(&lock);
 
  fbt_mutex_lock(&lock);
  int counter = 0;
  int i;
  
  #define NUM_THREADS 10
  
  pthread_t threads[NUM_THREADS];
  
  for (i = 0; i < 10; ++i) {
    pthread_create(&threads[i], NULL, &increment10000, &counter);
  }
  
  fbt_mutex_unlock(&lock);
  
  // Wait for all threads to finish
  for (i = 0; i < 10; ++i) {
    pthread_join(threads[i], NULL);
  }
  
  ASSERT_EQ(NUM_THREADS * 10000, counter);
  
  fbt_mutex_init(&lock);
  fbt_mutex_cleanup(&lock);  
}

