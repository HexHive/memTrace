/**
 * Unit tests for shared data among multiple threads
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
#include <semaphore.h>

#include "test_util.h"

#ifdef SHARED_DATA

/** Idles until the pthread_mutex_t passed as an argument is available */
static void *idle(void *mutex) {
  pthread_mutex_lock((pthread_mutex_t *)mutex);
  pthread_mutex_unlock((pthread_mutex_t *)mutex);
  return NULL;
}

/** Tests that threads are correctly being tracked */
TEST(SharedDataTest, ThreadTracking)
{
  DEBUG_START();

  struct thread_local_data *tld = fbt_init(NULL);
  pthread_t t0, t1;  
  
  fbt_start_transaction(tld, fbt_commit_transaction);
  
  /** Initialize the lock on which threads will wait on */
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_lock(&lock);
  
  /** Create two threads that wait on 'lock' */
  pthread_create(&t0, NULL, &idle, &lock);
  pthread_create(&t1, NULL, &idle, &lock);    

  fbt_commit_transaction();

  printf("Created threads\n");
  
  /** We should now have 3 threads (including the main thread) */
  ASSERT_EQ_WITHIN(3, count_num_threads(tld), 1000, 20);
  
  /** Let child threads finish */
  pthread_mutex_unlock(&lock);
  pthread_join(t0, NULL);
  pthread_join(t1, NULL);  
    
  /* We should only have 1 thread left */
  ASSERT_EQ_WITHIN(1, count_num_threads(tld), 1000, 20);

  fbt_exit(tld);

  DEBUG_END();
}

/** Tests whether the shared_data data structure is set when we are using one thread */
TEST(SharedDataTest, Init)
{
  struct thread_local_data *tld = fbt_init(NULL);
  ASSERT_NE((struct shared_data *)NULL, tld->shared_data);
  fbt_exit(tld);
}

#else /* SHARED_DATA */

TEST(SharedDataTest, Define)
{
  printf("*** Not testing, SHARED_DATA not set.\n");
}
#endif /* SHARED_DATA */
