/**
 * Unit tests related to TRACK_CFTX
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

#if defined(TRACK_CFTX)

#include "libfastbt.h"
#include "fbt_debug.h"
#include "fbt_mem_mgmt.h"
#include "fbt_syscall.h"
#include "fbt_restart_transaction.h"

#include <sys/mman.h>

#include <pthread.h>
#include <semaphore.h>

#include "test_util.h"



/** Idles until the pthread_mutex_t passed as an argument is available */
static void *idle(void *mutex) {
  printf("idling..\n");
  pthread_mutex_lock((pthread_mutex_t *)mutex);
  pthread_mutex_unlock((pthread_mutex_t *)mutex);
  printf("Thread stopping.\n");
  return NULL;
}

static void *idle2(void *target) {
  void (*func)(void) = (void (*)(void))target;

  printf("idling..\n");
  func();
  printf("done idling\n");
  return NULL;
}

void callback(struct thread_local_data *) {
    
}

/** Tests that we can stop threads using real-time signals */
TEST(TrackCFTX, StopThread)
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
  
  /** We should now have 3 threads (including the main thread) */
  ASSERT_EQ_WITHIN(3, count_num_threads(tld), 1000, 10);
  usleep(1000);

  fbt_start_transaction(tld, fbt_commit_transaction);

  /* Perform callback */
  fbt_mutex_lock(&tld->shared_data->threads_mutex);
  struct thread_entry *te = tld->shared_data->threads;
  while (te != NULL) {
    if (te->tld == tld) {
      te = te->next;
      continue;
    }
    fbt_restart_transaction(tld, te->tld);
    te = te->next;
    printf("Done signaling %p, next_te=%p\n", te->tld, te);
    printf("---------\n");
  }
  fbt_mutex_unlock(&tld->shared_data->threads_mutex);
  fbt_commit_transaction();

  printf("Waiting for all threads to die..\n");
  
  /** Let child threads finish */
  pthread_mutex_unlock(&lock);
  pthread_join(t0, NULL);
  pthread_join(t1, NULL);  
  printf("All threads dead?\n");
    
  /* We should only have 1 thread left */
  ASSERT_EQ_WITHIN(1, count_num_threads(tld), 1000, 10);

  fbt_exit(tld);

  DEBUG_END();
}

TEST(TrackCFTX, StopThread2)
{
  DEBUG_START();

  /* Generate our idling function */
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char *idlefunc = target;

  BEGIN_ASM(target)
    L1:
      jmp L1
      ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);
  pthread_t t0, t1;  
  
  fbt_start_transaction(tld, fbt_commit_transaction);
  
  /** Initialize the lock on which threads will wait on */
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_lock(&lock);
  
  /** Create two threads that wait on 'lock' */
  pthread_create(&t0, NULL, &idle2, idlefunc);
  pthread_create(&t1, NULL, &idle2, idlefunc);    

  fbt_commit_transaction();
  
  /** We should now have 3 threads (including the main thread) */
  ASSERT_EQ_WITHIN(3, count_num_threads(tld), 1000, 10);
  sleep(2);

  /* We now overwrite the old idle function, which will be retranslated
     by the threads if they flush their cache */
  target = idlefunc;
  BEGIN_ASM(target)
    L1:
      jmp L2
    L2:
      ret
  END_ASM

  fbt_start_transaction(tld, fbt_commit_transaction);

  /* Perform callback */
  fbt_mutex_lock(&tld->shared_data->threads_mutex);  
  struct thread_entry *te = tld->shared_data->threads;
  ulong_t i = 0;
  while (te != NULL) {
    if (te->tld == tld) {
      te = te->next;
      continue;
    }
    thread_entry *next = te->next;
    fbt_restart_transaction(tld, te->tld);
    te = next;
    printf("Done signaling %p, next_te=%p\n", te->tld, te);
    printf("---------\n");
    i++;
  }
  fbt_mutex_unlock(&tld->shared_data->threads_mutex);  
  fbt_commit_transaction();

  printf("Waiting for all threads to die..\n");
  
  /** Let child threads finish */
  pthread_mutex_unlock(&lock);
  pthread_join(t0, NULL);
  pthread_join(t1, NULL);  
  printf("All threads dead?\n");

  sleep(1);
    
  /* We should only have 1 thread left */
  ASSERT_EQ_WITHIN(1, count_num_threads(tld), 1000, 10);

  fbt_exit(tld);

  DEBUG_END();
}

TEST(TrackCFTX, StopThread3)
{
  DEBUG_START();

  /* Generate our idling function */
  char *target = (char *)mmap(0, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char *idlefunc = target;

  BEGIN_ASM(target)
    L1:
      movl ${idlefunc}, %eax // Address of ret
      jmp *%eax
      ret
  END_ASM

  struct thread_local_data *tld = fbt_init(NULL);
  pthread_t t0, t1;  
  
  fbt_start_transaction(tld, fbt_commit_transaction);
  
  /** Initialize the lock on which threads will wait on */
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_lock(&lock);
  
  /** Create two threads that wait on 'lock' */
  pthread_create(&t0, NULL, &idle2, idlefunc);
  pthread_create(&t1, NULL, &idle2, idlefunc);    

  fbt_commit_transaction();
  
  /** We should now have 3 threads (including the main thread) */
  ASSERT_EQ_WITHIN(3, count_num_threads(tld), 1000, 10);

  /* We now overwrite the old idle function, which will be retranslated
     by the threads if they flush their cache */
  printf("Overwriting original code.\n");
  target = idlefunc;
  BEGIN_ASM(target)
    L1:
      movl ${idlefunc + 5 + 2}, %eax // Address of ret
      jmp *%eax
      ret
  END_ASM

  fbt_start_transaction(tld, fbt_commit_transaction);

  /* Perform callback */
  struct thread_entry *te = tld->shared_data->threads;
  
  fbt_mutex_lock(&tld->shared_data->threads_mutex);
  ulong_t i = 0;
  while (te != NULL) {
    if (te->tld == tld) {
      te = te->next;
      continue;
    }
    thread_entry *next = te->next;
    fbt_restart_transaction(tld, te->tld);
    te = next;
    i++;
  }
  fbt_mutex_unlock(&tld->shared_data->threads_mutex);

  fbt_commit_transaction();

  printf("Waiting for all threads to die..\n");
  
  /** Let child threads finish */
  pthread_mutex_unlock(&lock);
  printf("All threads dead?\n");
    
  /* We should only have 1 thread left */
  ASSERT_EQ_WITHIN(1, count_num_threads(tld), 5000, 10);

  fbt_exit(tld);

  DEBUG_END();
}

#else /* TRACK_CFTX */

TEST(TrackCFTX, Define)
{
  printf("*** Not testing, TRACK_CFTX not set.\n");
}
#endif /* TRACK_CFTX */
