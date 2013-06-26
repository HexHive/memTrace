/**
 * @file fbt_mutex.c
 *
 * Implementation of a futex-based mutex data structure
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * $Date: 2011-12-30 14:24:05 +0100 (ven, 30 dic 2011) $
 * $LastChangedDate: 2011-12-30 14:24:05 +0100 (ven, 30 dic 2011) $
 * $LastChangedBy: payerm $
 * $Revision: 1134 $
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

#include "fbt_datatypes.h"
#include "fbt_mutex.h"
#include "fbt_syscalls_64.h"

#include <linux/futex.h>
#include <sys/syscall.h>

#define FUTEX_INVALID -1
#define FUTEX_UNLOCKED 0
#define FUTEX_LOCKED 1
#define FUTEX_CONTENDED 2

static long sys_futex(void *addr1, int op, int val1, void *timeout, void *addr2, int val3)
{
  long res;
  res = (long)fbt_syscall6(SYS64_futex, (uint64_t)addr1, op, val1, (uint64_t)timeout, (uint64_t)addr2, val3);
  return res;
}

int fbt_mutex_init(fbt_mutex_t *futex) {
  *futex = FUTEX_UNLOCKED;
  return 0;
}

int fbt_mutex_lock(fbt_mutex_t *futex) {
  /* Try to lock */
  fbt_mutex_t current = __sync_val_compare_and_swap(futex, FUTEX_UNLOCKED, FUTEX_LOCKED);
  if (current == FUTEX_UNLOCKED) {
#ifdef DBGMUTEXES
   uint32_t tid = fbt_syscall(SYS64_gettid);
   llprintf("thread %d locked\n", tid);
#endif
   return 0;
  }

  if (current == FUTEX_LOCKED) {
    current = __sync_lock_test_and_set(futex, FUTEX_CONTENDED);
  }

  while (current != FUTEX_UNLOCKED) {
    sys_futex(futex, FUTEX_WAIT, FUTEX_CONTENDED, NULL, NULL, 0);
    current = __sync_lock_test_and_set(futex, FUTEX_CONTENDED);
  }

#ifdef DBGMUTEXES
  uint32_t tid = fbt_syscall(SYS64_gettid);
  llprintf("thread %d locked under contention\n", tid);
#endif

  return 0;
}

int fbt_mutex_trylock(fbt_mutex_t *futex) {
  int current = __sync_val_compare_and_swap(futex, FUTEX_UNLOCKED, FUTEX_LOCKED);
  if (current == FUTEX_UNLOCKED) {
    return 0;
  }
  return -1;
}

int fbt_mutex_unlock(fbt_mutex_t *futex)
{
#ifdef DBGMUTEXES
  uint32_t tid = fbt_syscall(SYS64_gettid);
  llprintf("thread %d unlocking\n", tid);
#endif

  if (*futex == FUTEX_CONTENDED) {
    *futex = FUTEX_UNLOCKED;
  } else if(__sync_lock_test_and_set(futex, FUTEX_UNLOCKED) == FUTEX_LOCKED) {
    return 0;
  }

  // Wake up a waiting thread
  sys_futex(futex, FUTEX_WAKE, FUTEX_LOCKED, NULL, NULL, 0);

  return 0;
}

int fbt_mutex_cleanup(fbt_mutex_t *futex) {
  *futex = FUTEX_INVALID;
  return 0;
}

