#ifndef TEST_UTIL_H
#define TEST_UTIL_H

/** Macro that can be used to check for conditions that might be timing dependant:
  * We evaluate <code>expr</code> every <code>dt</code>ms until at least
  * <code>t</code>ms have elapsed. If in this time frame, it never evaluates to
  * <code>expected</code>, this check fails. */
#define ASSERT_EQ_WITHIN(expected, expr, t, dt) \
{ \
  ulong_t elapsed = 0; \
  while (elapsed < t) { \
    if (expr == expected) { \
      break; \
    } \
    usleep(dt*1000); \
    elapsed += dt; \
  } \
 \
  if (elapsed >= t) { \
    ASSERT_EQ(expected, expr); \
  } \
}

/** Counts the number of threads currently tracked */
static long count_num_threads(struct thread_local_data *tld) {
  fbt_mutex_lock(&tld->shared_data->threads_mutex);
  
  long num_threads = 0;
  struct thread_entry *current = tld->shared_data->threads;

  while (current != NULL) {
    num_threads += 1;
    current = current->next;
  }
  
  fbt_mutex_unlock(&tld->shared_data->threads_mutex);  
  
  return num_threads;
}

#endif