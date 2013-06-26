#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/futex.h>
#include <sys/time.h>

#define SS 0x10000000

#define FUTEX_INVALID -1
#define FUTEX_UNLOCKED 0
#define FUTEX_LOCKED 1
#define FUTEX_CONTENDED 2

typedef int mutex_t;

int fbt_mutex_init(mutex_t *fut)
{
  *fut = FUTEX_UNLOCKED;
  return 0;
}

int fbt_mutex_lock(mutex_t *fut)
{
  /* Try to lock */
  mutex_t current = __sync_val_compare_and_swap(fut, FUTEX_UNLOCKED, FUTEX_LOCKED);
  if (current == FUTEX_UNLOCKED) {
    return 0;
  }

  if (current == FUTEX_LOCKED) {
    current = __sync_lock_test_and_set(fut, FUTEX_CONTENDED);
  }

  while (current != FUTEX_UNLOCKED) {
    syscall(SYS_futex, fut, FUTEX_WAIT, FUTEX_CONTENDED, NULL, NULL, 0);
    current = __sync_lock_test_and_set(fut, FUTEX_CONTENDED);
  }

  return 0;
}

int fbt_mutex_trylock(mutex_t *fut)
{
  int current = __sync_val_compare_and_swap(fut, FUTEX_UNLOCKED, FUTEX_LOCKED);
  if (current == FUTEX_UNLOCKED) {
    return 0;
  }
  return -1;
}

int fbt_mutex_unlock(mutex_t *fut)
{
  if (*fut == FUTEX_CONTENDED) {
    *fut = FUTEX_UNLOCKED;
  } else if(__sync_lock_test_and_set(fut, FUTEX_UNLOCKED) == FUTEX_LOCKED) {
    return 0;
  }

  // Wake up a waiting thread
  syscall(SYS_futex, fut, FUTEX_WAKE, FUTEX_LOCKED, NULL, NULL, 0);

  return 0;
}

int fbt_mutex_cleanup(mutex_t *fut)
{
  *fut = FUTEX_INVALID;
  return 0;
}

int variable;
int variable_mutex[44];

int do_something() {
  int i,j;
  for (i=0; i<10000000; i++){
    for (j=0; j<1000; j++){
      if (i%4){variable_mutex[1] = 0;} else variable_mutex[1]=variable;
      fbt_mutex_lock(&variable_mutex[0]);
      variable++;
      fbt_mutex_unlock(&variable_mutex[0]);
    }
  }
  printf("thrd done\n");
  return 0;
}

void pv(){
  printf("The variable is %d\n", variable);
}

int main(int argc, char *argv[])
{
  void **child_stack;
  child_stack = (void **) malloc(SS);

  variable = 0;
  fbt_mutex_init(&variable_mutex[0]);

  pv();

  clone(do_something, ((char*)child_stack)+SS-16, CLONE_VM|CLONE_FILES, NULL);

  int i;
  for (i=0; i<10; i++){
    if (!(i%4)){variable_mutex[1] = 0;} else variable_mutex[1]=(-variable);
    fbt_mutex_lock(&variable_mutex[0]);
    sleep(1);
    variable++;
    fbt_mutex_unlock(&variable_mutex[0]);
  }
  printf("main done\n");

  sleep(100);

  fbt_mutex_cleanup(&variable_mutex[0]);

  pv();
  if (variable == 20000000){
    return 42; /* THE answer */
  } else {
    return 3;
  }
}



