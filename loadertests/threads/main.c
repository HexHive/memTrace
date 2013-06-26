/**
 * @file main.c
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Tobias Hartmann <tobi.hartmann@gmail.com>
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * $Date: 2011-12-30 14:24:05 +0100 (Fri, 30 Dec 2011) $
 * $LastChangedDate: 2011-12-30 14:24:05 +0100 (Fri, 30 Dec 2011) $
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
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

void *functionCount1();
void *functionCount2();
int count = 0;
#define COUNT_DONE  10
#define COUNT_HALT1  3
#define COUNT_HALT2  6

pthread_key_t key;
void *value;


int main() {
  pthread_t thread1, thread2;
  
  /* key create without destructor */
  pthread_key_create(&key, NULL);

  pthread_create(&thread1, NULL, &functionCount1, NULL);
  pthread_create(&thread2, NULL, &functionCount2, NULL);
  
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  if (count == 10) {
    printf("\nTest \"threads\" successful.\n\n");
    return 0;
  } else {
    printf("\nError test \"threads\" failed.\n\n");
    return 1;
  }
}


// Write numbers 1-3 and 8-10 as permitted by functionCount2()
void *functionCount1() {
  printf("\nThread 1 started.\n");

  /* Set thread specific data */
  pthread_setspecific(key, (void *) 12345);
  
  while(1) {
    pthread_mutex_lock(&count_mutex);
    
    pthread_cond_wait(&condition_var, &count_mutex);

    count++;
    
    pthread_mutex_unlock( &count_mutex );
    
    if(count >= COUNT_DONE) {
      /* key previously created */
      value = pthread_getspecific(key);
      if ((int)value != 12345)
        count = 0;

      return NULL;
    }
  }
}

// Write numbers 4-7
void *functionCount2() {
  printf("\nThread 2 started.\n");

  int ts = 6789;
  pthread_setspecific(key, (void *)&ts);

  while(1) {
    pthread_mutex_lock( &count_mutex );
    
    if( count < COUNT_HALT1 || count > COUNT_HALT2 ) {
      pthread_cond_signal( &condition_var );
    } else {
      count++;
    }
    
    pthread_mutex_unlock( &count_mutex );
    
    if(count >= COUNT_DONE) {
      value = pthread_getspecific(key);
      int val = *((int *)value);
      if (val != 6789)
        count = 0;
      
      return NULL;
    }
  }
}
