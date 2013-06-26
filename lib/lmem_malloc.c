/**
 * @file fbt_lmem_malloc.c
 * Malloc wrappers that can be preloaded or directly linked by
 * C applications.
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedDate: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1184 $
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

/**
 * This is a our malloc replacement which protects
 * borders.
 */
#include "fbt_lmem_api.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void* __libc_malloc(size_t size);
void  __libc_free(void* ptr);
void* __libc_realloc(void* ptr, size_t size);
void* __libc_calloc(size_t nmemb, size_t size);
void* __libc_valloc(size_t size);
void* __libc_pvalloc(size_t size);
void* __libc_memalign(size_t alignment, size_t size);

__attribute__((visibility("default")))
void* malloc(size_t size) {
  printf("malloc wrapper\n");

  void* block = __libc_malloc(size+12);
  void* res_begin = block + 8;
  void* res_end = block + 8 + size;

  // store the size of the block in the first four bytes
  *((unsigned*)block) = 0xdeadbeef;
  *(((unsigned*)block)+1) = size;

  lmem_protect(block+0);
  lmem_protect(block+1);
  lmem_protect(block+2);
  lmem_protect(block+3);
  lmem_protect(block+4);
  lmem_protect(block+5);
  lmem_protect(block+6);
  lmem_protect(block+7);
  lmem_protect(res_end);
  lmem_protect(res_end+1);
  lmem_protect(res_end+2);
  lmem_protect(res_end+3);

  return res_begin;
}

__attribute__((visibility("default")))
void free(void* addr) {
  printf("free wrapper\n");

  if (addr == 0){
    return;
  }

  void* block = addr-8;

  /* to be able to read the tag*/
  lmem_unprotect(block+0);
  lmem_unprotect(block+1);
  lmem_unprotect(block+2);
  lmem_unprotect(block+3);
  lmem_unprotect(block+4);
  lmem_unprotect(block+5);
  lmem_unprotect(block+6);
  lmem_unprotect(block+7);

  unsigned tag = *((unsigned*)block);
  if (tag != 0xdeadbeef){
    printf("WARNING: WAS NOT ALLOCATED BY US: IGNORING\n");
    return;
  }

  size_t size = *(((unsigned*)block)+1);
  void* res_end = block + 8 + size;

  lmem_unprotect(res_end);
  lmem_unprotect(res_end+1);
  lmem_unprotect(res_end+2);
  lmem_unprotect(res_end+3);

  __libc_free(block);
}

__attribute__((visibility("default")))
void* realloc(void* addr, size_t size) {

  // implemented from the spec. in the man page
  if (addr == 0){
    return malloc(size);
  } else {
    char* newmem = malloc(size);
    if (newmem == 0){
      printf("fbt_sdbg.c: realloc wrapper: "
            "malloc failed!\n");
      return 0;
    } else {
                        // see our malloc wrapper
      unsigned olsiz = *(((unsigned*)addr)-1);
      unsigned minsiz = size;
      if (olsiz < size){
        minsiz = olsiz;
      }
      int i;
      for (i=0; i<minsiz; i++){
        newmem[i] = ((char*)addr)[i];
      }
      free(addr);
      return newmem;
    }
  }
}

__attribute__((visibility("default")))
void* calloc(size_t num, size_t size)
{
  void* res = malloc(num*size);
  int i=0;
  for (i=0; i<num*size; i++){
    ((char*)res)[i]=0;
  }
  return res;
}

__attribute__((visibility("default")))
void* valloc(size_t size)
{
  printf("valloc not yet implemented! (should be easy)\n");
  exit(1);
  // __libc_valloc(size_t size)
  return 0;
}

__attribute__((visibility("default")))
void* pvalloc(size_t size)
{
  printf("pvalloc not yet implemented! (should be easy)\n");
  exit(1);
  // __libc_pvalloc(size_t size)
  return 0;
}

__attribute__((visibility("default")))
void* memalign(size_t alignment, size_t size)
{
  printf("memalign not yet implemented! (should be easy)\n");
  exit(1);
  // __libc_memalign(size_t alignment, size_t size)
  return 0;
}
