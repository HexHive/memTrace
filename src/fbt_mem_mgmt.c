/**
 * @file fbt_mem_mgmt.c
 * Implementation of the internal memory management for the BT (code cache,
 * trampolines, mapping table, internal memory)
 *
 * Copyright (c) 2012 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
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

#include "fbt_mem_mgmt.h"

#include <asm-generic/mman.h>

#include "fbt_memory.h"
#include "fbt_signals.h"
#include "fbt_asm_macros.h"
#include "fbt_code_cache.h"
#include "fbt_datatypes.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_syscall.h"
#include "fbt_address_space.h"
#include "fbt_syscalls_64.h"
#include "fbt_shared_data.h"

#if defined(DEBUG)
#include <sys/stat.h>
#include <stdarg.h>
#endif /* DEBUG */

struct thread_local_data *fbt_init_tls(BOOL lock)
{
  return fbt_reinit_tls(NULL, lock);
}

struct thread_local_data *fbt_reinit_tls(struct thread_local_data *tld, 
                                         BOOL lock)
{
  /* allocate (bootstrapping) memory */
  if (lock){
    fbt_mutex_lock(&shared_data_mutex);
  }
  void *mem;
  if (tld == NULL) {
    mem = int_mmap(SMALLOC_PAGES * PAGESIZE,
                   PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS);
    shared_data.total_internal_allocated_data += (SMALLOC_PAGES+1) * PAGESIZE;
    //llprintf("REINIT_TLS: Total internal allocated data till now..: ");
    //print64(2, shared_data.total_internal_allocated_data);
    //llprintf("\n");
    if (mem <= (void*)0x200000000){
      fbt_suicide_str("got an address that is too low!");
    }
  } else {
    /* Free all the dynamic memory we have allocated. Note that this will
       leave us with the one single chunk that we initially allocated that
       contains stack and tld.
       This last chunk will be reset so that it can be used like the mmap
       above. */
    fbt_mem_free(tld, lock);
    mem = tld->chunk->ptr;
  }
  if (lock){
    fbt_mutex_unlock(&shared_data_mutex);
  }

  /* stack grows BT_STACK_SIZE pages down */
  void *stack = mem + (BT_STACK_SIZE * PAGESIZE);

  assert(tld == NULL || (tld != NULL && tld == stack));
  tld = (struct thread_local_data*)(stack);
  tld->ind_target = NULL;
  tld->stack = stack;

  /* fill the thread id */
  tld->tid = fbt_gettid();

  /* initialize memory allocation */
  tld->chunk = (struct mem_info*)(tld + 1);
  tld->chunk->next = NULL;
  tld->chunk->type = MT_INTERNAL;
  tld->chunk->ptr = mem;
  tld->chunk->size = SMALLOC_PAGES * PAGESIZE;

  tld->transl_instr = NULL;
  tld->code_cache_end = NULL;
  tld->trampos = NULL;

  tld->totranslate_stacktop = 0;

  tld->smalloc = (void*)(tld->chunk + 1);
  tld->smalloc_size = (SMALLOC_PAGES * PAGESIZE) - ((uint64_t)(tld->smalloc) -
      (uint64_t)(mem));

  tld->in_bt_context = 1; /* we are in bt context now, not in application context */

  assert(tld->smalloc_size > 0);

  /* starting from this point we can use our internal memory allocation */

  /* allocate memory for hashtable.
     lalloc uses mmap and map_anonymous, so the table is initialized with 0x0
     therefore we don't need to memset the whole table+4 for 0x1 guard for
     tcache_find_fast asm function */
  tld->mappingtable = fbt_lalloc(tld, (MAPPINGTABLE_SIZE / PAGESIZE) + 1,
      MT_MAPPING_TABLE, lock);


  /* guard for find_fast-wraparound used in optimizations */
  *(uint32_t*)((uint64_t)(tld->mappingtable)+MAPPINGTABLE_SIZE) = 0x1; 

  PRINT_DEBUG("allocated mappingtable: %p -> %p",
      tld->mappingtable, tld->mappingtable + MAPPINGTABLE_SIZE);


  /* initialize trampolines */
  tld->ret2app_trampoline = NULL;
  tld->opt_ijump_trampoline = NULL;
  tld->opt_icall_trampoline = NULL;
  tld->unmanaged_code_trampoline = NULL;
  tld->opt_ret_trampoline = NULL;

  tld->syscall_location = 0;
  uint32_t table_size = (((MAX_SYSCALLS_TABLE*sizeof(void*)) + (PAGESIZE-1)) &
      (~(PAGESIZE-1))) / PAGESIZE;

  //llprintf("alloc syscalltbl\n");
  tld->syscall_table = \
      (enum syscall_auth_response (**)(struct thread_local_data*, uint32_t,
          uint32_t, uint32_t, uint32_t, uint32_t,
          uint32_t, uint32_t, uint32_t, uint32_t*))
          fbt_lalloc(tld, table_size, MT_SYSCALL_TABLE, lock);
  assert(table_size == 1);

  /* add code cache */
  fbt_allocate_new_code_cache(tld, lock);

  return tld;
}

void fbt_allocate_new_code_cache(struct thread_local_data *tld, BOOL lock)
{
  //llprintf("alloc code cache\n");
  void *mem = fbt_lalloc(tld, CODE_CACHE_ALLOC_PAGES, MT_CODE_CACHE, lock);
  tld->transl_instr = mem;
  tld->code_cache_end = mem + (CODE_CACHE_ALLOC_PAGES * PAGESIZE);
}

void fbt_allocate_new_trampolines(struct thread_local_data *tld, BOOL lock)
{
  uint32_t trampo_size = (((ALLOC_TRAMPOLINES * sizeof(struct trampoline)) +
      (PAGESIZE-1)) & (~(PAGESIZE-1))) / PAGESIZE;

  //llprintf(");

  //llprintf("alloc trampo\n");
  void *mem = fbt_lalloc(tld, trampo_size, MT_TRAMPOLINE, lock);

  struct trampoline *trampos = (struct trampoline*)mem;

  /* initialize linked list */
  long i;
  for (i=0; i<ALLOC_TRAMPOLINES-1; ++i) {
    trampos->next = trampos+1;
    trampos = trampos->next;
  }
  trampos->next = tld->trampos;

  tld->trampos = (struct trampoline*)mem;
}

void fbt_trampoline_free(struct thread_local_data *tld,
    struct trampoline *trampo, BOOL lock)
{
  trampo->next = tld->trampos;
  tld->trampos = trampo;
}

void fbt_mem_free(struct thread_local_data *tld, BOOL lock)
{
  assert(tld != NULL);
  long kbfreed = 0;
  struct mem_info *chunk = tld->chunk;
  while (chunk->next != NULL) {
    /* we need to save the next pointer. munmap could unmap the last allocated
       data and chunk itself would no longer be valid. this is a bootstrapping
       problem and takes care of the last allocated chunk. */
    struct mem_info *next = chunk->next;
    kbfreed += chunk->size >> 10;
    int_munmap((uint64_t)chunk->ptr, chunk->size);
    shared_data.total_internal_allocated_data -= chunk->size;
    chunk = next;
  }
  tld->chunk = chunk;
  PRINT_DEBUG("%d KB freed on fbt_mem_free", kbfreed);
}

void *fbt_lalloc(struct thread_local_data *tld, int pages,
    enum mem_type type,
    BOOL lock)
{
  if (lock) fbt_mutex_lock(&shared_data_mutex);

  assert(pages > 0);
  if (pages <= 0)
    fbt_suicide_str("Trying to allocate 0 pages (fbt_lalloc: fbt_mem_mgmt.c)\n");

  /* an improvement could be to add guard pages for stack, mapping table, code cache */
  int alloc_size = pages * PAGESIZE;

  struct mem_info *chunk = fbt_smalloc(tld, sizeof(struct mem_info), FALSE);

  /* what flags should we use for the current alloc? */
  uint64_t prot = 0;
  switch (type) {
  case MT_INTERNAL:
  case MT_MAPPING_TABLE:
  case MT_SHARED_DATA:
  case MT_SYSCALL_TABLE:
    prot = PROT_READ|PROT_WRITE;
    break;
  case MT_CODE_CACHE:
  case MT_TRAMPOLINE:
    prot = PROT_READ|PROT_WRITE|PROT_EXEC;
    break;
  }

  uint64_t as = round_up_to_pagesize(alloc_size);

  //llprintf("wanna allocate amount...: ");
  //print64(2, as); 
  //llprintf("\n");

  void *retval;
  retval = int_mmap(as,
                    prot,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED);
  shared_data.total_internal_allocated_data += (as + HOST_PAGESIZE);
    //llprintf("FBT_LALLOC: Total internal allocated data till now...: ");
    //print64(2, shared_data.total_internal_allocated_data);
    //llprintf("\n");
  if (retval <= (void*)0x200000000){
    fbt_suicide_str("got an address that is too low!!!");
  }

  /* we do not track shared data, as it should never be freed */
  int track_chunk = 1;
  switch(type) {
  case MT_SHARED_DATA:
    track_chunk = 0;
    break;
  default:
    break;
  }

  /* fill in the memory chunk information and store it in the list */
  if (track_chunk)  {
    chunk->ptr = retval;
    chunk->size = alloc_size;
    chunk->type = type;
    chunk->next = tld->chunk;
    tld->chunk = chunk;
  }

  if (lock) fbt_mutex_unlock(&shared_data_mutex);

  return retval;
}

void *fbt_smalloc(struct thread_local_data *tld, long size, BOOL lock)
{
  if (lock){
    fbt_mutex_lock(&shared_data_mutex);
  }
  /* ensure that we use smalloc only for small stuff */
  if (size > SMALLOC_MAX || size <= 0) {
    fbt_suicide_str("Too much memory requested (fbt_smalloc: fbt_mem_mgmt.c)\n");
  }
  /* do we need to allocate additional small memory space? */
  if (size > tld->smalloc_size) {
    void *mem;
    mem = int_mmap(SMALLOC_PAGES * PAGESIZE,
                   PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS);
    shared_data.total_internal_allocated_data += (1+SMALLOC_PAGES) * PAGESIZE;
    if (mem <= (void*)0x200000000){
      fbt_suicide_str("got an address that is too low!!!!!!");
    }

    tld->smalloc_size = SMALLOC_PAGES * PAGESIZE;
    tld->smalloc = mem;

    struct mem_info *chunk = (struct mem_info*) \
        fbt_smalloc(tld, sizeof(struct mem_info), FALSE);

    chunk->type = MT_INTERNAL;
    chunk->ptr = mem;
    chunk->size = SMALLOC_PAGES * PAGESIZE;

    chunk->next = tld->chunk;
    tld->chunk = chunk;
  }
  /* let's hand that chunk of memory back to the caller */
  void *mem = tld->smalloc;
  tld->smalloc += size;
  tld->smalloc_size -= size;

  assert(((long)tld->smalloc) == ((long)mem)+size);

  if (lock){
    fbt_mutex_unlock(&shared_data_mutex);
  }
  return mem;
}

void fbt_init_shared_data(struct thread_local_data* tld)
{
  PRINT_DEBUG("INITIALIZING DATA SHARED BETWEEN THREADS\n");

  fbt_mutex_init(&shared_data_mutex);

  // Address space datastruct
  init_address_space(tld);

  for (int i=0; i<MAX_NR_SIGNALS; i++){
    shared_data.signals[i].sigaction = (uint64_t)SIG_DFL;
  }

  /* this behavious is not quite accurate. The process stack is normally used
   * unles sigaltstack has been specified */
  shared_data.signal_stack_area = do_guest_mmap(
      tld,
      SIGNAL_STACK_AREA_BOTTOM,
      SIGNAL_STACK_AREA_SIZE,
      PROT_READ|PROT_WRITE,
      MAP_PRIVATE|MAP_ANONYMOUS,
      -1,
      0,
      "signal stack area");
  shared_data.signal_stack_area += SIGNAL_STACK_AREA_SIZE/2; /* in the middle just to be safe */
  shared_data.signal_stack_area = (shared_data.signal_stack_area & 0xfffffff0);
    //llprintf("INIT SHARED DATA Total internal allocated data till now.....: ");
    //print64(2, shared_data.total_internal_allocated_data);
    //llprintf("\n");

  shared_data.num_shm_entries = 0;

  int t1 = shared_data.signal_stack_area;
  if (t1 > -255 && t1 < 0){
    fbt_suicide_str("fffff\n");
  }

  shared_data.sighandler_wrapper32 =
      do_guest_mmap(
        tld,
        SIGHANDWRAPPER_BOTTOM,  /* Later we should choose an address that is free
                                   at program startup, add it to the address space so
                                   that the translated program will not be able to
                                   map the same memory. But this method is fine too. */
        SIGHANDWRAPPER_SIZE,    /* You may want to adjust it */
        PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,
        -1,
        0,
        "sighand wrapper");

  int t2 = shared_data.sighandler_wrapper32;
  if (t2 > -255 && t2 < 0){
    fbt_suicide_str("fffff\n");
  }

  char* tmp = (char*)(uint64_t)shared_data.sighandler_wrapper32;
  BEGIN_32ASM(tmp)
    /* Glibc has a similar routine called "__kernel_sigreturn" iirc */

    /* the (original) address of the signal handler
       is put in %eax by the caller (sighelper()) */
    call *%eax;

    /* special system call similar to 'sigreturn' */
    mov $501, %eax;
    int $0x80;

    /* should not be reached */
    hlt
  END_ASM

  // done!
  shared_data.is_initialized = 1;

  PRINT_DEBUG_FUNCTION_END("");
}
