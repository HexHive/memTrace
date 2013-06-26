/**
 * @file fbt_mem_mgmt.h
 * Internal memory management for the BT (code cache, trampolines, mapping
 * table, internal memory).
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
#ifndef FBT_MEM_MGMT_H
#define FBT_MEM_MGMT_H

#include "fbt_datatypes.h"

/* number of pages for the private stack */
#define BT_STACK_SIZE 25  // before, it was five.

/* allocate this many pages every time we run out of small memory */
#define SMALLOC_PAGES (5+BT_STACK_SIZE)
/* max. nr of bytes that can be allocated in a smalloc call */
#define SMALLOC_MAX 0x100


/* forward declaration */
struct thread_local_data;
struct trampoline;

/** always allocate some reasonable amount of additional code cache memory */
#define CODE_CACHE_ALLOC_PAGES 0x1600

/** pagesize of the system we are running on.
   we don't use sysconf as this would introduce an additional dependency on
   libc */
#define PAGESIZE 0x1000

#define NRPAGES(x) (((x) + (PAGESIZE-1)) & (~(PAGESIZE-1))) / PAGESIZE

/** we can fit 1024 trampolines of size 28/56 (7*4/8) into 7 pages (32b) or 14
   pages (64bit) */
#define ALLOC_TRAMPOLINES 1024

/** different types for memory chunks */
enum mem_type {
  MT_CODE_CACHE,  /**< code cache (RX[W]) */
  MT_MAPPING_TABLE,  /**< mapping table (R[W]) */
  MT_SYSCALL_TABLE, /**< syscall table (R[W]) */
  MT_TRAMPOLINE,  /**< trampolines to translate new code blocks (RX[W]) */
  MT_INTERNAL,  /**< internally used memory (R[W]) */
  MT_SHARED_DATA, /** <  used for shared data (R[W]) */
};

/** Information about a memory chunk */
struct mem_info {
  enum mem_type type;  /**< chunk type */
  struct mem_info *next;  /**< pointer to next chunk or NULL */
  void *ptr;  /**< pointer to allocated memory */
  long size;  /**< length of allocated memory */
};

/**
 * Initialize thread local data storage.
 * @return Pointer to thread local data.
 */
struct thread_local_data *fbt_init_tls(BOOL lock);

/**
 * Reinitialize thread local data storage.
 * @param tld pointer to thread local data to be reinitialized
 * @return Pointer to thread local data.
 */
struct thread_local_data *fbt_reinit_tls(struct thread_local_data *tld,
                                         BOOL lock);

/**
 * Reinitializes thread local data storage for a new process.
 * @param tld pointer to thread local data to be reinitialized
 */
//void fbt_reinit_new_process(struct thread_local_data *tld);

/**
 * Allocates size bytes of thread local storage (RW). This memory is freed
 * whenever the thread exits.
 * @param tld pointer to thread local data
 * @param size number of bytes (must be smaller than 
 * @return the address of the allocated (unaligned) memory
 */
void *fbt_smalloc(struct thread_local_data *tld, long size, BOOL lock);

/**
 * allocate a number of pages in memory.
 * This function allocates the specified number of pages in memory. The
 * allocated memory is inserted into a list of memory to be freed when the
 * thread exits.
 * @param tld thread local data of the current thread
 * @param pages how many pages to allocate
 * @param type type of memory (specifies the protection flags)
 * @return the address of the allocated, page aligned memory
 */
void *fbt_lalloc(struct thread_local_data *tld, int pages,
                 enum mem_type type, BOOL lock);

/**
 * Allocate a new code cache and make it available in the TLD struct.
 * @param tld thread local data of the current thread
 */
void fbt_allocate_new_code_cache(struct thread_local_data *tld,
                                 BOOL lock);

/**
 * Free all allocated BT memory of this thread
 * @param tld thread local data of the current thread
 */
void fbt_mem_free(struct thread_local_data *tld,
                  BOOL lock);

/**
 * Allocate a new set of trampolines and make them available in the TLD struct.
 * @param tld thread local data of the current thread
 */
void fbt_allocate_new_trampolines(struct thread_local_data *tld,
                                  BOOL lock);

/**
 * Free a given trampoline and enqueue it in the list of unused trampolines
 * @param tld thread local data of the current thread
 * @param tramp Trampoline that is about to be freed.
 */     
void fbt_trampoline_free(struct thread_local_data *tld,
    struct trampoline *trampo,
    BOOL lock);

/** 
 * Initializes the shared data for this tld. This should only be done once and
 * the structure should then be passed on to created threads.
 */
void fbt_init_shared_data(struct thread_local_data* tld);

#endif  /* FBT_MEM_MGMT_H */
