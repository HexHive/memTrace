/**
 * @file fbt_memory.c
 *
 * Copyright (c) 2012 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-21 13:23:02 +0100 (sab, 21 gen 2012) $
 * $LastChangedDate: 2012-01-21 13:23:02 +0100 (sab, 21 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1201 $
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

#include "fbt_memory.h"

#include "fbt_syscalls_64.h"
#include "fbt_llio.h"
#include "fbt_libc.h"
#include "fbt_shared_data.h"
#include "fbt_debug.h"

/* for the mmap constants */
#include <asm-generic/mman-common.h>
#include <sys/mman.h>
#include <linux/mman.h>

#define LOWEST_INTERNAL_MMAP_ADDR 0x900000000
#define UPPERMOST_INTERNAL_MMAPPABLE_ADDRESS 0xA00000000

void int_print_address_space();

#define PAGESIZE 4096
static inline uint64_t round_up_to_pagesize(uint64_t p)
{
  return ((p+PAGESIZE-1)/PAGESIZE)*PAGESIZE;
}

/*
 This file has all the mmap brk munmap mremap logic of the translated program.
 We explicitly keep track of what is allocated and what not.
 */


/**
 * Mark region as allocated in our explicit representation 
 * of the address space.
 */
static void int_mark_as_allocated(struct internal_memory* as, 
                                  uint64_t where,
                                  uint64_t size)
{
  //llprintf("marking as alloc = ");
  //print64(2, where);
  //llprintf(" size = ");
  //print64(2, size);
  if (as->num_entries < MAX_INTERNAL_MEMORY_ENTRIES){

    /* Find out where to insert */
    int insertat = as->num_entries; /* for the case no hit in for loop */
    for (int i=0; i<as->num_entries; i++){
      if (as->entries[i].begin > where){
        insertat = i;
        break;
      }
    }

    /* Shift a whole bunch to the right */
    for (int i=as->num_entries; i>insertat; i--){
      as->entries[i] = as->entries[i-1];
    }
    /* And finally place our element (this keeps them sorted) */
    struct internal_memory_entry ase;
    ase.begin = where;
    ase.size = size;
    as->entries[insertat] = ase;

    as->num_entries++;
  } else {
    fbt_suicide_str("No more address entries available\n");
  }
}

/**
 * Mark everything between 'where' and 'where+len' as deallocated in 
 * our explicit representation of the address space.
 */
static void int_mark_range_as_deallocated(struct internal_memory* as, 
                                      uint64_t where,
                                      uint64_t len)
{
  //llprintf("marking as dealloc = ");
  //print64(2, where);
  //llprintf(" size = ");
  //print64(2, len);

  /* Remove elements that are totally in the unmapped region */
  while (1){

    /* Find element to delete */
    int todel = -1;
    for (int i=0; i<as->num_entries; i++){
      if (as->entries[i].begin >= where &&
          (as->entries[i].begin + as->entries[i].size)  <= (where+len)){
        todel = i;
        break;
      }
    }

    /* If there is none we are done */
    if (todel == -1){
      break;
    }

    if (todel != (-1)){
      /* Shift whole block to the left (to keep sorted) */
      for (int i=todel; i<as->num_entries-1; i++){
        as->entries[i] = as->entries[i+1];
      }
    }

    as->num_entries--;
  }
}

/**
 * Searches for a place where size bytes are free in our explicit
 * rep. of the address space.
 */
uint64_t int_find_free_address(struct internal_memory* as, uint64_t size)
{
  /* The lowest address we are allowed to use */
  uint64_t candidate = LOWEST_INTERNAL_MMAP_ADDR;
  uint64_t roundsize = round_up_to_pagesize(size);
  for (int i=0; i<as->num_entries; i++){
    if (as->entries[i].begin > candidate){
      uint64_t space = as->entries[i].begin - candidate;
      if (space >= roundsize){
        if (candidate < LOWEST_INTERNAL_MMAP_ADDR) {
          fbt_suicide_str("should never be reached.\n");
        }
        /* Ok, there is enough space */
        return candidate;
      }
    }
    uint64_t npc =
        round_up_to_pagesize(as->entries[i].begin+as->entries[i].size) +
        1*PAGESIZE;        /* Leave some space in between. This is entirely optional */
    if (npc > candidate){
      candidate = npc;
    }
  }
  if (UPPERMOST_INTERNAL_MMAPPABLE_ADDRESS > candidate){
    uint64_t space = UPPERMOST_INTERNAL_MMAPPABLE_ADDRESS - candidate;
    if (space >= roundsize){
      /* Ok, there is enough space */
      return candidate;
    }
  }
  fbt_suicide_str("Impossible to find a free address\n");
  return (-1); /* otherwise gcc emits a warning */
}

#ifdef DEBUG
static BOOL overlap(uint64_t abeg, uint64_t aend,
                    uint64_t bbeg, uint64_t bend)
{
  if (abeg > bbeg && abeg < bend){ return TRUE; }
  if (aend > bbeg && aend < bend){ return TRUE; }
  if (bbeg > abeg && bbeg < aend){ return TRUE; }
  if (bend > abeg && bend < aend){ return TRUE; }
  return FALSE;
}
#endif

/** when mmap is intercepted, this is called */
void* int_mmap(uint64_t length,
               uint64_t prot,
               uint64_t flags)
{
  PRINT_DEBUG("internal mmap\n");

  //fbt_mutex_lock(&shared_data_mutex);

  // Find where to allocate
  uint64_t free_addr = int_find_free_address(&shared_data.intmem, length);

  if (free_addr == 0){
    fbt_suicide_str("invalid free address");
  }

  //llprintf("free addr = ");
  //print64(2, free_addr);

  // Do the real allocation
  flags |= MAP_FIXED;
  void* rv = (void*)fbt_mmap( 
      (uint64_t)free_addr,
      length,
      prot,
      flags,
      -1,
      0, 
      "err in fbt_mmap for internal addrss");

  if ((int64_t)rv < 0 && (int64_t)rv > -128){
    PRINT_DEBUG_ADDRESS_SPACE("mmap failed with error code %d\n", -((int32_t)(int64_t)rv));
    fbt_suicide_str("mmap failed in fbt_address_space.c");
  }
  if (rv != (void*)(uint64_t)free_addr){
    PRINT_DEBUG("didnt get prec\n");
    fbt_suicide_str("did not get precisely the wanted address in "
        "() [1]!\n");
  }

  int_mark_as_allocated(&shared_data.intmem, 
                        free_addr, 
                        length);

  void* result = NULL;
  result = (void*)free_addr;

  //int_print_address_space();

  //fbt_mutex_unlock(&shared_data_mutex);

  return result;
}

/** when munmap is intercepted, this is called */
int64_t int_munmap(uint64_t addr,
                   uint64_t length)
{
  PRINT_DEBUG("guest munmap\n");
  fbt_munmap((uint64_t)addr, length, "error in munmap");
  int_mark_range_as_deallocated(&shared_data.intmem, addr, length);
  return 0;
}

/** debugging function */
void int_print_address_space()
{
  struct internal_memory* as = &shared_data.intmem;

  uint64_t total_used = 0;
  llprintf("THE %d ENTRIES:", as->num_entries);
  for (int i=0; i<as->num_entries; i++){
    if (i%8 == 0){
      llprintf("\n");
    }
    llprintf(":::\n");
    print64(2, as->entries[i].begin);
    print64(2, as->entries[i].begin+as->entries[i].size);
    total_used += as->entries[i].size;
  }

  for (int i=1; i<as->num_entries; i++){
    if (as->entries[i-1].begin > as->entries[i].begin){
      fbt_suicide_str("address space not sorted\n");
    }
  }

  for (int i=1; i<as->num_entries; i++){
    if (as->entries[i-1].begin + as->entries[i-1].size > as->entries[i].begin){
      llprintf("address space overlaps at %d\n", i);
    }
  }

  llprintf("TOTAL USED %d MB\n", (int)(total_used/1000000));
  llprintf("\n");
}

