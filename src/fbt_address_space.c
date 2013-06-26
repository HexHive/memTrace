/**
 * @file fbt_address_space.c
 * Datatypes used in the BT
 *
 * Copyright (c) 2011 ETH Zurich
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

#include "fbt_address_space.h"

#include "fbt_syscalls_64.h"  // fbt_mmap
#include "fbt_llio.h"
#include "fbt_libc.h"
#include "fbt_translate.h"
#include "fbt_shared_data.h"
#include "fbt_debug.h"

// for the mmap constants
#include <unistd.h>
#include <asm-generic/mman-common.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <sys/stat.h>
#include <stdarg.h>

#define O_CREAT  00000100
#define O_WRONLY 00000001
#define O_TRUNC  00001000

/*
 This file has all the mmap brk munmap mremap logic of the translated program.
 We explicitly keep track of what is allocated and what not.
 */


static BOOL overlap(uint64_t abeg, uint64_t aend,
                     uint64_t bbeg, uint64_t bend)
{
  if (abeg > bbeg && abeg < bend){ return TRUE; }
  if (aend > bbeg && aend < bend){ return TRUE; }
  if (bbeg > abeg && bbeg < aend){ return TRUE; }
  if (bend > abeg && bend < aend){ return TRUE; }
  return FALSE;
}

/** debugging function */
static void print_address_space(BOOL lock)
{
  if (lock){
    fbt_mutex_lock(&shared_data_mutex);
  }

  struct address_space* as = &shared_data.address_space;

#ifdef DEBUG
  uint32_t total_used = 0;
  PRINT_DEBUG_ADDRESS_SPACE("THE %d ENTRIES:", as->num_entries);
  for (int i=0; i<as->num_entries; i++){
 /*   if (i%8 == 0){
      PRINT_DEBUG_ADDRESS_SPACE("\n");
    }
    PRINT_DEBUG_ADDRESS_SPACE(" (%x,%x)",
        as->entries[i].begin,
        as->entries[i].begin+as->entries[i].size); */
    total_used += as->entries[i].size;
  }

#endif


  for (int i=1; i<as->num_entries; i++){
    if (as->entries[i-1].begin > as->entries[i].begin){
      fbt_suicide_str("address space not sorted\n");
    }
  }

#ifdef DEBUG
  for (int i=1; i<as->num_entries; i++){
    if (as->entries[i-1].begin + as->entries[i-1].size > as->entries[i].begin){
      PRINT_DEBUG_ADDRESS_SPACE("address space overlaps at %d\n", i);
    }
  }
#endif

  PRINT_DEBUG_ADDRESS_SPACE("TOTAL USED %d MB\n", (int)(total_used/1000000));
  PRINT_DEBUG_ADDRESS_SPACE("\n");

  if (lock){
    fbt_mutex_unlock(&shared_data_mutex);
  }
}

/**
 * Mark region as allocated in our explicit representation 
 * of the address space.
 */
static void mark_as_allocated(struct address_space* as, 
                                  guestptr_t where,
                                  uint32_t size,
                                  enum address_space_entry_type memtype,
                                  char* desc)
{
  PRINT_DEBUG_ADDRESS_SPACE("Marking %x as allocated\n", where);
  if (as->num_entries < MAX_ADDRESS_SPACE_ENTRIES){

    // Find out where to insert
    int insertat = as->num_entries; // for the case no hit in for loop
    for (int i=0; i<as->num_entries; i++){
      if (as->entries[i].begin > where){
        insertat = i;
        break;
      }
    }

    // Shift a whole bunch to the right
    for (int i=as->num_entries; i>insertat; i--){
      as->entries[i] = as->entries[i-1];
    }
    // And finally place our element (this keeps them sorted)
    struct address_space_entry ase = {memtype, where, size, desc};
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
static void mark_range_as_deallocated(
    struct address_space* as,
    guestptr_t where,
    uint32_t len)
{
  PRINT_DEBUG_ADDRESS_SPACE("Marking range %x of len %x as deallocated\n", where, len);

  // Remove elements that are totally in the unmapped region
  while (1){

    // Find element to delete
    int todel = -1;
    for (int i=0; i<as->num_entries; i++){
      if (as->entries[i].begin >= where &&
          (as->entries[i].begin + as->entries[i].size)  <= (where+len)){
        todel = i;
        break;
      }
    }

    // If there is none we are done
    if (todel == -1){
      break;
    }

    if (todel != (-1)){
      // Shift whole block to the left (to keep sorted)
      for (int i=todel; i<as->num_entries-1; i++){
        as->entries[i] = as->entries[i+1];
      }
    }

    as->num_entries--;
  }

  // Shrink elements that are only partially deallocated
  guestptr_t debeg = where;
  guestptr_t deend = where + len;

  for (int i=0; i<as->num_entries; i++){
    if (overlap(debeg, deend, as->entries[i].begin, as->entries[i].begin + as->entries[i].size)){
      //llprintf("bef  to dealloc: (%x, %x) ... toshrink: (%x, %x)\n",
      //         debeg, deend, as->entries[i].begin, as->entries[i].begin + as->entries[i].size);
      BOOL beginside = FALSE;
      BOOL endinside = FALSE;
      if (as->entries[i].begin >= debeg &&
          as->entries[i].begin <= deend){
        beginside = TRUE;
      }
      if ((as->entries[i].begin + as->entries[i].size) >= debeg &&
          (as->entries[i].begin + as->entries[i].size) <= deend){
        endinside = TRUE;
      }
      if (beginside && endinside){
        fbt_suicide_str("lmem fail: this region should have been already removed completely\n");
      }

      if (beginside || endinside){
        // one-sided shrinking

        guestptr_t newbeg =as->entries[i].begin;
        guestptr_t newend =as->entries[i].begin + as->entries[i].size;

        if (beginside) {
          newbeg = deend;
        } else if (endinside) {
          newend = debeg;
        } else {
          fbt_suicide_str("lmem logic error 834\n");
        }
        as->entries[i].begin = newbeg;
        as->entries[i].size = newend - newbeg;

        //llprintf("aft  to dealloc: (%x, %x) ... toshrink: (%x, %x)\n",
        //         debeg, deend, as->entries[i].begin, as->entries[i].begin + as->entries[i].size);
      } else {
        // A hole... must create new region
        fbt_suicide_str("to implement (creates a hole...)\n");
      }
    }
  }
}

void write_ps_address_space()
{
  unsigned bottom = 50;
  unsigned scale = (unsigned)((uint64_t)0x100000000/(uint64_t)700);
  unsigned off = 100;
  struct address_space* as = &shared_data.address_space;
  int fl = fbt_open((uint64_t)"as.ps",
          O_CREAT | O_TRUNC | O_WRONLY,
          S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |  \
          S_IWOTH,
          "Could not open debug file (debug_start: fbt_debug.c).\n");
  if (!valid_result((int64_t)fl)){
    fbt_suicide_str("could not write ps file for address space\n");
  }
  fllprintf(fl, "\% open with gv or convert to pdf and open with evince\n");
  fllprintf(fl, "newpath\n");
  fllprintf(fl, "%d %d moveto\n", off, bottom);
  fllprintf(fl, "%d %d lineto\n", off, bottom + 0x100000000/scale);
  fllprintf(fl, "stroke\n");

  fllprintf(fl, "/Times-Roman findfont\n");
  fllprintf(fl, "12 scalefont\n");
  fllprintf(fl, "setfont\n");

  for (int i=0; i<as->num_entries; i++){
    int o = (i%10)*3;
    unsigned s = (uint64_t)as->entries[i].begin/scale;
    unsigned e = (uint64_t)(as->entries[i].begin+as->entries[i].size)/scale;
    fllprintf(fl, "newpath\n");
    fllprintf(fl, "%d %d moveto\n", off+o, bottom + s);
    fllprintf(fl, "%d %d lineto\n", off+o, bottom + e);
    fllprintf(fl, "stroke\n");
    if (as->entries[i].size > 0x1000000){
      fllprintf(fl, "newpath\n");
      fllprintf(fl, "%d %d moveto\n", off+o, bottom + (s+e)/2);
      fllprintf(fl, "(%s from %x to %x) show\n",
          as->entries[i].description,
          as->entries[i].begin,
          as->entries[i].begin+as->entries[i].size);
    }
  }
}

/**
 * Searches for a place where size bytes are free in our explicit
 * rep. of the address space.
 */
static guestptr_t find_free_address(struct address_space* as, uint32_t size)
{
  PRINT_DEBUG_ADDRESS_SPACE("Searching for %x free bytes\n", size);

#if 0
  // The lowest address we are allowed to use
  guestptr_t candidate = LOWEST_AUTO_MMAP_ADDR;
  uint32_t roundsize = round_up_to_guest_pagesize(size);
  for (int i=0; i<as->num_entries; i++){
    if (as->entries[i].begin > candidate){
      uint32_t space = as->entries[i].begin - candidate;
      if (space >= roundsize){
        if (candidate < LOWEST_AUTO_MMAP_ADDR) fbt_suicide_str("ainthappenin\n");
        // Ok, there is enough space
        return candidate;
      }
    }
    guestptr_t npc =
        round_up_to_guest_pagesize(as->entries[i].begin+as->entries[i].size) +
        1*GUEST_PAGESIZE; // Leave some space in between (could be removed)
    if (npc > candidate){
      candidate = npc;
    }
  }
  if (GUEST_UPPERMOST_MMAPPABLE_ADDRESS > candidate){
    uint32_t space = GUEST_UPPERMOST_MMAPPABLE_ADDRESS - candidate;
    if (space >= roundsize){
      // Ok, there is enough space
      return candidate;
    }
  }

#else

  /*
   * This strategy tries to map higher addresses first, so as to
   * leave space for the 'brk' to grow if necessary.
   */
  uint32_t roundsize = round_up_to_guest_pagesize(size);
  PRINT_DEBUG("SYS: roundsize = %x\n", roundsize);
  for (int i=as->num_entries-1; i>=0; i--){
    guestptr_t lower_limit;
    if (i>0){
      //lower_limit = as->entries[i-1].begin + as->entries[i-1].size;
      lower_limit = round_up_to_guest_pagesize(as->entries[i-1].begin + as->entries[i-1].size);
    } else {
      lower_limit = LOWEST_AUTO_MMAP_ADDR;
    }
    uint32_t beg = round_down_to_guest_pagesize(as->entries[i].begin);
    if (lower_limit < beg){
      uint32_t freespace = beg - lower_limit;
      if (roundsize < freespace){
        uint32_t res = beg - roundsize;
#ifdef DEBUG
        if (res != round_up_to_guest_pagesize(res)){
          fbt_suicide_str("find free addr must return round address\n");
        }
#endif
#ifdef DEBUG
        for (int k=0; k<as->num_entries; k++){
          if (overlap(res, res+roundsize,
                      as->entries[i].begin, as->entries[i].begin+as->entries[i].size)){
            fbt_suicide_str("Bug in xx\n");
          } 
        }
#endif
        return res;
      }
    }
  }


  /*
   * If we got here, we could try to shrink the 'brk'
   */

#endif
  PRINT_DEBUG_ADDRESS_SPACE("failed to find a free address\n\n");

  fllwrite(2, "could not find enough free address space, writing postscript\n");
  print_address_space(FALSE);

  PRINT_DEBUG_ADDRESS_SPACE("BEGIN POSTSCRIPT VISUALIZATION TO FILE\n\n");
  write_ps_address_space();
  PRINT_DEBUG_ADDRESS_SPACE("END POSTSCRIPT VISUALIZATION\n\n");

  fbt_suicide_str("Impossible to find a free address!\n");

  return (-1); // shut up gcc
}

/**
 * Performs a shadow allocation
 */
void shadow_alloc(guestptr_t orig_addr, uint32_t length){
  // Do the shadow allocation
  void* shad_wanted = (void*)(orig_addr + 0x100000000);
  void* shad_got = (void*)fbt_syscall6(
      SYS64_mmap, (uint64_t)shad_wanted, length,
      PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
      -1, 0);

  if (shad_got != shad_wanted){
    fbt_suicide_str("did not get the wanted shadow address\n");
  }
}

/**
 * One can use different strategies here. For now we use the strategy
 * that shadow memory is never freed in order to detect dangling pointer
 * accesses and the like. An improvement might be to fill it with ones.
 */
void shadow_dealloc(guestptr_t orig_addr, uint32_t length)
{
}

/** when mmap is intercepted, this is called */
guestptr_t reserve_address_chunk(
    struct thread_local_data* tld,
    guestptr_t addr,
    uint32_t length)
{
  PRINT_DEBUG_ADDRESS_SPACE("reserving chunk at %x of length %x\n", addr, length);

  fbt_mutex_lock(&shared_data_mutex);

  guestptr_t res = -1;
  if (addr == 0){

    // Find where to allocate
    guestptr_t free_addr = find_free_address(&shared_data.address_space, length);
    PRINT_DEBUG_ADDRESS_SPACE("found free address at %x\n", free_addr);

    mark_as_allocated(&shared_data.address_space, free_addr, length, ASET_FREE, "for shared memory");

    res = free_addr;
  } else {
    PRINT_DEBUG_ADDRESS_SPACE("reserve_address_chunk does not support fixed addresses");
    fbt_suicide_str("reserve_address_chunk does not support fixed addresses");
  }

  fbt_mutex_unlock(&shared_data_mutex);
  return res;
}

/** when mmap is intercepted, this is called */
guestptr_t do_guest_mmap(
    struct thread_local_data* tld,
    guestptr_t addr,
    uint32_t length,
    int32_t prot,
    int32_t flags,
    int32_t fd,
    uint32_t off,
    char* description)
{
  PRINT_DEBUG_ADDRESS_SPACE("guest mmap %x %x\n", addr, length);

  fbt_mutex_lock(&shared_data_mutex);

  guestptr_t result = 0;

  if (addr == 0){

    // Find where to allocate
    guestptr_t free_addr = 
        find_free_address(&shared_data.address_space, length);

    PRINT_DEBUG_ADDRESS_SPACE("found free address at %x\n", free_addr);

    PRINT_DEBUG_ADDRESS_SPACE("performing real mmap %x %x %x %x %x %x\n", free_addr, length, prot, flags, fd, off);

    // Do the real allocation
    flags |= MAP_FIXED;
    void* rv = (void*)fbt_syscall6(SYS64_mmap, 
        (uint64_t)free_addr,
        length,
        prot,
        flags,
        fd,
        off);
    if ((int32_t)(int64_t)rv < 0 && (int32_t)(int64_t)rv > -128){
      PRINT_DEBUG_ADDRESS_SPACE("mmap failed with error code %d\n", -((int32_t)(int64_t)rv));
      fbt_suicide_str("mmap failed in fbt_address_space.c");
    }
    if (rv != (void*)(uint64_t)free_addr){
      PRINT_DEBUG_ADDRESS_SPACE("didnt get prec\n");
      fbt_suicide_str("did not get precisely the wanted address in "
          "do_guest_mmap() [1]!\n");
    }

#ifdef DEBUG
    if (!(flags & MAP_ANONYMOUS)){
      int k;
      for (k=0; k<length && k<20; k++){
        PRINT_DEBUG_ADDRESS_SPACE("SYS... %x\n", (uint32_t)(*(unsigned char*)rv+k));
      }
    }
#endif

    PRINT_DEBUG_ADDRESS_SPACE("do_guest_mmap(0x%x, %d, %d, 0x%x, %d, %d)\n",
        addr, length, prot, flags, fd, off);


    mark_as_allocated(&shared_data.address_space, free_addr, length, ASET_FREE, description);


    result = free_addr;

  } else {

    if ((uint64_t)addr > UINT32_MAX){
      PRINT_DEBUG_ADDRESS_SPACE("ADDR too big!!!\n");
      fbt_suicide_str("atobig!!!\n");
    }

    /* forbid overlapping mappings */
    for (int i=0; i<shared_data.address_space.num_entries; i++){
       if (overlap(shared_data.address_space.entries[i].begin,
                   shared_data.address_space.entries[i].begin+shared_data.address_space.entries[i].size,
                   addr,
                   addr+length)){
         PRINT_DEBUG_ADDRESS_SPACE("warning: guest mmap overlap detected %x %x, %x %x\n",
             shared_data.address_space.entries[i].begin,
                                shared_data.address_space.entries[i].begin+shared_data.address_space.entries[i].size,
                                addr,
                                addr+length);
         if (shared_data.address_space.entries[i].type == ASET_FREE){
           //fbt_suicide_str("overlaps with free addresses not tolerated\n");
         }
       }
     }


    PRINT_DEBUG_ADDRESS_SPACE("wanna map %x to %x\n", addr, addr+length);

    void* rv;
    rv = (void*)fbt_mmap((uint64_t)addr, 
        length,
        prot,
        flags | MAP_FIXED,
        fd,
        off,
        "FAILED TO MMAP REGION");

    if ((int32_t)(int64_t)rv < 0 && (int32_t)(int64_t)rv > -128){
      PRINT_DEBUG_ADDRESS_SPACE("mmap failed with error code %d!!\n", -((int32_t)(int64_t)rv));
      fbt_suicide_str("mmap failed in fbt_address_space.c!!");
    }
    if ((uint64_t)rv > UINT32_MAX){
      PRINT_DEBUG_ADDRESS_SPACE("too big\n");
      llprintf("rv: ");
      print64(2, (uint64_t)rv);
      llprintf("\n");
      fbt_suicide_str("tlobig!!!\n");
    }
    if (rv != (void*)(uint64_t)addr){
      PRINT_DEBUG_ADDRESS_SPACE("didnt get prec II (got %x instead of %x)\n", rv, addr);
      fbt_suicide_str("did not get precisely the wanted address in "
          "do_guest_mmap() [2]!!\n");
    }

    PRINT_DEBUG_ADDRESS_SPACE("result = %x\n", rv);

    mark_as_allocated(&shared_data.address_space, 
        (guestptr_t)(uint64_t)rv, length, ASET_FIXED, description);

    result = addr;
  }

#ifdef SHADOW_ALLOCATIONS
  shadow_alloc(result, length);
#endif

  // Debugging (optional)
  //print_address_space(tld);

  fbt_mutex_unlock(&shared_data_mutex);

  return result;
}

/** Allocates a fixed size brk. An improvement would be to 
    make it grow dynamically. */
static void create_fake_brk(struct thread_local_data* tld)
{

  guestptr_t where =
      do_guest_mmap(tld,
          FAKE_BRK_BOTTOM,
          FAKE_BRK_SIZE,
          PROT_READ|PROT_WRITE,
          MAP_PRIVATE|MAP_ANONYMOUS,
          -1,
          0,
          "fake brk");

  fbt_mutex_lock(&shared_data_mutex);

  shared_data.fake_brk_begin = where;
  shared_data.fake_brk_current_brk = where;
  shared_data.fake_brk_end = where+FAKE_BRK_SIZE;

  if (!(uint64_t)shared_data.fake_brk_end > shared_data.fake_brk_begin){
    fbt_suicide_str("Inconsistent fake brk\n");
  }

  fbt_mutex_unlock(&shared_data_mutex);

  PRINT_DEBUG_ADDRESS_SPACE("end %x, beg %x, diff %x\n",
              shared_data.fake_brk_end,
              shared_data.fake_brk_begin,
              (int)(shared_data.fake_brk_end - shared_data.fake_brk_begin));
}

/** when mremap is intercepted, this is called */
guestptr_t do_guest_mremap(struct thread_local_data* tld,
    guestptr_t oldaddr,
    uint32_t oldsiz,
    uint32_t newsiz,
    int32_t mremap_flags,
    int32_t optional_new_address)
{
  fbt_mutex_lock(&shared_data_mutex);

  if (!(mremap_flags & MREMAP_MAYMOVE)){
    fbt_suicide_str("mremap without 'may move' flag unsupported\n");
  }
  if (mremap_flags & MREMAP_FIXED){
    fbt_suicide_str("mremap with 'mremap fixed' flag unsupported (would "
        "need to use new address parameter)\n");
  }

  PRINT_DEBUG_ADDRESS_SPACE("guest mremap\n");

#ifdef SHADOW_ALLOCATIONS
  shadow_dealloc(oldaddr, oldsiz);
#endif

  guestptr_t free_addr = find_free_address(&shared_data.address_space, newsiz);

  void* rv = (void*)fbt_syscall6(SYS64_mmap, 
      (uint64_t)free_addr, newsiz,
      3 /*rw*/,
      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
      -1,
      0);
  if(rv != (void*)(uint64_t)free_addr){
    fbt_suicide_str("Did not get precisely the wanted address "
        "in realloc (fbt_address_space.c)\n");
  }
  guestptr_t result = (guestptr_t)(uint64_t)rv;

  int mn = oldsiz < newsiz ? oldsiz : newsiz;
  fbt_memcpy((void*)(uint64_t)free_addr, (void*)(uint64_t)oldaddr, mn);

  mark_as_allocated(&shared_data.address_space, result, newsiz, 0, "reallocated");

#ifdef SHADOW_ALLOCATIONS
  shadow_alloc(result, newsiz);
#endif

  mark_range_as_deallocated(&shared_data.address_space, oldaddr, oldsiz);

  //print_address_space(tld);
  fbt_mutex_unlock(&shared_data_mutex);

  return result;
}

/** when munmap is intercepted, this is called */
int32_t do_guest_munmap(struct thread_local_data* tld,
    guestptr_t addr,
    uint32_t length)
{
  fbt_mutex_lock(&shared_data_mutex);

  PRINT_DEBUG_ADDRESS_SPACE("guest munmap\n");

  PRINT_DEBUG_ADDRESS_SPACE("wanna unmap %x to %x\n", addr, addr+length);

  if (overlap(shared_data.fake_brk_begin, shared_data.fake_brk_end,
              addr, addr+length)){
    fbt_suicide_str("lmem: tried to unmap a part of the brk");
  }

  fbt_munmap((uint64_t)addr, length, "error in munmap");

  /*mark_range_as_deallocated(&shared_data.address_space, addr, length);

#ifdef DEBUG
  uint32_t dealbeg = addr;
  uint32_t dealend = addr+length;
  for (int i=0; i<shared_data.address_space.num_entries; i++){
    uint32_t bb = shared_data.address_space.entries[i].begin;
    uint32_t be = shared_data.address_space.entries[i].begin + shared_data.address_space.entries[i].size;
    if (overlap(dealbeg, dealend, bb, be)){
      llprintf("deall overlap.  to dealloc: (%x, %x) ... still there: (%x, %x)\n",
               dealbeg, dealend, bb, be);
      fbt_suicide_str("guest unmap did not do its job properly\n");
    }
  }
#endif
*/
  fbt_mutex_unlock(&shared_data_mutex);

  //print_address_space();
  return 0;
}


/** To be called at beginning of process (not thread) */
void init_address_space(struct thread_local_data* tld)
{
  fbt_mutex_lock(&shared_data_mutex);
  shared_data.address_space.num_entries = 0;
  fbt_mutex_unlock(&shared_data_mutex);

  create_fake_brk(tld);
}

