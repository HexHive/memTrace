/**
 * @file fbt_code_cache.c
 * Implementation of methods needed to handle the code cache.
 * The code cache stores translated program code and uses the mapping table
 * to map between untranslated and translated code.
 *
 * Copyright (c) 2012 ETH Zurich
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

#include "fbt_code_cache.h"

#include "fbt_asm_macros.h"
#include "fbt_datatypes.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_mem_mgmt.h"
#include "fbt_syscall.h"
#include "fbt_trampoline.h"
#include "fbt_shared_data.h"

void *fbt_ccache_find(struct thread_local_data *tld, guestptr_t orig_address)
{
  PRINT_DEBUG_FUNCTION_START("fbt_ccache_find(*tld=%p, *orig_address=%p)",
      tld, orig_address);

  assert(tld != NULL);

  /* calculate offset into hashtable (this instruction is our hash function) */
  uint32_t offset = C_MAPPING_FUNCTION(orig_address);
  uint32_t pos = 0;
  struct ccache_entry *entry = tld->mappingtable + offset;

  /* check entry if src address equals orig_address */
  while (entry->src != 0) {
    if (orig_address == entry->src) {
      /* return corresponding dest address */
      PRINT_DEBUG_FUNCTION_END("-> %p", entry->dst);
      assert(entry->dst != NULL);
      if (pos!=0) {
        /* not optimal entry! swap suboptimal entry! */
        guestptr_t tmpguest;
        void* tmphost;
        struct ccache_entry *firstentry = tld->mappingtable +
            C_MAPPING_FUNCTION((uint32_t)orig_address);
        tmpguest = firstentry->src;
        firstentry->src = entry->src;
        entry->src = tmpguest;
        tmphost = firstentry->dst;
        firstentry->dst = entry->dst;
        entry->dst = tmphost;
        entry = firstentry;
      }
      return entry->dst;
    }
    /* We mustn't access memory beyond the hashtable!!
     * Bitwise AND with (HASHTABLE_SIZE - 1) is the same as
     * modulo HASHTABLE_SIZE. */
    offset = (offset + sizeof(struct ccache_entry)) & (MAPPINGTABLE_SIZE-1);
    pos++;
    entry = tld->mappingtable + offset;
  }

  PRINT_DEBUG_FUNCTION_END("-> %p", NULL);
  return NULL;
}

void fbt_ccache_add_entry(struct thread_local_data *tld,
    guestptr_t orig_address,
    void *transl_address)
{
  PRINT_DEBUG_FUNCTION_START("fbt_ccache_add_entry(*tld=%p, *orig_address=%p, "
      "*transl_address=%p)", tld, orig_address,
      transl_address);
  /* calculate offset into hashtable that corresponds to this orig_address*/
  uint64_t offset = C_MAPPING_FUNCTION((guestptr_t) orig_address);
  struct ccache_entry *entry = tld->mappingtable + offset;

  int count = 0;

  /* search the hastable for a free position, beginning at offset */
  while (entry->src != 0) {
    offset = (offset + sizeof(struct ccache_entry)) & (MAPPINGTABLE_SIZE - 1);
    entry = tld->mappingtable + offset;
    count++;
    if (count>=MAPPINGTABLE_MAXENTRIES/10) {
      fbt_suicide_str("ERROR: mappingtable out of space (fbt_code_cache.c)\n");
    }
  }

  /* insert entry into hashtable */
  entry->src = orig_address;
  entry->dst = transl_address;
  PRINT_DEBUG_FUNCTION_END(" ");
}

guestptr_t fbt_ccache_find_reverse(struct thread_local_data *tld,
    void *transl_address)
{
  PRINT_DEBUG_FUNCTION_START("fbt_ccache_find_reverse(*tld=%p,"
      " *transl_address=%p)", tld, transl_address);
  struct ccache_entry *entry = tld->mappingtable;
  struct ccache_entry *end = tld->mappingtable + MAPPINGTABLE_SIZE;
  /* search the hastable for a free position, beginning at offset */
  while (entry < end) {
    if (entry->dst == transl_address) {
      PRINT_DEBUG_FUNCTION_END("-> %p", entry->src);
      return entry->src;
    }
    entry++;
  }
  PRINT_DEBUG_FUNCTION_END("-> %p", NULL);
  return 0;
}

struct trampoline *fbt_create_trampoline(
    struct thread_local_data *tld,
    guestptr_t call_target,
    void *origin,
    enum origin_type origin_t,
    BOOL lock)
{
  if (tld->trampos == NULL) {
    fbt_allocate_new_trampolines(tld, lock);
  }

  struct trampoline *trampo = tld->trampos;

  tld->trampos = tld->trampos->next;

  trampo->target = call_target;
  trampo->origin = origin;
  trampo->origin_t = origin_t;

  unsigned char *code = (unsigned char*)&(trampo->code);

  int64_t o = (int64_t)code - (int64_t)tld->stack;
  int64_t poso;
  if (o < 0)
    poso = -o;
  else
    poso = o;
  BOOL need_long_version = FALSE;
  if (poso > 0x7fffff00) { /* a little safety margin */
    PRINT_DEBUG("too far away!\n");
    PRINT_DEBUG("t = ");
    PRINT_DEBUG64(trampo);
    PRINT_DEBUG("s = ");
    PRINT_DEBUG64(tld->stack);

    fllprintf(2,"t = ");
    print64(2,(uint64_t)trampo);
    fllprintf(2,"s = ");
    print64(2,(uint64_t)tld->stack);

    llprintf("Total internal allocated data till now: ");
    print64(2, shared_data.total_internal_allocated_data);
    llprintf("\n");
    fbt_suicide_str("Signed offset not encodable in 32 bits (stack too far away)!\n");
    need_long_version = TRUE;
  }

  /* write code to trampoline */
  /*
   Basically we want:
     mov %rsp, secure_stack_top (here we have a problem if the secure stack is too far away)
     mov secure_stack_top, %rsp
     call unmanaged_code_trampoline (here we have a problem if the trampoline is too far away)
   */

#ifdef DEBUG
  uint64_t oldcode = (uint64_t)code;
#endif
  if (need_long_version){
    fbt_suicide_str("lmem: long version not implemented yet");
  } else {
    // switching to secure stack
    PCREL_MOV_RSP_MEM32(code, (uint64_t)(tld->stack-1));  /* 7 bytes long */
    MOV_IMM64_RSP(code, (uint64_t)(tld->stack-1));  /* 9 bytes long */
    // and calling our assembly coded function
    CALL_REL32(code, (uint64_t)tld->unmanaged_code_trampoline); /* 5 bytes long */
  }
#ifdef DEBUG
  uint64_t bytesused = (uint64_t)code-oldcode;
  if (bytesused < 10){
    fbt_suicide_str("lmem: impossible so little bytes!\n");
  }
  if (bytesused > sizeof(trampo->code)){
    fbt_suicide_str("lmem: trampoline overflowed (too man bytes used)!\n");
  }
#endif

  return trampo;
}
