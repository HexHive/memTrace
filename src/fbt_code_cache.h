/**
 * @file fbt_code_cache.h
 * Methods needed to handle the code cache.
 * The code cache stores translated program code and uses the mapping table
 * to map between untranslated and translated code.
 *
 * Copyright (c) 2011 ETH Zurich
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
#ifndef FBT_CODE_CACHE_H
#define FBT_CODE_CACHE_H

#include "fbt_datatypes.h"

/* forward declare structs */
struct thread_local_data;
enum origin_type;

/** mappingtable size: we use 20bit out of the 32bit of an address to perform a
   lookup in the hashtable. 2^20 * 16 bytes (enough space for a 32bit original
   address and one 64 bit translated address) Has to be a power of 2.  */
#define MAPPINGTABLE_NRBITS  23 /*23*/
#define MAPPINGTABLE_SIZE (0x1<<MAPPINGTABLE_NRBITS)
#define MAPPINGTABLE_MAXENTRIES (MAPPINGTABLE_SIZE>>4)
/**< (i % MAPPINGTABLE_SIZE) should be the same as (i & (HASHTABLE_SIZE - 1)),
     and the compiler is good at precomputing constant expressions such as
     (HASHTABLE_SIZE - 1) */

/** We take bits with exponents 2 to 21 (inclusive) of the source address to
    determine the position in the hash table. Because an entry in the table is 8
    bytes long, we can only address locations in the table with 8 bytes
    granularity. To achieve that, the address is shifted one bit to the left and
    ANDed with this pattern. This gives us the offset into the table.  WARNING:
    code in fbt_asm_function.S depends on the layout of this definition!
 */
#define MAPPING_PATTERN ((MAPPINGTABLE_SIZE-1)^0x7)

/** Implementation of the hash mapping function as C code. The assembly code
      must follow this hash function! */
#define C_MAPPING_FUNCTION(addr)  ((addr<<4) & MAPPING_PATTERN)

/**
 * Checks the mappingtable and checks if there is an entry for orig_address.
 * @param tld pointer to thread local data
 * @param orig_address address in the original program
 * @return pointer to the translated code (or NULL)
 */
void *fbt_ccache_find(struct thread_local_data *tld, guestptr_t orig_address);

/**
 * Adds an entry into the mapping table from orig_address to transl_address.
 * @param tld pointer to thread local data
 * @param orig_address address in the original program
 * @param transl_address pointer to the translated code fragment
 */
void fbt_ccache_add_entry(struct thread_local_data *tld,
    guestptr_t orig_address,
    void *transl_address);

/**
 * Flushes the code cache
 * @param tld pointer to thread local data
 */
void fbt_ccache_flush(struct thread_local_data *tld);

/**
 * Scans the mappingtable and checks if there is an entry with transl_address.
 * @param tld pointer to thread local data
 * @param transl_address address in the translated program
 * @return pointer to the original code (or NULL)
 */
guestptr_t fbt_ccache_find_reverse(struct thread_local_data *tld,
    void *transl_address);

/**
 * Creates and returns a new trampoline.
 * If there are no more trampolines available in the TLD then we allocate a
 * whole bunch of new trampolines.
 * @param tld thread local data
 * @param call_target IP in the untranslated code
 * @param origin pointer to the address in the generated code that points to
 * the generated trampoline
 * @param origin_type addressing type of the origin
 * @return pointer to the trampoline
 */
struct trampoline *fbt_create_trampoline(struct thread_local_data *tld,
    guestptr_t call_target,
    void *origin,
    enum origin_type origin_type,
    BOOL lock);

#endif  /* FBT_CODE_CACHE_H */
