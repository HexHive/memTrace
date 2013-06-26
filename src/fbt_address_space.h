/**
 * @file fbt_address_space.h
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

/*
 * This module controls the address space of the guest program.
 * It keeps track of the mapped files, of mmap allocations the 'brk'
 * memory region. Etc.
 * Since it knows the whole address space it can print it for debug purposes.
 */

#ifndef FBT_ADDRESS_SPACE_H_
#define FBT_ADDRESS_SPACE_H_

#include "fbt_datatypes.h"

#define UPPERMOST 0x100000000

#define STACK_TOP                (UPPERMOST-0x1000)
#define STACK_SIZE               0x1ffff000
#define STACK_BOTTOM             (STACK_TOP-STACK_SIZE)

#define FAKE_BRK_TOP             (STACK_BOTTOM-0x1000)
#define FAKE_BRK_SIZE            0x2ffff000
#define FAKE_BRK_BOTTOM          (FAKE_BRK_TOP-FAKE_BRK_SIZE)

#define SIGNAL_STACK_AREA_TOP    (FAKE_BRK_BOTTOM-0x1000)
#define SIGNAL_STACK_AREA_SIZE   0xfff000
#define SIGNAL_STACK_AREA_BOTTOM (SIGNAL_STACK_AREA_TOP-SIGNAL_STACK_AREA_SIZE)

#define SIGHANDWRAPPER_TOP       (SIGNAL_STACK_AREA_BOTTOM-0x1000)
#define SIGHANDWRAPPER_SIZE      0x10000
#define SIGHANDWRAPPER_BOTTOM    (SIGHANDWRAPPER_TOP-SIGHANDWRAPPER_SIZE)

#define LOWEST_AUTO_MMAP_ADDR   (LOADER_BASE_ADDRESS+0x100000)
#define LOADER_BASE_ADDRESS     0x050000




/** see .c file for comments on these functions */

void init_address_space(struct thread_local_data* tld);

guestptr_t do_guest_mmap(struct thread_local_data* tld,
                         guestptr_t addr,
                         uint32_t length,
                         int32_t prot,
                         int32_t flags,
                         int32_t fd,
                         uint32_t off,
                         char* description);

int32_t do_guest_munmap(struct thread_local_data* tld,
                        guestptr_t addr,
                        uint32_t length);

guestptr_t do_guest_mremap(struct thread_local_data* tld,
                           guestptr_t oldaddr,
                           uint32_t oldsiz,
                           uint32_t newsiz,
                           int32_t mremap_flags,
                           int32_t optional_new_address);

guestptr_t reserve_address_chunk(
    struct thread_local_data* tld,
    guestptr_t addr,
    uint32_t length);

#define HOST_PAGESIZE 4096
#define GUEST_PAGESIZE 4096
#define GUEST_UPPERMOST_MMAPPABLE_ADDRESS 0xa0000000

static inline guestptr_t round_down_to_guest_pagesize(guestptr_t p)
{
  return (p/GUEST_PAGESIZE)*GUEST_PAGESIZE;
}

static inline guestptr_t round_up_to_guest_pagesize(guestptr_t p)
{
  return ((p+GUEST_PAGESIZE-1)/GUEST_PAGESIZE)*GUEST_PAGESIZE;
}

static inline uint64_t round_up_to_pagesize(uint64_t p)
{
  return ((p+HOST_PAGESIZE-1)/HOST_PAGESIZE)*HOST_PAGESIZE;
}

void write_ps_address_space();

#endif /* FBT_ADDRESS_SPACE_H_ */
