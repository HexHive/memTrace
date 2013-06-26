/**
 * @file fbt_config.h
 * Contains some configuration options
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

#ifndef FBT_CONFIG_H_
#define FBT_CONFIG_H_

/**
 * The offset at which shadow allocations are done.
 */
#define LMEM_SHIFT_OFFSET    0x100000000

/**
 * If defined provides a way for the application itself to
 * set and remove watchpoints. Keep in synch with assembly code
 * if there is ever a need to change this.
 */
#define LMEM_WATCHPOINT_SYSCALL_NR 500

/**
 *
 */
#define LMEM_SPECIAL_SIGRET_SYSCALL_NR 501


/**
 * Just static asserts
 */
#ifndef CONFIG_NAME
//#error "No configuration specified in Makedefs!!"
#endif

#ifdef ENABLE_MEMCHECKS
#ifndef SHADOW_ALLOCATIONS
#error "ENABLE_MEMCHECKS requires SHADOW_ALLOCATIONS"
#endif
#ifndef ENABLE_EFLAGS_SAVEREST
#error "ENABLE_MEMCHECKS requires ENABLE_EFLAGS_SAVEREST"
#endif
#ifndef ENABLE_MEMACCESSES
#error "ENABLE_MEMCHECKS requires ENABLE_MEMACCESSES"
#endif
#endif

#ifdef ENABLE_MEMACCESSES
#ifndef SHADOW_ALLOCATIONS
#error "SHADOW_ALLOCATIONS requires SHADOW_ALLOCATIONS"
#endif
#ifndef ENABLE_EFLAGS_SAVEREST
#error "SHADOW_ALLOCATIONS requires ENABLE_EFLAGS_SAVEREST"
#endif
#endif


#endif /* FBT_CONFIG_H_ */
