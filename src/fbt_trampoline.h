/**
 * @file fbt_trampoline.h
 * Handles the generation of thread local trampolines for secure
 * code transitions and control flow transfers
 *
 * Copyright (c) 2011 ETH Zurich
 *
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

#ifndef FBT_TRAMPOLINE_H
#define FBT_TRAMPOLINE_H

/* forward declare structs */
struct thread_local_data;

/**
 * Initializes all thread local trampolines that are used for control flow
 * transfers and transfers to secure code. Pointers inside tld are updated and
 * will point to newly generated code.
 * @param tld pointer to thread local data
 */
void fbt_initialize_trampolines(struct thread_local_data *tld);

#endif  /* FBT_TRAMPOLINE_H */

