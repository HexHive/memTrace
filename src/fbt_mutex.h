/**
 * @file fbt_mutex.h
 *
 * Futex-based mutex data structure
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

#ifndef FBT_MUTEX_H
#define FBT_MUTEX_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int fbt_mutex_t;

#define FBT_MUTEX_INITIALIZER 0

int fbt_mutex_init(fbt_mutex_t *mutex);
int fbt_mutex_lock(fbt_mutex_t *mutex);
int fbt_mutex_trylock(fbt_mutex_t *mutex);
int fbt_mutex_unlock(fbt_mutex_t *mutex);
int fbt_mutex_cleanup(fbt_mutex_t *mutex);

#ifdef __cplusplus
}
#endif

#endif /* FBT_MUTEX_H */
