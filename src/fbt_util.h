/**
 * @file fbt_util.h
 * Defines some macros that are useful throughout.
 *
 * Copyright (c) 2011 ETH Zurich
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

#ifndef FBT_UTIL_H

#include "fbt_llio.h"
#include "fbt_debug.h"

/**
 * Breaks if in a debugger, otherwise just kill the program.
 * @param exitnr is ignored
 */
#define fbt_suicide(exitnr) __asm__ volatile("hlt")

/**
 * Prints a message and kill the program
 * @param str the message to be printed
 */
#define fbt_suicide_str(str)	do {		\
    fllwrite(2, str);		\
    fbt_suicide(255); } while (0)

#ifdef NDEBUG
#define assert(x)
#else
#define assert(x) \
  if (!(x)){\
    PRINT_DEBUG("assertion failure"); \
    fbt_suicide_str("assertion failure");\
  } /* useful to break when in a debugger */
#endif

#endif
