/**
 * @file fbt_lmem_api.h
 * Datatypes used for communication with selDebug
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedDate: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1184 $
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

#ifndef FBT_LMEM_API_H_
#define FBT_LMEM_API_H_

/*
 * This file is meant to be included by applications wanting to explicitly
 * set breakpoints. It is also used by our malloc wrapper.
 */

#ifdef __x86_64__

#error "lmem_api only available in 32 bit!"

#else

void lmem_protect(void* addr){
  asm ("push %%eax;"
       "push %%ebx;"
       "movl $500, %%eax;"  // special 'sdbg syscall' has number 500
       "movl $0, %%ebx;"    // 0 means protect, 1 means unprotect
       "int $0x80;"
       "pop %%ebx;"
       "pop %%eax;"
       : /* no result */
       : "c" (addr) /* put currmem in ecx (second parameter of syscall) */);
}

void lmem_unprotect(void* addr){
  asm ("push %%eax;"
       "push %%ebx;"
       "movl $500, %%eax;"  // special 'sdbg syscall' has number 500
       "movl $1, %%ebx;"    // 0 means protect, 1 means unprotect
       "int $0x80;"
       "pop %%ebx;"
       "pop %%eax;"
       : /* no result */
       : "c" (addr) /* put currmem in ecx (second parameter of syscall) */);
}

#endif

#endif /* FBT_LMEM_API_H_ */

