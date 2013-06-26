/**
 * @file fbt_libc.h
 * This file contains reimplementations of some library functions
 * to remove dependencies on these libs.
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
#ifndef FBT_LIBC_H
#define FBT_LIBC_H

#include "fbt_syscalls_64.h"

/** definition of NULL */
#if !defined(NULL)
#define NULL ((void *)0)
#endif

/**
 * Local implementation of memcpy. Copies one memory region to another address.
 * @param dest Destination memory region
 * @param src Source region
 * @param n number of bytes that are copied
 * @return Pointer to the target region.
 */
void *fbt_memcpy(void *dest, const void *src, int n);

/**
 * Local implementation of memcmp. Compares two memory regions.
 * @param s1 First region.
 * @param s2 Second region.
 * @param n Length that is compared.
 * @return Returns 0 if they are equal.
 */
int fbt_memncmp(const char *s1, const char *s2, int n);

/**
 * Local implementation of strncpy. Copies one string into another buffer.
 * @param dest Destination memory region.
 * @param src Source region.
 * @param n Max. number of copied characters.
 * @return Pointer to the copied string.
 */
char *fbt_strncpy(char *dest, const char *src, int n);

/**
 * Local implementation of strnlen. Calculates the length of a string.
 * @param s Source string
 * @param maxlen Maximum length
 * @return Length of the string or maxlen.
 */
int fbt_strnlen(const char *s, int maxlen);

/** a bit simpler than fbt_strnlen */
int fbt_strlen(const char *s);

/**
 * Local implementation of strncmp. Compares two strings.
 * @param s1 First string.
 * @param s2 Second string.
 * @param n Maximum length that is compared.
 * @return Returns 0 if they are equal.
 */
int fbt_strncmp(const char *s1, const char *s2, int n);

/**
 * Convert integer to string
 * @param value to convert.
 * @param str array where to store string.
 * @param base numerical base.
 * @return same as str.
 */
char *fbt_itoa(int value, char* str, int base);

/**
 * Fill the first 'len' bytes of the memory area pointed to by 'dest' with the
 * constant byte 'val'
 * 
 * @param dest Pointer to start of memory area to fill
 * @param val  Byte to fill with
 * @param len  Length of area in bytes
 * */
void *fbt_memset(void *dest, long val, long len);

#endif  /* FBT_LIBC_H */
