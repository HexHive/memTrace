/**
 * @file fbt_libc.c
 * This file contains reimplementations of some library functions
 * to remove dependencies on these libs.
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

#include "fbt_libc.h"

#include "fbt_llio.h"

/* functions from string.h */
void *fbt_memcpy(void *dest, const void *src, int n)
{
  char *target = (char*)dest;
  char *source = (char*)src;
  for (int i=0; i<n; i++) {
    target[i]=source[i];
  }
  return (void*)dest;
}

int fbt_memncmp(const char *s1, const char *s2, int n)
{
  for (int i = 0; i < n; ++i) {
    if (s1[i] != s2[i]) return s1[i] < s2[i] ? -1 : 1;
  }
  return 0;
}

char *fbt_strncpy(char *dest, const char *src, int n)
{
  int i;
  for (i=0; i<n && src[i]!='\0'; i++)
    dest[i]=src[i];
  dest[i] = '\0';
  return dest;
}

int fbt_strnlen(const char *s, int maxlen) {
  int i=0;
  if (maxlen!=0) while (s[i]!=0x0 && i<maxlen) i++;
  else while (s[i]!=0x0) i++;
  return i;
}

int fbt_strlen(const char *s) {
  int i=0;
  while (s[i]!=0x0) i++;
  return i;
}

int fbt_strncmp(const char *s1, const char *s2, int n) {
  for (; *s1 == *s2; ++s1, ++s2, --n)
    if (*s1 == 0 || n==0)
      return 0;
  return *(unsigned char *)s1 < *(unsigned char *)s2 ? -1 : 1;
}

char *fbt_itoa(int value, char* str, int base) {
  unsigned int i = 0;
  do {
    str[i] = (char)(value % base + '0');
    value /= base;
    i++;
  } while(value != 0);
  str[i] = '\0';

  /* reverse string */
  unsigned int j = 0;
  i--;
  while(i != j && i+1 != j) {
    char c = str[j];
    str[j] = str[i];
    str[i] = c;
    j++;
    i--;
  }

  return str;
}

void *fbt_memset(void *dest, long val, long len) {
  register char *ptr = (char *)dest;
  while (len-- > 0) {
    *ptr++ = val;
  }
  return dest;
}
