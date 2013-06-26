/**
 * @file main.c
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Tobias Hartmann <tobi.hartmann@gmail.com>
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * $Date: 2011-12-30 14:24:05 +0100 (Fri, 30 Dec 2011) $
 * $LastChangedDate: 2011-12-30 14:24:05 +0100 (Fri, 30 Dec 2011) $
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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

main(int argc, char **argv, char **envp) {
  
  /* This tests the support for symbols of type STT_GNU_IFUNC  */ 
  char string[]="abc";
  size_t len = strlen(string);

  /*
  char *path = getenv("_");
  printf("path: %s \n", path);

  char *buf = malloc(256);
  readlink("/proc/self/exe", buf, 256);
  printf("path: %s \n", buf);

  char *buf2 = malloc(256);
  getcwd(buf2, 256);
  printf("cwd: %s \n", buf2);

  printf("argv: %s\n", argv[0]);
  */
  
  if (len == 3) {
    printf("\nTest \"libc_basic\" successful.\n\n");
    return 0;
  } else {
    printf("\nError: test \"libc_basic\" failed %d.\n\n", len);
    return 1;
  }
}


