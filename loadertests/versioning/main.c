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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>


#include "lib1.h"

/* This checks if relocation resolving of right symbol version works*/
extern int global_old;
extern int global;
extern int global1;

extern int method_old(int);
extern int method(int, int);
extern int method1(int, int);

asm(".symver global_old, global1@VERS_1.0");
asm(".symver global, global1@VERS_2.0");

/* This checks if runtime resolving of right symbol version works */
asm(".symver method_old, method1@VERS_1.0");
asm(".symver method, method1@VERS_2.0");

int main(int argc, char **argv, char **envp) {

  void *handle;
  char *(*fh)(int, int);
  char *error;
  
  handle = dlopen ("", RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror();

  /* Lookup undefined symbol */
  fh = dlsym(handle, "method1");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }
  
  if (global_old == 1
      && global == 2
      && global1 == 3
      && method_old(1) == 1
      && method(1,2) == 2
      /* Default versions */
      && method1(1,2) == 3
      && (long)fh(0,0) == 3) {
    printf("\nTest \"versioning\" successful.\n\n");
  } else {
    printf("\nTest \"versioning\" failed.\n\n");
  }
  
  return 0;
}




