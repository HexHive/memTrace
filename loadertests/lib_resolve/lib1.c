/**
 * @file lib1.c
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

int m_called = 0;
int global = 33;

void method() {
  m_called = 1;
}

char* test(char *lib_path) {
  void *handle;
  void *global_handle;
  char *(*fh)();
  char *error;

  char *lib2 = malloc(256);
  int len = strnlen(lib_path, 256)-4;
  strncpy(lib2, lib_path, len);
  lib2[len] = '\0';
  strcat(lib2, "lib2.so");
    
  /* Open lib2 in local scope */
  handle = dlopen (lib2, RTLD_LAZY|RTLD_LOCAL);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror(); 

  /* Lookup defined symbols */
  fh = dlsym(handle, "lib2_go");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }
  fh();
  fh = dlsym(handle, "lib3_go");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }
  fh();

  /* This should fail, because we only search in
     local scope */
  fh = dlsym(handle, "main");
  if (dlerror() == NULL)  {
    printf("Error: main found in local scope\n");
    exit(1);
  }
  
  /* Check if method called */
  if (!m_called) { 
    printf("Error: method in lib1 not called\n");
    exit(1);
  }

  /* Get handle to global scope */
  global_handle = dlopen ("", RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror(); 

  /* This should fail, because lib2 is NOT
     in global scope! */
  fh = dlsym(global_handle, "lib2_go");
  if (dlerror() == NULL)  {
    printf("Error: lib2 is in global scope\n");
    exit(1);
  }

  dlclose(handle);
  /* Now open lib2 in global scope */
  handle = dlopen (lib2, RTLD_LAZY|RTLD_GLOBAL);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror();

  /* These should pass, because lib2 is now
     in global scope! */
  fh = dlsym(global_handle, "lib2_go");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }
  fh = dlsym(global_handle, "lib3_go");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }

  dlclose(handle);
  dlclose(global_handle);

  return "\nTest \"lib resolve\" successful.\n";
}
