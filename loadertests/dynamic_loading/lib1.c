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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include "lib1.h"

int fini_called = 0;

char* get_string (char *lib_path) {
  void *handle;
  char *(*fh)(int, int);
  int (*fh2)();
  char *ret;
  char *error;

  char *path = malloc(256);
  int len = strnlen(lib_path, 256)-4;
  strncpy(path, lib_path, len);
  path[len] = '\0';
  strcat(path, "lib2.so");
    
  handle = dlopen (path, RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror(); 

  /* Lookup undefined symbol */
  fh = dlsym(handle, "abc");
  if ((error = dlerror()) == NULL)  {
    /* No error -> fail */
    return "Error: lookup undef symbol not handled\n";
  }

  /* Lookup defined symbol */
  fh = dlsym(handle, "printTest");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }

  /* Check if init called */
  int init_called = (int)dlsym(handle, "init_called");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }

  if (!init_called) {
    printf("Error: init not called\n");
    exit(1);
  }
  
  /* Call function and check return value */
  ret = (*fh)(1, 2);
  if (strcmp(ret, "ok"))
    return "\nError: test \"dynamic_loading\" failed.\n";

  /* Close handle */
  dlclose(handle);

  /* Check if fini called */
  if (!fini_called) {
    printf("Error: fini not called\n");
    exit(1);
  }
  
  /* Open nonexistent library */
  handle = dlopen ("abc", RTLD_LAZY);
  if (handle) {
    /* No error -> fail */
    return "Error: open nonexistent library not handled\n";
  }
  
  /* Open library needing dynamic tls */
  strncpy(path, lib_path, len);
  path[len] = '\0';
  strcat(path, "lib_tls_dynamic.so");
  handle = dlopen (path, RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror(); 

  fh2 = dlsym(handle, "get_data");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }

  if (fh2() != 123) {
    return "\nError: return value of get_data form lib_tls_dynamic.so wrong\n";
  }

  dlclose(handle);

  /* Open library needing dynamic _and_ static tls */
  /* NOT SUPPORTED so do not test
  strncpy(path, lib_path, len);
  path[len] = '\0';
  strcat(path, "libs/lib_tls.so");
  handle = dlopen (path, RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror(); 

  fh2 = dlsym(handle, "get_data");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }
  
  fh2();
  */

  /* Handle to main */
  handle = dlopen (0, RTLD_LAZY);
  if (!handle) {
    fprintf (stderr, "%s\n", dlerror());
    exit(1);
  }
  dlerror();

  /* Lookup symbol in main object */
  fh2 = dlsym(handle, "global_func");
  if ((error = dlerror()) != NULL)  {
    fprintf (stderr, "%s\n", error);
    exit(1);
  }

  fh2();

  dlclose(handle);

  Dl_info *info = malloc(sizeof(Dl_info));
  if (dladdr(fh2, info) != 0) {
    printf("name: %s, base: %p, sname: %s, saddr %p\n", info->dli_fname,
           info->dli_fbase, info->dli_sname, info->dli_saddr);
  } else {
    printf("Error dladdr\n");
    exit(1);
  }
  
  return "\nTest \"dynamic_loading\" successful.\n";
}
