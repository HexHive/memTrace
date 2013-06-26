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
#include "lib1.h"

extern void func();

/* This adds an R_386_GLOB_DAT entry in the relocation section. 
   This checks if the loader updates the GOT entry to point to 
   the object in the application memory. */
int global = 42;

/* This is only referenced in this library */
int local = 10;

/* This adds an DT_INIT entry to the dynamic section, should
   be called after loading of shared library. */
void _init (void) {
  local = 9;
}

void _fini (void) {
  // TODO
}

const char *get_string (int param) {

  /* This adds an R_386_32 entry in the relocation section. Global2
     is defined in lib2. This checks if the loader updates the 
     memory address. */
  static int *p = &global2;
  *p = 42;

  func();

  global3 = 42;

  if (global3 == 42 &&  global == 43 && local == 9) {
    const char *ret = method(global);
        
    return ret;
  }  else {
    return "Error\n";
  }
}

