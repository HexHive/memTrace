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
#include "lib1.h"

int initCalled = 1;

void _init() {
  initCalled = 1;
}

void _start() {
  
  /* This adds a R_386_COPY entry to the relocation section.
     We increment it to check if the inital value from lib1 is
     copied successfully by our loader. */
  global++;

  const char *str = get_string(3);

  if (!initCalled) {
    str = "Error\n";
  }
  
  asm("int  $0x80"
      : 
      : "a" (4), "b" (1), "c" (str), "d" (34)
      );
	
  asm("int  $0x80"
      : // no output registers
      : "a" (1), "b" (0)
      );

}
