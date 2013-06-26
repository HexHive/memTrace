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
#include "lib1.h"

int global1_1 = 1;
int global1_2 = 2;
int global1_3 = 3;
asm(".symver global1_1, global1@VERS_1.0");
asm(".symver global1_2, global1@VERS_2.0");
asm(".symver global1_3, global1@@VERS_3.0");


int method1_1(int param) {
  return 1;
}
asm(".symver method1_1, method1@VERS_1.0");

int method1_2(int param, int flag) {
  return 2;
}
asm(".symver method1_2, method1@VERS_2.0");

/* Default version */
int method1_3(int param, int flag) {
  return 3;
}
asm(".symver method1_3, method1@@VERS_3.0");

int method1_4(int param, int flag) {
  return 4;
}
asm(".symver method1_4, method1@VERS_4.0");

int method2() {
  return 5;
}
