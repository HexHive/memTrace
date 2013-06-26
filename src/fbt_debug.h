/**
 * @file fbt_debug.h
 * This handles the debug output that can be customized in the Makefile
 *
 * IMPORTANT:
 * - The macro START_DEBUG and START_DUMP must be called before any
 *   call to PRINT_* or DUMP_* respectively, otherwise the program
 *   will fail.
 * - The macro STOP_DEBUG and STOP_DUMP clean up the data structure
 *   after calling one of these macros the corresponding debugging
 *   features must not be called anymore otherwise the program will
 *   abort.
 *
 * WARNING: concerns DEBUG_FUNCTION_{START,END} and DEBUG_PRINT_N
 * - Everything_ written on the same line after one of the above
 *   macros will be ignored!
 * - output is written to file (i.e. debug.txt)
 * - macros are thread safe
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
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

#ifndef FBT_DEBUG_H
#define FBT_DEBUG_H

#ifdef DEBUG

#include "fbt_datatypes.h"

extern int debugStream;

/* use debug */
void debug_start();
void debug_print_function_start(char *str, ...);
void debug_print_function_end(char *str, ...);

/* print a debug string with indentation */
void debug_print(const char *str, ...);
void debug_print64(uint64_t);
char* debug_memdump(unsigned char *addr, unsigned int n);
void print_disasm_instruction(int f,
                                  struct translate* ts,
                                  unsigned int instr_len);

#define DEBUG_START() debug_start()
#define PRINT_DEBUG(...) debug_print(__VA_ARGS__)
#define PRINT_DEBUG64(x) debug_print64(x)
#define PRINT_DEBUG_FUNCTION_START(...)
//debug_print("start fun: "); debug_print(__VA_ARGS__); debug_print("\n");
#define PRINT_DEBUG_FUNCTION_END(...)
//debug_print("end fun: "); debug_print(__VA_ARGS__); debug_print("\n");
#define MEMDUMP(addr, n)


#else

#define DEBUG_START()
#define PRINT_DEBUG(...)
#define PRINT_DEBUG64(x)
#define PRINT_DEBUG_FUNCTION_START(...)
#define PRINT_DEBUG_FUNCTION_END(...)
#define MEMDUMP(addr, n)

#endif

#define PRINT_DEBUG_ACTIONS(...)

//#define PRINT_DEBUG_TRANSLATE(...)
#define PRINT_DEBUG_TRANSLATE PRINT_DEBUG

#define PRINT_DEBUG_DISAS(...)

//#define PRINT_DEBUG_ADDRESS_SPACE(...)
#define PRINT_DEBUG_ADDRESS_SPACE PRINT_DEBUG

//#define PRINT_DEBUG_SYSCALL(...)
#define PRINT_DEBUG_SYSCALL PRINT_DEBUG

#endif  /* FBT_DEBUG_H */
