/**
 * @file fbt_llio.h
 * Interface for low level IO (without any dependencies to libC).
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
#ifndef FBT_LLIO_H
#define FBT_LLIO_H

#include "fbt_datatypes.h"

#include <stdarg.h>

#define STDOUT_FILENO 1

/**
 * Print a string str to file descriptor fd.
 * This function is a replacement for (f)printf with verbatim printing of the
 * format string, i. e. no conversion specifications.
 * In effect, this is just a wrapper around the write(2) system call which
 * handles interrupted writes.
 * @param fd the target file descriptor
 * @param str the string to write
 * @return the number of characters written
 */
int fllwrite(int fd, const char* str);

/**
 * Write a formatted string to the file descriptor fd (might use a buffer).
 * @param fd File descriptor that is written to.
 * @param format format string that is interpreted (including all varargs).
 * @return Number of bytes written.
 */
int fllprintf(int fd, const char *format, ...);

/**
 * Writes on standard out
 */
int llprintf(const char *format, ...);


/**
 * Write a formatted string to the file descriptor fd (might use a buffer). Used
 * only during debugging.
 * @param fd File descriptor that is written to.
 * @param format format string that is interpreted (including all varargs).
 * @param ap List of var args.
 * @return Number of bytes written.
 */
int fllprintfva(int fd, const char* format, va_list ap);


/**
 * Writes a 64 bit number on file descriptor fd
 */
void print64(int fd, uint64_t n);

#endif  /* FBT_LLIO_H */
