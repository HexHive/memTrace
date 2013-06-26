/**
 * @file fbt_disas.h
 * This module translates one code region and puts the result into the code
 * cache.
 *
 * Copyright (c) 2010 ETH Zurich
 *
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
#ifndef FBT_DISAS_H
#define FBT_DISAS_H

#include "fbt_datatypes.h"

/**
 * Disassembles one instruction and fills in all information into the
 * struct translate.
 * This function disassembles the current instruction at ts->next_instr and
 * retrieves the length of the instruction in bytes (including prefixes, opcode,
 * ptr, modR/M, SIB, and immediates) and the pointer to the function that shall
 * be used to handle this instruction.
 * @param ts pointer to translate struct. ts is changed to correspond to the
 * current instruction.
 */
void fbt_disasm_instr(struct translate *ts);

uint32_t fbt_operand_size(uint32_t operandFlags, unsigned char prefix);

#endif /* FBT_TRANSLATE_H */
