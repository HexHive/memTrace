/**
 * @file fbt_instruction.h
 * This module defines a higher level instuction information struct
 * and functions that compute it.
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-20 17:51:17 +0100 (ven, 20 gen 2012) $
 * $LastChangedDate: 2012-01-20 17:51:17 +0100 (ven, 20 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1198 $
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


#ifndef FBT_LMEM_INSTRUCTION_H
#define FBT_LMEM_INSTRUCTION_H

#include "fbt_datatypes.h"

/* For each instruction in a basic block we track how it
 * uses the flags register. */
#define FL_USES 1               /* The instruction reads the flags register */
#define FL_CHANGES_ALL 2        /* The instruction changes all the arithmetic flags (o..szapc)
                                   but not necessarily other flags (like interrupt or direction).
                                   This type of instruction is very helpful since it allows us not
                                   to save/restore eflags because it gets overwritten anyway. */
#define FL_CHANGES_SOME 4       /* The instruction changes some of the arithmetic flags*/

/**
 * Bit masks to encode register usage (currently register analysis disabled)
 */
typedef enum {
  AL_BITS =0x00000001,
  AH_BITS =0x00000002,
  AX_BITS =0x00000003,
  EAX_BITS=0x0000000F,

  CL_BITS =0x00000010,
  CH_BITS =0x00000020,
  CX_BITS =0x00000030,
  ECX_BITS=0x000000F0,

  DL_BITS =0x00000100,
  DH_BITS =0x00000200,
  DX_BITS =0x00000300,
  EDX_BITS=0x00000F00,

  BL_BITS =0x00001000,
  BH_BITS =0x00002000,
  BX_BITS =0x00003000,
  EBX_BITS=0x0000F000,

  SP_BITS =0x00030000,
  ESP_BITS=0x000F0000,

  BP_BITS =0x00300000,
  EBP_BITS=0x00F00000,

  SI_BITS =0x03000000,
  ESI_BITS=0x0F000000,

  DI_BITS =0x30000000,
  EDI_BITS=0xF0000000,

  ALL_REG_BITS=0xFFFFFFFF
} GpRegisterBits;

/**
 * This struct holds high level information about instructions
 * that we need for lightweight memory tracing.
 */
struct lmem_instruction {

  /**
   * The arithmetic flags are 'oszapc'
   * This bitfield tells us whether the instruction uses
   * (some of) the arithmetic flags, sets them all or sets
   * some of them.
   */
  unsigned arithmetic_flag_info; // bitfield for FL_*

#ifdef LMEM_REGISTER_ANALYSIS

  /**
   * Bitfield encoding what general purpose
   * registers are read by the instruction. Since
   * instructions can do rather complex address
   * computations there may be more than one register
   * that is read.
   * (note: we don't distinguish between eax, ax, ah etc.)
   */
  GpRegisterBits gp_registers_read;

  /**
   * Bitfield encoding what general purpose registers
   * are written by the instruction. Recall that there
   * are instructions such as 'div' that write to more
   * than one register.
   * (note: we don't distinguish between eax, ax, ah etc.)
   */
  GpRegisterBits gp_registers_written;

  /**
   * The size of the operands on which this instruction
   * acts upon.
   */
  int opsize;

#endif /* LMEM_REGISTER_ANALYSIS */

  /**
   * Boolean telling us if this instruction has been
   * successfully decoded. If this is 0 then our algorithms
   * should assume the worst.
   * They can however assume that it is not a control flow
   * transfer.
   */
  BOOL supported;

  /**
   * Encodes whether this instruction reads memory
   */
  BOOL reads_memory;
  /**
   * Encodes whether this instruction writes memory
   */
  BOOL writes_memory;
};

/**
 * Given a disassembled instruction, computes some higher level
 * information.
 * @param ts the disassembled instruction
 * @param tesult the computed higher level representation
 */
void compute_lmem_instruction(struct translate* ts,
    struct lmem_instruction* result);

#endif

