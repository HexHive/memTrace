/**
 * @file fbt_translate.c
 * This modules translates one code region and puts the result into the code
 * cache.
 *
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * $Date: 2012-01-14 21:34:20 +0100 (sab, 14 gen 2012) $
 * $LastChangedDate: 2012-01-14 21:34:20 +0100 (sab, 14 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1171 $
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
#include "fbt_disas.h"

#include "fbt_translate.h"
#include "fbt_actions.h"
#include "fbt_datatypes.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_x86_opcode.h"
#include "fbt_opcode_tables.h"

/* bit test masks for ModR/M byte */
#define MASK_MOD 0xC0
#define MASK_REG 0x38
#define SHIFT_REG 3
#define MASK_RM  0x07

uint32_t fbt_operand_size(uint32_t operandFlags, unsigned char prefix) {
  unsigned char rprefix = 0x0;
  if (prefix == PREFIX_OP_SZ_OVR && ((operandFlags & ADDRM_I) == ADDRM_I))
    rprefix = prefix;
  if (prefix == PREFIX_ADDR_SZ_OVR && (((operandFlags & ADDRM_A) == ADDRM_A)
      || ((operandFlags & ADDRM_J) == ADDRM_J) || ((operandFlags & ADDRM_O)
          == ADDRM_O)))
    rprefix = PREFIX_OP_SZ_OVR; // use simple override

  switch (operandFlags & OPT_MASK) {
  case OPT_b:
    return 1;
  case OPT_w:
    return 2;
  case OPT_d:
  case OPT_fs:
    return 4;
  case OPT_pi:
  case OPT_q:
  case OPT_fd:
    return 8;
  case OPT_s:
  case OPT_fe:
  case OPT_fp:
    return 10;
  case OPT_dq:
  case OPT_ps:
  case OPT_pd:
  case OPT_ss:
  case OPT_sd:
    return 16;
  case OPT_fv:
    return 28;
  case OPT_fst:
    return 108;
    /* special handling if OP_SZ is present */
  case OPT_c:
    if (rprefix == PREFIX_OP_SZ_OVR)
      return 1;
    return 2;
  case OPT_a:
    if (rprefix == PREFIX_OP_SZ_OVR)
      return 4;
    return 8;
  case OPT_z:
    if (rprefix == PREFIX_OP_SZ_OVR)
      return 2;
    return 4;
  case OPT_v:
    if (rprefix == PREFIX_OP_SZ_OVR)
      return 2;
    return 4;
  case OPT_p:
    /* 32bit ptr (16b addr mode), 48bit ptr (32b addr mode) or 80b ptr (64b addr
     mode) */
  case OPT_si:
    /* doubleword register - unhandled */
    fbt_suicide_str("Doubleword register, unhandled (fbt_operand_size: "
        "fbt_translate.c)\n");
    return -1;
  }
  return 0;
}

void fbt_disasm_instr(struct translate *ts)
{
  const struct ia32_opcode *opcode, *opcode_table = opcode_table_onebyte;
  int bytes_argument;

  //llprintf("\n\n\nBEG DISAS\n\n");

  ts->cur_instr = ts->next_instr;
  unsigned char *cur = (unsigned char*) (uint64_t) ts->cur_instr;
  ts->num_prefixes = 0;

  /* 0x1 - operand overwrite */
  unsigned char prefix = 0;

  /*#ifdef __LP64__
   unsigned char rex = 0;
   #endif */

  //int cnt = 0;
  while (1) {
    //llprintf("step %d: cur opc %x\n", cnt++, (int)*cur);

    opcode = opcode_table + (unsigned int) *cur;

    if ((*cur == PREFIX_OP_SZ_OVR || *cur == PREFIX_REPNEZ || *cur
        == PREFIX_MISC) && (*(cur + 1) == 0x0F) && /* opcode esc */
        /* ensure that we can escape to a table and the destination is valid */
        (OPCODETABLE(opcode->tableFlags)
            && ((opcode->opcode.table + *(cur + 2))->opcode.handler) != 0)) {
      /* this is an opcode escape -> we have to perform a lookup in an
       additional table */
      //PRINT_DEBUG_DISAS("opcode escape found to 3byte opcode: %x", *cur);
      //llprintf("!!opc escape %x\n", (int)*cur);
      /* there are some 3byte opcodes which start with a prefix and then escape
       through 0x0f we take care of them _here_ otherwise, we just go back to
       the first table and continue our translation */
      opcode_table = opcode->opcode.table;
      //llprintf("!!switching to opcode table %x, the other is %x\n", (unsigned)opcode->opcode.table,  opcode_table_660F);
      cur += 2; /* skip the 0x0f escape byte */
      continue; /* do one more iteration */
      /* check for OPCODE_ESC */
    } else if ((opcode->tableFlags & OPCODE_ESC) != 0) {
      /* this is an opcode escape -> we have to perform a lookup in an
       additional table */
      PRINT_DEBUG_DISAS("opcode escape found: %x", *cur);
      opcode_table = opcode->opcode.table;
      cur++;
      continue; /* do one more iteration */
    } else if ((opcode->tableFlags & OPCODE_PREFIX_ESC) != 0) {
      /* this is a prefix -> we have to perform a lookup in an additional
       table */
      PRINT_DEBUG_DISAS("prefix found: %x", *cur);
      ts->num_prefixes++;
      /* for performance reasons we _now_ only support 1 out of ADDR or OP SZ
       OVR prefix. more can be added. */
      if (!(ts->num_prefixes <= 1 || ((prefix != PREFIX_ADDR_SZ_OVR) && (prefix
          != PREFIX_OP_SZ_OVR)))) {
        /* we only support one prefix atm */
        fbt_suicide_str("Only one prefix supported (disasm_instr: "
            "fbt_disassemble.c)\n");
      }
      prefix = *cur;
      /* go back to the first table if it is not a special escape prefix! */
      opcode_table = opcode_table_onebyte;
      cur++;
      continue; /* do one more iteration */
    } else {
      /* this was the last byte of the opcode */
      ts->first_byte_after_opcode = cur + 1;

      //llprintf("else case: mnemonic is '%s'\n", opcode->mnemonic);

      /* check if this instruction has any kind of ModRM byte */
      if (anyModRMOp(opcode) || (opcode->tableFlags & OPCODE_MODRM_ESC)
          || (opcode->tableFlags & OPCODE_FPU_ESC)) {

        //llprintf("has some modrm\n");

        cur++;
        bytes_argument = 0;

        /* check for OPCODE_RM */
        if (opcode->tableFlags & OPCODE_MODRM_ESC) {
          /* this opcode extends into the reg bits of the ModR/M byte */
          /* get the opcode from the group table */
          PRINT_DEBUG_DISAS("opcode table: %p -> %p (%p)\n", opcode,
              opcode->opcode.table,
              opcode->opcode.table + ((*cur & MASK_REG) >> SHIFT_REG));
          opcode = opcode->opcode.table + ((*cur & MASK_REG) >> SHIFT_REG);
          /* check for FPU_ESC */
        } else if (opcode->tableFlags & OPCODE_FPU_ESC) {
          /* this opcode extends into a fpu table */
          /* get the opcode from the fpu table */
          opcode = opcode->opcode.table + (unsigned int) *cur;
        }
        if ((opcode->tableFlags & HAS_MODRM) && (*cur & MASK_MOD) != 0xC0) {
          /* this instruction has a modRM byte and it refers to a memory
           location */
          if (prefix != PREFIX_ADDR_SZ_OVR) {
            if ((*cur & MASK_RM) == 0x04) {
              /* there follows a SIB byte (SIB bytes only follow in 32bit
               mode! */
              if ((*cur & MASK_MOD) == 0x00 && (*(cur + 1) & 0x07) == 0x05) {
                /* after the SIB there follows a 32bit displacement */
                bytes_argument += 5;
              } else {
                bytes_argument++;
              }
            }
            if ((*cur & MASK_MOD) == 0x00 && (*cur & MASK_RM) == 0x05) {
              /* mod bits are 00, R/M bits are 101 -> another case of 32bit
               displacement */
              bytes_argument += 4;
            } else if ((*cur & MASK_MOD) == 0x40) {
              /* mod bits are 01 -> 8bit displacement */
              bytes_argument++;
            } else if ((*cur & MASK_MOD) == 0x80) {
              /* Mod bits are 10 -> 32bit displacement */
              bytes_argument += 4;
            }
          } else {
            /* we have 16bit addr mode (prefix override)!! */
            PRINT_DEBUG_DISAS("Prefix found: ADDR_SZ_OVR!");
            if ((*cur & MASK_MOD) == 0x00 && (*cur & MASK_RM) == 0x06) {
              /* mod bits are 00, R/M bits are 110 -> another case of 16bit
               displacement */
              bytes_argument += 2;
            } else if ((*cur & MASK_MOD) == 0x40) {
              /* mod bits are 01 -> 8bit displacement */
              bytes_argument++;
            } else if ((*cur & MASK_MOD) == 0x80) {
              /* Mod bits are 10 -> 16bit displacement */
              bytes_argument += 2;
            }
          }
          cur += bytes_argument;
        }
      }

      /* set the action */
      ts->cur_instr_info = opcode;
      assert(!OPCODETABLE(opcode->tableFlags));

      ts->dest_operand_size = 0;
      ts->src_operand_size = 0;
      ts->aux_operand_size = 0;
      /* read info regarding immediate arguments (imms, code offset, etc.) */
      if (hasImmOp(opcode->destFlags)) {
        ts->dest_operand_size = fbt_operand_size(opcode->destFlags, prefix);
        cur += ts->dest_operand_size;
      }
      if (hasImmOp(opcode->srcFlags)) {
        ts->src_operand_size = fbt_operand_size(opcode->srcFlags, prefix);
        cur += ts->src_operand_size;
      }
      if (hasImmOp(opcode->auxFlags)) {
        ts->aux_operand_size = fbt_operand_size(opcode->auxFlags, prefix);
        cur += ts->aux_operand_size;
      }
    }

    /* if we reach this point we are done */
    break;
  }

  //llprintf("\n\n\nEND DISAS\n\n");

  /* now we know how many bytes the current instructions takes */
  ts->next_instr = (guestptr_t) (uint64_t) (cur + 1);
}
