/**
 * @file fbt_debug.c
 * This handles the debug output that can be customized in the Makefile
 *
 * Copyright (c) 2012 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-19 20:17:12 +0100 (gio, 19 gen 2012) $
 * $LastChangedDate: 2012-01-19 20:17:12 +0100 (gio, 19 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1195 $
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
#ifdef DEBUG

#include <unistd.h>
//#include <asm-generic/fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "fbt_translate.h"
#include "fbt_debug.h"
#include "fbt_code_cache.h"
#include "fbt_datatypes.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_disas.h"
#include "fbt_x86_opcode.h"

#define O_CREAT     00000100
#define O_WRONLY    00000001
#define O_TRUNC     00001000
#define FD_CLOEXEC  1 
#define F_SETFD 2

/**
 * The file names for the output
 */
#define DEBUG_FILE_NAME "debug.txt"
#define CODE_DUMP_FILE_NAME "code_dump.txt"
#define JMP_TABLE_DUMP_FILE_NAME "jmpTable_dump.txt"

/* size of buffer for memory dumps into text files */
#define PRINT__BUF__SIZE 512

/**
 * The global variables needed for debugging
 */
int debugStream = 0;
fbt_mutex_t debugOutputLock;

void debug_start()
{
  if (debugStream == 0) {
    fbt_mutex_init(&debugOutputLock);
    debugStream = fbt_open((uint64_t)DEBUG_FILE_NAME,
        O_CREAT | O_TRUNC | O_WRONLY,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |  \
        S_IWOTH,
        "Could not open debug file (debug_start: fbt_debug.c).\n");
    int newnr = 562;
    fbt_dup2(debugStream, newnr, "err in dup2\n");
    fbt_close(debugStream, "err in close debug\n");
    debugStream = newnr; 
    fbt_syscall3(SYS64_fcntl, debugStream, F_SETFD, FD_CLOEXEC);
  } else {
    fbt_suicide_str("debug_start must be called only once!");
  }
  PRINT_DEBUG("debugStream file descriptor is %d\n", debugStream);
}

void debug_print64(uint64_t val)
{
  fbt_mutex_lock(&debugOutputLock);
  print64(debugStream, val);
  fbt_mutex_unlock(&debugOutputLock);
}

void debug_print(const char *format, ...)
{
  fbt_mutex_lock(&debugOutputLock);
  va_list argptr;
  va_start(argptr,format);
  fllprintfva(debugStream, format, argptr);
  va_end(argptr);
  fbt_mutex_unlock(&debugOutputLock);
}

static char scan_half_byte(unsigned char hb)
{
  switch (hb & 0x0f) {
  case 10:
    return 'a';
  case 11:
    return 'b';
  case 12:
    return 'c';
  case 13:
    return 'd';
  case 14:
    return 'e';
  case 15:
    return 'f';
  }
  return hb + '0';
}

char* debug_memdump(unsigned char *addr, unsigned int n)
{
  fbt_mutex_lock(&debugOutputLock);
  static char print_buf[PRINT__BUF__SIZE];
  unsigned i;
  for (i=0; i<n && i<(PRINT__BUF__SIZE-1)/2; ++i) {
    print_buf[2*i] = scan_half_byte(addr[i] >> 4);
    print_buf[2*i+1] = scan_half_byte(addr[i] & 0x0f);
  }
  print_buf[2*i] = '\0';
  fbt_mutex_unlock(&debugOutputLock);
  return print_buf;
}

/* implicit operand masks */
#define   REG_IDX_MASK    0x0000000F
#define   REG_TYPE_MASK   0x000000F0
static int printOperandString(int f, const unsigned int operandFlags,
    const unsigned char implOperandFlags,
    const unsigned char tableFlags,
    const unsigned char operandSize,
    struct translate* ts,
    unsigned int instr_len)
{

  /* tables with the names of the registers */
  static const char const
  *register_names[10][8]={
      { "al",    "cl",    "dl",    "bl",    "ah",    "ch",    "dh",    "bh"    },
      { "ax",    "cx",    "dx",    "bx",    "sp",    "bp",    "si",    "di"    },
      { "eax",   "ecx",   "edx",   "ebx",   "esp",   "ebp",   "esi",   "edi"   },
      { "mm0",   "mm1",   "mm2",   "mm3",   "mm4",   "mm5",   "mm6",   "mm7"   },
      { "xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7"  },
      { "es",    "cs",    "ss",    "ds",    "fs",    "gs",    "ERR",   "ERR"   },
      { "tr0",   "tr1",   "tr2",   "tr3",   "tr4",   "tr5",   "tr6",   "tr7"   },
      { "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)" },
      /* only ring 0 */
      { "cr0",   "ERR",   "cr2",   "cr3",   "cr4",   "ERR",   "ERR",   "ERR"   },
      /* only ring 0 */
      { "dr0",   "dr1",   "dr2",   "dr3",   "dr4",   "dr5",   "dr6",   "dr7"   }
  };
  unsigned char prefix = 0x0;
  const char const *seg_ovr = NULL;
  if (ts->num_prefixes!=0) {
    prefix = *(unsigned char*)(uint64_t)(ts->cur_instr);
    int nriters = 0;
    /* look out for a prefix we handle */
    for (nriters = 0; nriters < ts->num_prefixes; ++nriters) {
      unsigned char cur_prefix = *(unsigned char*)(uint64_t)(ts->cur_instr+nriters);
      if ((cur_prefix == PREFIX_ADDR_SZ_OVR) || (cur_prefix == PREFIX_OP_SZ_OVR))
        prefix = cur_prefix; 
      if (prefix == PREFIX_ES_SEG_OVR) seg_ovr = register_names[5][0];
      if (prefix == PREFIX_CS_SEG_OVR) seg_ovr = register_names[5][1];
      if (prefix == PREFIX_SS_SEG_OVR) seg_ovr = register_names[5][2];
      if (prefix == PREFIX_DS_SEG_OVR) seg_ovr = register_names[5][3];
      if (prefix == PREFIX_FS_SEG_OVR) seg_ovr = register_names[5][4];
      if (prefix == PREFIX_GS_SEG_OVR) seg_ovr = register_names[5][5];
    }
  }

  int len = 0;
  if (seg_ovr != NULL && hasMemOp(operandFlags)) {
    len += fllprintf(f, "%%");
    len += fllprintf(f, seg_ovr);
    len += fllprintf(f, ":");
  }

  if (implOperandFlags!=NONE) {
    /* implicit operands */
    if (!(implOperandFlags & REG_TYPE_MASK)) {
      len += fllprintf(f, "$%d", implOperandFlags & REG_IDX_MASK);
      return len;
    } else {
      int table_select = ((implOperandFlags&REG_TYPE_MASK)>>4)-1;
      if (prefix==PREFIX_OP_SZ_OVR || prefix==PREFIX_ADDR_SZ_OVR)
        table_select--;
      len += fllprintf(f, "%%%s",
          register_names[table_select][(implOperandFlags &
              REG_IDX_MASK)]);
      return len;
    }
  } else if (hasImmOp(operandFlags)) {
    /* immediate operands (after whole instruction) */
    if (operandFlags & EXECUTE) {
      len += fllprintf(f,"+");
    } else if (hasMemOp(operandFlags) && !(operandFlags & EXECUTE)) {
      len += fllprintf(f,"(");
    } else {
      len += fllprintf(f,"$");
    }
    len += fllprintf(f,"0x");
    unsigned char *startaddr = (unsigned char*)(uint64_t)(ts->cur_instr + instr_len - operandSize);
    switch (operandSize) {
    case 1:
      len += fllprintf(f, "%.2x", *(startaddr));
      break;
    case 2:
      len += fllprintf(f, "%.4x", *((unsigned short*)startaddr));
      break;
    case 4:
      len += fllprintf(f, "%.8x", *((unsigned int*)startaddr));
      break;
    default:
      len += fllprintf(f, "not supported");
    }
    if (hasMemOp(operandFlags) && !(operandFlags&EXECUTE)) {
      len += fllprintf(f,")");
    }
    return len;
  } else if (tableFlags&HAS_MODRM) {
    /* modrm byte */
    if (ModRMparseRM(operandFlags)) {
      /* we read our information from the RM part, this is the regular 'free'
         option */
      int table_select = 0;
      switch (operandFlags&OP_ADDRM_MASK) {
      case ADDRM_E:
      case ADDRM_M:
      case ADDRM_R:
        table_select = 2;
        break;
      case ADDRM_Q:
      case ADDRM_U:
      case ADDRM_W:
        table_select = 4;
        break;
      }
      if (prefix==PREFIX_OP_SZ_OVR || prefix==PREFIX_ADDR_SZ_OVR)
        table_select--;
      unsigned char modrm = *(ts->first_byte_after_opcode);
      /* decode ModRM byte */
      if (MODRM_MOD(modrm)==0x3) {
        /* only regs - plain and simple, just print it */
        len += fllprintf(f, "%%%s",
            register_names[table_select][MODRM_RM(modrm)]);
      } else if (MODRM_MOD(modrm)==0 && MODRM_RM(modrm)==5) {
        /* special disp32 - we just print int */
        len += fllprintf(f, "%.8x",
            *((unsigned int*)(ts->first_byte_after_opcode+1)));
      } else {
        if (prefix==PREFIX_ADDR_SZ_OVR) {
          return fllprintf(f, "ModRMERR");
        };
        /* we have some compination of disp and register and maybe a sib
           escape */
        /* offset for disp value */
        int dispstarts = (MODRM_RM(modrm)==4) ? 2 : 1;
        switch (MODRM_MOD(modrm)) {
        case 0:
          if (MODRM_RM(modrm)==4 &&
              SIB_BASE(*(ts->first_byte_after_opcode+1))==5) {
            /* sib byte includes a backward reference to an disp32 */
            len += fllprintf(f, "0x%.8x",
                *((unsigned int*)(ts->first_byte_after_opcode +
                    dispstarts)));
          }
          break;
        case 1:
          len += fllprintf(f, "0x%.2x", *(ts->first_byte_after_opcode +
              dispstarts));
          break;
        case 2:
          len += fllprintf(f, "0x%.8x",
              *((unsigned int*)(ts->first_byte_after_opcode +
                  dispstarts)));
          break;
        }
        len += fllprintf(f, "(");
        if (MODRM_RM(modrm)==4) {
          /* sib byte - we need to decode that as well */
          unsigned char sib = *(ts->first_byte_after_opcode+1);
          if (SIB_BASE(sib)!=5) {
            /* sib base register */
            len += fllprintf(f, "%%%s", register_names[2][SIB_BASE(sib)]);
          } else {
            /* special sib position */
            switch (MODRM_MOD(modrm)) {
            case 1:
            case 2:
              fllprintf(f, "%%ebp");
              len += 4;
            }
          }
          if (SIB_INDEX(sib)!=4) {
            /* print scaled index register */
            len += fllprintf(f, ", %%%s", register_names[2][SIB_INDEX(sib)]);
            switch (SIB_SCALE(sib)) {
            /* sib byte used to scale index */
            case 0:
              break;
            case 1:
              len+=fllprintf(f, "*2");
              break;
            case 2:
              len+=fllprintf(f, "*4");
              break;
            case 3:
              len+=fllprintf(f, "*8");
              break;
            }
          }
        } else {
          len += fllprintf(f, "%%%s",
              register_names[table_select][MODRM_RM(modrm)]);
        }
        len += fllprintf(f, ")");
      }
      return len;
    } else if (ModRMparseREG(operandFlags)) {
      /* we parse the REG part of the ModRM byte, this is the more restricted
         option (the top column of the ModR/M table)
       */
      int table_select=0;
      switch (operandFlags&OP_ADDRM_MASK) {
      case ADDRM_G:
      case ADDRM_S:
        table_select = 2;
        break; /* unsure about S */
      case ADDRM_N:
      case ADDRM_V:
        table_select = 4;
        break;
        /* these two need ring 0 privs: */
      case ADDRM_C:
        table_select = 8;
        break;
      case ADDRM_D:
        table_select = 9;
        break;
      }
      unsigned char modrm = *(ts->first_byte_after_opcode);
      len += fllprintf(f, "%%%s",
          register_names[table_select][MODRM_REG(modrm)]);
      return len;
    } else {
      /* although this instructions has a ModR/M byte,
         this argument (either dst, src, aux) does not use it*/
      return 0;
    }
  } else if ((operandFlags&ADDRM_X) == ADDRM_X) {
    return len + fllprintf(f, "%ds:(%esi)");
  } else if ((operandFlags&ADDRM_Y) == ADDRM_Y) {
    return len + fllprintf(f, "%es:(%edi)");
  }
  return 0;
}

/**
 * Prints instructions to the file (and disassembles it)
 */
void print_disasm_instruction(int f, struct translate* ts,
    unsigned int instr_len)
/* we need to pass instr_len of the current instruction because we can't trust
   the ts struct the problem is that a call instruction will tether next_instr
   and we cannot calculate the length of the current instruction by subtracting
   next_instr - cur_instr as next_instr will follow the call! so we need to pass
   the length as well!
 */
{
  fbt_mutex_lock(&debugOutputLock);

  unsigned int j, plen = 0, args = 0;
  fllprintf(f, "0x");
  for (j=0; j<instr_len; ++j) {
    fllprintf(f, "%.2x", (unsigned char)(*(unsigned char*)(uint64_t)(ts->cur_instr+j)));
  }
  for (j=0; j<24-2*instr_len; ++j) {
    fllprintf(f, " ");
  }
  plen = fllprintf(f, "%s ", ts->cur_instr_info->mnemonic);

  if (ts->cur_instr_info->srcFlags) {
    plen += printOperandString(f, ts->cur_instr_info->srcFlags,
        ts->cur_instr_info->implSrcFlags,
        ts->cur_instr_info->tableFlags,
        ts->src_operand_size, ts, instr_len);
    args = 1;
  }
  if (ts->cur_instr_info->auxFlags) {
    if (args) {
      plen+=fllprintf(f, ", ");
    }
    plen+=printOperandString(f, ts->cur_instr_info->auxFlags,
        ts->cur_instr_info->implAuxFlags,
        ts->cur_instr_info->tableFlags,
        ts->aux_operand_size, ts, instr_len);
    args=1;
  }
  if (ts->cur_instr_info->destFlags) {
    if (args) {
      plen+=fllprintf(f, ", ");
    }
    plen+=printOperandString(f, ts->cur_instr_info->destFlags,
        ts->cur_instr_info->implDestFlags,
        ts->cur_instr_info->tableFlags,
        ts->dest_operand_size, ts, instr_len);
  }

  if (plen<32) {
    for (j=0; j<32-plen; ++j) {
      fllprintf(f, " ");
    }
  } else {
    fllprintf(f, " ");
  }
  fllprintf(f, "\n");

  fbt_mutex_unlock(&debugOutputLock);
}

#endif  /* DEBUG */
