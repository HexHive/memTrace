/**
 * @file fbt_actions.c
 * This module defines some generic default actions that are used to translate
 * specific machine codes.
 *
 * Copyright (c) 2012 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwe1lt.net>
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

#include "fbt_actions.h"

#include <stddef.h> /* offsetof */

#include "fbt_translate.h"
#include "fbt_asm_macros.h"
#include "fbt_code_cache.h"
#include "fbt_debug.h"
#include "fbt_datatypes.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_syscalls_64.h"
#include "fbt_disas.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"

enum translation_state action_none(struct translate *ts, BOOL lock) {
  PRINT_DEBUG_FUNCTION_START("action_none(*ts=%p)", ts);
  /* do nothing */
  PRINT_DEBUG_FUNCTION_END("-> neutral");
  return NEUTRAL;
}

/**
 * This function is part of the method that translates x86 instructions
 * to x64 instructions. It handles opcodes 0xa0 and 0xa3.
 * Opcodes A0 to A3 are somewhat a special case.
 */
static void transform_moffset_instr(struct translate* ts, 
    uchar **transl_instr_ptr,
    BOOL transform_to_lea)
{
  uchar *cur_instr = (uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes);
  for (int i=0; i<ts->num_prefixes; i++){
    *(*transl_instr_ptr)++ = *(uchar*)(uint64_t)(ts->cur_instr + i);
  }

  switch (*cur_instr){
  case 0xa0:
    if (transform_to_lea){
      /* lea into r8 */
      *(*transl_instr_ptr)++ = 0x4c;
      *(*transl_instr_ptr)++ = 0x8d;
    } else {
      /* generic mov opcode */
      *(*transl_instr_ptr)++ = 0x8a;
    }

    /* eax + sib so that we don't
       get rip-relative addressing */
    *(*transl_instr_ptr)++ = 0x04;  //

    /* the sib that consists only of
       a displacement */
    *(*transl_instr_ptr)++ = 0x25;

    /* the (absolute) displacement */
    *((uint32_t*)(*transl_instr_ptr)) = 
        *((uint32_t*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1));
    (*transl_instr_ptr) += 4;
    break;

  case 0xa1:

    if (transform_to_lea){
      /* lea into r8 */
      *(*transl_instr_ptr)++ = 0x4c;
      *(*transl_instr_ptr)++ = 0x8d;
    } else {
      /* generic mov opcode */
      *(*transl_instr_ptr)++ = 0x8b;
    }

    /* eax + sib so that we don't
       get rip-relative addressing */
    *(*transl_instr_ptr)++ = 0x04;  //

    /* the sib that consists only of
       a displacement */
    *(*transl_instr_ptr)++ = 0x25;

    /* the (absolute) displacement */
    *((uint32_t*)(*transl_instr_ptr)) = 
        *((uint32_t*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1));
    (*transl_instr_ptr) += 4;
    break;

  case 0xa2:

    if (transform_to_lea){
      /* lea into r8 */
      *(*transl_instr_ptr)++ = 0x4c;
      *(*transl_instr_ptr)++ = 0x8d;
    } else {
      /* generic mov opcode */
      *(*transl_instr_ptr)++ = 0x88;
    }

    /* eax + sib so that we don't
       get rip-relative addressing */
    *(*transl_instr_ptr)++ = 0x04;

    /* the sib that consists only of
       a displacement */
    *(*transl_instr_ptr)++ = 0x25;

    /* the (absolute) displacement */
    *((uint32_t*)(*transl_instr_ptr)) = 
        *((uint32_t*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1));
    (*transl_instr_ptr) += 4;
    break;

  case 0xa3:

    if (transform_to_lea){
      /* lea into r8 */
      *(*transl_instr_ptr)++ = 0x4c;
      *(*transl_instr_ptr)++ = 0x8d;
    } else {
      /* generic mov opcode */
      *(*transl_instr_ptr)++ = 0x89;
    }

    /* eax + sib so that we don't
       get rip-relative addressing */
    *(*transl_instr_ptr)++ = 0x04;  //

    /* the sib that consists only of
       a displacement */
    *(*transl_instr_ptr)++ = 0x25;

    /* the (absolute) displacement */
    *((uint32_t*)(*transl_instr_ptr)) = *((uint32_t*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1));
    (*transl_instr_ptr) += 4;

    break;
  }
}

/**
 * This function has most of the logic for the transformation of
 * x86 instructions to x64 instructions.
 */
static int transform_generic_instruction(struct translate* ts,
    unsigned char **transl_instr_ptr,
    BOOL transform_to_lea)
{
  long length = ts->next_instr - ts->cur_instr;
  uchar *cur_instr = (uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes);

  uchar the_prefix = 0;
  if (ts->num_prefixes > 1) {
    if (ts->num_prefixes > 2) {
      fbt_suicide_str("more than 2 prefixes not supported\n");
    }
    PRINT_DEBUG_ACTIONS("There are 2 prefixes\n");
    PRINT_DEBUG_ACTIONS("pr1 = %x\n", (uint32_t)*(uchar*)(uint64_t)ts->cur_instr);
    PRINT_DEBUG_ACTIONS("pr2 = %x\n", (uint32_t)*(uchar*)((uint64_t)ts->cur_instr+1));

    *(*transl_instr_ptr)++ = 0xf0; /* Add the lock prefix */

    /* Consume the 'lock' prefix */
    if (!transform_to_lea){
      if (*(uchar*)(uint64_t)ts->cur_instr != 0xf0){
        fbt_suicide_str("we require fst prefix of two is lock\n");
      }
      the_prefix = *(((uchar*)(uint64_t)ts->cur_instr)+1);
    } else {
      fbt_suicide_str("invalid parameter combination\n");
    }
  } else {
    the_prefix = *(uchar*)(uint64_t)ts->cur_instr;
  }

  BOOL gs_seg = (the_prefix == 0x65);

  if ((ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_GROUP_MASK) ==
      OPCODEFL_ARRAY){
    if (transform_to_lea){
      /* Almost never occurs in practice. Add support if desired. */
      return 1; 
    } else {
      fbt_memcpy(*transl_instr_ptr, (void*)(uint64_t)ts->cur_instr, length);
      ts->tld->transl_instr += length;
      *transl_instr_ptr += length;
      return 0;
    }
  }

  if (!(hasModRMOp(ts->cur_instr_info->destFlags)) &&
      !(hasModRMOp(ts->cur_instr_info->srcFlags))) {
    if (!transform_to_lea){
      fbt_suicide_str("No modrm operand (probably you should use "
                      "transform_moffset_instr() before calling this)");
    } else {
      PRINT_DEBUG_ACTIONS("Warning, no modrm operand found.\n");
      return 1;
    }
  }

  unsigned char modRM = *ts->first_byte_after_opcode;
  cur_instr = ts->first_byte_after_opcode + 1;
  if (MODRM_MOD(modRM) == 0x3) { /* operand is register */
    PRINT_DEBUG_ACTIONS("operand is register. This case is processed by "
                        "string instruction handlers.");
    return 1;
  } else {

    BOOL has_sib = MODRM_RM(modRM) == 0x4 && MODRM_MOD(modRM) != 3;
    int sib = 0;
    if (has_sib) {

      /* prefix that tells to use 32 bit version */
      if (!gs_seg){
        *(*transl_instr_ptr)++ = 0x67;
      }

      if (transform_to_lea){
        /* 4c 8d 84 */
        *(*transl_instr_ptr)++ = 0x4c;
        *(*transl_instr_ptr)++ = 0x8d;
        *(*transl_instr_ptr)++ = modRM & 0xc7;
      } else {
        /* Copy prefixes and opcode verbatim */
        unsigned char* it = (uchar*)(uint64_t)ts->cur_instr;
        for (;it != ts->first_byte_after_opcode; ++it){
          *(*transl_instr_ptr)++ = *it;
        }

        /* Copy modRM byte */
        *(*transl_instr_ptr)++ = modRM;
      }

      /* copy sib byte */
      sib = *cur_instr++;
      *(*transl_instr_ptr)++ = sib;

    } else {

      if (MODRM_RM(modRM) == 0x05 && MODRM_MOD(modRM) == 0){
        /* A disp32 follows, but the instruction doesn't have a
           sib byte. If we just
           copied it verbatim, it would not be correct since x64
           uses rip-relative addressing by default. */

        if (transform_to_lea){
          *(*transl_instr_ptr)++ = 0x4c;
          *(*transl_instr_ptr)++ = 0x8d;
          *(*transl_instr_ptr)++ = 0x04;
        } else {
          /* Copy prefixes and opcode verbatim */
          uchar* it = (uchar*)(uint64_t)ts->cur_instr;
          for (;it != ts->first_byte_after_opcode; ++it){
            *(*transl_instr_ptr)++ = *it;
          }

          /* Copy modRM byte, tell to use the sib byte */
          *(*transl_instr_ptr)++ = (modRM & 0xF8) | 0x04;

        }

        /* make a sib byte that uses no register */
        *(*transl_instr_ptr)++ = 0x25;

      } else {

        /* prefix that tells to use 32 bit version */
        if (!gs_seg){
          *(*transl_instr_ptr)++ = 0x67;
        }

        if (transform_to_lea){
          *(*transl_instr_ptr)++ = 0x4c;
          *(*transl_instr_ptr)++ = 0x8d;
          /* Copy modRM byte */
          *(*transl_instr_ptr)++ = modRM & 0xc7;;
        } else {
          /* Copy prefixes and opcode verbatim */
          uchar* it = (uchar*)(uint64_t)ts->cur_instr;
          for (;it != ts->first_byte_after_opcode; ++it){
            *(*transl_instr_ptr)++ = *it;
          }
          /* Copy modRM byte */
          *(*transl_instr_ptr)++ = modRM;
        }
      }
    }

    switch (MODRM_MOD(modRM)) {
    case 1:
      /* disp8 */
      *(*transl_instr_ptr)++ = *cur_instr++;

      if (!transform_to_lea){
        /* copy immediate if any */
        while (cur_instr != (uchar*)(uint64_t)ts->next_instr){
          *(*transl_instr_ptr)++ = *cur_instr++;
        }
      }

      break;

    case 0:

      /* displacement (See modrm table in intel doc) */
      if (MODRM_RM(modRM) == 5){

        *((int32_t*)(*transl_instr_ptr)) = *((int32_t*)cur_instr);
        (*transl_instr_ptr) += 4;
        cur_instr += 4;

      } else if (has_sib){  /* (See sib table in intel doc) */
        if (SIB_BASE(sib) == 5){

          if (MODRM_MOD(modRM)==0){

            *((int32_t*)(*transl_instr_ptr)) = *((int32_t*)cur_instr);
            (*transl_instr_ptr) += 4;
            cur_instr += 4;

          } else if (MODRM_MOD(modRM)==1){
            fbt_suicide_str("not impl rm 1!!!");
          } else if (MODRM_MOD(modRM)==2){
            fbt_suicide_str("not impl rm 2!!!");
          } else {
            fbt_suicide_str("Invalid");
          }
        }
      }

      /* copy immediate if any */
      if (!transform_to_lea){
        while (cur_instr != (uchar*)(uint64_t)ts->next_instr){
          *(*transl_instr_ptr)++ = *cur_instr++;
        }
      }

      break;

    case 2:
      /* disp32 */
      *((int32_t*)(*transl_instr_ptr)) = *((int32_t*)cur_instr);
      (*transl_instr_ptr) += 4;
      cur_instr += 4;

      /* copy immediate if any */
      if (!transform_to_lea){
        while (cur_instr != (uchar*)(uint64_t)ts->next_instr){
          *(*transl_instr_ptr)++ = *cur_instr++;
        }
      }

      break;
    }
  }

  return 0;
}

/**
 * This function transforms a x86 instruction to the corresponding x64 one.
 */
void transform_instruction(struct translate *ts)
{
  uchar *transl_instr = ts->tld->transl_instr;
  long length = ts->next_instr - ts->cur_instr;
  uchar *cur_instr = (uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes);

  if (*cur_instr == 0xa0 || *cur_instr == 0xa1 || 
      *cur_instr == 0xa2 || *cur_instr == 0xa3){
    transform_moffset_instr(ts, &ts->tld->transl_instr, FALSE);
    return;
  }

  if (hasMemOp(ts->cur_instr_info->auxFlags)) {
    fbt_suicide_str("Instruction with auxiliary memory operand not"
                    " supported yet");
  }

  unsigned char modRM = *ts->first_byte_after_opcode;

 /* llprintf("\nsrcflags = %x\ndestflags = %x\nauxflags = %x\n",
           ts->cur_instr_info->srcFlags,
           ts->cur_instr_info->destFlags,
           ts->cur_instr_info->auxFlags);

  llprintf("\nsrcflagsMEM = %x\ndestflagsMEM = %x\n",
           hasMemOp(ts->cur_instr_info->srcFlags),
           hasMemOp(ts->cur_instr_info->destFlags)); */

  if ((hasMemOp(ts->cur_instr_info->destFlags) ||
       hasMemOp(ts->cur_instr_info->srcFlags)) &&
       MODRM_MOD(modRM) != 0x3)
  {
    if (ts->num_prefixes > 1) {
      PRINT_DEBUG_ACTIONS("warning: more than one prefix");
    }

    int ret = transform_generic_instruction(ts, &transl_instr, FALSE);
    if (ret){
      PRINT_DEBUG_ACTIONS("warning: transform_generic_instruction() failed\n");
      //fbt_suicide_str("failure!");
    }

    ts->tld->transl_instr = transl_instr;
  } else {
    fbt_memcpy(transl_instr, (void*)(uint64_t)ts->cur_instr, length);
    ts->tld->transl_instr += length;
  }
}

/**
 * This function transforms an x86 instruction that accesses memory
 * into a x64 leal instruction that puts the corresponding memory address 
 * in %r10. If it is not possible to do so (maybe no memory is accessed?)
 * then FALSE is returned. 
 */
BOOL transform_instruction_to_leal_if_appropriate(struct translate *ts) 
{
  /* prefetch does not really access memory (is even allowed on 
     invalid pointers). The strncmp is actually rather efficient
     since not many instructions start with 'p' */
  if (fbt_strncmp(ts->cur_instr_info->mnemonic, "prefetch", 8) == 0) {
    return FALSE;
  }

  /* a leal does not need no memory check */
  if (0x8d == *(uchar*)(uint64_t)(ts->cur_instr+ts->num_prefixes)){
    return FALSE;
  }

  uchar *transl_instr = ts->tld->transl_instr;
  /* 'the_prefix' only makes sense if there is some prefix */
  uchar the_prefix = *(char*) (uint64_t) ts->cur_instr;
  uchar *cur_instr = (uchar*) (uint64_t) (ts->cur_instr + ts->num_prefixes);

  if (ts->num_prefixes > 1) {
    /* Very rarely some programs use more than one prefix. To make them
       work nevertheless, we just skip handling these instructions. 
       We should add support to such instructions */
    PRINT_DEBUG_ACTIONS("Skipping instruction with more than one prefix.");
    //fbt_suicide_str("not implemented yet.\n"); 
    return FALSE;
  }

  if (ts->num_prefixes == 1) {
    switch (the_prefix) {
    case PREFIX_LOCK:
    case PREFIX_OP_SZ_OVR:
      /* ignore lock and operand size prefix because
       * the (effective) address is loaded not accessed */
      break;
    case PREFIX_ES_SEG_OVR:
    case PREFIX_CS_SEG_OVR:
    case PREFIX_SS_SEG_OVR:
    case PREFIX_DS_SEG_OVR:
    case PREFIX_FS_SEG_OVR:
    case PREFIX_GS_SEG_OVR:
    case PREFIX_REPNEZ:
    case PREFIX_MISC:
    case PREFIX_ADDR_SZ_OVR:
      return FALSE; /* don't translate anything */
    }
  }

  if (*cur_instr == 0xa0 || *cur_instr == 0xa1 || *cur_instr == 0xa2
      || *cur_instr == 0xa3) {
    transform_moffset_instr(ts, &ts->tld->transl_instr, TRUE);
    return TRUE;
  }

  if (hasMemOp(ts->cur_instr_info->auxFlags)) {
    fbt_suicide_str("Instruction with auxiliary memory operand not "
                    "supported yet. Unused in practice.");
  }

  unsigned char modRM = *ts->first_byte_after_opcode;

  if ((hasMemOp(ts->cur_instr_info->destFlags)
      || hasMemOp(ts->cur_instr_info->srcFlags)) && MODRM_MOD(modRM) != 0x3) {
    if (ts->num_prefixes > 1) {
      PRINT_DEBUG_ACTIONS("Attention. Handling more than one prefix.");
    }
    int ret = transform_generic_instruction(ts, &transl_instr, TRUE);
    if (ret) {
      return FALSE;
    }

    ts->tld->transl_instr = transl_instr;
    return TRUE;
  } else {
    return FALSE; /* No memory operand... nothing to do */
  }
}


enum translation_state action_copy(struct translate *ts, BOOL lock)
{
  uchar *transl_instr = ts->tld->transl_instr;
  long length = ts->next_instr - ts->cur_instr;
  const uchar * const cur_instr = (uchar*)(uint64_t)
                    (ts->cur_instr + ts->num_prefixes);

  if (*cur_instr == 0xc4 ||
      *cur_instr == 0xc5){
    fbt_suicide_str("class of instructions ( vzeroall, vmovdqu,  vpaddd...) not supported yet\n");
  }

  // print_disasm_instruction(2, ts, length);

  uchar* ci = (uchar*)(uint64_t)ts->cur_instr;

  /* See if it is an interrupt */
  if (*cur_instr == 0xcc){
    /* 0xcc - int3 (debug) */

    /* int3... useful to copy verbatim for debugging: suppose
       that an application doesn't work under translation and you
       don't know why and where. Then a good method is to do a binary
       search in the application code by inserting 'int3' at appropriate
       places and see if the translated application manages to reach
       the inserted 'int3' */
    *transl_instr++ = 0xcc;
    ts->tld->transl_instr = transl_instr;

    return NEUTRAL;
  } else if (*cur_instr == 0xcd ||    /* int imm8 */
      *cur_instr == 0xce ||           /* into */
      (*(ci+0) == 0x65 &&             /* call *%gs:0x10 (used by libc) */
          *(ci+1) == 0xff &&
          *(ci+2) == 0x15 &&
          *(ci+3) == 0x10 &&
          *(ci+4) == 0x0 &&
          *(ci+5) == 0x0 &&
          *(ci+6) == 0x0)) {

    /*
     * we just copied an interrupt
     * 0xcd - int imm8
     * 0xce - into (int 4) if overflow flag is set to 1
     * because we might execute a kernel routine (which might not return or
     * might do something funny to our stack) we finish the TU here 
        and->syscall_location)
     * issue some glue code to restart the translation if we resume after the
     * int itself
     */
    if (*(uchar*)(uint64_t)(ts->cur_instr) == 0xcd  ||
        *ci == 0x65) {

      if (*(uchar*)(uint64_t)(ts->cur_instr) == 0xcd &&
          *(uchar*)(uint64_t)(ts->first_byte_after_opcode) != 0x80) {
        PRINT_DEBUG_ACTIONS("got interrupt %x\n", *(uchar*)(uint64_t)(ts->first_byte_after_opcode));
        fbt_suicide_str("Illegal interrupt encountered (fbt_actions.c)\n");
        uchar* trd = ts->tld->transl_instr;
        BEGIN_ASM(trd)
        hlt
        hlt
        hlt
        END_ASM
        ts->tld->transl_instr = trd;
      }
      if (*cur_instr == 0x65){
        PRINT_DEBUG_ACTIONS("translating call via gs segment to syscall, as that's "
            "what glibc uses it for\n");
      }

      uchar* transl_addr = ts->tld->transl_instr;


      BEGIN_ASM(transl_addr)
      /* store location of this syscall */
      movl ${ts->cur_instr}, %r9d
      movabs_to_r8 {&(ts->tld->syscall_location)}
      movl %r9d, (%r8)

      movabs_to_r8 {&ts->tld->ind_target}
      mov %r8, %r9
      movabs_to_r8 {0xdeadbeefc0ffee}
      END_ASM
      /* pointer to 64 bit constant */
      uint64_t *ptr = (uint64_t*)(transl_addr-8);
      BEGIN_ASM(transl_addr)
      mov %r8, (%r9)
      END_ASM

      /* write: jump instruction to trampoline */
      JMP_REL32(transl_addr, ts->tld->int80_trampoline);
      *ptr = (uint64_t)(transl_addr);
      ts->tld->transl_instr = transl_addr;

      return CLOSE_GLUE;

    } else {

      fbt_memcpy(transl_instr, (void*)(uint64_t)ts->cur_instr, length);
      ts->tld->transl_instr += length;

      return CLOSE_GLUE;
    }

    PRINT_DEBUG_ACTIONS("Encountered an interrupt - closing TU with some glue code\n");

  }

  transform_instruction(ts);

  return NEUTRAL;
}

enum translation_state action_warn(struct translate *ts, BOOL lock) {
  PRINT_DEBUG_FUNCTION_START("action_warn(*ts=%p)", ts);
  PRINT_DEBUG_ACTIONS("Will try if it works to simply copy the instruction into the "
                      "code cache, but something bad could happen now...");
  PRINT_DEBUG_FUNCTION_END("-> ???");
  //fbt_suicide_str("action_warn... suiciding\n");
  return action_copy(ts, lock);
}

enum translation_state action_fail(struct translate *ts, BOOL lock)
{
  PRINT_DEBUG_FUNCTION_START("action_fail(*ts=%p)", ts);
  PRINT_DEBUG_ACTIONS("giving up!!!");
  PRINT_DEBUG_FUNCTION_END("-> FAIL");
  fbt_suicide(255);
  return CLOSE;
}

enum translation_state action_push(struct translate *ts, BOOL lock)
{
  unsigned char* transl_addr = ts->tld->transl_instr;
  unsigned char fstopcode = *(unsigned char*)(uint64_t)
                        (ts->cur_instr + ts->num_prefixes);

  uchar segopref = 0x0; /* none */

  if (ts->num_prefixes > 0){
    if (ts->num_prefixes == 1 &&
        *(uchar*)(uint64_t)ts->cur_instr == 0x65){
      segopref = 0x65;
    } else {
      PRINT_DEBUG_ACTIONS("push pref not supported at %x\n",ts->cur_instr);
      fbt_suicide_str("prefixes not supported yet in push");
    }
  }

  if (0x50 <= fstopcode && fstopcode <= 0x57){
    /* push register */
    int regnr = fstopcode - 0x50;

    /* Important: push %esp pushes the *old* value of esp. */

    /* mov reg, 4(%esp)
       4004b8: 67 89 44 24 04       	mov    %eax,0x4(%esp) */

    *(transl_addr++) = 0x67;
    *(transl_addr++) = 0x89;
    *(transl_addr++) = 0x44 | (regnr << 3);
    *(transl_addr++) = 0x24;
    *(transl_addr++) = 0xfc;

    DEC_ESP_BY_FOUR(transl_addr);

  } else {
    switch (fstopcode){
    case 0x60:
      fbt_suicide_str("pusha");
      break;

    case 0x68:

      /* From objdump 32 bit: "68 ef be ad de  push $0xdeadbeef" */

      /* We assume 32 bit push since we do not support 16 bit programs */

      DEC_ESP_BY_FOUR(transl_addr);

      /* From objdump 64 bit: "67 c7 04 24 ef be ad de  movl $0xdeadbeef,(%esp)" */
      *(transl_addr++) = 0x67;
      *(transl_addr++) = 0xc7;
      *(transl_addr++) = 0x04;
      *(transl_addr++) = 0x24;
      *(uint32_t*)transl_addr = *(uint32_t*)(uint64_t)
                           (ts->cur_instr + ts->num_prefixes + 1);
      transl_addr += 4;
      break;
    case 0x6A:
      /* 6a 17   push $0x17 */

      DEC_ESP_BY_FOUR(transl_addr);

      *(transl_addr++) = 0x67;
      *(transl_addr++) = 0xc7;
      *(transl_addr++) = 0x04;
      *(transl_addr++) = 0x24;
      uchar theimm = *(uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1);
      *(transl_addr++) = theimm;
      if (theimm & 0x80){
        *(transl_addr++) = 0xff;
        *(transl_addr++) = 0xff;
        *(transl_addr++) = 0xff;
      } else {
        *(transl_addr++) = 0x00;
        *(transl_addr++) = 0x00;
        *(transl_addr++) = 0x00;
      }
      break;

    case 0x9c:

      /* Do a 32 bit pushf */
      BEGIN_ASM(transl_addr)
        nop; nop;
        mov %rsp, %r9                      /* save stack pointer */
        movabs_to_r8 {&ts->tld->tmps[2]}   /* address of mini stack in r8 */
        mov %r8, %rsp                      /* switch to mini tmp stack */
        pushf                              /* 64 bit pushf */
        movl (%rsp), %r8d                  /* put the relevant 32 bits in r8d */
        movl %r8d, -4(%r9)                 /* store them on the right place on (saved) application stack */
        lea -4(%r9), %rsp                  /* restore and decrement the stack pointer by four */
        nop; nop;
      END_ASM

      break;

    case 0xff:
      /*
       * I deduced the rules for this case by examining objdump's output
       *
       32 BIT OBJDUMP:

       8048397:	ff 35 ee db ea 0d    	pushl  0xdeadbee
       804839d:	ff b4 98 ee db ea 0d 	pushl  0xdeadbee(%eax,%ebx,4)

       8048397:	ff 75 1c             	pushl  0x1c(%ebp)
       804839a:	ff 72 1c             	pushl  0x1c(%edx)

       64 BIT OBJDUMP:

       4004b8:	44 8b 04 25 ee db ea 	mov    0xdeadbee,%r8d
       4004bf:	0d
       4004c0:	67 44 8b 84 98 ee db 	mov    0xdeadbee(%eax,%ebx,4),%r8d
       4004c7:	ea 0d
       4004c9:	67 44 8b 84 b9 ee db 	mov    0xdeadbee(%ecx,%edi,4),%r8d
       4004d0:	ea 0d
       4004d2:	67 44 8b 84 b2 ee db 	mov    0xdeadbee(%edx,%esi,4),%r8d
       4004d9:	ea 0d
       4004db:	67 44 8b 84 80 ee db 	mov    0xdeadbee(%eax,%eax,4),%r8d
       4004e2:	ea 0d
       4004e4:	67 44 8b 84 bf ee db 	mov    0xdeadbee(%edi,%edi,4),%r8d
       4004eb:	ea 0d
       */

      ; /* needed */
      uchar *afteropc =
          (uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1);
      uchar modRM = *afteropc;

      if (segopref){
        *(transl_addr++) = segopref;
      }
      BOOL has_sib = MODRM_RM(modRM) == 0x4 && MODRM_MOD(modRM) != 3;
      if (has_sib) {
        uchar sib = *(afteropc+1);

        switch (MODRM_MOD(modRM)){
        case 0:
          if (MODRM_RM(modRM) == 5){
            fbt_suicide("not implemented since unused in practice (modRM 5).");
          } else {
            if (SIB_BASE(sib) == 5){
              if (MODRM_MOD(modRM)==0){
                *(transl_addr++) = 0x67;
                *(transl_addr++) = 0x44;
                *(transl_addr++) = 0x8b;
                *(transl_addr++) = 0x04;
                *(transl_addr++) = *(afteropc+1);
                *(transl_addr++) = *(afteropc+2);
                *(transl_addr++) = *(afteropc+3);
                *(transl_addr++) = *(afteropc+4);
                *(transl_addr++) = *(afteropc+5);
              } else if (MODRM_MOD(modRM)==1){
                fbt_suicide_str("not implemented since unused in practice (modRM 1).");
              } else if (MODRM_MOD(modRM)==2){
                fbt_suicide_str("not implemented since unused in practice (modRM 2).");
              } else {
                fbt_suicide_str("should never be reached.");
              }
            } else {
              *(transl_addr++) = 0x67;
              *(transl_addr++) = 0x44;
              *(transl_addr++) = 0x8b;
              *(transl_addr++) = 0x04;
              *(transl_addr++) = *(afteropc+1);
            }
          }
          break;
        case 1:
          *(transl_addr++) = 0x67;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = 0x8b;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = *(afteropc+1);
          *(transl_addr++) = *(afteropc+2);
          break;
        case 2:
          *(transl_addr++) = 0x67;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = 0x8b;
          *(transl_addr++) = 0x84;
          *(transl_addr++) = *(afteropc+1);
          *(transl_addr++) = *(afteropc+2);
          *(transl_addr++) = *(afteropc+3);
          *(transl_addr++) = *(afteropc+4);
          *(transl_addr++) = *(afteropc+5);
          break;
        default:
          fbt_suicide_str("should never be reached.");
        }

      } else if (MODRM_RM(modRM) == 0x05 && MODRM_MOD(modRM) == 0){
        // A disp32 follows, but the instruction doesn't have a
        // sib byte.

        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = 0x04;
        *(transl_addr++) = 0x25;
        *(transl_addr++) = *(afteropc+1);
        *(transl_addr++) = *(afteropc+2);
        *(transl_addr++) = *(afteropc+3);
        *(transl_addr++) = *(afteropc+4);

      } else {
        switch (MODRM_MOD(modRM)) {
        case 1:

          /* disp8 */
          *(transl_addr++) = 0x67;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = 0x8b;
          *(transl_addr++) = 0x40 | (*(afteropc) & 0x07);
          *(transl_addr++) = *(afteropc+1);

          break;

        case 0:

          /* faa */
          *(transl_addr++) = 0x67;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = 0x8b;
          *(transl_addr++) = *(afteropc) & 0x07;


          break;

        case 2:

          /* disp32 */

          *(transl_addr++) = 0x67;
          *(transl_addr++) = 0x44;
          *(transl_addr++) = 0x8b;
          *(transl_addr++) = 0x80 | (*(afteropc) & 0x07);
          *(transl_addr++) = *(afteropc+1);
          *(transl_addr++) = *(afteropc+2);
          *(transl_addr++) = *(afteropc+3);
          *(transl_addr++) = *(afteropc+4);

          break;

        default:

          fbt_suicide_str("unhandled case in push.\n");
        }
      }

      DEC_ESP_BY_FOUR(transl_addr);

      /* 67 44 89 04 24       	mov    %r8d,(%esp) */
      *(transl_addr++) = 0x67;
      *(transl_addr++) = 0x44;
      *(transl_addr++) = 0x89;
      *(transl_addr++) = 0x04;
      *(transl_addr++) = 0x24;

      break;
    default:
      fbt_suicide_str("unknown push opcode");
    }

  }


  ts->tld->transl_instr = transl_addr;

  return NEUTRAL;
}

enum translation_state action_pop(struct translate *ts, BOOL lock)
{
  unsigned char* transl_addr = ts->tld->transl_instr;

  unsigned char fstopcode = *(unsigned char*)(uint64_t)(ts->cur_instr + ts->num_prefixes);

  if (ts->num_prefixes > 0){
    PRINT_DEBUG_ACTIONS("push pref not supported at %x\n",ts->cur_instr);
    fbt_suicide_str("prefixes not supported yet in push");
  }

  if (0x58 <= fstopcode && fstopcode <= 0x5f){
    int regnr = fstopcode - 0x58;

    /* Important: this ordering is meant so that pop esp works */

    INC_ESP_BY_FOUR(transl_addr);

    /* mov -4(%esp), reg */
    *(transl_addr++) = 0x67;
    *(transl_addr++) = 0x8b;
    *(transl_addr++) = 0x44 | (regnr << 3);
    *(transl_addr++) = 0x24;
    *(transl_addr++) = 0xfc;

  } else {
    switch (fstopcode) {
    case 0xc9: /* leave */
      /*
	89 ec          mov %ebp,%esp
	67 8b 2c 24    mov (%esp),%ebp
	67 8d 64 24 04 lea 0x4(%esp),%esp
       */
      *(transl_addr++) = 0x89;
      *(transl_addr++) = 0xec;
      *(transl_addr++) = 0x67;
      *(transl_addr++) = 0x8b;
      *(transl_addr++) = 0x2c;
      *(transl_addr++) = 0x24;
      *(transl_addr++) = 0x67;
      *(transl_addr++) = 0x8d;
      *(transl_addr++) = 0x64;
      *(transl_addr++) = 0x24;
      *(transl_addr++) = 0x04;
      break;

    case 0x9d:

      /* Do a 32 bit popf */
      BEGIN_ASM(transl_addr)
        nop; nop;
        mov %rsp, %r9                     /* save stack pointer */
        movabs_to_r8 {&ts->tld->tmps[2]}  /* address of mini stack in r8 */
        mov %r8, %rsp                     /* switch to mini tmp stack */
        movl (%r9), %r8d                  /* saved eflags in r8d */
        push %r8                          /* 64 bit push */
        popf                              /* 64 bit popf */
        lea 4(%r9), %rsp                  /* restore and increment the stack pointer by four */
        nop; nop;
      END_ASM

      break;

    default:
      fbt_suicide_str("unsupported one-byte pop");
      break;
    }
  }

  ts->tld->transl_instr = transl_addr;

  return NEUTRAL;
}


enum translation_state action_inc(struct translate *ts, BOOL lock)
{
  unsigned char* addr = (unsigned char*)(uint64_t)ts->cur_instr;
  unsigned char* transl_addr = ts->tld->transl_instr;
  long length = ts->next_instr - ts->cur_instr;

  unsigned char fstopcode = *(unsigned char*)(uint64_t)(ts->cur_instr + ts->num_prefixes);

  if (0x40 <= fstopcode && fstopcode <=  0x47){

    /* These need special handling since these
       opcodes have changed their meaning and are
       used as prefixes that specify 64 bit specific
       stuff.
       Nevertheless one can always find an equivalent 'inc'. */

    /* copy the prefixes verbatim (if any) */
    uchar* it = (uchar*)(uint64_t)ts->cur_instr;
    for (int i=0; i<ts->num_prefixes; i++){
      *(transl_addr++) = *(it++);
    }

    /* Use the alternative two byte encoding (nice solution) */
    int regnr = fstopcode - 0x40;
    *(transl_addr++) = 0xff;
    *(transl_addr++) = 0xc0 | regnr;

  } else {
    /* To my knowledge all other incs can be copied verbatim */

    fbt_memcpy(transl_addr, addr, length);
    transl_addr += length;
  }

  ts->tld->transl_instr = transl_addr;

  return NEUTRAL;
}

/**
 * Needed in order to handle the single-byte inc and dec
 * because these do not longer exist in 64 bit mode.
 */
enum translation_state action_dec(struct translate *ts, BOOL lock)
{
  unsigned char* addr = (unsigned char*)(uint64_t)ts->cur_instr;
  unsigned char* transl_addr = ts->tld->transl_instr;
  long length = ts->next_instr - ts->cur_instr;

  unsigned char fstopcode = *(unsigned char*)(uint64_t)(ts->cur_instr + ts->num_prefixes);

  if (0x48 <= fstopcode && fstopcode <=  0x4f){

    /* These need special handling since these
       opcodes have changed their meaning and are
       used as prefixes that specify 64 bit specific
       stuff. */

    /* copy the prefixes verbatim (if any) */
    uchar* it = (uchar*)(uint64_t)ts->cur_instr;
    for (int i=0; i<ts->num_prefixes; i++){
      *(transl_addr++) = *(it++);
    }

    /* Use the alternative two byte encoding (nice solution) */
    int regnr = fstopcode - 0x48;
    *(transl_addr++) = 0xff;
    *(transl_addr++) = 0xc8 | regnr;

  } else {
    /* All other decs can be copied verbatim */
    fbt_memcpy(transl_addr, addr, length);
    transl_addr += length;
  }

  ts->tld->transl_instr = transl_addr;

  return NEUTRAL;
}


enum translation_state action_jmp(struct translate *ts, BOOL lock)
{
  unsigned char* addr  = (unsigned char*)(uint64_t)ts->cur_instr;

  unsigned char *original_addr = addr;

  PRINT_DEBUG_ACTIONS("original_addr=%x / addr=%x\n", original_addr, addr);

#ifdef DEBUG
  unsigned char* transl_addr = ts->tld->transl_instr;
#endif
  int length = ts->next_instr - ts->cur_instr;

  PRINT_DEBUG_FUNCTION_START("action_jmp(*addr=%p, *transl_addr=%p, length=%i)",
      addr, transl_addr, length);

  PRINT_DEBUG_ACTIONS("action_jmp\n");

  /* read call argument (either 8bit or 32bit offset) and add EIP (EIP = addr +
     length) to argument --> absolute target address = addr + length + offset */
  assert(!HAS_PREFIX(*addr)); /* no prefixes allowed */

  guestptr_t jump_target=0;
  if (*addr == 0xE9) {
    /* 32bit offset */
    jump_target = *((int32_t*)(addr + 1)) + (int32_t)(int64_t)original_addr + length;
    PRINT_DEBUG_ACTIONS("jump_target = %x + %x + %x\n", *(int32_t*)(addr + 1), original_addr, length);
  } else {
    /* our argument is only an 8bit offset */
    jump_target = (int32_t)(*((char*)(addr + 1)) + (int32_t)(int64_t)original_addr + length);
    PRINT_DEBUG_ACTIONS("jump_target 8 bit target\n");
  }

  PRINT_DEBUG_ACTIONS("original jmp_target: %p\n", jump_target);

  /* we still have to translate the call target */
  PRINT_DEBUG_FUNCTION_END("-> open, transl_length=0");
  /* no need to actually jump
     simply change the next instr pointer to the first instr of the function
     this will put the body of the function right as the next instr in the
     translated code */
  ts->next_instr = jump_target;
  /* put the target into the tcache so later jumps can use the translated
     code */
  PRINT_DEBUG_ACTIONS("ts nextinstr open: %p\n", ts->next_instr);

  return OPEN;
}

/**
 * Helper function used by action_jmp_indirect():
 * Input: ts has disassembled an indirect jump instruction
 * Output: a code that stores the destination of the indirect
 *         jump in r8d is written at the location *transl_addr_ptr
 * This function has associated unit tests that specify it.
 */
void jump_target_into_r8(struct translate* ts, unsigned char** transl_addr_ptr) 
{

  unsigned char* transl_addr = *transl_addr_ptr; // remember to update on return
  /*
    ff a4 bf ee db ea 0d 	jmp    *0xdeadbee(%edi,%edi,4)
    ff a4 06 ee db ea 0d 	jmp    *0xdeadbee(%esi,%eax,1)
    ff a4 cb ee db ea 0d 	jmp    *0xdeadbee(%ebx,%ecx,8)
    ff 24 bd ee db ea 0d 	jmp    *0xdeadbee(,%edi,4)
    ff a3 ee db ea 0d    	jmp    *0xdeadbee(%ebx)



    ff 20                	jmp    *(%eax)
    ff 22                	jmp    *(%edx)
   */

  /*
    ff 94 bf ee db ea 0d  call   *0xdeadbee(%edi,%edi,4)
    ff 94 06 ee db ea 0d 	call   *0xdeadbee(%esi,%eax,1)
    ff 94 cb ee db ea 0d 	call   *0xdeadbee(%ebx,%ecx,8)
    ff 14 bd ee db ea 0d 	call   *0xdeadbee(,%edi,4)
    ff 93 ee db ea 0d    	call   *0xdeadbee(%ebx)
    ff 15 ee db ea 0d    	call   *0xdeadbee
    ff 10                	call   *(%eax)
    ff 12                	call   *(%edx)
   */

  uchar *afteropc = (uchar*)(uint64_t)(ts->cur_instr + ts->num_prefixes + 1);

  if (ts->num_prefixes > 0){
    if (ts->num_prefixes == 1 &&
        0x65 == *(char*)(uint64_t)ts->cur_instr){
      *(transl_addr++) = 0x65;
    } else {
      PRINT_DEBUG_ACTIONS("warning: possibly currently not supported amount of prefixes! err 72983\n");
      //fbt_suicide_str("currently not suppppp! err 72983\n");
    }
  }

  if (hasModRMOp(ts->cur_instr_info->destFlags) ||
      hasModRMOp(ts->cur_instr_info->srcFlags)) {

    uchar modRM = *afteropc;
    BOOL has_sib = MODRM_RM(modRM) == 0x4 && MODRM_MOD(modRM) != 3;
    if (has_sib) {
      uchar sib = *(afteropc+1);

      // for example     jmp *0x0a(%ebx, %eax, 4)

      switch(MODRM_MOD(modRM)){
      case 0: // 0 byte displ

        if (MODRM_RM(modRM) == 5){
          fbt_suicide("not implem rm 5!!!!1");
        } else {

          if (SIB_BASE(sib) == 5){
            if (MODRM_MOD(modRM)==0){
              *(transl_addr++) = 0x67;
              *(transl_addr++) = 0x44;
              *(transl_addr++) = 0x8b;
              *(transl_addr++) = 0x04;
              *(transl_addr++) = *(afteropc+1);
              *(transl_addr++) = *(afteropc+2);
              *(transl_addr++) = *(afteropc+3);
              *(transl_addr++) = *(afteropc+4);
              *(transl_addr++) = *(afteropc+5);
            } else if (MODRM_MOD(modRM)==1){
              fbt_suicide_str("untested");
            } else if (MODRM_MOD(modRM)==2){
              fbt_suicide_str("untested");
            } else {
              fbt_suicide_str("impossible");
            }
          } else {
            *(transl_addr++) = 0x67;
            *(transl_addr++) = 0x44;
            *(transl_addr++) = 0x8b;
            *(transl_addr++) = 0x04;
            *(transl_addr++) = *(afteropc+1);
          }
        }
        break;

      case 1: // 1 byte displ
        *(transl_addr++) = 0x67;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = *(afteropc+1);
        *(transl_addr++) = *(afteropc+2);
        break;

      case 2: // 4 byte displ
        *(transl_addr++) = 0x67;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = 0x84;
        *(transl_addr++) = *(afteropc+1);
        *(transl_addr++) = *(afteropc+2);
        *(transl_addr++) = *(afteropc+3);
        *(transl_addr++) = *(afteropc+4);
        *(transl_addr++) = *(afteropc+5);
        break;

      default:
        fbt_suicide_str("impossible case!!!! jklflkjsadfj");
      }
    } else if (MODRM_RM(modRM) == 0x05 && MODRM_MOD(modRM) == 0){

      // ff 25 ee db ea 0d        jmp *0xdeadbee

      // A disp32 follows, but the instruction doesn't have a
      // sib byte.

      *(transl_addr++) = 0x44;
      *(transl_addr++) = 0x8b;
      *(transl_addr++) = 0x04;
      *(transl_addr++) = 0x25;
      *(transl_addr++) = *(afteropc+1);
      *(transl_addr++) = *(afteropc+2);
      *(transl_addr++) = *(afteropc+3);
      *(transl_addr++) = *(afteropc+4);

    } else {
      switch (MODRM_MOD(modRM)) {
      case 1:
        // for example   jmp *0x0a(%ebx)

        /* disp8 */
        *(transl_addr++) = 0x67;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = 0x40 | (*(afteropc) & 0x07);
        *(transl_addr++) = *(afteropc+1);

        break;

      case 0:
        // FOR EXAMPLE jmp *(%ebx)
        *(transl_addr++) = 0x67;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = *(afteropc) & 0x07;
        break;

      case 2:
        /* disp32 */
        // for example  jmp *0xdeadfee(%ebx)
        *(transl_addr++) = 0x67;
        *(transl_addr++) = 0x44;
        *(transl_addr++) = 0x8b;
        *(transl_addr++) = 0x80 | (*(afteropc) & 0x07);
        *(transl_addr++) = *(afteropc+1);
        *(transl_addr++) = *(afteropc+2);
        *(transl_addr++) = *(afteropc+3);
        *(transl_addr++) = *(afteropc+4);
        break;

      case 3:

        // for example  jmp *%eax
        *(transl_addr++) = 0x41;
        *(transl_addr++) = 0x89;
        *(transl_addr++) = 0xc0 | (((*afteropc)&0x07)<<3);
        break;

      default:
        fbt_suicide_str("jump_target_into_r8: unreachable code");
      }
    }
  } else {
    fbt_suicide_str("doesnt happen\n");
  }

  *transl_addr_ptr = transl_addr;
}


enum translation_state action_jmp_indirect(struct translate *ts, BOOL lock)
{
  unsigned char* transl_addr = ts->tld->transl_instr;

  PRINT_DEBUG_FUNCTION_START("action_jmp_indirect(*addr=%p, *transl_addr=%p, " \
      "length=%i)", \
      (uchar*)(uint64_t)ts->cur_instr, \
      transl_addr,  \
      (ts->next_instr - ts->cur_instr));

  PRINT_DEBUG_ACTIONS("action jmp ind\n");

  if (ts->num_prefixes != 0) {
    /* no prefixes allowed */
    PRINT_DEBUG_ACTIONS("push pref not supported at %x\n",ts->cur_instr);
    fbt_suicide_str("No prefixes handled in action_jmp_indirect! " \
        "(fbt_actions.c)\n");
  }

  /* this is a fast version of the ind jmp - handoptimized assembler code
   * which does a fast lookup in the hashtable and dispatches if it hits
   * otherwise it recovers to an indirect jump
   */

  // make sure our assumptino holds
  if (*(uchar*)(uint64_t)(ts->cur_instr+ts->num_prefixes) != 0xff) {
    fbt_suicide_str("No t supp!!!");
  }

  // generate code that puts the place where we want
  // to jump to into %r8
  jump_target_into_r8(ts, &transl_addr);

  // and go to the ijump trampoline!
  JMP_REL32(transl_addr, ts->tld->opt_ijump_trampoline);

  PRINT_DEBUG_FUNCTION_END("-> close, transl_length=%i",
      transl_addr - ts->tld->transl_instr);
  ts->tld->transl_instr = transl_addr;

  return CLOSE;
}

enum translation_state action_call_indirect(struct translate *ts, BOOL lock)
{
  unsigned char* transl_addr = ts->tld->transl_instr;

  PRINT_DEBUG_FUNCTION_START("action_call_indirect(*addr=%p, *transl_addr=%p, " \
      "length=%i)", \
      (uchar*)(uint64_t)ts->cur_instr, \
      transl_addr,  \
      (ts->next_instr - ts->cur_instr));

  /* this is a fast version of the ind jmp - handoptimized assembler code
   * which does a fast lookup in the hashtable and dispatches if it hits
   * otherwise it recovers to an indirect jump
   */

  // make sure our assumptino holds
  if (*(uchar*)(uint64_t)(ts->cur_instr+ts->num_prefixes) != 0xff) {
    fbt_suicide_str("No t supp!!!");
  }

  // generate code that puts the place where we want
  // to jump to into %r8
  jump_target_into_r8(ts, &transl_addr);

  /* do a 32 bit push of the ip of the next instruction
   * just as the regular icall does */
  BEGIN_ASM(transl_addr)
  lea -4(%rsp), %rsp
  movl ${ts->next_instr}, (%rsp)
  END_ASM

  // and go to the ijump trampoline!
  JMP_REL32(transl_addr, ts->tld->opt_icall_trampoline);

  PRINT_DEBUG_FUNCTION_END("-> close, transl_length=%i",
      transl_addr - ts->tld->transl_instr);
  ts->tld->transl_instr = transl_addr;

  return CLOSE;
}

enum translation_state action_call(struct translate *ts,
                                   BOOL lock) 
{
  unsigned char *addr = (unsigned char*)(uint64_t)ts->cur_instr;

  guestptr_t original_addr = (guestptr_t)(uint64_t)addr;

  unsigned char* transl_addr = ts->tld->transl_instr;
  int length = ts->next_instr - ts->cur_instr;

  PRINT_DEBUG_ACTIONS("action_call\n");

  const guestptr_t return_addr = ts->next_instr;

  PRINT_DEBUG_FUNCTION_START("action_call(*addr=%p, *transl_addr=%p," \
                             " length=%i)", addr, transl_addr, length);

  /* total length of a call we handle must be 5, otherwise we have prefixes and
     such in our stream */
  assert(length == 5 && !HAS_PREFIX(*addr));

  /* our opcode should be 0xE8, a near relative call */

  /* read call argument (32bit immediate) and add EIP (EIP = addr + length) to
     argument --> absolute target address */
  guestptr_t call_target = *((uint32_t*) (addr + 1)) + original_addr + length;
  PRINT_DEBUG_ACTIONS("original call_target: %p", (void*)(uint64_t)call_target);

  /* let's check if this call only wants to get the EIP, following conditions
   * must hold:
   *  - the next instruction is called (imm. following, so rel. addr is 0x0
   *  - the next instruction is a pop %reg.
   * assembly code: call return_addr, pop %reg
   */
  if (*((uint32_t*) (addr + 1)) == 0x0 && 
      *((unsigned char*)(uint64_t)return_addr) >= 0x58 && 
      *((unsigned char*)(uint64_t)return_addr) <= 0x5F) {

    BEGIN_ASM(transl_addr)
              leal -4(%esp), %esp
              movl ${return_addr}, (%esp)
              END_ASM
              PRINT_DEBUG_FUNCTION_END("-> open, transl_length=%i",
                  transl_addr - ts->tld->transl_instr);
              ts->tld->transl_instr = transl_addr;

              return OPEN;
  }

  /* write: push original EIP (we have to do this either way) */
  // 64bit needs a 64bit push!
  guestptr_t return_address = return_addr;
  PRINT_DEBUG_ACTIONS("return_address = %x\n", return_address);

  BEGIN_ASM(transl_addr)
  leal -4(%esp), %esp
  movl ${return_address}, (%esp)
  END_ASM

#ifdef FAST_RET

  BEGIN_ASM(transl_addr)
  movl ${return_addr}, %r13d
  END_ASM
  int foo = 0xdadada;
  BEGIN_ASM(transl_addr)
  movabs_to_r14 {foo}
  END_ASM
  void** wheretoputit = (void**)(uint64_t)(transl_addr-8);

  /* check if target is already translated; if not, do so now */
  void *transl_retaddr = fbt_ccache_find(ts->tld, return_addr);
  if (transl_retaddr == NULL){
    ts->tld->totrans[ts->tld->totranslate_stacktop] = return_addr;
    ts->tld->topatch[ts->tld->totranslate_stacktop] = wheretoputit;
    if (ts->tld->totranslate_stacktop >= 64){
      fbt_suicide_str("way too much on stk\n");
    }
    ts->tld->totranslate_stacktop++;
  } else {
    *wheretoputit = transl_retaddr;
  }
#endif

  /* we still have to translate the call target */
  PRINT_DEBUG_FUNCTION_END("-> open, transl_length=%i",
      transl_addr - ts->tld->transl_instr);
  ts->tld->transl_instr = transl_addr;
  /* No need to actually call the function.
     Simply change the next instr pointer to the first instr of the function.
     This will put the body of the function right as the next instr in the
     translated code */
  ts->next_instr = call_target;

  return OPEN;
}

enum translation_state action_jcc(struct translate *ts, BOOL lock) 
{
  guestptr_t addr = ts->cur_instr;
  unsigned char* transl_addr = ts->tld->transl_instr;
  int length = ts->next_instr - ts->cur_instr;

  PRINT_DEBUG_ACTIONS("action_jcc\n");

  guestptr_t original_addr = addr;
  guestptr_t virtual_fallthrough = ts->next_instr;

  PRINT_DEBUG_FUNCTION_START("action_jcc(*addr=%p, *transl_addr=%p, length=%i)",
      addr, transl_addr, length);

  guestptr_t jump_target;
  guestptr_t fallthru_target;
  void* transl_target;

  if (ts->num_prefixes != 0) {
    PRINT_DEBUG_ACTIONS("Instruction at %p uses prefixes (len: %d)!\n", addr, length);
    if (*(unsigned char*)(uint64_t)addr == PREFIX_FS_SEG_OVR) {
      addr++;
      length--;
    } else
      fbt_suicide_str("No prefixes handled in action_jcc! (fbt_actions.c)\n");
  }
  assert((*(unsigned char*)(uint64_t)addr == 0x0F && length == 6) || 
      (length == 2));

  /* check if we have jecxz (jump if ecx register is zero) */
  if (*(unsigned char*)(uint64_t)addr == 0xE3) {
    PRINT_DEBUG_ACTIONS("processing jecxz");

    /* This is a little tricky. because JECXZ has only a 8bit offset we can not
       jmp directly to the trampoline therefore two unconditional jumps are
       inserted. first the unconditional jmp for the fall through target and
       then the jmp for the original jump target. A JECXZ inst is then used to
       jump over the jump of the fall through target if the RCX register is
       zero */

    /* calculate the jump targets */
    fallthru_target = original_addr + length;
    jump_target = *((unsigned char*)(uint64_t)(addr + 1)) + fallthru_target;

    /* insert a jecxz to jump over the fall through jump if CX is 0 */
    JECXZ_I8(transl_addr, 0x05);

    /* write: jump to trampoline for fallthrough address */
    /* create trampoline if one is needed, otherwise lookup and go */

    transl_target = fbt_ccache_find(ts->tld, virtual_fallthrough);
    if (transl_target != 0) {
      BEGIN_ASM(transl_addr)
                jmp_abs {transl_target}
      END_ASM
    } else {
      struct trampoline *trampo =
          fbt_create_trampoline(ts->tld,
              virtual_fallthrough,
              (void*)(transl_addr+1),
              ORIGIN_RELATIVE,
              lock);
      BEGIN_ASM(transl_addr)
      jmp_abs {trampo->code}
      END_ASM
    }

    /* if we have an jecxz then the jump target comes second (switchted)
       but we can use the code from the normal jcc, so we don't need to copy
       the jmp_rel32 and all */
    PRINT_DEBUG_ACTIONS("jcc switching trick\n");
    fallthru_target = jump_target;
  } else {
    int16_t jcc_type;
    if (*(unsigned char*)(uint64_t)addr != 0x0F) {
      /* find out if we have a one-byte or a two-byte opcode */
      PRINT_DEBUG_ACTIONS("processing one-byte jcc");
      /* write two-byte jcc equivalent to the one-byte jcc */
      /* the trick is: opcode + 0x10 = second byte of twobyte Jcc instruction */
      jcc_type = 0x0F + ((*(unsigned char*)(uint64_t)addr+0x10)<<8);

      fallthru_target = original_addr + length;
      jump_target = *((char*)(uint64_t)(addr + 1)) + fallthru_target;

    } else {
      PRINT_DEBUG_ACTIONS("processing two-byte jcc");
      /* write: copy of two-byte jcc */
      jcc_type = *((int16_t*)(uint64_t)addr);

      fallthru_target = (uint64_t)original_addr + length;
      jump_target = *((uint32_t*)(uint64_t)(addr + 2)) + fallthru_target;

    }

    /* write: jump address to trampoline; create trampoline if one is needed,
       otherwise lookup and go */
    transl_target = fbt_ccache_find(ts->tld, jump_target);
    if ( transl_target != NULL ) {
      JCC_2B(transl_addr, jcc_type, (uint64_t)transl_target);
    } else {
      struct trampoline *trampo =
          fbt_create_trampoline(ts->tld,
              jump_target,
              (void*)(((uint64_t)transl_addr)+2), 
              ORIGIN_RELATIVE,
              lock);
      JCC_2B(transl_addr, jcc_type, (uint64_t)(trampo->code));
    }
  }

  /* write: jump to trampoline for fallthrough address */
  transl_target = fbt_ccache_find(ts->tld, fallthru_target);
  if ( transl_target != NULL ) {
    JMP_REL32(transl_addr, (uint64_t)transl_target);
  } else {
    struct trampoline *trampo =
        fbt_create_trampoline(ts->tld,
            fallthru_target,
            (void*)((uint64_t)(transl_addr)+1),
            ORIGIN_RELATIVE,
            lock);
    BEGIN_ASM(transl_addr)
    jmp_abs {trampo->code}
    END_ASM
  }

  PRINT_DEBUG_FUNCTION_END("-> close, transl_length=%i",
      transl_addr - ts->tld->transl_instr);
  ts->tld->transl_instr = transl_addr;
  return CLOSE;
}

enum translation_state action_sysenter(struct translate *ts, BOOL lock) {

  /* We can support all programs used in practice without needing to
     support sysenter directly, since we detect the jump to %gs:0x10. 
     If you would like to support it, it should be easy to implement it
     just like the int80h handling */
  fbt_suicide_str("sysenter supported only indirectly through %gs:0x10.");
  return CLOSE;
}

enum translation_state action_ret(struct translate *ts, BOOL lock) 
{
  unsigned char *addr = (unsigned char*)(uint64_t)ts->cur_instr;
  unsigned char* transl_addr = ts->tld->transl_instr;
  unsigned char *first_byte_after_opcode = ts->first_byte_after_opcode;

#ifdef DEBUG
  int length = ts->next_instr - ts->cur_instr;
  PRINT_DEBUG_FUNCTION_START("action_ret(*addr=%p, *transl_addr=%p, length=%i)",
      addr, transl_addr, length);

  /* ret plus evtl imm16 - no opcode prefixes */
  assert((!HAS_PREFIX(*addr) && ((*addr==0xC2 && length==3) ||          \
      (*addr==0xC3 && length==1))) ||        \
      (*addr==PREFIX_MISC &&  ((*(addr+1)==0xC2 && length==4) ||     \
          (*(addr+1)==0xC3 && length==2))));

  /* see: http://readlist.com/lists/gcc.gnu.org/gcc-help/1/8765.html */
  if (!(!HAS_PREFIX(*addr) && ((*addr==0xC2 && length==3) || \
      (*addr==0xC3 && length==1))) \
      && *addr==PREFIX_MISC) {
    PRINT_DEBUG_ACTIONS("Useless REPZ Prefix found (and removed) in RET (ugly gcc " \
                        "hack for Athlon and K8)");
  }
#endif

  /* useless prefix found, skip to the real ret instr */
  if (*addr == PREFIX_MISC) {
    addr++;
  }

  /*
   * This is the simple case, we just replace the ret
   * with an indirect jump that translates the control flow
   * back to the callee (no optimization)
   */
  if (*addr == 0xc2) {
    /* this ret wants to pop some bytes of the stack */

    int16_t rem_bytes = *((int16_t*)first_byte_after_opcode);
    PRINT_DEBUG_ACTIONS("we must remove additional bytes: %d\n", rem_bytes);
    if (rem_bytes < 0) {
      fbt_suicide_str("Ret removes a negative amount of bytes, this is "
                      "illegal! (fbt_actions.c)\n");
    }

    BEGIN_ASM(transl_addr)
      movl (%rsp), %r8d
      lea 4(%rsp), %rsp
      lea {rem_bytes}(%rsp), %rsp
      jmp_abs {ts->tld->opt_ret_trampoline}
    END_ASM

  } else if (*addr == 0xc3) {
    /* Normal ret */
    BEGIN_ASM(transl_addr)
      movl (%rsp), %r8d
      lea 4(%rsp), %rsp
#ifdef FAST_RET
      cmp %r8d, %r13d
      jne_abs {ts->tld->opt_ret_trampoline}
      jmp *%r14
#else
      jmp_abs {ts->tld->opt_ret_trampoline}
#endif
    END_ASM
  }

  PRINT_DEBUG_FUNCTION_END("-> close, transl_length=%i",
      transl_addr - ts->tld->transl_instr);
  ts->tld->transl_instr = transl_addr;
  return CLOSE;
}


