/*
 * @file fbt_translate.c
 * This module is used to translate basic blocks.
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedDate: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1184 $
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

#include "fbt_translate.h"

#include "fbt_disas.h"
#include "fbt_actions.h"
#include "fbt_asm_macros.h"
#include "fbt_code_cache.h"
#include "fbt_datatypes.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"
#include "fbt_syscall.h"
#include "fbt_debug.h"
#include "fbt_instruction.h"
#include "fbt_disas.h"

#ifdef DEBUG
extern int debugStream;
#endif

/**
 * These macros define in a common place how the value in the
 * shadow address is checked (using 'test' or 'or')
 */
#define SHADOW_CMP_R8_BYTE     cmp (%r8, %r15),  %r12b;
#define SHADOW_CMP_R8_DOUBLE   cmp (%r8, %r15),  %r12w;
#define SHADOW_CMP_R8_WORD     cmp (%r8, %r15),  %r12d;
#define SHADOW_CMP_R8_QUAD     cmp (%r8, %r15),  %r12;
#define SHADOW_CMP_R8_DECA     or (%r8, %r15),  %r12; cmp 8(%r8, %r15),  %r12w;
#define SHADOW_CMP_RSP_DOUBLE  cmp (%rsp, %r15), %r12d;
#define SHADOW_CMP_RSP_BYTE    cmp (%rsp, %r15), %r12b;
#define SHADOW_CMP_RDI_BYTE    cmp (%rdi, %r15), %r12b;
#define SHADOW_CMP_RDI_WORD    cmp (%rdi, %r15), %r12w;
#define SHADOW_CMP_RDI_DOUBLE  cmp (%rdi, %r15), %r12d;
#define SHADOW_CMP_RSI_DOUBLE  cmp (%rsi, %r15), %r12d;
#define SHADOW_OR_RDI_BYTE     or   (%rdi, %r15), %r12b;
#define SHADOW_OR_RDI_WORD     or   (%rdi, %r15), %r12w;
#define SHADOW_OR_RDI_DOUBLE   or   (%rdi, %r15), %r12d;
#define SHADOW_OR_RSI_BYTE     or   (%rsi, %r15), %r12b;
#define SHADOW_OR_RSI_WORD     or   (%rsi, %r15), %r12w;
#define SHADOW_OR_RSI_DOUBLE   or   (%rsi, %r15), %r12d;

/**
 * Part of the optimization that restores flags by
 * repeating the arithmetic instructions.
 */
enum fpatch_type {
  FPATCH_NONE,
  FPATCH_CMPREGREG,
  FPATCH_TSTREGREG,
  FPATCH_CMPIMMREG,
  FPATCH_TSTIMMREG,
  FPATCH_CMPIMMMEM,
  FPATCH_CMPREGMEM,
  FPATCH_CMPMEMREG};
/**
 * Part of the optimization that restores flags by
 * repeating the arithmetic instructions.
 */
enum frest_type {FREST_NONE,
  FREST_CMP,
  FREST_TST};

/**
 * Part of the optimization that restores flags by
 * repeating the arithmetic instructions.
 * Only relevant fields are valid depending
 * on 'fpt'.
 */
struct flags_patching{
  enum fpatch_type fpt;
  uchar reg1;
  uchar reg2;
  uint32_t imm;
  enum frest_type frt;
};

#if 1
//#ifdef ENABLE_EFLAGS_SAVEREST

/**
 * This is the main function implementing the eflags patching
 * optimization.
 *
 * Note that this is meant as 'proof of concept' to evaluate
 * its effectiveness and hence is a bit messy.
 *
 * @param instructions an array of high information about instructions
 * @param transl an array of disassembled instructions
 * @param fps the array in which the result will be returned
 * @param needs_memcheck an array saying whether a given instruction performs
 *        a watchpoint check
 * @param ninstr the length of all these arrays
 */
static void optimize_flags_pass(
    struct lmem_instruction* instructions,
    struct translate* transl,
    struct flags_patching* fps,
    int* needs_memcheck,
    int ninstr)
{
  PRINT_DEBUG_TRANSLATE("\n\n opt flags pass \n");
  for (int i=0; i<ninstr; i++){
    fps[i].fpt = FPATCH_NONE;
    fps[i].frt = FREST_NONE;
  }

  //return; // optimizing flags pass causes povray to crash

  for (int i=0; i<ninstr; i++){
    if (instructions[i].arithmetic_flag_info & FL_CHANGES_ALL){
      uchar* ins = (uchar*)(uint64_t)transl[i].cur_instr;

      /* First discover how we would patch */
      BOOL canpatch = FALSE;
      enum fpatch_type fpt = FPATCH_NONE;
      enum frest_type frt = FREST_NONE;

      if ((*ins == 0x39) && ((*(ins+1) & 0xc0) == 0xc0)){
        assert(transl[i].next_instr - transl[i].cur_instr == 2);
        /* cmp reg reg */
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif
        unsigned b = *(ins+1);
        fps[i].reg1 = (b >> 3) & 7;
        fps[i].reg2 = b & 7;

        fpt = FPATCH_CMPREGREG;
        frt = FREST_CMP;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... compares reg %d with reg %d\n",
            fps[i].reg1, fps[i].reg2);
      } else if ((*ins == 0x85) && ((*(ins+1) & 0xc0) == 0xc0)){
        assert(transl[i].next_instr - transl[i].cur_instr == 2);
        /* cmp reg reg */
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "test",-1) != 0){
          fbt_suicide("internal failure 234\n");
        }
#endif
        unsigned b = *(ins+1);
        fps[i].reg1 = (b >> 3) & 7;
        fps[i].reg2 = b & 7;

        fpt = FPATCH_TSTREGREG;
        frt = FREST_TST;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... tests reg %d with reg %d\n", fps[i].reg1, fps[i].reg2);
      } else if ((*ins == 0x81) && ((*(ins+1) & 0xf8) == 0xf8)
          && (*(ins+1) != 0xf8) /* eax has its own opcode !!! */){
        assert(transl[i].next_instr - transl[i].cur_instr == 6);
        /* cmp reg reg */
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("internal failure 3241\n");
        }
#endif
        unsigned b = *(ins+1);
        fps[i].imm = (uint32_t)*(uint32_t*)(ins+2);
        fps[i].reg2 = b & 7;

        fpt = FPATCH_CMPIMMREG;
        frt = FREST_CMP;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... cmp imm %x with reg!=eax %d\n",
            fps[i].imm, fps[i].reg2);
      } else if ((*ins == 0xf7) && ((*(ins+1) & 0xf8) == 0xc0)
          && (*(ins+1) != 0xc0) /* eax has its own opcode !!! */){
        assert(transl[i].next_instr - transl[i].cur_instr == 6);
        /* cmp reg reg */
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "test",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif
        unsigned b = *(ins+1);
        fps[i].imm = (uint32_t)*(uint32_t*)(ins+2);
        fps[i].reg2 = b & 7;

        fpt = FPATCH_TSTIMMREG;
        frt = FREST_TST;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... test imm %x with reg!=eax %d\n", fps[i].imm, fps[i].reg2);
      } else if ((*ins == 0x83) && ((*(ins+1) & 0xf8) == 0xf8)) {
        assert(transl[i].next_instr - transl[i].cur_instr == 3);
        /* cmp reg reg */
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif
        unsigned b = *(ins+1);

        /* very important that it is signed! */
        fps[i].imm = (int32_t)(*(signed char*)(ins+2));
        fps[i].reg2 = b & 7;

        fpt = FPATCH_CMPIMMREG;
        frt = FREST_CMP;

        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... cmp imm8 %x with reg %d\n", fps[i].imm, fps[i].reg2);
      } 
#if 0 
      else if (0 && /* MAKES POVRAY TEST DATASET CRASH */  *ins == 0xa8) {
        assert(transl[i].next_instr - transl[i].cur_instr == 2);
#error "Makes povray test dataset crash"
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "test",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif
        /* very important that it is signed! */
        fps[i].imm = (int32_t)(*(signed char*)(ins+1));
        fps[i].reg2 = 0 /* eax */;

        fpt = FPATCH_TSTIMMREG;
        frt = FREST_TST;

        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... test imm8 %x with eax\n", fps[i].imm);
      } 
#endif
      else if (*ins == 0x3d) {
        /* cmp imm eax*/
        assert(transl[i].next_instr - transl[i].cur_instr == 5);
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("internal failure 231\n");
        }
#endif
        fps[i].imm = (uint32_t)*(uint32_t*)(ins+1);
        fps[i].reg2 = 0 /* eax */;

        fpt = FPATCH_CMPIMMREG;
        frt = FREST_CMP;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... cmp imm %x with eax\n", fps[i].imm);
      } else if (*ins == 0xa9) {
        /* test imm eax*/
        assert(transl[i].next_instr - transl[i].cur_instr == 5);
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "test",-1) != 0){
          fbt_suicide("internal failure 543\n");
        }
#endif
        fps[i].imm = (uint32_t)*(uint32_t*)(ins+1);
        fps[i].reg2 = 0 /* eax */;

        fpt = FPATCH_TSTIMMREG;
        frt = FREST_TST;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("... test imm %x with eax\n", fps[i].imm);
      } else if ((*ins == 0x39) && 
          ((*(ins+1) & 0xc0) == 0x80) &&
          ((*(ins+1) & 0x07) != 0x04)){
        assert(transl[i].next_instr - transl[i].cur_instr == 6);
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif

        unsigned b = *(ins+1);
        fps[i].reg1 = (b>>3) & 7;

        fpt = FPATCH_CMPREGMEM;
        frt = FREST_CMP;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("cmp reg mem\n");
      } else if ((*ins == 0x3b) && 
          ((*(ins+1) & 0xc0) == 0x80) &&
          ((*(ins+1) & 0x07) != 0x04)){
        assert(transl[i].next_instr - transl[i].cur_instr == 6);
#ifndef NDEBUG
        if (fbt_strncmp(transl[i].cur_instr_info->mnemonic, "cmp",-1) != 0){
          fbt_suicide("fifififi\n");
        }
#endif

        unsigned b = *(ins+1);
        fps[i].reg2 = (b>>3) & 7;

        fpt = FPATCH_CMPMEMREG;
        frt = FREST_CMP;
        canpatch = TRUE;

        PRINT_DEBUG_TRANSLATE("cmp reg mem\n");
      }
      /* ... in future, others as well ... */

      BOOL some_needed_memcheck = FALSE;
      if (canpatch){
        int j;
        for (j = i+1; j<ninstr /* the last may be a cft */; j++){
          if (instructions[j].arithmetic_flag_info & FL_CHANGES_SOME){
            /* the patching idea does not work if there is some instruction in
             * the middle that changes only *some* arithmetic flags */
            i = j+1;
            break;
          }
          if (instructions[j].arithmetic_flag_info & FL_CHANGES_ALL){
            /* there is no need to do the pathing trick since there 
               is an instruction that changes all arithmetic flags 
               anyway. Continue from this one */
            i = j;
            break;
          }
          if (needs_memcheck[j]){
            some_needed_memcheck = TRUE;
          }
          if (some_needed_memcheck &&
              instructions[j].arithmetic_flag_info & FL_USES){
            fps[i].fpt = fpt;
            fps[j].frt = frt;

            instructions[j].arithmetic_flag_info &= (~FL_USES);
            instructions[j].arithmetic_flag_info |= FL_CHANGES_ALL;
          }
        }
      }

    }
  }
  PRINT_DEBUG_TRANSLATE("\n");
}

#endif

/**
 * Bit field definitions for the result
 * of analyze_flags_save_restore_needs()
 */
enum FlagsAction {
  EF_SAV = 1, EF_RST = 2
};
#if 1
//#ifdef ENABLE_EFLAGS_SAVEREST

/**
 * Given information about instructions, this function
 * decides which instructions are responsible for saving
 * and/or restoring flags.
 * @param instructions an array of high level instruction info
 * @param transl an array of disassembled instructions
 * @param needs_memcheck an array telling for each instr whether
 *                       it has a watchpoint check
 * @param num_instructions the length of these arrays
 * @param saverest the result, namely the info who needs to save
 *                 and/or restore.
 */
static void analyze_flags_save_restore_needs(
    struct lmem_instruction* instructions,
    struct translate* transl,
    int* needs_memcheck,
    int num_instructions,
    int* saverest)
{
  enum FlagNeeds {
    S_DONTNEEDFLAGS, S_NEED_FLAGS_IN_EFLAGS, S_NEED_FLAGS_IN_MEMORY
  };

  if (num_instructions == 0) {
    PRINT_DEBUG_TRANSLATE("warning... bb with 0 instructions");
    return;
  }

  PRINT_DEBUG_TRANSLATE("BEGIN FLAG ANALYSIS");
  int i;
  for (i = 0; i < num_instructions; i++) {
    saverest[i] = 0;
  }

  /**
   * The protocols for passing the flags between one basic block
   * and another says that if the next basic block might need the flags
   * then they need to be put in the eflags register by the preceding
   * basic block.
   */
  int s = S_NEED_FLAGS_IN_EFLAGS;

  if (transl[num_instructions - 1].cur_instr_info->opcode.handler == action_call) {
    if (LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_CALL){
      s = S_DONTNEEDFLAGS;
    }
  } else if (fbt_strncmp(transl[num_instructions - 1].cur_instr_info->mnemonic, "ret", 256) == 0) {
    if (LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_RET){
      s = S_DONTNEEDFLAGS;
    } else {
      s = S_NEED_FLAGS_IN_MEMORY;
    }
  } else if (transl[num_instructions - 1].cur_instr_info->opcode.handler == action_call_indirect) {
    if (LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_CALL_INDIRECT){
      s = S_DONTNEEDFLAGS;
    } else {
      s = S_NEED_FLAGS_IN_MEMORY;
    }
  } else if (transl[num_instructions - 1].cur_instr_info->opcode.handler == action_jmp_indirect) {
    s = S_NEED_FLAGS_IN_MEMORY;
  }


  i = num_instructions - 1; /* last instr. of basic block */
  while (i >= 0) {
    if (s == S_DONTNEEDFLAGS) {
      if (instructions[i].arithmetic_flag_info & FL_USES
          && instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        PRINT_DEBUG_TRANSLATE("f");
        if (needs_memcheck[i]) {
          s = S_NEED_FLAGS_IN_MEMORY;
          saverest[i] |= EF_RST;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
        }
      }
      if (instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        PRINT_DEBUG_TRANSLATE("a");
        // we don't care about flags
        // next instructions don't care about flags
        // so we're ok doing nothing
      } else if (instructions[i].arithmetic_flag_info & FL_CHANGES_SOME) {
        PRINT_DEBUG_TRANSLATE("b");
        // we don't care about flags
        // next instructions don't care about flags
        // so we're ok doing nothing
      } else if (instructions[i].arithmetic_flag_info & FL_USES) {
        PRINT_DEBUG_TRANSLATE("c");
        if (needs_memcheck[i]) {
          saverest[i] |= EF_RST;
          s = S_NEED_FLAGS_IN_MEMORY;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
        }
      } else {
        PRINT_DEBUG_TRANSLATE("d");
      }
    } else if (s == S_NEED_FLAGS_IN_EFLAGS) {
      if (instructions[i].arithmetic_flag_info & FL_USES
          && instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        PRINT_DEBUG_TRANSLATE("F");
        if (needs_memcheck[i]) {
          saverest[i] |= EF_RST;
          s = S_NEED_FLAGS_IN_MEMORY;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
        }
      } else if (instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        PRINT_DEBUG_TRANSLATE("A");
        /* since this instruction changes all flags, they 
           are automatically in eflags
           also, this instruction doesn't care about flags */
        s = S_DONTNEEDFLAGS;
      } else if (instructions[i].arithmetic_flag_info & FL_CHANGES_SOME) {
        PRINT_DEBUG_TRANSLATE("B");
        if (needs_memcheck[i]) {
          saverest[i] |= EF_RST;
          s = S_NEED_FLAGS_IN_MEMORY;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
        }
      } else if (instructions[i].arithmetic_flag_info & FL_USES) {
        PRINT_DEBUG_TRANSLATE("C");
        if (needs_memcheck[i]) {
          saverest[i] |= EF_RST;
          s = S_NEED_FLAGS_IN_MEMORY;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
        }
      } else {
        PRINT_DEBUG_TRANSLATE("D");
        if (needs_memcheck[i]) {
          s = S_NEED_FLAGS_IN_MEMORY;
          saverest[i] |= EF_RST;
        }
      }
    } else if (s == S_NEED_FLAGS_IN_MEMORY) {
      if (instructions[i].arithmetic_flag_info & FL_USES
          && instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        PRINT_DEBUG_TRANSLATE("6.");
        if (needs_memcheck[i]) {
          s = S_NEED_FLAGS_IN_MEMORY;
          saverest[i] |= EF_RST;
          saverest[i + 1] |= EF_SAV;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
          saverest[i + 1] |= EF_SAV;
        }
      } else if (instructions[i].arithmetic_flag_info & FL_CHANGES_ALL) {
        if (instructions[i].arithmetic_flag_info & FL_USES){
          PRINT_DEBUG_TRANSLATE("Unhandled caaswseee!");
          fbt_suicide_str("bye");
        }
        PRINT_DEBUG_TRANSLATE("1.");
        saverest[i + 1] |= EF_SAV;
        s = S_DONTNEEDFLAGS; 
      } else if (instructions[i].arithmetic_flag_info & FL_CHANGES_SOME) {
        if (instructions[i].arithmetic_flag_info & FL_USES){
          PRINT_DEBUG_TRANSLATE("Unhandled caaswseee!");
          fbt_suicide_str("bye");
        }
        PRINT_DEBUG_TRANSLATE("2.");
        if (needs_memcheck[i]) {
          s = S_NEED_FLAGS_IN_MEMORY;
          saverest[i] |= EF_RST;
          saverest[i + 1] |= EF_SAV; 
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
          saverest[i + 1] |= EF_SAV;
        }
      } else if (instructions[i].arithmetic_flag_info & FL_USES) {
        PRINT_DEBUG_TRANSLATE("3.");
        // since this instruction uses eflags, we need the flags  to be in
        // eflags. So...
        if (needs_memcheck[i]) {
          s = S_NEED_FLAGS_IN_MEMORY;  // Changed
          saverest[i] |= EF_RST;
        } else {
          s = S_NEED_FLAGS_IN_EFLAGS;
          saverest[i] |= EF_SAV; 
        }
      } else {
        PRINT_DEBUG_TRANSLATE("4.");
      }
    }
    i--;
  }

  /*
   * If the first instruction needs flags in memory then
   * it needs to save them, since it is passed from the
   * previous block in the eflags register
   */
  if (s == S_NEED_FLAGS_IN_MEMORY) {
    assert(num_instructions>0);
    saverest[0] |= EF_SAV;
  }

  PRINT_DEBUG_TRANSLATE("END FLAG ANALYSIS");
}

#endif

/**
 * Given the address of a jump instruction and its length
 * finds out where it's gonna jump.
 * @param addr where the instruction is in memory
 * @param length its length
 * @return where it's gonna jump
 */
static guestptr_t get_jump_target(guestptr_t addr, int length)
{
  assert(!HAS_PREFIX(*(uchar*)(uint64_t)addr)); /* no prefixes allowed */
  int32_t jump_target = 0;
  if (*(uchar*)(uint64_t)addr == 0xE9) { /* 32bit offset */
    jump_target = *((int32_t*) (uint64_t) (addr + 1)) +
        (int32_t)(uint64_t)addr + length;
  } else { /* our argument is only an 8bit offset */
    jump_target = (int32_t) (*((char*) (uint64_t) (addr + 1)) +
        (int32_t)(uint64_t)addr + length);
  }
  return (guestptr_t) jump_target;
}

/**
 * Starts disassembling at 'start' until the end of the basic block
 * is reached. The result is written in the array 'result' and the
 * number of translated instructions is written in 'resultsize'.
 * If the basic block is longer than maxresultsize then the disassembling
 * stops to avoid a buffer overflow.
 * @param start a struct translate where its fields encode where the
 *              translation should start.
 * @param maxresultsize the maximum, to prevent overflows
 * @param result an array where the disassembled instructions will be written
 * @param result_size a result saying how many instructions were disassembled
 */
static void disassemble_basic_block(const struct translate* start,
    int maxresultsize,
    struct translate* result,
    int* result_size) {

  PRINT_DEBUG_TRANSLATE("diasa_bb begin\n");

  result[0] = *start;
  (*result_size) = 0;
  int end_lookahead = 0;
  while ((*result_size) < maxresultsize - 1 && !end_lookahead) {
    if (*result_size == 0){
      result[(*result_size)] = *start;
    } else {
      result[(*result_size)] = result[(*result_size) - 1];
    }

    fbt_disasm_instr(&result[(*result_size)]);

    PRINT_DEBUG_TRANSLATE("orig=0x%x: ", (uint32_t)result[(*result_size)].cur_instr);
#ifdef DEBUG
    print_disasm_instruction(debugStream, &result[(*result_size)], result[(*result_size)].next_instr-result[(*result_size)].cur_instr);
#endif

    int length = result[(*result_size)].next_instr - result[(*result_size)].cur_instr;


    const uchar * const cur_instr = (uchar*)(uint64_t)
                      (result[(*result_size)].cur_instr + result[(*result_size)].num_prefixes);

    // these are the instructions where one can continue in straight line...
    actionFunP_t handl = result[(*result_size)].cur_instr_info->opcode.handler;
    if (handl == action_copy ||
        handl == action_warn ||
        handl == action_push ||
        handl == action_pop ||
        handl == action_inc ||
        handl == action_dec ||
        handl == action_call ||
        handl == action_jmp) {

      // unconditional jump...
      if (result[(*result_size)].cur_instr_info->opcode.handler == action_jmp) {
        unsigned jump_target = get_jump_target(result[(*result_size)].cur_instr, length);
        result[(*result_size)].next_instr = jump_target;
      } else if (result[(*result_size)].cur_instr_info->opcode.handler == action_call) {
        const uchar *addr = (uchar*)(uint64_t)result[(*result_size)].cur_instr;
        assert(length == 5 && !HAS_PREFIX(*addr));
        uint32_t call_target = *((uint32_t*) (addr + 1)) + (uint64_t) addr + length;
        uchar *next_instr = (uchar*)(uint64_t)result[(*result_size)].next_instr;

        // call only wants to get eip
        if (*((uint32_t*) (addr + 1)) == 0x0 && *(next_instr) >= 0x58
            && *(next_instr) <= 0x5F) {
          // next instruction will be just the instruction after 'call'
        } else {
          result[(*result_size)].next_instr = call_target;
        }
      } else if (*cur_instr == 0xcd) { /* interrupt different from int3 */
        (*result_size)++;               /* should be the last! */
        break;
      }
      (*result_size)++;
    } else {
      (*result_size)++;
      break;
    }
  }

  PRINT_DEBUG_TRANSLATE("diasa_bb end\n");
}

BOOL transform_instruction_to_leal_if_appropriate(struct translate *ts);


/**
 * Translates a nonstring x86 instruction to x64. Possible inserting
 * flag saving/restoring code and/or watchpoint checking code.
 * @param tld the thread local data
 * @param ts the instruction to translate
 * @param save_restore whether this instruction is responsible for saving
 *                     and/or restoring flags
 * @param needs_memcheck whether watchpoint checking code should be inserted
 * @param fps info to implement the flags patching optimization
 * @param stopper_jumps here this function writes where stopper jumps should be
 *                      backpatched.
 * @param num_stopper_jumps this can be increased by this function.
 */
static enum translation_state
translate_single_nonstring_instruction(
    struct thread_local_data *tld,
    struct translate* ts,
    struct lmem_instruction* inst,
    int save_restore,
    int needs_memcheck,
    struct flags_patching fps,
    uchar** stopper_jumps,
    int* num_stopper_jumps,
    BOOL lock)
{
  assert((ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_GROUP_MASK) != OPCODEFL_ARRAY);

#ifdef LMEM_SELFCHECKS

#ifdef ENABLE_MEMCHECKS
#error "ENABLE_MEMCHECKS does not work together with LMEM_SELFCHECKS"
#endif
#ifdef ENABLE_EFLAGS_SAVEREST
#error "ENABLE_SELFCHECKS does not work together with ENABLE_EFLAGS_SAVEREST"
#endif

  if (save_restore & EF_SAV) {
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
    SAVE_FLAGS
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  }
  if (save_restore & EF_RST) {
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
    CHECK_THAT_SAVED_FLAGS_EQUAL_EFLAGS
    RESTORE_FLAGS_CLOBBERING_R8_R9
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  }
#else
#ifdef ENABLE_EFLAGS_SAVEREST
  if (save_restore & EF_SAV)
  {
    uchar *transl_instr = tld->transl_instr;
    BEGIN_ASM(transl_instr);
    SAVE_FLAGS
    END_ASM;
    tld->transl_instr = transl_instr;
    PRINT_DEBUG_TRANSLATE("SAV\n");
  }
#endif

#ifdef ENABLE_MEMACCESSES
  if (needs_memcheck) {
    /*
     * At this point we do the leal computation. It is important
     * that the registers that leal uses for its address computation
     * have still the original values.
     */

    BOOL ok = transform_instruction_to_leal_if_appropriate(ts);
    if (ok) {
      PRINT_DEBUG_TRANSLATE("leal-based check (opsize = %d)\n", inst->opsize);

      uchar *transl_instr = tld->transl_instr;

      switch (inst->opsize){
      case 0: // Handle as byte
        PRINT_DEBUG_TRANSLATE("warning: size zero\n");
        break;
      case 1:
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_R8_BYTE
        END_ASM;
        break;
      case 2:
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_R8_WORD
        END_ASM;
        break;
      case 4:
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_R8_DOUBLE
        END_ASM;
        break;
      case 8:
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_R8_QUAD
        END_ASM;
        break;
      case 10:
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_R8_DECA
        END_ASM;
        break;
      default:
        PRINT_DEBUG_TRANSLATE("opsize %d\n", (int)inst->opsize);
        fbt_suicide_str("unknown operand size!");
      }

#ifdef ENABLE_MEMCHECKS

      stopper_jumps[*num_stopper_jumps] = transl_instr;
      (*num_stopper_jumps)++;
      BEGIN_ASM(transl_instr);
      nop;nop;nop;nop;nop;nop; // Sufficient space for stopper jump
      END_ASM;

#endif

      tld->transl_instr = transl_instr;
    } 

    /**
     * Support for stack instructions
     */
    if ((ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_GROUP_MASK) == OPCODEFL_STACK){
      PRINT_DEBUG_TRANSLATE("pop-based check\n", inst->opsize);
      unsigned type = ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_TYPE_MASK;
      if (type == OPCODEFL_PUSH || type == OPCODEFL_PUSHFLAGS){
        uchar *transl_instr = tld->transl_instr;

#ifdef ENABLE_MEMCHECKS

        BEGIN_ASM(transl_instr);
        SHADOW_CMP_RSP_DOUBLE
        END_ASM;

        stopper_jumps[*num_stopper_jumps] = transl_instr;
        (*num_stopper_jumps)++;
        BEGIN_ASM(transl_instr);
        nop;nop;nop;nop;nop;nop; // Sufficient space for stopper jump
        END_ASM;

#endif

        tld->transl_instr = transl_instr;
        PRINT_DEBUG_TRANSLATE("CHECK (stack write)\n");
      }
      if (type == OPCODEFL_PUSHREGS){
        PRINT_DEBUG_TRANSLATE("PUSHA AND COMPANY NOT SUPPORTED\n");
      }
      if (type == OPCODEFL_POP || type == OPCODEFL_POPFLAGS){
        uchar *transl_instr = tld->transl_instr;

#ifdef ENABLE_MEMCHECKS

        PRINT_DEBUG_TRANSLATE("push-based check\n", inst->opsize);
        BEGIN_ASM(transl_instr);
        SHADOW_CMP_RSP_DOUBLE
        END_ASM;

        stopper_jumps[*num_stopper_jumps] = transl_instr;
        (*num_stopper_jumps)++;
        BEGIN_ASM(transl_instr);
        nop;nop;nop;nop;nop;nop; // Sufficient space for stopper jump
        END_ASM;

#endif

        tld->transl_instr = transl_instr;
        PRINT_DEBUG_TRANSLATE("CHECK (stack read)\n");
      }
      if (type == OPCODEFL_POPREGS){
        PRINT_DEBUG_TRANSLATE("POPA AND COMPANY NOT SUPPORTED\n");
      }
    }
  }
#else
#ifdef ENABLE_EFLAGS_SAVEREST
  if (needs_memcheck) {
    /*
     * At this point we do the leal computation. It is important
     * that the registers that leal uses for its address computation
     * have still the original values.
     */
    unsigned char *dbg = tld->transl_instr;
    BOOL ok = transform_instruction_to_leal_if_appropriate(ts); // NEEDED BY FLAG OPTIMIZATION

  }
#endif
#endif

#ifdef ENABLE_EFLAGS_SAVEREST
  if (save_restore & EF_RST)
  {
    uchar *transl_instr = tld->transl_instr;
    BEGIN_ASM(transl_instr);
    RESTORE_FLAGS_CLOBBERING_R8_R9
    END_ASM;
    tld->transl_instr = transl_instr;
    PRINT_DEBUG_TRANSLATE("RST\n");
  }
#endif
#endif


#ifdef ENABLE_EFLAGS_SAVEREST
  if (fps.frt == FREST_NONE){
    /* common case, do nothing */
  } else if (fps.frt == FREST_CMP){
    PRINT_DEBUG_TRANSLATE("RESTORING VIA CMP\n");
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
    cmp %r10d, %r11d
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  } else if (fps.frt == FREST_TST){
    PRINT_DEBUG_TRANSLATE("RESTORING VIA TST\n");
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
    test %r10d, %r11d
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  }
#endif

 /* {
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
      nop;
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  } */

  if (*(uchar*) (uint64_t) ts->cur_instr == 0x65) {
    uchar *transl_instr = ts->tld->transl_instr;
    BEGIN_ASM(transl_instr);
    movsxd %eax, %rax
    movsxd %ebx, %rbx
    movsxd %ecx, %rcx
    movsxd %edx, %rdx
    movsxd %esi, %rsi
    movsxd %edi, %rdi
    movsxd %ebp, %rbp
    END_ASM;
    ts->tld->transl_instr = transl_instr;
  }

  enum translation_state result;

  /* For interrupts we use action_copy explicitly */
  if (*(uchar*) (uint64_t) ts->cur_instr == 0x65) {
    uchar* ci = (uchar*) (uint64_t) ts->cur_instr;
    if (*(ci + 1) == 0xff && *(ci + 2) == 0x15 && *(ci + 3) == 0x10 &&
        *(ci + 4) == 0x0 && *(ci + 5) == 0x0 && *(ci + 6) == 0x0) {
      PRINT_DEBUG_TRANSLATE("translating call via gs segment to syscall, "
          "as that's what glibc uses it for\n");
      result = action_copy(ts, lock);
    } else {
      PRINT_DEBUG_TRANSLATE("Handling something with a segment override, "
          " prefi %x %x %x\n", *(ci+1), *(ci+2), *(ci+3));
      result = ts->cur_instr_info->opcode.handler(ts, lock);
    }
  } else {
    /* call the action specified for this instruction */
    result = ts->cur_instr_info->opcode.handler(ts, lock);
  }

  if (fps.fpt == FPATCH_CMPREGREG){
    PRINT_DEBUG_TRANSLATE("PATCHING CMP REG REG\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc2 | (fps.reg1 << 3);
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc3 | (fps.reg2 << 3);
    ts->tld->transl_instr = transl_instr;
  } else if (fps.fpt == FPATCH_TSTREGREG){
    PRINT_DEBUG_TRANSLATE("PATCHING TST REG REG\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc2 | (fps.reg1 << 3);
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc3 | (fps.reg2 << 3);
    ts->tld->transl_instr = transl_instr;
  } else if (fps.fpt == FPATCH_CMPIMMREG){
    PRINT_DEBUG_TRANSLATE("PATCHING CMP IMM REG\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x41;
    *(transl_instr++) = 0xba;
    *(uint32_t*)transl_instr = fps.imm;
    transl_instr+=4;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc3 | (fps.reg2 << 3);
    ts->tld->transl_instr = transl_instr;
  } else if (fps.fpt == FPATCH_TSTIMMREG){
    PRINT_DEBUG_TRANSLATE("PATCHING TEST IMM REG\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x41;
    *(transl_instr++) = 0xba;
    *(uint32_t*)transl_instr = fps.imm;
    transl_instr+=4;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc3 | (fps.reg2 << 3);
    ts->tld->transl_instr = transl_instr;
  } else if (fps.fpt == FPATCH_CMPREGMEM){
    PRINT_DEBUG_TRANSLATE("PATCHING CMP REG MEM\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc2 | (fps.reg1 << 3);
    *(transl_instr++) = 0x45;
    *(transl_instr++) = 0x8b;
    *(transl_instr++) = 0x18;
    ts->tld->transl_instr = transl_instr;
  }  else if (fps.fpt == FPATCH_CMPMEMREG){
    PRINT_DEBUG_TRANSLATE("PATCHING CMP MEM REG\n");
    uchar *transl_instr = ts->tld->transl_instr;
    *(transl_instr++) = 0x45;
    *(transl_instr++) = 0x8b;
    *(transl_instr++) = 0x10;
    *(transl_instr++) = 0x49;
    *(transl_instr++) = 0x89;
    *(transl_instr++) = 0xc3 | (fps.reg2 << 3);
    ts->tld->transl_instr = transl_instr;
  }

  return result;
}

/*
 * original and translated ip information in r8 and r9 (see src for order)
 */
#define GOTO_WATCHPOINT_HANDLER call_abs {tld->watchpoint_trampoline};

/**
 * The sequence used to stop on watchpoint hit
 */
#define SIMPLE_CONDITIONAL_GOTO_WP_HANDLER \
    je oky; \
    xor %r8,%r8;  /* do not pass any ip info */ \
    xor %r9,%r9;  \
    GOTO_WATCHPOINT_HANDLER; \
    oky:


static enum translation_state
translate_single_string_instruction(struct thread_local_data *tld,
    struct translate* ts,
    struct lmem_instruction* inst,
    int save_restore,
    int needs_memcheck,
    struct flags_patching fps,
    uchar** stopper_jumps,
    int* num_stopper_jumps,
    BOOL lock)
{
  assert((ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_GROUP_MASK) == 
      OPCODEFL_ARRAY);

  if (save_restore & EF_SAV)
  {
    uchar *transl_instr = tld->transl_instr;
    BEGIN_ASM(transl_instr);
    SAVE_FLAGS
    END_ASM;
    tld->transl_instr = transl_instr;
    PRINT_DEBUG_TRANSLATE("SAV\n");
  }
  if (save_restore & EF_RST)
  {
    uchar *transl_instr = tld->transl_instr;
    BEGIN_ASM(transl_instr);
    RESTORE_FLAGS_CLOBBERING_R8_R9
    END_ASM;
    tld->transl_instr = transl_instr;
    PRINT_DEBUG_TRANSLATE("RST\n");
  }

  /* The 64 bit string instructions use the rsi/rdi registers
     instead of the esi/edi registers so we *have* to make sure
     that the top 32 bits are cleared. */
  uchar *transl_instr = tld->transl_instr;
  BEGIN_ASM(transl_instr);
  mov %esi, %esi
  mov %edi, %edi
  END_ASM;
  tld->transl_instr = transl_instr;

  /* This limitation could be relaxed */
  assert(ts->num_prefixes <= 1); 

  return action_copy(ts, lock);
}


/**
 * Translates a x86 instruction to x64. Possible inserting
 *
 * @param tld the thread local data
 * @param ts the instruction to translate
 * @param save_restore whether this instruction is responsible for saving
 *                     and/or restoring flags
 * @param needs_memcheck whether watchpoint checking code should be inserted
 * @param fps info to implement the flags patching optimization
 * @param stopper_jumps here this function writes where stopper jumps should be
 *                      backpatched.
 * @param num_stopper_jumps this can be increased by this function.
 */
static enum translation_state
translate_single_instruction(struct thread_local_data *tld,
    struct translate* ts,
    struct lmem_instruction* inst,
    int save_restore,
    int needs_memcheck,
    struct flags_patching fps,
    uchar** stopper_jumps,
    int* num_stopper_jumps,
    BOOL lock)
{
  if ((ts->cur_instr_info->opcodeFlags & OPCODEFL_INS_GROUP_MASK) == 
      OPCODEFL_ARRAY){
    return translate_single_string_instruction(tld,
        ts,
        inst,
        save_restore,
        needs_memcheck,
        fps,
        stopper_jumps,
        num_stopper_jumps,
        lock);
  } else {
    return translate_single_nonstring_instruction(tld,
        ts,
        inst,
        save_restore,
        needs_memcheck,
        fps,
        stopper_jumps,
        num_stopper_jumps,
        lock);
  }
}


#define MAIN_BB_MAX_INSTRNS 256

/**
 * This function starts the translation of one basic block
 * starting at orig_address
 * @param tld the thread local data
 * @param orig_address where to start translating
 * @return the address where the code has been translated
 */
void *fbt_translate_noexecute_impl(struct thread_local_data *tld,
    guestptr_t orig_address,
    BOOL lock)
{
  ENFORCE_ALIGNMENT(tld->transl_instr);

  assert(tld != NULL);

  /* if the target is already translated then we return the cached version  */
  void *already_translated = fbt_ccache_find(tld, orig_address);
  if (already_translated != NULL) {
    PRINT_DEBUG_FUNCTION_END("already translated -> %p",
        already_translated);
    return already_translated;
  }

  /* we need to translate TU, add to ccache index,
   jump to the translated code */
  enum translation_state tu_state = NEUTRAL;

  int bytes_translated = 0;
  struct translate thets;
  thets.tld = tld;
  thets.next_instr = orig_address;
  struct translate *ts = &thets;

  /* check if more memory needs to be allocated for tcache */
  if ((uint64_t)(tld->code_cache_end - tld->transl_instr) < MAX_BLOCK_SIZE) {
    PRINT_DEBUG_TRANSLATE("Not enough memory for new code block - allocating more!");
    uchar *prev_transl_instr = tld->transl_instr;

    fbt_allocate_new_code_cache(tld, lock);

    /* add a jmp connect old and new tcache memory blocks */
    if (prev_transl_instr != NULL) {
      JMP_REL32(prev_transl_instr, tld->transl_instr);
    }
  }
  PRINT_DEBUG_TRANSLATE("tld->ts.transl_instr: %p", tld->transl_instr);

  /* add entry to ccache index */
  fbt_ccache_add_entry(tld, orig_address, tld->transl_instr);

  /* look up address in translation cache index */
  void *transl_address = tld->transl_instr;

  /*
   * Disassemble the main basic block, where by main basic block
   * we mean the basic block that we are going to translate in this
   * function execution.
   */
  int main_bb_ninstr = (-1);
  struct translate main_bb[MAIN_BB_MAX_INSTRNS];
  disassemble_basic_block(ts, MAIN_BB_MAX_INSTRNS, 
      &main_bb[0], &main_bb_ninstr);
  assert(main_bb_ninstr <= MAIN_BB_MAX_INSTRNS);

  /**
   * Decode instructions in a friendly format
   */
  struct lmem_instruction instructions[MAIN_BB_MAX_INSTRNS];
  assert(main_bb_ninstr < MAIN_BB_MAX_INSTRNS);
  for (int i = 0; i < main_bb_ninstr; i++) {
    compute_lmem_instruction(&main_bb[i], &instructions[i]);
  }

  /**
   * Find which instructions need instrumentation
   */
  int needs_memcheck[MAIN_BB_MAX_INSTRNS];
  assert(main_bb_ninstr < MAIN_BB_MAX_INSTRNS);
  for (int i = 0; i < main_bb_ninstr; i++) {
    needs_memcheck[i] = instructions[i].writes_memory || 
        instructions[i].reads_memory;
  }

  struct flags_patching flagspatches[MAIN_BB_MAX_INSTRNS];
  optimize_flags_pass(&instructions[0], &main_bb[0],
      &flagspatches[0], &needs_memcheck[0],
      main_bb_ninstr);

  /**
   * For each instruction see if before the instruction is
   * executed flags need to be saved and/or restored
   */
  int saverest[MAIN_BB_MAX_INSTRNS];
  assert(main_bb_ninstr < MAIN_BB_MAX_INSTRNS);
  analyze_flags_save_restore_needs(&instructions[0], &main_bb[0],
      &needs_memcheck[0], main_bb_ninstr,
      &saverest[0]);

  uchar* stopper_jumps[MAIN_BB_MAX_INSTRNS];
  int num_stopper_jumps = 0;

  int fialled = 0;

  PRINT_DEBUG_TRANSLATE("ninstr %d\n", main_bb_ninstr);

  /* It is important that we translate the whole block*/
  int instrnr;
  for (instrnr = 0; instrnr<main_bb_ninstr; instrnr++){
    PRINT_DEBUG_TRANSLATE("in %d\n", instrnr);

    /* we must make sure that the maximum number of instructions
       times the average translated instruction size is by a margin
       smaller than MAX_BLOCK_SIZE so that this will not happen */
    if (bytes_translated >= MAX_BLOCK_SIZE){
      fbt_suicide_str("Block size exceeded!!! Bailing out!\n");
    }

    /* translate an instruction */
    fbt_disasm_instr(ts);
    uchar *old_transl_instr =
        (uchar*)(uint64_t)tld->transl_instr;

    struct translate* sss = &main_bb[instrnr];
    if (sss->cur_instr != ts->cur_instr){
      fbt_suicide_str("fffiiiaalll\n");
    }
    if (fbt_strncmp(sss->cur_instr_info->mnemonic, ts->cur_instr_info->mnemonic, -1) != 0){
      fialled=1;
    }

#ifdef DEBUG
    print64(debugStream, (uint64_t)ts->tld->transl_instr);
    fllprintf(debugStream, ": (orig=0x%x)", (uint32_t)ts->cur_instr);
    print_disasm_instruction(debugStream, ts, ts->next_instr-ts->cur_instr);
#endif

    tu_state = translate_single_instruction(tld,
        ts,
        &instructions[instrnr],
        saverest[instrnr],
        needs_memcheck[instrnr],
        flagspatches[instrnr],
        &stopper_jumps[0],
        &num_stopper_jumps,
        lock);

    bytes_translated += (tld->transl_instr - old_transl_instr);
  }

  if (fialled){
    fbt_suicide_str("failure.\n");
  }

  PRINT_DEBUG_TRANSLATE("endlp\n");

#ifdef ENABLE_MEMCHECKS
  {
    uchar *transl_instr = tld->transl_instr;
    uchar *stopper_code = transl_instr;
    BEGIN_ASM(transl_instr);
    jmp skip; /* needed since sometimes fallthrough is used between basic blocks */
              /* will jump to this location if a watchpoint is hit*/
    nop; nop; nop; nop;
    xor %r8,%r8;  /* do not pass any ip info for now */
    xor %r9,%r9;
    GOTO_WATCHPOINT_HANDLER
    skip:
    END_ASM;
    tld->transl_instr = transl_instr;

    // Now backpatch all locations that want to jump to this
    // stopper code

    /* RECALL OPCODES OF JUMPS:
     *
      e6:       eb 34                   jmp    11c <nearlab>
      e8:       75 32                   jne    11c <nearlab>
      ea:       74 30                   je     11c <nearlab>
      ec:       e9 2b 01 00 00          jmpq   21c <middlelab>
      f1:       0f 85 25 01 00 00       jne    21c <middlelab>
      f7:       0f 84 1f 01 00 00       je     21c <middlelab>
      fd:       e9 4c 0f 00 00          jmpq   104e <gugus>
     102:       0f 85 46 0f 00 00       jne    104e <gugus>
     108:       0f 84 40 0f 00 00       je     104e <gugus>
    */

    while (num_stopper_jumps > 0){
      num_stopper_jumps--;
      uchar* wheretopatch = stopper_jumps[num_stopper_jumps];

      int32_t joffs = (int32_t)((int64_t)stopper_code - (int64_t)wheretopatch) - 2;
      if (joffs < 0){fbt_suicide_str("this is not possible!");}
      *(wheretopatch++) = 0x0f;
      *(wheretopatch++) = 0x85;
      *((int32_t*)wheretopatch) = joffs;
      wheretopatch += 4;
    }
  }
#endif

  /* if the TU was finished because the number of instructions hit the limit, we
   have to add glue code to the TU */
  if (tu_state != CLOSE) {
    if (tu_state != CLOSE_GLUE) {
      PRINT_DEBUG_TRANSLATE("finishing TU because instruction limit was hit, invoking"
          "translation function on %p", ts->next_instr);
    } else {
      PRINT_DEBUG_TRANSLATE("closing TU upon request, invoking translation function on"
          " %p", ts->next_instr);
    }
    /* takes care of the flag register! */
    /* write: jump to trampoline that does chaining if next block needs to be
     translated or does fallthrough otherwise */
    struct trampoline *trampo = fbt_create_trampoline(tld,
        ts->next_instr,
        tld->transl_instr + 1,
        ORIGIN_RELATIVE,
        lock);
    JMP_REL32(tld->transl_instr, trampo->code);
  }

  PRINT_DEBUG_FUNCTION_END("-> %p,   next_tu=%p (len: %d)", transl_address, ts->next_instr, bytes_translated);

  return transl_address;
}

/**
 * A thin wrapper: starts the translation of one basic block
 * starting at orig_address. This wrapper is needed in order
 * to save stack space when the FAST_RET is enabled. The
 * reason is that FAST_RET wants to translate bigger chunks
 * of code at a time (by dfs) and that fbt_translate_noexecute_impl()
 * uses a lot of stack space. This wrapper solves this issue.
 * @param tld the thread local data
 * @param orig_address where to start translating
 * @return the address where the code has been translated
 */
void *fbt_translate_noexecute(struct thread_local_data *tld,
    guestptr_t orig_address,
    BOOL lock)
{
  //tld->in_bt_context++;

  void* res = fbt_translate_noexecute_impl(tld, orig_address, lock);

  static int ff = 0;
  PRINT_DEBUG("ff=%d\n",ff);
  ff++;

#ifdef FAST_RET
  while (tld->totranslate_stacktop > 0){
    tld->totranslate_stacktop--;
    uint32_t whatorig = tld->totrans[tld->totranslate_stacktop];
    void** wheretopatch =
        (void**)(uint64_t)tld->topatch[tld->totranslate_stacktop];

    void* res = fbt_translate_noexecute(tld, whatorig, lock);
    *wheretopatch = res;
  }
#endif

  //tld->in_bt_context--;
  return res;
}

