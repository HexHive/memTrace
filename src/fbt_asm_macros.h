/**
 * @file fbt_asm_macros.h
 * This header file contains all macros needed in fbt_actions.c to
 * generate the machine code used in the ccfs
 *
 * If FBT is compiled with statistics, then they will be collected here.
 *
 * Copyright (c) 2010 ETH Zurich
 *   Mathias Payer <mathias.payer@nebelwelt.net>
 *   Enrico Kravina <enrico.kravina@gmail.com>
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
#ifndef FBT_ASM_MACROS_H
#define FBT_ASM_MACROS_H

/* Control flow instructions */
#define CHECKREL32PTR(dst, rel32)                                       \
    if ((((uint64_t)rel32 - (uint64_t)dst - 4) & ((uint64_t)0x0)) != 0) {   \
      fbt_suicide_str("Relative jump target is too far away!\n");         \
    }

#define REL32PTR(dst, rel32) CHECKREL32PTR(dst, rel32)                  \
    *((uint32_t*)dst) = (uint32_t)((uint64_t)rel32 - (uint64_t)dst - 4);

#define CHECKMEM32PTR(mem32)                                            \
    if (((uint64_t)((uint32_t)(uint64_t)(mem32))) != ((uint64_t)(mem32))) {                 \
      fbt_suicide_str("Memory address not encodable (64b->32b)!\n");     \
    }

#define CHECK_IF_ENCODABLE_AS_SIGNED_32_BIT(offs)                     \
    if ((int32_t)(offs) != (int64_t)(offs)) {                          \
      fbt_suicide_str("Signed offset not encodable in 32 bits!\n");     \
    }

/* relative 32bit jump, valid in ia32 / amd64 */
#define JMP_REL32(dst, rel32) *dst++=0xe9; REL32PTR(dst, rel32); dst+=4

#define INC_ESP_BY_FOUR(dst) *dst++=0x8d; *dst++=0x64; *dst++=0x24; *dst++=0x04;
#define DEC_ESP_BY_FOUR(dst) *dst++=0x8d; *dst++=0x64; *dst++=0x24; *dst++=0xfc;

/* relative 8bit jump */
#define JMP_I8(dst, rel8) *dst=0xeb; *(dst+1)=(rel8); dst+=2

#define MOV_ESP_MEM32(dst, mem32) \
    *dst++=0x89; \
    *dst++=0x25; \
    CHECKMEM32PTR(mem32) \
    *((uint32_t*)dst) = (uint32_t)((ulong_t)mem32); \
    dst+=4;

#define PCREL_MOV_RSP_MEM32(dst, memloc) \
    { \
  *dst++=0x48; \
  *dst++=0x89; \
  *dst++=0x25; \
  int64_t offs = (int64_t)memloc - (int64_t)(dst+4); \
  CHECK_IF_ENCODABLE_AS_SIGNED_32_BIT(offs); \
  *((int32_t*)dst) = (int32_t)offs; \
  dst+=4; \
    }

#define MOV_IMM32_ESP(dst, imm32) \
    *dst++=0xbc; \
    CHECKMEM32PTR(imm32); \
    *((uint32_t*)dst) = (uint32_t)(imm32); \
    dst+=4;

#define MOV_IMM64_RSP(dst, imm64) \
    *dst++=0x48; \
    *dst++=0xbc; \
    *((uint64_t*)dst) = (uint64_t)(imm64); \
    dst+=8;

/* movl imm8(mem32), rm32 */
#define MOVL_IMM8RM32SIB_R32(dst, modrm, sib, imm8) *dst++=0x8b; *dst++=modrm; \
    *dst++=sib; *dst++=imm8
#define MOVL_IMM8RM32_R32(dst, modrm, imm8) *dst++=0x8b; *dst++=modrm; \
    *dst++=imm8
/* movl (mem32), r32 */
#define MOVL_IMM32RM32_R32(dst, modrm, imm32) *dst++=0x8b; *dst++=modrm; \
    CHECKMEM32PTR(imm32) *((uint32_t*)dst) = (uint32_t)((ulong_t)imm32); dst+=4
/* movl r32, rm32 */
#define MOVL_R32_RM32(dst, modrm) *dst++=0x89; *dst++=modrm

#define MOVL_IMM32_IMM8RM32(dst, modrm, imm8, imm32) *dst++=0xc7; *dst++=modrm; \
    *dst++=imm8; CHECKMEM32PTR(imm32) \
    *((uint32_t*)dst) = (uint32_t)((ulong_t)imm32); dst+=4

#define MOVL_IMM32_RM32(dst, modrm, imm32) *dst++=0xc7; *dst++=modrm; \
    CHECKMEM32PTR(imm32) *((uint32_t*)dst) = (uint32_t)((ulong_t)imm32); dst+=4

#define MOVL_IMM32_EAX(dst, imm32) *dst++=0xb8; \
    *((uint32_t*)dst) = imm32; dst+=4;

#define MOVL_IMM32_MEM32(dst, modrm, imm32, mem32) \
    *dst++=0xc7; \
    *dst++=modrm;  \
    CHECKMEM32PTR(mem32); \
    *((uint32_t*)dst) = (uint32_t)((ulong_t)mem32); \
    dst+=4; \
    CHECKMEM32PTR(imm32); \
    *((uint32_t*)dst) = (uint32_t)((ulong_t)imm32); \
    dst+=4;


#define MOVL_EAX_MEM32(dst, mem32) *dst++=0xA3; \
    CHECKMEM32PTR(mem32) *((uint32_t*)dst) = (uint32_t)((ulong_t)mem32); dst+=4

#define MOV_IMM32_R9(dst, imm32) *dst++=0x49; *dst++=0xc7; *dst++=0xc1; *((int32_t*)dst) = imm32; dst+=4;

#define MOVB_IMM8_MEM8(dst, modrm, imm8, mem8) *dst++=0xc6; \
    CHECKMEM32PTR(mem8) *((uint32_t*)dst) = (uint32_t)((ulong_t)mem8); dst+=4; \
    *dst++=imm8

#define CALL_REL32(dst, rel32) *dst++=0xe8; REL32PTR(dst, rel32); dst+=4

#define JECXZ_I8(dst, i8) *dst++=0xe3; *dst++=i8

#define JCC_2B(dst, jcc, rel32) *((uint16_t*)dst)=(uint16_t)jcc; dst+=2; \
    REL32PTR(dst, rel32) dst+=4

#define JE_I8(dst, i8) *dst=0x74; *(dst+1)=i8; dst+=2;
#define JNE_I8(dst, i8) *dst=0x75; *(dst+1)=i8; dst+=2;

#define JMP_IND_M32(dst, m32) *dst++ = 0xff; *dst++ = 0x25; \
    *((int32_t*)dst) = m32; dst+=4

#define CALL_IND_MODRM_SIB_IMM32(dst, modrm, sib, imm32) *dst++=0xff; \
    *dst++=modrm; *dst++=sib; CHECKMEM32PTR(imm32) \
    *((uint32_t*)dst) = (uint32_t)((ulong_t)imm32); dst+=4

#define PUSHL_IMM32(dst, imm) *dst++=0x68; *((int32_t*)dst) = imm; dst+=4
#define PUSHL_RM32_SIB_IMM8(dst, rm32, sib, imm8) *dst++=0xff; *dst++=rm32; \
    *dst++=sib; *dst++=imm8

/* valid only in ia32 */
#define ADDL_IMM8_M32(dst, modrm, imm8, m32) *dst++= 0x83; *dst++=modrm; \
    *((int32_t*)dst) = m32; dst+=4; *dst++ = imm8
#define ADDL_IMM32_RM32(dst, modrm, imm32) *dst++=0x81; *dst++=modrm; \
    *((int32_t*)dst) = imm32; dst+=4
#define ANDL_IMM32_RM32(dst, modrm, imm32) ADDL_IMM32_RM32(dst, modrm, imm32)
#define ADDL_RM32SIB_R32(dst, modrm, sib) *dst++=0x03; *dst++=modrm; *dst++=sib

/* cmpl r32, imm32(modrm sib) */
#define CMPL_R32_IMM32RM32SIB(dst, modrm, sib, imm32) *dst++=0x3b; \
    *dst++=modrm; *dst++=sib; *((int32_t*)dst) = imm32; dst+=4
#define CMPL_R32_M32(dst, modrm, m32) *dst++=0x3b; *dst++=modrm; \
    *((int32_t*)dst) = m32; dst+=4
#define CMPL_R32_IMM8RM32SIB(dst, modrm, sib, imm8) *dst++=0x3b;        \
    *dst++=modrm; *dst++=sib; *dst++=imm8
#define CMPL_R32_IMM8(dst, modrm, imm8) *dst++=0x83; *dst++=modrm; *dst++=imm8
#define CMPL_MEM32_IMM8(dst, mem32, imm8) *dst++=0x83; *dst++=0x3d; \
    CHECKMEM32PTR(mem32) *((uint32_t*)dst) = (uint32_t)((ulong_t)mem32); dst+=4; \
    *dst++=imm8
#define CMPL_RM32_IMM32(dst, modrm, imm32) *dst++=0x81; *dst++=modrm; \
    *((int32_t*)dst) = imm32; dst+=4
#define CMPL_IMM32RM32SIB_IMM32(dst, modrm, sib, disp32, imm32) *dst++=0x81; \
    *dst++=modrm; *dst++=sib; *((int32_t*)dst) = disp32; dst+=4; \
    *((int32_t*)dst) = imm32; dst+=4
#define CMPL_IMM8RM32SIB_IMM32(dst, modrm, sib, disp8, imm32) *dst++=0x81; \
    *dst++=modrm; *dst++=sib; *dst++ = disp8; *((int32_t*)dst) = imm32; dst+=4
#define CMPL_RM32SIB_IMM32(dst, modrm, sib, imm32) *dst++=0x81; \
    *dst++=modrm; *dst++=sib; *((int32_t*)dst) = imm32; dst+=4
#define CMPL_DISP32_IMM32(dst, modrm, disp32, imm32) *dst++=0x81; \
    *dst++=modrm; *((int32_t*)dst) = disp32; dst+=4; \
    *((int32_t*)dst) = imm32; dst+=4
#define CMPL_DISP8_IMM32(dst, modrm, disp8, imm32) *dst++=0x81; \
    *dst++=modrm; *dst++=disp8; *((int32_t*)dst) = imm32; dst+=4
/* movl imm32(mem32), rm32 */
#define MOVL_IMM32RM32SIB_R32(dst, modrm, sib, imm32) *dst++=0x8b; \
    *dst++=modrm; *dst++=sib; *((int32_t*)dst) = imm32; dst+=4
/* movl r32, i32rm32 */
#define MOVL_R32_IMM32RM32(dst, modrm, imm32) *dst++=0x89; *dst++=modrm; \
    *((int32_t*)dst) = imm32; dst+=4

#define PUSHL_EAX(dst) *dst++=0x50
#define PUSHL_ECX(dst) *dst++=0x51
#define PUSHL_EDX(dst) *dst++=0x52
#define PUSHL_EBX(dst) *dst++=0x53
#define PUSHL_ESP(dst) *dst++=0x54
#define PUSHL_EBP(dst) *dst++=0x55
#define PUSHL_ESI(dst) *dst++=0x56
#define PUSHL_EDI(dst) *dst++=0x57
#define PUSHAD(dst) *dst++=0x60
#define PUSHFL(dst) *dst++=0x9c
#define PUSHL_RM32IMM8(dst, modrm, imm8) *dst++=0xff; *dst++=modrm; *dst++=imm8
#define PUSHL_MEM32(dst, mem32) *dst++=0xff; *dst++=0x35; \
    CHECKMEM32PTR(mem32) *((uint32_t*)dst) = (uint32_t)((ulong_t)mem32); dst+=4
#define POPL_EAX(dst) *dst++=0x58
#define POPL_ECX(dst) *dst++=0x59
#define POPL_EDX(dst) *dst++=0x5a
#define POPL_EBX(dst) *dst++=0x5b
#define POPL_ESP(dst) *dst++=0x5c
#define POPL_EBP(dst) *dst++=0x5d
#define POPL_ESI(dst) *dst++=0x5e
#define POPL_EDI(dst) *dst++=0x5f
#define POPAD(dst) *dst++=0x61
#define POPFL(dst) *dst++=0x9d

#define LEAL_IMM8RM32_R(dst, modrm, sib, imm8) *dst++=0x8d; *dst++=modrm; \
    *dst++=sib; *dst++=imm8

#define LEAL_IMM32RM32_R(dst, modrm, sib, imm32) *dst++=0x8d; *dst++=modrm; \
    *dst++=sib; *((int32_t*)dst) = imm32; dst+=4

#define ADDL_RM32_SIB_IMM8(dst, modrm, sib, imm8) *dst++=0x83; *dst++=modrm; \
    *dst++=sib; *dst++=imm8

#define ADDL_RM32_IMM32IMM8(dst, modrm, imm32, imm8) *dst++=0x83; *dst++=modrm; \
    *((int32_t*)dst) = imm32; dst+=4; *dst++=imm8

#define SYSENTER(dst) *dst++=0x0f; *dst++=0x34
#define INT80(dst) *dst++=0xcd; *dst++=0x80

#define INT3(dst) *dst++=0xcc

#define LOCK_PREFIX(dst) *dst++=0xF0

#define XOR_R32_R32(dst, modrm) *dst++=0x31; *dst++=modrm

#endif  /* FBT_ASM_MACROS_H */
