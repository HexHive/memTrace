/**
 * @file fbt_x86_opcode.h
 * This file defines specific opcode information for x86 machine code
 * These can and should be used by a user program.
 *
 * Copyright (c) 2010 ETH Zurich
 *
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * $Date: 2012-01-22 21:05:54 +0100 (dom, 22 gen 2012) $
 * $LastChangedDate: 2012-01-22 21:05:54 +0100 (dom, 22 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1206 $
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

#ifndef FBT_X86_OPCODE_H
#define FBT_X86_OPCODE_H

/* REX bits */
#define REXW 0x8

/**
 * ModR/M flags
 */
/** a ModR/M byte follows the opcode */
#define HAS_MODRM 0x10
#define NO_MODRM 0x00

/* ModR/M fields */
#define MODRM_MOD(x) ((x>>6)&0x3)
#define MODRM_REG(x) ((x>>3)&0x7)
#define MODRM_RM(x) (x&0x7)
/* sib fields */
#define SIB_SCALE(x) MODRM_MOD(x)
#define SIB_INDEX(x) MODRM_REG(x)
#define SIB_BASE(x) MODRM_RM(x)

/**
 * escape flags
 */
/** escape for prefix */
#define OPCODE_PREFIX_ESC 0x01
/** escape for multibyte opcodes */
#define OPCODE_ESC 0x02
/** escape for fpu opcodes */
#define OPCODE_FPU_ESC 0x04
/** opcode extension in the three reg bits of the ModR/M byte */
#define OPCODE_MODRM_ESC 0x08
#define OPCODETABLE(x) (x&0xF) /* we escape into a table */

/** this is a special action that is not called from within the disasm_insn-function */
#define NO_ACTION_CALLED 0

/* special prefixes */
#define PREFIX_LOCK        0xf0
#define PREFIX_REPNEZ      0xf2
#define PREFIX_MISC        0xf3
#define PREFIX_ES_SEG_OVR  0x26
#define PREFIX_CS_SEG_OVR  0x2e
#define PREFIX_SS_SEG_OVR  0x36
#define PREFIX_DS_SEG_OVR  0x3e
#define PREFIX_FS_SEG_OVR  0x64
#define PREFIX_GS_SEG_OVR  0x65
#define PREFIX_OP_SZ_OVR   0x66
#define PREFIX_ADDR_SZ_OVR 0x67

/* does the given opcode use a prefix? */
#define HAS_PREFIX(opc_byte) \
    ((opc_byte==PREFIX_LOCK) \
        || (opc_byte==PREFIX_REPNEZ) \
        || (opc_byte==PREFIX_CS_SEG_OVR) \
        || (opc_byte==PREFIX_SS_SEG_OVR) \
        || (opc_byte==PREFIX_DS_SEG_OVR) \
        || (opc_byte==PREFIX_ES_SEG_OVR) \
        || (opc_byte==PREFIX_FS_SEG_OVR) \
        || (opc_byte==PREFIX_GS_SEG_OVR) \
        || (opc_byte==PREFIX_OP_SZ_OVR) \
        || (opc_byte==PREFIX_ADDR_SZ_OVR))

/*******************************************************\
 * operand flags                                       *
\*******************************************************/
/* operand not used by this instruction */
#define	NONE            0x00000000
#define	ARG_NONE        0x00000000

/* operand masks */
#define	OP_USE_MASK     0x0000000F  /* how is this operand used */
#define	OP_SPECIAL_MASK 0x000000F0  /* special flags for this operand */
#define	OP_ADDRM_MASK   0x00001F00  /* addressing method */
#define	OPT_MASK        0x00FF0000  /* type of operand */



/* how is the opeand used in this instruction */
#define RWX             0x00000007
#define READ            0x00000001  /* operand is read */
#define WRITE           0x00000002  /* operand is written */
#define MODIFY          READ | WRITE  /* operand is modified */
#define EXECUTE         0x00000004  /* operand is executed */

/* special operands and flags */
#define IMPL            0x00000010  /* implizit register */
#define CONST           0x00000020  /* implizit constant value */
#define SIGEND          0x00000040  /* operand is signed */

/* addresing methods - taken from intel manual */
#define ADDRM_A         0x00000100
#define ADDRM_C         0x00000200
#define ADDRM_D         0x00000300
#define ADDRM_E         0x00000400
#define ADDRM_F         0x00000500
#define ADDRM_G         0x00000600
#define ADDRM_I         0x00000700
#define ADDRM_J         0x00000800
#define ADDRM_M         0x00000900
#define ADDRM_N         0x00000A00
#define ADDRM_O         0x00000B00
#define ADDRM_P         0x00000C00
#define ADDRM_Q         0x00000D00
#define ADDRM_R         0x00000E00
#define ADDRM_S         0x00000F00
#define ADDRM_U         0x00001000
#define ADDRM_V         0x00001100
#define ADDRM_W         0x00001200
#define ADDRM_X         0x00001300
#define ADDRM_Y         0x00001400
#define ADDRM_RM        0x00001500
#define ADDRM_UM        0x00001600

#define hasModRMOp(x) (((x&OP_ADDRM_MASK)==ADDRM_C)||((x&OP_ADDRM_MASK)==ADDRM_D)||((x&OP_ADDRM_MASK)==ADDRM_E)||((x&OP_ADDRM_MASK)==ADDRM_G)||((x&OP_ADDRM_MASK)==ADDRM_M)||((x&OP_ADDRM_MASK)==ADDRM_N)||((x&OP_ADDRM_MASK)==ADDRM_P)||((x&OP_ADDRM_MASK)==ADDRM_Q)||((x&OP_ADDRM_MASK)==ADDRM_R)||((x&OP_ADDRM_MASK)==ADDRM_S)||((x&OP_ADDRM_MASK)==ADDRM_U)||((x&OP_ADDRM_MASK)==ADDRM_V)||((x&OP_ADDRM_MASK)==ADDRM_W)||((x&OP_ADDRM_MASK)==ADDRM_RM)||((x&OP_ADDRM_MASK)==ADDRM_UM))

#define anyModRMOp(x) (hasModRMOp(x->destFlags)||hasModRMOp(x->srcFlags)||hasModRMOp(x->auxFlags))

#define ModRMparseRM(x) (((x&OP_ADDRM_MASK)==ADDRM_E)||((x&OP_ADDRM_MASK)==ADDRM_M)||((x&OP_ADDRM_MASK)==ADDRM_Q)||((x&OP_ADDRM_MASK)==ADDRM_R)||((x&OP_ADDRM_MASK)==ADDRM_U)||((x&OP_ADDRM_MASK)==ADDRM_W)||((x&OP_ADDRM_MASK)==ADDRM_RM)||((x&OP_ADDRM_MASK)==ADDRM_UM))

#define ModRMparseREG(x) (((x&OP_ADDRM_MASK)==ADDRM_G)||((x&OP_ADDRM_MASK)==ADDRM_N)||((x&OP_ADDRM_MASK)==ADDRM_P)||((x&OP_ADDRM_MASK)==ADDRM_S)||((x&OP_ADDRM_MASK)==ADDRM_V)||((x&OP_ADDRM_MASK)==ADDRM_C)||((x&OP_ADDRM_MASK)==ADDRM_D))

#define hasImmOp(x) (((x&OP_ADDRM_MASK)==ADDRM_A)||((x&OP_ADDRM_MASK)==ADDRM_I)||((x&OP_ADDRM_MASK)==ADDRM_J)||((x&OP_ADDRM_MASK)==ADDRM_O))

#define anyImmOp(x) (hasModRMOp(x->destFlags)||hasModRMOp(x->srcFlags)||hasModRMOp(x->auxFlags))

#define immIsPtr(x) (hasImmOp(x) && ((x&OP_ADDRM_MASK)!=ADDRM_I)) /* address or offset */
#define hasMemOp(x) (((x&OP_ADDRM_MASK)==ADDRM_A)||((x&OP_ADDRM_MASK)==ADDRM_E)||((x&OP_ADDRM_MASK)==ADDRM_J)||((x&OP_ADDRM_MASK)==ADDRM_M)||((x&OP_ADDRM_MASK)==ADDRM_O)||((x&OP_ADDRM_MASK)==ADDRM_Q)||((x&OP_ADDRM_MASK)==ADDRM_W)||((x&OP_ADDRM_MASK)==ADDRM_Y)||((x&OP_ADDRM_MASK)==ADDRM_RM)||((x&OP_ADDRM_MASK)==ADDRM_UM))

/* operand types - taken from intel manual */
#define OPT_a           0x00010000
#define OPT_b           0x00020000
#define OPT_c           0x00030000
#define OPT_d           0x00040000
#define OPT_dq          0x00050000
#define OPT_p           0x00060000
#define OPT_pd          0x00070000
#define OPT_pi          0x00080000
#define OPT_ps          0x00090000
#define OPT_q           0x000A0000
#define OPT_s           0x000B0000
#define OPT_ss          0x000C0000
#define OPT_sd          0x000D0000  /* this one is not in the intel manual! */
#define OPT_si          0x000E0000
#define OPT_v           0x000F0000
#define OPT_w           0x00100000
#define OPT_z           0x00110000
/* operand types for FPU - these are not found in the intel manual */
#define OPT_fs          0x00200000  /* single-real*/
#define OPT_fd          0x00210000  /* double-real */
#define OPT_fe          0x00220000  /* extended-real */
#define OPT_fp          0x00230000  /* packed-BCD */
#define OPT_fv          0x00240000  /* FPU env (14/28 bytes) */
#define OPT_fst         0x00250000  /* FPU state (98/108 bytes) */


/*******************************************************\
 * implizit operand flags                              *
\*******************************************************/
/* implizit operand masks */
#define		REG_IDX_MASK		0x0000000F
#define		REG_TYPE_MASK		0x000000F0

/* register types */
#define		BYTE_REG				0x00000010
#define		WORD_REG				0x00000020
#define		DWORD_REG				0x00000030
#define		MMX_REG					0x00000040
#define		XMM_REG					0x00000050
#define		SEGMENT_REG				0x00000060
#define		TEST_REG				0x00000070
#define		FPU_REG					0x00000080

#define		AL						0x00000010
#define		CL						0x00000011
#define		DL						0x00000012
#define		BL						0x00000013
#define		AH						0x00000014
#define		CH						0x00000015
#define		DH						0x00000016
#define		BH						0x00000017

#define		AX						0x00000020
#define		CX						0x00000021
#define		DX						0x00000022
#define		BX						0x00000023
#define		SP						0x00000024
#define		BP						0x00000025
#define		SI						0x00000026
#define		DI						0x00000027

#define		rAX						0x00000030
#define		rCX						0x00000031
#define		rDX						0x00000032
#define		rBX						0x00000033
#define		rSP						0x00000034
#define		rBP						0x00000035
#define		rSI						0x00000036
#define		rDI						0x00000037

#define		MM0						0x00000040
#define		MM1						0x00000041
#define		MM2						0x00000042
#define		MM3						0x00000043
#define		MM4						0x00000044
#define		MM5						0x00000045
#define		MM6						0x00000046
#define		MM7						0x00000047

#define		XMM0					0x00000050
#define		XMM1					0x00000051
#define		XMM2					0x00000052
#define		XMM3					0x00000053
#define		XMM4					0x00000054
#define		XMM5					0x00000055
#define		XMM6					0x00000056
#define		XMM7					0x00000057

#define		CS						0x00000060
#define		DS						0x00000061
#define		ES						0x00000062
#define		FS						0x00000063
#define		GS						0x00000064
#define		SS						0x00000065

#define		T0						0x00000070
#define		T1						0x00000071
#define		T2						0x00000072

#define		ST0						0x00000080
#define		ST1						0x00000081
#define		ST2						0x00000082
#define		ST3						0x00000083
#define		ST4						0x00000084
#define		ST5						0x00000085
#define		ST6						0x00000086
#define		ST7						0x00000087


/*******************************************************\
 * instruction flags                                   *
\*******************************************************/
#define		OPCODEFL_INS_TYPE_MASK			0x0000FFFF
#define		OPCODEFL_INS_GROUP_MASK			0x0000F000
#define		OPCODEFL_INS_PREFIX_MASK			0x0FFF0000


/* prefixes */
#define		OPCODEFL_PREFIX_LOCK				0x00010000
#define		OPCODEFL_PREFIX_REP				0x00020000
#define		OPCODEFL_PREFIX_REPNZ			0x00040000
#define		OPCODEFL_PREFIX_OP_SIZE			0x00100000
#define		OPCODEFL_PREFIX_ADDR_SIZE		0x00200000

#define		OPCODEFL_PREFIX_CS				0x01000000
#define		OPCODEFL_PREFIX_SS				0x02000000
#define		OPCODEFL_PREFIX_DS				0x03000000
#define		OPCODEFL_PREFIX_ES				0x04000000
#define		OPCODEFL_PREFIX_FS				0x05000000
#define		OPCODEFL_PREFIX_GS				0x06000000



/* instruction types [groups] */
#define		OPCODEFL_EXEC					0x00001000
#define		OPCODEFL_ARITH					0x00002000
#define		OPCODEFL_LOGIC					0x00003000
#define		OPCODEFL_STACK					0x00004000
#define		OPCODEFL_COND					0x00005000
#define		OPCODEFL_LOAD					0x00006000
#define		OPCODEFL_ARRAY					0x00007000
#define		OPCODEFL_BIT						0x00008000
#define		OPCODEFL_FLAG					0x00009000
#define		OPCODEFL_FPU						0x0000A000
#define		OPCODEFL_TRAPS					0x0000D000
#define		OPCODEFL_SYSTEM				0x0000E000
#define		OPCODEFL_OTHER					0x0000F000

/* EXEC group */
#define		OPCODEFL_BRANCH					(OPCODEFL_EXEC | 0x01)			/* Unconditional branch */
#define		OPCODEFL_BRANCHCC				(OPCODEFL_EXEC | 0x02)			/* Conditional branch */
#define		OPCODEFL_CALL					(OPCODEFL_EXEC | 0x03)			/* Jump to subroutine */
#define		OPCODEFL_CALLCC					(OPCODEFL_EXEC | 0x04)			/* Jump to subroutine */
#define		OPCODEFL_RET						(OPCODEFL_EXEC | 0x05)			/* Return from subroutine */
#define		OPCODEFL_LOOP					(OPCODEFL_EXEC | 0x06)			/* loop to local label */

/* ARITH group */
#define		OPCODEFL_ADD						(OPCODEFL_ARITH | 0x01)
#define		OPCODEFL_SUB						(OPCODEFL_ARITH | 0x02)
#define		OPCODEFL_MUL						(OPCODEFL_ARITH | 0x03)
#define		OPCODEFL_DIV						(OPCODEFL_ARITH | 0x04)
#define		OPCODEFL_INC						(OPCODEFL_ARITH | 0x05)		/* increment */
#define		OPCODEFL_DEC						(OPCODEFL_ARITH | 0x06)		/* decrement */
#define		OPCODEFL_SHL						(OPCODEFL_ARITH | 0x07)		/* shift right */
#define		OPCODEFL_SHR						(OPCODEFL_ARITH | 0x08)		/* shift left */
#define		OPCODEFL_ROL						(OPCODEFL_ARITH | 0x09)		/* rotate left */
#define		OPCODEFL_ROR						(OPCODEFL_ARITH | 0x0A)		/* rotate right */

/* LOGIC group */
#define		OPCODEFL_AND						(OPCODEFL_LOGIC | 0x01)
#define		OPCODEFL_OR						  (OPCODEFL_LOGIC | 0x02)
#define		OPCODEFL_XOR						(OPCODEFL_LOGIC | 0x03)
#define		OPCODEFL_NOT						(OPCODEFL_LOGIC | 0x04)
#define		OPCODEFL_NEG						(OPCODEFL_LOGIC | 0x05)

/* STACK group */
#define		OPCODEFL_PUSH					  (OPCODEFL_STACK | 0x01)
#define		OPCODEFL_POP						(OPCODEFL_STACK | 0x02)
#define		OPCODEFL_PUSHREGS			  (OPCODEFL_STACK | 0x03)		/* push register context */
#define		OPCODEFL_POPREGS				(OPCODEFL_STACK | 0x04)		/* pop register context */
#define		OPCODEFL_PUSHFLAGS			(OPCODEFL_STACK | 0x05)		/* push all flags */
#define		OPCODEFL_POPFLAGS				(OPCODEFL_STACK | 0x06)		/* pop all flags */
#define		OPCODEFL_ENTER					(OPCODEFL_STACK | 0x07)		/* enter stack frame */
#define		OPCODEFL_LEAVE					(OPCODEFL_STACK | 0x08)		/* leave stack frame */

/* COND group */
#define		OPCODEFL_TEST					  (OPCODEFL_COND | 0x01)
#define		OPCODEFL_CMP						(OPCODEFL_COND | 0x02)

/* LOAD group */
#define		OPCODEFL_MOV						(OPCODEFL_LOAD | 0x01)
#define		OPCODEFL_MOVCC					(OPCODEFL_LOAD | 0x02)
#define		OPCODEFL_XCHG					  (OPCODEFL_LOAD | 0x03)
#define		OPCODEFL_XCHGCC					(OPCODEFL_LOAD | 0x04)

/* ARRAY group */
#define		OPCODEFL_STRCMP					(OPCODEFL_ARRAY | 0x01)
#define		OPCODEFL_STRLOAD				(OPCODEFL_ARRAY | 0x02)
#define		OPCODEFL_STRMOV					(OPCODEFL_ARRAY | 0x03)
#define		OPCODEFL_STRSTOR				(OPCODEFL_ARRAY | 0x04)
#define		OPCODEFL_XLAT					  (OPCODEFL_ARRAY | 0x05)

/* BIT group */
#define		OPCODEFL_BITTEST				(OPCODEFL_BIT | 0x01)
#define		OPCODEFL_BITSET					(OPCODEFL_BIT | 0x02)
#define		OPCODEFL_BITCLR					(OPCODEFL_BIT | 0x03)

/* FLAG group */
#define		OPCODEFL_CLEARCF				(OPCODEFL_FLAG | 0x01)			/* clear Carry flag */
#define		OPCODEFL_CLEARZF				(OPCODEFL_FLAG | 0x02)			/* clear Zero flag */
#define		OPCODEFL_CLEAROF				(OPCODEFL_FLAG | 0x03)			/* clear Overflow flag */
#define		OPCODEFL_CLEARDF				(OPCODEFL_FLAG | 0x04)			/* clear Direction flag */
#define		OPCODEFL_CLEARSF				(OPCODEFL_FLAG | 0x05)			/* clear Sign flag */
#define		OPCODEFL_CLEARPF				(OPCODEFL_FLAG | 0x06)			/* clear Parity flag */
#define		OPCODEFL_SETCF					(OPCODEFL_FLAG | 0x07)
#define		OPCODEFL_SETZF					(OPCODEFL_FLAG | 0x08)
#define		OPCODEFL_SETOF					(OPCODEFL_FLAG | 0x09)
#define		OPCODEFL_SETDF					(OPCODEFL_FLAG | 0x0A)
#define		OPCODEFL_SETSF					(OPCODEFL_FLAG | 0x0B)
#define		OPCODEFL_SETPF					(OPCODEFL_FLAG | 0x0C)
#define		OPCODEFL_TOGCF					(OPCODEFL_FLAG | 0x10)			/* toggle */
#define		OPCODEFL_TOGZF					(OPCODEFL_FLAG | 0x20)
#define		OPCODEFL_TOGOF					(OPCODEFL_FLAG | 0x30)
#define		OPCODEFL_TOGDF					(OPCODEFL_FLAG | 0x40)
#define		OPCODEFL_TOGSF					(OPCODEFL_FLAG | 0x50)
#define		OPCODEFL_TOGPF					(OPCODEFL_FLAG | 0x60)

/* TRAP */
#define		OPCODEFL_TRAP					  (OPCODEFL_TRAPS | 0x01)		/* generate trap */
#define		OPCODEFL_TRAPCC					(OPCODEFL_TRAPS | 0x02)		/* conditional trap gen */
#define		OPCODEFL_TRET					  (OPCODEFL_TRAPS | 0x03)		/* return from trap */
#define		OPCODEFL_BOUNDS					(OPCODEFL_TRAPS | 0x04)		/* gen bounds trap */
#define		OPCODEFL_DEBUG					(OPCODEFL_TRAPS | 0x05)		/* gen breakpoint trap */
#define		OPCODEFL_TRACE					(OPCODEFL_TRAPS | 0x06)		/* gen single step trap */
#define		OPCODEFL_INVALIDOP			(OPCODEFL_TRAPS | 0x07)		/* gen invalid instruction */
#define		OPCODEFL_OFLOW					(OPCODEFL_TRAPS | 0x08)		/* gen overflow trap */

/* SYSTEM */
#define		OPCODEFL_HALT					(OPCODEFL_SYSTEM | 0x01)		/* halt machine */
#define		OPCODEFL_IN						(OPCODEFL_SYSTEM | 0x02)	/* input form port */
#define		OPCODEFL_OUT						(OPCODEFL_SYSTEM | 0x03)		/* output to port */
#define		OPCODEFL_CPUID					(OPCODEFL_SYSTEM | 0x04)		/* identify cpu */

/* OTHER */
#define		OPCODEFL_NOP						(OPCODEFL_OTHER | 0x01)
#define		OPCODEFL_BCDCONV				(OPCODEFL_OTHER | 0x02)		/* convert to/from BCD */
#define		OPCODEFL_SZCONV					(OPCODEFL_OTHER | 0x03)		/* convert size of operand */


/** entry for opcode table */
struct ia32_opcode {

  /* opcode flags tell us the instruction type (STACK, ARITH)
   * and cathegory (PUSH, POP, ...)	 */
  unsigned int opcodeFlags;

  /* the following hold flags for the operands */
  /* the value NONE means the opcode does not make use of this operand */
  const unsigned int destFlags;
  const unsigned int srcFlags;
  const unsigned int auxFlags;

  /* implicit flags */
  const unsigned char implDestFlags;
  const unsigned char implSrcFlags;
  const unsigned char implAuxFlags;

  /* table flags */
  const unsigned char tableFlags;

  /* table or function ptr */
  union {
    /* offset in opcode extension table (only relevant if OPCODE_RM flag set) */
    const struct ia32_opcode* const table;
    /* pointer to the function that shall handle that instruction */
    const actionFunP_t handler;
  } opcode;

  //#ifdef DEBUG
  const char* mnemonic;
  //#endif

};
typedef struct ia32_opcode ia32_opcode_t;

#endif  /* FBT_X86_OPCODE_H */
