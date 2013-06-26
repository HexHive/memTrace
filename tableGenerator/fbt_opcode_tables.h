/***  !! THIS IS A GENERATED FILE !!  ***/
/***  DO NOT MODIFY THIS FILE - ALL CHANGES WILL BE OVERWRITTEN WHEN A NEW VERSION IS GENERATED  ***/


#ifndef FBT_OPCODE_TABLES_H
#define FBT_OPCODE_TABLES_H


/*
 * tables for opcode extensions in ModR/M byte.
 * The opcodes extend into the reg bits (5, 4, 3) of the ModR/M byte.
 */

/** group 1 OPCODE 0x80 */
struct ia32_opcode opcode_table_80_rm[] = {
	{ 0x2001, MODIFY | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 000 ADD imm8, r/m8 */
	{ 0x3002, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 001 OR imm8, r/m8 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 010 ADC imm8, r/m8 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 011 SBB imm8, r/m8 */
	{ 0x3001, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 100 AND imm8, r/m8 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 101 SUB imm8, r/m8 */
	{ 0x3003, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 110 XOR imm8, r/m8 */
	{ 0x5002, READ | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" }	/* 111 CMP imm8, r/m8 */
};


/** group 1 OPCODE 0x81 */
struct ia32_opcode opcode_table_81_rm[] = {
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 000 ADD imm32, r/m32 */
	{ 0x3002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 001 OR imm32, r/m32 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 010 ADC imm32, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 011 SBB imm32, r/m32 */
	{ 0x3001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 100 AND imm32, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 101 SUB imm32, r/m32 */
	{ 0x3003, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 110 XOR imm32, r/m32 */
	{ 0x5002, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" }	/* 111 CMP imm32, r/m32 */
};


/** group 1 OPCODE 0x82 */
struct ia32_opcode opcode_table_82_rm[] = {
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 000 ADD imm8, r/m32 */
	{ 0x3002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 001 OR imm8, r/m32 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 010 ADC imm8, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 011 SBB imm8, r/m32 */
	{ 0x3001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 100 AND imm8, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 101 SUB imm8, r/m32 */
	{ 0x3003, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 110 XOR imm8, r/m32 */
	{ 0x5002, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" }	/* 111 CMP imm8, r/m32 */
};


/** group 1 OPCODE 0x83 */
struct ia32_opcode opcode_table_83_rm[] = {
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 000 ADD imm8, r/m32 */
	{ 0x3002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 001 OR imm8, r/m32 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 010 ADC imm8, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 011 SBB imm8, r/m32 */
	{ 0x3001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 100 AND imm8, r/m32 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 101 SUB imm8, r/m32 */
	{ 0x3003, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 110 XOR imm8, r/m32 */
	{ 0x5002, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" }	/* 111 CMP imm8, r/m32 */
};


/** group 2 OPCODE 0xC0 */
struct ia32_opcode opcode_table_C0_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL imm8, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR imm8, r/m8 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL imm8, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR imm8, r/m8 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL imm8, r/m8 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR imm8, r/m8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR imm8, r/m8 */
};


/** group 2 OPCODE 0xC1 */
struct ia32_opcode opcode_table_C1_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL imm8, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR imm8, r/m32 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL imm8, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR imm8, r/m32 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL imm8, r/m32 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR imm8, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR imm8, r/m32 */
};


/** group 2 OPCODE 0xD0 */
struct ia32_opcode opcode_table_D0_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL $1, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR $1, r/m8 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL $1, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR $1, r/m8 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL $1, r/m8 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR $1, r/m8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR $1, r/m8 */
};


/** group 2 OPCODE 0xD1 */
struct ia32_opcode opcode_table_D1_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL $1, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR $1, r/m32 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL $1, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR $1, r/m32 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL $1, r/m32 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR $1, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ |  CONST , ARG_NONE, 0x0, 0x1, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR $1, r/m32 */
};


/** group 2 OPCODE 0xD2 */
struct ia32_opcode opcode_table_D2_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL CL, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR CL, r/m8 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL CL, r/m8 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR CL, r/m8 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL CL, r/m8 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR CL, r/m8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR CL, r/m8 */
};


/** group 2 OPCODE 0xD3 */
struct ia32_opcode opcode_table_D3_rm[] = {
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rol" },	/* 000 ROL CL, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "ror" },	/* 001 ROR CL, r/m32 */
	{ 0x2009, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rcl" },	/* 010 RCL CL, r/m32 */
	{ 0x200a, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "rcr" },	/* 011 RCR CL, r/m32 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "shl" },	/* 100 SHL CL, r/m32 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "shr" },	/* 101 SHR CL, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x11, 0x0, HAS_MODRM, {.handler = action_copy}, "sar" }	/* 111 SAR CL, r/m32 */
};


/** group 3 OPCODE 0xF6 */
struct ia32_opcode opcode_table_F6_rm[] = {
	{ 0x5001, READ | ADDRM_E | OPT_b, READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "test" },	/* 000 TEST imm8, r/m8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0x3004, MODIFY | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "not" },	/* 010 NOT, r/m8 */
	{ 0x3005, MODIFY | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "neg" },	/* 011 NEG, r/m8 */
	{ 0x2003, WRITE |  IMPL , READ | ADDRM_E | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mul" },	/* 100 MUL %ax = %al * r/m8 */
	{ 0x2003, WRITE |  IMPL , READ | ADDRM_E | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "imul" },	/* 101 IMUL %ax = %al * r/m8 */
	{ 0x2004, WRITE |  IMPL , READ | ADDRM_E | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "div" },	/* 110 DIV %al = %eax / r/m8   %ah = %eax % r/m8 */
	{ 0x2004, WRITE |  IMPL , READ | ADDRM_E | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "idiv" }	/* 111 IDIV %al = %eax / r/m8   %ah = %eax % r/m8 */
};


/** group 3 OPCODE 0xF7 */
struct ia32_opcode opcode_table_F7_rm[] = {
	{ 0x5001, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "test" },	/* 000 TEST imm32, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0x3004, WRITE | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "not" },	/* 010 NOT, r/m32 */
	{ 0x3005, WRITE | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "neg" },	/* 011 NEG, r/m32 */
	{ 0x2003, WRITE |  IMPL , READ | ADDRM_E | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mul" },	/* 100 MUL %edx:%eax = %eax * r/m32 */
	{ 0x2003, WRITE |  IMPL , READ | ADDRM_E | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "imul" },	/* 101 IMUL %edx:%eax = %eax * r/m32 */
	{ 0x2004, WRITE |  IMPL , READ | ADDRM_E | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "div" },	/* 110 DIV %eax = %edx:%eax / r/m32   %edx = %edx:%eax % r/m32 */
	{ 0x2004, WRITE |  IMPL , READ | ADDRM_E | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "idiv" }	/* 111 IDIV %eax = %edx:%eax / r/m32   %edx = %edx:%eax % r/m32 */
};


/** group 4 OPCODE 0xFE */
struct ia32_opcode opcode_table_FE_rm[] = {
	{ 0x2005, MODIFY | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_inc}, "inc" },	/* 000 INC, r/m8 */
	{ 0x2006, MODIFY | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_dec}, "dec" },	/* 001 DEC, r/m8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 010  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 5 OPCODE 0xFF */
struct ia32_opcode opcode_table_FF_rm[] = {
	{ 0x2005, MODIFY | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_inc}, "inc" },	/* 000 INC, r/m32 */
	{ 0x2006, MODIFY | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_dec}, "dec" },	/* 001 DEC, r/m32 */
	{ 0x1003, EXECUTE | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_call_indirect}, "call" },	/* 010 CALL near indirect */
	{ 0x1003, EXECUTE | ADDRM_E | OPT_p, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "call" },	/* 011 CALL far -> we should not CALL kernel functions directly */
	{ 0x1001, EXECUTE | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_jmp_indirect}, "jmp" },	/* 100 JMP, r/m32 */
	{ 0x1001, EXECUTE | ADDRM_E | OPT_p, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "jmp" },	/* 101 JMP far -> we should not JMP to kernel functions directly */
	{ 0x4001, READ | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_push}, "push" },	/* 110 PUSH, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 6 OPCODE 0x0F00 */
struct ia32_opcode opcode_table_0F00_rm[] = {
	{ 0xe000, WRITE | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sldt" },	/* 000 SLDT, r/m16 */
	{ 0xe000, WRITE | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "str" },	/* 001 STR, r/m16 */
	{ 0xe000, READ | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lldt" },	/* 010 LLDT, r/m16 */
	{ 0xe000, READ | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ltr" },	/* 011 LTR, r/m16 */
	{ 0xe000, READ | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "verr" },	/* 100 VERR, r/m16 */
	{ 0xe000, READ | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "verw" },	/* 101 VERW, r/m16 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 7 OPCODE 0x0F01 */
struct ia32_opcode opcode_table_0F01_rm[] = {
	{ 0xe000, WRITE | ADDRM_M | OPT_s, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sgdt" },	/* 000 SGDT, m80 */
	{ 0xe000, WRITE | ADDRM_M | OPT_s, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sidt" },	/* 001 SIDT, m80 */
	{ 0xe000, READ | ADDRM_M | OPT_s, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lgdt" },	/* 010 LGDT, m80 */
	{ 0xe000, READ | ADDRM_M | OPT_s, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lidt" },	/* 011 LIDT, m80 */
	{ 0xe000, WRITE | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "smsw" },	/* 100 SMSW, r/m16 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xe000, READ | ADDRM_E | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lmsw" },	/* 110 LMSW, r/m16 */
	{ 0xe000, READ | ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "invlpg" }	/* 111 INVLPG, m8 */
};


/** group 8 OPCODE Ox0FBA */
struct ia32_opcode opcode_table_0FBA_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 010  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bt" },	/* 100 BT imm8, r/m32 */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bts" },	/* 101 BTS imm8, r/m32 */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "btr" },	/* 110 BTR imm8, r/m32 */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "btc" }	/* 111 BTC imm8, r/m32 */
};


/** group 9 OPCODE Ox0FC7 */
struct ia32_opcode opcode_table_0FC7_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x6004, MODIFY | ADDRM_M | OPT_q, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmpxch8b" },	/* 001 CMPXCH8B, m64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 010  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 12 OPCODE Ox0F71 */
struct ia32_opcode opcode_table_0F71_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlw" },	/* 010 PSRLW imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psraw" },	/* 100 PSRAW imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllw" },	/* 110 PSLLW imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 13 OPCODE Ox0F72 */
struct ia32_opcode opcode_table_0F72_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrld" },	/* 010 PSRLD imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrad" },	/* 100 PSRAD imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pslld" },	/* 110 PSLLD imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 14 OPCODE Ox0F73 */
struct ia32_opcode opcode_table_0F73_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlq" },	/* 010 PSRLQ imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllq" },	/* 110 PSLLQ imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 15 OPCODE Ox0FAE */
struct ia32_opcode opcode_table_0FAE_rm[] = {
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "fxsave" },	/* 000 FXSAVE */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "fxrstor" },	/* 001 FXRSTOR */
	{ 0xf000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "ldmxcsr" },	/* 010 LDMXCSR */
	{ 0xf000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "stmxcsr" },	/* 011 STMXCSR */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "lfence" },	/* 101 LFENCE */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "mfence" },	/* 110 MFENCE */
	{ 0xe000, ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "clflush" }	/* 111 CLFLUSH (clflush or sfence, depending on MODR/M) */
};


/** group 16 OPCODE Ox0F18 */
struct ia32_opcode opcode_table_0F18_rm[] = {
	{ 0xe000, ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "prefetch" },	/* 000 PREFETCH NTA */
	{ 0xe000, ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "prefetch" },	/* 001 PREFETCH T0 */
	{ 0xe000, ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "prefetch" },	/* 010 PREFETCH T1 */
	{ 0xe000, ADDRM_M | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "prefetch" },	/* 011 PREFETCH T2 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 110  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 12 OPCODE Ox660F71 (with 0x66 prefix) */
struct ia32_opcode opcode_table_660F71_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlw" },	/* 010 PSRLW imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psraw" },	/* 100 PSRAW imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllw" },	/* 110 PSLLW imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 13 OPCODE Ox660F72 (with 0x66 prefix) */
struct ia32_opcode opcode_table_660F72_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrld" },	/* 010 PSRLD imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 011  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrad" },	/* 100 PSRAD imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pslld" },	/* 110 PSLLD imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 111  undefined opcode */
};


/** group 14 OPCODE Ox660F73 (with 0x66 prefix) */
struct ia32_opcode opcode_table_660F73_rm[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 000  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 001  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlq" },	/* 010 PSRLQ imm8, reg128 */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrldq" },	/* 011 PSRLDQ imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 100  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 101  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllq" },	/* 110 PSLLQ imm8, reg128 */
	{ 0xf000, MODIFY | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pslldq" }	/* 111 PSLLDQ imm8, reg128 */
};




/*
 * tables for fpu opcodes.
 */

/** fpu OPCODE 0xD8 */
struct ia32_opcode opcode_table_D8_fpu[] = {
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD800 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD801 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD802 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD803 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD804 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD805 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD806 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD807 FADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD808 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD809 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80A FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80B FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80C FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80D FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80E FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD80F FMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD810 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD811 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD812 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD813 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD814 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD815 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD816 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD817 FCOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD818 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD819 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81A FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81B FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81C FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81D FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81E FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD81F FCOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD820 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD821 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD822 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD823 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD824 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD825 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD826 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD827 FSUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD828 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD829 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82A FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82B FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82C FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82D FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82E FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD82F FSUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD830 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD831 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD832 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD833 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD834 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD835 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD836 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD837 FDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD838 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD839 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83A FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83B FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83C FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83D FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83E FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD83F FDIVR ST0 = m32 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD840 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD841 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD842 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD843 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD844 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD845 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD846 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD847 FADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD848 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD849 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84A FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84B FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84C FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84D FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84E FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD84F FMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD850 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD851 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD852 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD853 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD854 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD855 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD856 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD857 FCOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD858 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD859 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85A FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85B FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85C FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85D FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85E FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD85F FCOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD860 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD861 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD862 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD863 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD864 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD865 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD866 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD867 FSUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD868 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD869 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86A FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86B FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86C FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86D FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86E FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD86F FSUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD870 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD871 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD872 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD873 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD874 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD875 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD876 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD877 FDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD878 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD879 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87A FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87B FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87C FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87D FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87E FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD87F FDIVR ST0 = m32 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD880 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD881 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD882 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD883 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD884 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD885 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD886 FADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD887 FADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD888 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD889 FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88A FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88B FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88C FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88D FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88E FMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD88F FMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD890 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD891 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD892 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD893 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD894 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD895 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD896 FCOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD897 FCOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD898 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD899 FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89A FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89B FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89C FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89D FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89E FCOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD89F FCOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A0 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A1 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A2 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A3 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A4 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A5 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A6 FSUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8A7 FSUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8A8 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8A9 FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AA FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AB FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AC FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AD FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AE FSUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8AF FSUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B0 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B1 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B2 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B3 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B4 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B5 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B6 FDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8B7 FDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8B8 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8B9 FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BA FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BB FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BC FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BD FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BE FDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8BF FDIVR ST0 = m32 / ST0 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C0 FADD ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C1 FADD ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C2 FADD ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C3 FADD ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C4 FADD ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C5 FADD ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C6 FADD ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xD8C7 FADD ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8C8 FMUL ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8C9 FMUL ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CA FMUL ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CB FMUL ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CC FMUL ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CD FMUL ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CE FMUL ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xD8CF FMUL ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D0 FCOM ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D1 FCOM ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D2 FCOM ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D3 FCOM ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D4 FCOM ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D5 FCOM ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D6 FCOM ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcom" },	/* 0xD8D7 FCOM ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8D8 FCOMP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8D9 FCOMP ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DA FCOMP ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DB FCOMP ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DC FCOMP ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DD FCOMP ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DE FCOMP ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xD8DF FCOMP ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E0 FSUB ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E1 FSUB ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E2 FSUB ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E3 FSUB ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E4 FSUB ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E5 FSUB ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E6 FSUB ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xD8E7 FSUB ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8E8 FSUBR ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8E9 FSUBR ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8EA FSUBR ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8EB FSUBR ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8EC FSUBR ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8ED FSUBR ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8EE FSUBR ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xD8EF FSUBR ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F0 FDIV ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F1 FDIV ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F2 FDIV ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F3 FDIV ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F4 FDIV ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F5 FDIV ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F6 FDIV ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xD8F7 FDIV ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8F8 FDIVR ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8F9 FDIVR ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8FA FDIVR ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8FB FDIVR ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8FC FDIVR ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8FD FDIVR ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xD8FE FDIVR ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" }	/* 0xD8FF FDIVR ST(7), ST(0) */
};


/** fpu OPCODE 0xD9 */
struct ia32_opcode opcode_table_D9_fpu[] = {
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD900 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD901 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD902 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD903 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD904 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD905 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD906 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD907 FLD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD908  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD909  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD90F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD910 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD911 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD912 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD913 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD914 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD915 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD916 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD917 FST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD918 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD919 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91A FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91B FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91C FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91D FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91E FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD91F FSTP ST(0), m32 */

	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD920 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD921 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD922 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD923 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD924 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD925 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD926 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD927 FLDENV, m224 */

	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD928 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD929 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92A FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92B FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92C FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92D FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92E FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD92F FLDCW, m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD930 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD931 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD932 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD933 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD934 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD935 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD936 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD937 FSTENV, m224 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD938 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD939 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93A FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93B FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93C FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93D FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93E FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD93F FSTCW, m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD940 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD941 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD942 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD943 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD944 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD945 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD946 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD947 FLD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD948  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD949  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD94F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD950 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD951 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD952 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD953 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD954 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD955 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD956 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD957 FST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD958 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD959 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95A FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95B FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95C FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95D FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95E FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD95F FSTP ST(0), m32 */

	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD960 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD961 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD962 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD963 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD964 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD965 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD966 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD967 FLDENV, m224 */

	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD968 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD969 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96A FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96B FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96C FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96D FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96E FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD96F FLDCW, m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD970 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD971 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD972 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD973 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD974 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD975 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD976 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD977 FSTENV, m224 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD978 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD979 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97A FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97B FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97C FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97D FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97E FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD97F FSTCW, m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD980 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD981 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD982 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD983 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD984 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD985 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD986 FLD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fs, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xD987 FLD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD988  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD989  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD98F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD990 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD991 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD992 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD993 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD994 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD995 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD996 FST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xD997 FST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD998 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD999 FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99A FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99B FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99C FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99D FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99E FSTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fs, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xD99F FSTP ST(0), m32 */

	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A0 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A1 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A2 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A3 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A4 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A5 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A6 FLDENV, m224 */
	{ 0xa000, READ | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldenv" },	/* 0xD9A7 FLDENV, m224 */

	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9A8 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9A9 FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AA FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AB FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AC FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AD FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AE FLDCW, m16 */
	{ 0xa000, READ | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fldcw" },	/* 0xD9AF FLDCW, m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B0 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B1 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B2 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B3 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B4 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B5 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B6 FSTENV, m224 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fv, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstenv" },	/* 0xD9B7 FSTENV, m224 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9B8 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9B9 FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BA FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BB FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BC FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BD FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BE FSTCW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstcw" },	/* 0xD9BF FSTCW, m16 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C0 FLD ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C1 FLD ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C2 FLD ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C3 FLD ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C4 FLD ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C5 FLD ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C6 FLD ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fld" },	/* 0xD9C7 FLD ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9C8 FXCH ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9C9 FXCH ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CA FXCH ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CB FXCH ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CC FXCH ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CD FXCH ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CE FXCH ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fxch" },	/* 0xD9CF FXCH ST(7), ST(0) */

	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fnop" },	/* 0xD9D0 FNOP */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9D9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9DF  undefined opcode */

	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fchs" },	/* 0xD9E0 FCHS */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fabs" },	/* 0xD9E1 FABS */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9E2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9E3  undefined opcode */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ftst" },	/* 0xD9E4 FTST */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fxam" },	/* 0xD9E5 FXAM */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9E6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9E7  undefined opcode */

	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fld1" },	/* 0xD9E8 FLD1 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fld2t" },	/* 0xD9E9 FLD2T */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fld2t" },	/* 0xD9EA FLD2T */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fldpi" },	/* 0xD9EB FLDPI */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fldlg2" },	/* 0xD9EC FLDLG2 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fldln2" },	/* 0xD9ED FLDLN2 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fldz" },	/* 0xD9EE FLDZ */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD9EF  undefined opcode */

	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "f2xm1" },	/* 0xD9F0 F2XM1 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fyl2x" },	/* 0xD9F1 FYL2X */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fptan" },	/* 0xD9F2 FPTAN */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fpatan" },	/* 0xD9F3 FPATAN */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fxtract" },	/* 0xD9F4 FXTRACT */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fprem1" },	/* 0xD9F5 FPREM1 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fdecstp" },	/* 0xD9F6 FDECSTP */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fincstp" },	/* 0xD9F7 FINCSTP */

	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fprem" },	/* 0xD9F8 FPREM */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fyl2xp1" },	/* 0xD9F9 FYL2XP1 */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fsqrt" },	/* 0xD9FA FSQRT */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fsincos" },	/* 0xD9FB FSINCOS */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "frndint" },	/* 0xD9FC FRNDINT */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fscale" },	/* 0xD9FD FSCALE */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fsin" },	/* 0xD9FE FSIN */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fcos" }	/* 0xD9FF FCOS */
};


/** fpu OPCODE 0xDA */
struct ia32_opcode opcode_table_DA_fpu[] = {
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA00 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA01 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA02 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA03 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA04 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA05 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA06 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA07 FIADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA08 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA09 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0A FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0B FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0C FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0D FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0E FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA0F FIMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA10 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA11 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA12 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA13 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA14 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA15 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA16 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA17 FICOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA18 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA19 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1A FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1B FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1C FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1D FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1E FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA1F FICOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA20 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA21 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA22 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA23 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA24 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA25 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA26 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA27 FISUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA28 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA29 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2A FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2B FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2C FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2D FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2E FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA2F FISUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA30 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA31 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA32 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA33 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA34 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA35 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA36 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA37 FIDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA38 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA39 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3A FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3B FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3C FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3D FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3E FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA3F FIDIVR ST0 = m32 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA40 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA41 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA42 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA43 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA44 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA45 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA46 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA47 FIADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA48 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA49 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4A FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4B FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4C FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4D FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4E FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA4F FIMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA50 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA51 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA52 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA53 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA54 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA55 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA56 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA57 FICOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA58 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA59 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5A FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5B FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5C FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5D FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5E FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA5F FICOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA60 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA61 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA62 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA63 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA64 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA65 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA66 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDA67 FISUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA68 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA69 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6A FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6B FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6C FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6D FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6E FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDA6F FISUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA70 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA71 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA72 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA73 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA74 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA75 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA76 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDA77 FIDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA78 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA79 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7A FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7B FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7C FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7D FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7E FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDA7F FIDIVR ST0 = m32 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA80 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA81 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA82 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA83 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA84 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA85 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA86 FIADD m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDA87 FIADD m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA88 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA89 FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8A FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8B FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8C FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8D FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8E FIMUL m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDA8F FIMUL m32, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA90 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA91 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA92 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA93 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA94 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA95 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA96 FICOM m32, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDA97 FICOM m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA98 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA99 FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9A FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9B FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9C FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9D FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9E FICOMP m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDA9F FICOMP m32, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA0 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA1 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA2 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA3 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA4 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA5 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA6 FISUB m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDAA7 FISUB m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAA8 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAA9 FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAA FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAB FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAC FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAD FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAE FISUBR ST0 = m32 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDAAF FISUBR ST0 = m32 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB0 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB1 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB2 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB3 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB4 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB5 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB6 FIDIV m32, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDAB7 FIDIV m32, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDAB8 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDAB9 FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABA FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABB FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABC FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABD FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABE FIDIVR ST0 = m32 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDABF FIDIVR ST0 = m32 / ST0 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC0 FCMOVB ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC1 FCMOVB ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC2 FCMOVB ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC3 FCMOVB ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC4 FCMOVB ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC5 FCMOVB ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC6 FCMOVB ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovb" },	/* 0xDAC7 FCMOVB ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDAC8 FCMOVE ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDAC9 FCMOVE ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACA FCMOVE ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACB FCMOVE ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACC FCMOVE ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACD FCMOVE ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACE FCMOVE ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmove" },	/* 0xDACF FCMOVE ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD0 FCMOVBE ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD1 FCMOVBE ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD2 FCMOVBE ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD3 FCMOVBE ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD4 FCMOVBE ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD5 FCMOVBE ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD6 FCMOVBE ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovbe" },	/* 0xDAD7 FCMOVBE ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDAD8 FCMOVU ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDAD9 FCMOVU ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADA FCMOVU ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADB FCMOVU ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADC FCMOVU ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADD FCMOVU ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADE FCMOVU ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovu" },	/* 0xDADF FCMOVU ST(7), ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAE8  undefined opcode */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucompp" },	/* 0xDAE9 FUCOMPP */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAEA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAEB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAEC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAEE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAEF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDAFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 0xDAFF  undefined opcode */
};


/** fpu OPCODE 0xDB */
struct ia32_opcode opcode_table_DB_fpu[] = {
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB00 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB01 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB02 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB03 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB04 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB05 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB06 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB07 FILD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB0F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB10 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB11 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB12 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB13 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB14 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB15 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB16 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB17 FIST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB18 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB19 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1A FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1B FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1C FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1D FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1E FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB1F FISTP ST(0), m32 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB20  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB21  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB22  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB27  undefined opcode */

	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB28 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB29 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2A FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2B FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2C FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2D FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2E FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB2F FLD m80, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB37  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB38 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB39 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3A FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3B FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3C FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3D FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3E FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB3F FSTP ST(0), m80 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB40 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB41 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB42 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB43 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB44 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB45 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB46 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB47 FILD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB4F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB50 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB51 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB52 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB53 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB54 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB55 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB56 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB57 FIST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB58 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB59 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5A FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5B FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5C FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5D FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5E FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB5F FISTP ST(0), m32 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB60  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB61  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB62  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB63  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB64  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB65  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB66  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB67  undefined opcode */

	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB68 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB69 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6A FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6B FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6C FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6D FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6E FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDB6F FLD m80, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB70  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB71  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB72  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB73  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB74  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB75  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB76  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB77  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB78 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB79 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7A FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7B FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7C FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7D FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7E FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDB7F FSTP ST(0), m80 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB80 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB81 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB82 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB83 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB84 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB85 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB86 FILD m32, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_d, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDB87 FILD m32, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDB8F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB90 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB91 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB92 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB93 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB94 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB95 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB96 FIST ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDB97 FIST ST(0), m32 */

	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB98 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB99 FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9A FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9B FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9C FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9D FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9E FISTP ST(0), m32 */
	{ 0xa000, WRITE | ADDRM_M | OPT_d, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDB9F FISTP ST(0), m32 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBA7  undefined opcode */

	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBA8 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBA9 FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAA FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAB FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAC FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAD FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAE FLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , WRITE | ADDRM_M | OPT_fe, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDBAF FLD m80, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBB7  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBB8 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBB9 FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBA FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBB FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBC FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBD FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBE FSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fe, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDBBF FSTP ST(0), m80 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC0 FCMOVNB ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC1 FCMOVNB ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC2 FCMOVNB ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC3 FCMOVNB ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC4 FCMOVNB ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC5 FCMOVNB ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC6 FCMOVNB ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnb" },	/* 0xDBC7 FCMOVNB ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBC8 FCMOVNE ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBC9 FCMOVNE ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCA FCMOVNE ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCB FCMOVNE ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCC FCMOVNE ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCD FCMOVNE ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCE FCMOVNE ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovne" },	/* 0xDBCF FCMOVNE ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD0 FCMOVNBE ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD1 FCMOVNBE ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD2 FCMOVNBE ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD3 FCMOVNBE ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD4 FCMOVNBE ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD5 FCMOVNBE ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD6 FCMOVNBE ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnbe" },	/* 0xDBD7 FCMOVNBE ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBD8 FCMOVNU ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBD9 FCMOVNU ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDA FCMOVNU ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDB FCMOVNU ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDC FCMOVNU ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDD FCMOVNU ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDE FCMOVNU ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcmovnu" },	/* 0xDBDF FCMOVNU ST(7), ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE1  undefined opcode */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fclex" },	/* 0xDBE2 FCLEX */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "finit" },	/* 0xDBE3 FINIT */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBE7  undefined opcode */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBE8 FUCOMI ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBE9 FUCOMI ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBEA FUCOMI ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBEB FUCOMI ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBEC FUCOMI ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBED FUCOMI ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBEE FUCOMI ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fucomi" },	/* 0xDBEF FUCOMI ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF0 FCOMI ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF1 FCOMI ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF2 FCOMI ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF3 FCOMI ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF4 FCOMI ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF5 FCOMI ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF6 FCOMI ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcomi" },	/* 0xDBF7 FCOMI ST(7), ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDBFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 0xDBFF  undefined opcode */
};


/** fpu OPCODE 0xDC */
struct ia32_opcode opcode_table_DC_fpu[] = {
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC00 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC01 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC02 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC03 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC04 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC05 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC06 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC07 FADD m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC08 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC09 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0A FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0B FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0C FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0D FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0E FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC0F FMUL m64, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC10 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC11 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC12 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC13 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC14 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC15 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC16 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC17 FCOM m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC18 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC19 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1A FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1B FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1C FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1D FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1E FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC1F FCOMP m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC20 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC21 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC22 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC23 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC24 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC25 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC26 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC27 FSUB m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC28 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC29 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2A FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2B FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2C FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2D FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2E FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC2F FSUBR ST0 = m64 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC30 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC31 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC32 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC33 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC34 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC35 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC36 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC37 FDIV m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC38 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC39 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3A FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3B FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3C FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3D FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3E FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC3F FDIVR ST0 = m64 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC40 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC41 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC42 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC43 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC44 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC45 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC46 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC47 FADD m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC48 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC49 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4A FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4B FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4C FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4D FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4E FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC4F FMUL m64, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC50 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC51 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC52 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC53 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC54 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC55 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC56 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC57 FCOM m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC58 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC59 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5A FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5B FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5C FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5D FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5E FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC5F FCOMP m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC60 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC61 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC62 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC63 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC64 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC65 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC66 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDC67 FSUB m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC68 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC69 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6A FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6B FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6C FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6D FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6E FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDC6F FSUBR ST0 = m64 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC70 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC71 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC72 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC73 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC74 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC75 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC76 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDC77 FDIV m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC78 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC79 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7A FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7B FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7C FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7D FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7E FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDC7F FDIVR ST0 = m64 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC80 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC81 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC82 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC83 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC84 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC85 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC86 FADD m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDC87 FADD m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC88 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC89 FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8A FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8B FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8C FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8D FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8E FMUL m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDC8F FMUL m64, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC90 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC91 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC92 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC93 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC94 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC95 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC96 FCOM m64, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcom" },	/* 0xDC97 FCOM m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC98 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC99 FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9A FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9B FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9C FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9D FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9E FCOMP m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fcomp" },	/* 0xDC9F FCOMP m64, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA0 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA1 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA2 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA3 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA4 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA5 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA6 FSUB m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCA7 FSUB m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCA8 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCA9 FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAA FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAB FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAC FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAD FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAE FSUBR ST0 = m64 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCAF FSUBR ST0 = m64 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB0 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB1 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB2 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB3 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB4 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB5 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB6 FDIV m64, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCB7 FDIV m64, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCB8 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCB9 FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBA FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBB FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBC FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBD FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBE FDIVR ST0 = m64 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCBF FDIVR ST0 = m64 / ST0 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC0 FADD ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC1 FADD ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC2 FADD ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC3 FADD ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC4 FADD ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC5 FADD ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC6 FADD ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fadd" },	/* 0xDCC7 FADD ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCC8 FMUL ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCC9 FMUL ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCA FMUL ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCB FMUL ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCC FMUL ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCD FMUL ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCE FMUL ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmul" },	/* 0xDCCF FMUL ST(0), ST(7) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDCDF  undefined opcode */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE0 FSUBR ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE1 FSUBR ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE2 FSUBR ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE3 FSUBR ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE4 FSUBR ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE5 FSUBR ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE6 FSUBR ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubr" },	/* 0xDCE7 FSUBR ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCE8 FSUB ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCE9 FSUB ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCEA FSUB ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCEB FSUB ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCEC FSUB ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCED FSUB ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCEE FSUB ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsub" },	/* 0xDCEF FSUB ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF0 FDIVR ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF1 FDIVR ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF2 FDIVR ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF3 FDIVR ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF4 FDIVR ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF5 FDIVR ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF6 FDIVR ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivr" },	/* 0xDCF7 FDIVR ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCF8 FDIV ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCF9 FDIV ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCFA FDIV ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCFB FDIV ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCFC FDIV ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCFD FDIV ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" },	/* 0xDCFE FDIV ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdiv" }	/* 0xDCFF FDIV ST(0), ST(7) */
};


/** fpu OPCODE 0xDD */
struct ia32_opcode opcode_table_DD_fpu[] = {
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD00 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD01 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD02 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD03 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD04 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD05 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD06 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD07 FLD m64, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD0F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD10 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD11 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD12 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD13 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD14 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD15 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD16 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD17 FST ST(0), m64 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD18 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD19 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1A FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1B FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1C FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1D FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1E FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD1F FSTP ST(0), m64 */

	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD20 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD21 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD22 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD23 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD24 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD25 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD26 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD27 FRSTOR, m864 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD28  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD29  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD2F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD30 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD31 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD32 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD33 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD34 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD35 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD36 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD37 FSAVE, m864 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD38 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD39 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3A FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3B FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3C FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3D FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3E FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD3F FSTSW, m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD40 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD41 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD42 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD43 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD44 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD45 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD46 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD47 FLD m64, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD4F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD50 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD51 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD52 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD53 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD54 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD55 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD56 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD57 FST ST(0), m64 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD58 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD59 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5A FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5B FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5C FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5D FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5E FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD5F FSTP ST(0), m64 */

	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD60 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD61 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD62 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD63 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD64 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD65 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD66 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDD67 FRSTOR, m864 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD68  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD69  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD6F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD70 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD71 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD72 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD73 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD74 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD75 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD76 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDD77 FSAVE, m864 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD78 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD79 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7A FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7B FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7C FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7D FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7E FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDD7F FSTSW, m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD80 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD81 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD82 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD83 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD84 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD85 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD86 FLD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fd, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fld" },	/* 0xDD87 FLD m64, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDD8F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD90 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD91 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD92 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD93 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD94 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD95 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD96 FST ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fst" },	/* 0xDD97 FST ST(0), m64 */

	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD98 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD99 FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9A FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9B FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9C FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9D FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9E FSTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fd, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDD9F FSTP ST(0), m64 */

	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA0 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA1 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA2 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA3 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA4 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA5 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA6 FRSTOR, m864 */
	{ 0xa000, READ | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "frstor" },	/* 0xDDA7 FRSTOR, m864 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDAF  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB0 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB1 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB2 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB3 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB4 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB5 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB6 FSAVE, m864 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fst, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fsave" },	/* 0xDDB7 FSAVE, m864 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDB8 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDB9 FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBA FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBB FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBC FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBD FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBE FSTSW, m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDDBF FSTSW, m16 */

	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x80, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC0 FFREE, ST(0) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x81, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC1 FFREE, ST(1) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x82, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC2 FFREE, ST(2) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x83, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC3 FFREE, ST(3) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x84, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC4 FFREE, ST(4) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x85, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC5 FFREE, ST(5) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x86, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC6 FFREE, ST(6) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x87, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "ffree" },	/* 0xDDC7 FFREE, ST(7) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDCF  undefined opcode */

	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x80, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD0 FST, ST(0) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x81, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD1 FST, ST(1) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x82, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD2 FST, ST(2) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x83, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD3 FST, ST(3) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x84, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD4 FST, ST(4) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x85, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD5 FST, ST(5) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x86, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD6 FST, ST(6) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x87, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fst" },	/* 0xDDD7 FST, ST(7) */

	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x80, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDD8 FSTP, ST(0) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x81, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDD9 FSTP, ST(1) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x82, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDA FSTP, ST(2) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x83, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDB FSTP, ST(3) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x84, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDC FSTP, ST(4) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x85, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDD FSTP, ST(5) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x86, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDE FSTP, ST(6) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x87, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstp" },	/* 0xDDDF FSTP, ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE0 FUCOM ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE1 FUCOM ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE2 FUCOM ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE3 FUCOM ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE4 FUCOM ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE5 FUCOM ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE6 FUCOM ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucom" },	/* 0xDDE7 FUCOM ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x80, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDE8 FUCOMP, ST(0) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x81, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDE9 FUCOMP, ST(1) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x82, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDEA FUCOMP, ST(2) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x83, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDEB FUCOMP, ST(3) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x84, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDEC FUCOMP, ST(4) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x85, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDED FUCOMP, ST(5) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x86, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDEE FUCOMP, ST(6) */
	{ 0xa000, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x87, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fucomp" },	/* 0xDDEF FUCOMP, ST(7) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDDFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 0xDDFF  undefined opcode */
};


/** fpu OPCODE 0xDE */
struct ia32_opcode opcode_table_DE_fpu[] = {
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE00 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE01 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE02 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE03 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE04 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE05 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE06 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE07 FIADD m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE08 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE09 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0A FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0B FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0C FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0D FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0E FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE0F FIMUL m16, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE10 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE11 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE12 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE13 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE14 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE15 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE16 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE17 FICOM m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE18 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE19 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1A FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1B FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1C FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1D FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1E FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE1F FICOMP m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE20 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE21 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE22 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE23 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE24 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE25 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE26 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE27 FISUB m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE28 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE29 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2A FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2B FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2C FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2D FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2E FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE2F FISUBR T0 = m16 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE30 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE31 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE32 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE33 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE34 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE35 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE36 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE37 FIDIV m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE38 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE39 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3A FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3B FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3C FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3D FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3E FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE3F FIDIVR T0 = m16 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE40 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE41 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE42 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE43 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE44 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE45 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE46 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE47 FIADD m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE48 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE49 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4A FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4B FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4C FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4D FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4E FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE4F FIMUL m16, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE50 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE51 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE52 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE53 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE54 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE55 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE56 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE57 FICOM m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE58 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE59 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5A FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5B FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5C FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5D FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5E FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE5F FICOMP m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE60 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE61 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE62 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE63 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE64 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE65 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE66 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDE67 FISUB m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE68 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE69 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6A FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6B FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6C FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6D FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6E FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDE6F FISUBR T0 = m16 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE70 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE71 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE72 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE73 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE74 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE75 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE76 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDE77 FIDIV m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE78 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE79 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7A FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7B FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7C FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7D FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7E FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDE7F FIDIVR T0 = m16 / ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE80 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE81 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE82 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE83 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE84 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE85 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE86 FIADD m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fiadd" },	/* 0xDE87 FIADD m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE88 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE89 FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8A FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8B FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8C FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8D FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8E FIMUL m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fimul" },	/* 0xDE8F FIMUL m16, ST(0) */

	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE90 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE91 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE92 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE93 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE94 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE95 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE96 FICOM m16, ST(0) */
	{ 0xa000, READ |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficom" },	/* 0xDE97 FICOM m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE98 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE99 FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9A FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9B FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9C FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9D FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9E FICOMP m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ficomp" },	/* 0xDE9F FICOMP m16, ST(0) */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA0 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA1 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA2 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA3 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA4 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA5 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA6 FISUB m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fisub" },	/* 0xDEA7 FISUB m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEA8 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEA9 FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAA FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAB FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAC FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAD FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAE FISUBR T0 = m16 - ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fisubr" },	/* 0xDEAF FISUBR T0 = m16 - ST0 */

	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB0 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB1 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB2 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB3 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB4 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB5 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB6 FIDIV m16, ST(0) */
	{ 0xa000, MODIFY |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fidiv" },	/* 0xDEB7 FIDIV m16, ST(0) */

	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEB8 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEB9 FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBA FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBB FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBC FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBD FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBE FIDIVR T0 = m16 / ST0 */
	{ 0xa000, READ | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fidivr" },	/* 0xDEBF FIDIVR T0 = m16 / ST0 */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC0 FADDP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC1 FADDP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC2 FADDP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC3 FADDP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC4 FADDP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC5 FADDP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC6 FADDP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "faddp" },	/* 0xDEC7 FADDP ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDEC8 FMULP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDEC9 FMULP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECA FMULP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECB FMULP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECC FMULP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECD FMULP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECE FMULP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fmulp" },	/* 0xDECF FMULP ST(0), ST(7) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDED8  undefined opcode */
	{ 0xa000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fcompp" },	/* 0xDED9 FCOMPP */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDEDF  undefined opcode */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE0 FSUBRP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE1 FSUBRP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE2 FSUBRP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE3 FSUBRP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE4 FSUBRP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE5 FSUBRP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE6 FSUBRP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubrp" },	/* 0xDEE7 FSUBRP ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEE8 FSUBP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEE9 FSUBP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEEA FSUBP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEEB FSUBP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEEC FSUBP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEED FSUBP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEEE FSUBP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fsubp" },	/* 0xDEEF FSUBP ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF0 FDIVRP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF1 FDIVRP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF2 FDIVRP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF3 FDIVRP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF4 FDIVRP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF5 FDIVRP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF6 FDIVRP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivrp" },	/* 0xDEF7 FDIVRP ST(0), ST(7) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEF8 FDIVP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x81, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEF9 FDIVP ST(0), ST(1) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x82, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEFA FDIVP ST(0), ST(2) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x83, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEFB FDIVP ST(0), ST(3) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x84, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEFC FDIVP ST(0), ST(4) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x85, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEFD FDIVP ST(0), ST(5) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x86, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" },	/* 0xDEFE FDIVP ST(0), ST(6) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x87, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fdivp" }	/* 0xDEFF FDIVP ST(0), ST(7) */
};


/** fpu OPCODE 0xDF */
struct ia32_opcode opcode_table_DF_fpu[] = {
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF00 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF01 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF02 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF03 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF04 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF05 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF06 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF07 FILD m16, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF0F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF10 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF11 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF12 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF13 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF14 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF15 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF16 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF17 FIST ST(0), m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF18 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF19 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1A FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1B FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1C FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1D FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1E FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF1F FISTP ST(0), m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF20 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF21 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF22 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF23 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF24 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF25 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF26 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF27 FBLD m80, ST(0) */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF28 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF29 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2A FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2B FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2C FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2D FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2E FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF2F FILD m64, ST(0) */

	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF30 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF31 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF32 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF33 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF34 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF35 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF36 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF37 FBSTP ST(0), m80 */

	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF38 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF39 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3A FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3B FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3C FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3D FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3E FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF3F FISTP ST(0), m64 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF40 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF41 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF42 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF43 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF44 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF45 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF46 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF47 FILD m16, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF4F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF50 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF51 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF52 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF53 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF54 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF55 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF56 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF57 FIST ST(0), m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF58 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF59 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5A FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5B FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5C FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5D FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5E FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF5F FISTP ST(0), m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF60 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF61 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF62 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF63 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF64 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF65 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF66 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDF67 FBLD m80, ST(0) */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF68 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF69 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6A FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6B FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6C FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6D FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6E FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF6F FILD m64, ST(0) */

	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF70 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF71 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF72 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF73 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF74 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF75 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF76 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDF77 FBSTP ST(0), m80 */

	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF78 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF79 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7A FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7B FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7C FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7D FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7E FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF7F FISTP ST(0), m64 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF80 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF81 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF82 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF83 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF84 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF85 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF86 FILD m16, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_w, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDF87 FILD m16, ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDF8F  undefined opcode */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF90 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF91 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF92 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF93 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF94 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF95 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF96 FIST ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, READ |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fist" },	/* 0xDF97 FIST ST(0), m16 */

	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF98 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF99 FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9A FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9B FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9C FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9D FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9E FISTP ST(0), m16 */
	{ 0xa000, WRITE | ADDRM_M | OPT_w, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDF9F FISTP ST(0), m16 */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA0 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA1 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA2 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA3 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA4 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA5 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA6 FBLD m80, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_fp, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fbld" },	/* 0xDFA7 FBLD m80, ST(0) */

	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFA8 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFA9 FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAA FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAB FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAC FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAD FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAE FILD m64, ST(0) */
	{ 0xa000, WRITE |  IMPL , READ | ADDRM_M | OPT_q, ARG_NONE, 0x80, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "fild" },	/* 0xDFAF FILD m64, ST(0) */

	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB0 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB1 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB2 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB3 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB4 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB5 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB6 FBSTP ST(0), m80 */
	{ 0xa000, WRITE | ADDRM_M | OPT_fp, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fbstp" },	/* 0xDFB7 FBSTP ST(0), m80 */

	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFB8 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFB9 FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBA FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBB FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBC FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBD FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBE FISTP ST(0), m64 */
	{ 0xa000, WRITE | ADDRM_M | OPT_q, MODIFY |  IMPL , ARG_NONE, 0x0, 0x80, 0x0, HAS_MODRM, {.handler = action_copy}, "fistp" },	/* 0xDFBF FISTP ST(0), m64 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFCF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFDF  undefined opcode */

	{ 0xa000,  IMPL , ARG_NONE, ARG_NONE, 0x20, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "fstsw" },	/* 0xDFE0 FSTSW, AX */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFE7  undefined opcode */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFE8 FUCOMIP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFE9 FUCOMIP ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFEA FUCOMIP ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFEB FUCOMIP ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFEC FUCOMIP ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFED FUCOMIP ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFEE FUCOMIP ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fucomip" },	/* 0xDFEF FUCOMIP ST(7), ST(0) */

	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x80, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF0 FCOMIP ST(0), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x81, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF1 FCOMIP ST(1), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x82, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF2 FCOMIP ST(2), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x83, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF3 FCOMIP ST(3), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x84, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF4 FCOMIP ST(4), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x85, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF5 FCOMIP ST(5), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x86, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF6 FCOMIP ST(6), ST(0) */
	{ 0xa000, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x80, 0x87, 0x0, NO_MODRM, {.handler = action_copy}, "fcomip" },	/* 0xDFF7 FCOMIP ST(7), ST(0) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xDFFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 0xDFFF  undefined opcode */
};




/*
 * tables for one and two byte opcodes.
 */

/** table for three byte opcodes with 0x66 (Operand-size override) PREFIX (0F38xx) */
struct ia32_opcode opcode_table_660F38[] = {
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pshufb" },	/* 0x660F3800 PSHUFB r/m128, reg128 */
	{ 0x2001, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddw" },	/* 0x660F3801 PHADDW r/m128, reg128 */
	{ 0x2001, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddd" },	/* 0x660F3802 PHADDD r/m128, reg128 */
	{ 0x2001, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddsw" },	/* 0x660F3803 PHADDSW r/m128, reg128 */
	{ 0x2001, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmaddubsw" },	/* 0x660F3804 PMADDUBSW r/m128, reg128 */
	{ 0x2002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phsubw" },	/* 0x660F3805 PHSUBW r/m128, reg128 */
	{ 0x2002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psubd" },	/* 0x660F3806 PSUBD r/m128, reg128 */
	{ 0x2002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phsubw" },	/* 0x660F3807 PHSUBW r/m128, reg128 */

	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignb" },	/* 0x660F3808 PSIGNB r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignw" },	/* 0x660F3809 PSIGNW r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignd" },	/* 0x660F380A PSIGND r/m128, reg128 */
	{ 0x2003, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmulhrsw" },	/* 0x660F380B PMULHRSW r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F380C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F380D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F380E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F380F  undefined opcode */

	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pblendvb" },	/* 0x660F3810 PBLENDVB r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3811  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3812  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3813  undefined opcode */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "blendvps" },	/* 0x660F3814 BLENDVPS r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "blendvpd" },	/* 0x660F3815 BLENDVPD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3816  undefined opcode */
	{ 0x5001, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "ptest" },	/* 0x660F3817 PTEST r/m128, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3818  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3819  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F381A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F381B  undefined opcode */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsb" },	/* 0x660F381C PABSB r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsw" },	/* 0x660F381D PABSW r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsd" },	/* 0x660F381E PABSD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F381F  undefined opcode */

	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxbw" },	/* 0x660F3820 PMOVSXBW UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxbd" },	/* 0x660F3821 PMOVSXBD UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxbq" },	/* 0x660F3822 PMOVSXBQ UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxwd" },	/* 0x660F3823 PMOVSXWD UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxwq" },	/* 0x660F3824 PMOVSXWQ UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovsxdq" },	/* 0x660F3825 PMOVSXDQ UM is a mixed type! */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3826  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3827  undefined opcode */

	{ 0x2003, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmuldq" },	/* 0x660F3828 PMULDQ r/m128, reg128 */
	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pcmpeqq" },	/* 0x660F3829 PCMPEQQ r/m128, reg128 */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_M | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "movntdqa" },	/* 0x660F382A MOVNTDQA m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "packusdw" },	/* 0x660F382B PACKUSDW r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F382C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F382D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F382E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F382F  undefined opcode */

	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxbw" },	/* 0x660F3830 PMOVZXBW UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxbd" },	/* 0x660F3831 PMOVZXBD UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxbq" },	/* 0x660F3832 PMOVZXBQ UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxwd" },	/* 0x660F3833 PMOVZXWD UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxwq" },	/* 0x660F3834 PMOVZXWQ UM is a mixed type! */
	{ 0x6001, ADDRM_V | OPT_dq, ADDRM_UM | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovzxdq" },	/* 0x660F3835 PMOVZXDQ UM is a mixed type! */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3836  undefined opcode */
	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pcmpgtq" },	/* 0x660F3837 PCMPGTQ r/m128, reg128 */

	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pminsb" },	/* 0x660F3838 PMINSB r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pminsd" },	/* 0x660F3839 PMINSD r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pminuw" },	/* 0x660F383A PMINUW r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pminud" },	/* 0x660F383B PMINUD r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmaxsb" },	/* 0x660F383C PMAXSB r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmaxsd" },	/* 0x660F383D PMAXSD r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmaxuw" },	/* 0x660F383E PMAXUW r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "paxud" },	/* 0x660F383F PAXUD r/m128, reg128 */

	{ 0x2003, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmulld" },	/* 0x660F3840 PMULLD r/m128, reg128 */
	{ 0x2000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phminposuw" },	/* 0x660F3841 PHMINPOSUW r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3842  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3843  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3844  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3845  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3846  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3847  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3848  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3849  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F384F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3850  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3851  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3852  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3853  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3854  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3855  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3856  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3857  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3858  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3859  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F385F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3860  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3861  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3862  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3863  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3864  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3865  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3866  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3867  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3868  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3869  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F386F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3870  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3871  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3872  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3873  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3874  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3875  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3876  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3877  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3878  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3879  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F387F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3880  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3881  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3882  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3883  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3884  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3885  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3886  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3887  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3888  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3889  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F388F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3890  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3891  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3892  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3893  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3894  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3895  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3896  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3897  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3898  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3899  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F389F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38A9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38AF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38B9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38BF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38C9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38CF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38D9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38DF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38E9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38EA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38EB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38EC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38ED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38EE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38EF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38F9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38FA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38FB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38FC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38FD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F38FE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0x660F38FF  undefined opcode */
};


/** table for three byte opcodes with 0x66 (Operand-size override) PREFIX (0F3Axx) */
struct ia32_opcode opcode_table_660F3A[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A00  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A01  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A02  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A03  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A05  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A06  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A07  undefined opcode */

	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "roundps" },	/* 0x660F3A08 ROUNDPS r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "rounddp" },	/* 0x660F3A09 ROUNDDP r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_ss, ADDRM_W | OPT_ss, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "roundss" },	/* 0x660F3A0A ROUNDSS r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_sd, ADDRM_W | OPT_sd, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "roundsd" },	/* 0x660F3A0B ROUNDSD r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "blendps" },	/* 0x660F3A0C BLENDPS r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "blendpd" },	/* 0x660F3A0D BLENDPD r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "plendw" },	/* 0x660F3A0E PLENDW r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "palignr" },	/* 0x660F3A0F PALIGNR r/m128, imm8, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A10  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A11  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A12  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A13  undefined opcode */
	{ 0xf000, ADDRM_RM | OPT_b, ADDRM_V | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pextrb" },	/* 0x660F3A14 PEXTRB r32 / m8, that's the problem, so we specify only OPT_b and not OPT_d as well */
	{ 0xf000, ADDRM_RM | OPT_w, ADDRM_V | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pextrw" },	/* 0x660F3A15 PEXTRW r32 / m8, that's the problem, so we specify only OPT_b and not OPT_d as well */
	{ 0xf000, ADDRM_E | OPT_q, ADDRM_V | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pextrq" },	/* 0x660F3A16 PEXTRQ reg128, imm8, r/m64 */
	{ 0xf000, ADDRM_E | OPT_d, ADDRM_V | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "extractps" },	/* 0x660F3A17 EXTRACTPS reg128, imm8, r/m32 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A18  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A1F  undefined opcode */

	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_E | OPT_d, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pinsrb" },	/* 0x660F3A20 PINSRB r/m32, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_UM | OPT_d, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "insertps" },	/* 0x660F3A21 INSERTPS MMX - double quadword vs. doubleword mem address, only used OPT_d */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_E | OPT_q, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pinsrq" },	/* 0x660F3A22 PINSRQ r/m64, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A27  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A28  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A29  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A2F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A38  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A3F  undefined opcode */

	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "dpps" },	/* 0x660F3A40 DPPS r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "dppd" },	/* 0x660F3A41 DPPD r/m128, imm8, reg128 */
	{ 0xf000, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mpsadbw" },	/* 0x660F3A42 MPSADBW r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A43  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A44  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A45  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A46  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A47  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A4F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A50  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A51  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A52  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A53  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A54  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A55  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A56  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A57  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A58  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A59  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A5F  undefined opcode */

	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x31, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "PCMPESTRM" },	/* 0x660F3A60 PCMPESTRM r/m128, imm8, reg128 */
	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x31, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "PCMPESTRI" },	/* 0x660F3A61 PCMPESTRI r/m128, imm8, reg128 */
	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x31, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "PCMPISTRM" },	/* 0x660F3A62 PCMPISTRM r/m128, imm8, reg128 */
	{ 0x5002, ADDRM_V | OPT_dq, ADDRM_W | OPT_dq, ADDRM_I | OPT_b, 0x31, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "PCMPISTRI" },	/* 0x660F3A63 PCMPISTRI r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A64  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A65  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A66  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A67  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A68  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A69  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A6F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A70  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A71  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A72  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A73  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A74  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A75  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A76  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A77  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A78  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A79  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A7F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A80  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A81  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A82  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A83  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A84  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A85  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A86  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A87  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A8F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A90  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A91  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A92  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A93  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A94  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A95  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A96  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A97  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A98  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A99  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3A9F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AAF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AB9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ABF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ACF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3ADF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AE9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AEA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AEB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AEC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AEE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AEF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3AFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0x660F3AFF  undefined opcode */
};


/** table for three byte opcodes with 0xF2 (Operand-size override) PREFIX (0F38xx) */
struct ia32_opcode opcode_table_F20F38[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3800  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3801  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3802  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3803  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3804  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3805  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3806  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3807  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3808  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3809  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F380F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3810  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3811  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3812  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3813  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3814  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3815  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3816  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3817  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3818  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3819  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F381F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3820  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3821  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3822  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3823  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3824  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3825  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3826  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3827  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3828  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3829  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F382F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3830  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3831  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3832  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3833  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3834  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3835  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3836  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3837  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3838  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3839  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F383F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3840  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3841  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3842  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3843  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3844  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3845  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3846  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3847  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3848  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3849  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F384F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3850  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3851  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3852  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3853  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3854  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3855  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3856  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3857  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3858  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3859  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F385F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3860  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3861  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3862  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3863  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3864  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3865  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3866  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3867  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3868  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3869  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F386F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3870  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3871  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3872  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3873  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3874  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3875  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3876  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3877  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3878  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3879  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F387F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3880  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3881  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3882  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3883  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3884  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3885  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3886  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3887  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3888  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3889  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F388F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3890  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3891  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3892  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3893  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3894  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3895  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3896  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3897  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3898  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3899  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F389F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38A9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38AF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38B9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38BF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38C9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38CF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38D9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38DF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38E9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38EA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38EB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38EC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38ED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38EE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38EF  undefined opcode */

	{ 0x2000, ADDRM_G | OPT_d, ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "CRC32" },	/* 0xF20F38F0 CRC32 r/m8, reg32 */
	{ 0x2000, ADDRM_G | OPT_d, ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "CRC32" },	/* 0xF20F38F1 CRC32 r/m32, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38F9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38FA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38FB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38FC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38FD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F38FE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0xF20F38FF  undefined opcode */
};


/** table for three byte opcodes with 0x0F38 */
struct ia32_opcode opcode_table_0F38[] = {
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pshufb" },	/* 0x0F3800 PSHUFB r/m64, reg64 */
	{ 0x2001, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddw" },	/* 0x0F3801 PHADDW r/m64, reg64 */
	{ 0x2001, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddd" },	/* 0x0F3802 PHADDD r/m64, reg64 */
	{ 0x2001, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phaddsw" },	/* 0x0F3803 PHADDSW r/m64, reg64 */
	{ 0x2001, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmaddubsw" },	/* 0x0F3804 PMADDUBSW r/m64, reg64 */
	{ 0x2002, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phsubw" },	/* 0x0F3805 PHSUBW r/m64, reg64 */
	{ 0x2002, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psubd" },	/* 0x0F3806 PSUBD r/m64, reg64 */
	{ 0x2002, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "phsubw" },	/* 0x0F3807 PHSUBW r/m64, reg64 */

	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignb" },	/* 0x0F3808 PSIGNB r/m64, reg64 */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignw" },	/* 0x0F3809 PSIGNW r/m64, reg64 */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "psignd" },	/* 0x0F380A PSIGND r/m64, reg64 */
	{ 0x2003, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pmulhrsw" },	/* 0x0F380B PMULHRSW r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F380C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F380D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F380E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F380F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3810  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3811  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3812  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3813  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3814  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3815  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3816  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3817  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3818  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3819  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F381A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F381B  undefined opcode */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsb" },	/* 0x0F381C PABSB r/m64, reg64 */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsw" },	/* 0x0F381D PABSW r/m64, reg64 */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "pabsd" },	/* 0x0F381E PABSD r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F381F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3820  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3821  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3822  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3823  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3824  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3825  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3826  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3827  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3828  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3829  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F382F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3830  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3831  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3832  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3833  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3834  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3835  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3836  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3837  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3838  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3839  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F383F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3840  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3841  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3842  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3843  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3844  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3845  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3846  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3847  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3848  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3849  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F384F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3850  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3851  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3852  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3853  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3854  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3855  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3856  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3857  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3858  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3859  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F385F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3860  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3861  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3862  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3863  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3864  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3865  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3866  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3867  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3868  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3869  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F386F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3870  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3871  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3872  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3873  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3874  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3875  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3876  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3877  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3878  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3879  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F387F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3880  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3881  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3882  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3883  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3884  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3885  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3886  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3887  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3888  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3889  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F388F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3890  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3891  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3892  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3893  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3894  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3895  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3896  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3897  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3898  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3899  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F389F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38A9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38AF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38B9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38BF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38C9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38CF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38D9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38DF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38E9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38EA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38EB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38EC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38ED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38EE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38EF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38F9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38FA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38FB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38FC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38FD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F38FE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0x0F38FF  undefined opcode */
};


/** table for three byte opcodes with 0x0F3A */
struct ia32_opcode opcode_table_0F3A[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A00  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A01  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A02  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A03  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A05  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A06  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A07  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A0E  undefined opcode */
	{ 0x2000, ADDRM_P | OPT_q, ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "palignr" },	/* 0x0F3A0F PALIGNR r/m64, reg64 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A10  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A11  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A12  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A13  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A14  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A15  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A16  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A17  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A18  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A1F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A20  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A21  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A22  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A27  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A28  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A29  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A2F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A38  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A3F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A40  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A41  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A42  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A43  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A44  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A45  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A46  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A47  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A4F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A50  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A51  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A52  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A53  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A54  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A55  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A56  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A57  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A58  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A59  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A5F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A60  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A61  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A62  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A63  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A64  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A65  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A66  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A67  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A68  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A69  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A6F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A70  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A71  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A72  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A73  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A74  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A75  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A76  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A77  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A78  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A79  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A7F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A80  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A81  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A82  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A83  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A84  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A85  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A86  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A87  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A8F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A90  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A91  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A92  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A93  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A94  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A95  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A96  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A97  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A98  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A99  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3A9F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AAF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AB9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ABF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ACF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3ADF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AE9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AEA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AEB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AEC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AEE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AEF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x0F3AFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0x0F3AFF  undefined opcode */
};


/** table for two byte opcodes with 0x66 (Operand-size override) PREFIX */
struct ia32_opcode opcode_table_660F[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F00  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F01  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F02  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F03  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F05  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F06  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F07  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F0F  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movupd" },	/* 0x660F10 MOVUPD r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_pd, READ | ADDRM_V | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movupd" },	/* 0x660F11 MOVUPD reg128, r/m128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_q, READ | ADDRM_M | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movlpd" },	/* 0x660F12 MOVLPD m64, reg64 */
	{ 0x6001, WRITE | ADDRM_M | OPT_q, READ | ADDRM_V | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movlpd" },	/* 0x660F13 MOVLPD reg64, m64 */
	{ 0xf000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "unpcklpd" },	/* 0x660F14 UNPCKLPD r/m64, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "unpckhpd" },	/* 0x660F15 UNPCKHPD r/m64, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_q, READ | ADDRM_M | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movhpd" },	/* 0x660F16 MOVHPD m64, reg64 */
	{ 0xf000, WRITE | ADDRM_M | OPT_q, READ | ADDRM_V | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movhpd" },	/* 0x660F17 MOVHPD reg64, m64 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F18  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F1F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F20  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F21  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F22  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F27  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movapd" },	/* 0x660F28 MOVAPD r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_pd, READ | ADDRM_V | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movapd" },	/* 0x660F29 MOVAPD reg128, r/m128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_Q | OPT_pi, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtpi2pd" },	/* 0x660F2A CVTPI2PD r/m64, reg128 */
	{ 0x6001, WRITE | ADDRM_M | OPT_pd, READ | ADDRM_V | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movntpd" },	/* 0x660F2B MOVNTPD reg128, m128 */
	{ 0xf000, WRITE | ADDRM_P | OPT_pi, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttpd2pi" },	/* 0x660F2C CVTTPD2PI r/m128, reg64 */
	{ 0xf000, WRITE | ADDRM_P | OPT_pi, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtpd2pi" },	/* 0x660F2D CVTPD2PI r/m128, reg64 */
	{ 0xf000, READ | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "ucomisd" },	/* 0x660F2E UCOMISD r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "comisd" },	/* 0x660F2F COMISD r/m128, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_660F38}, "" },	/* 0x660F38  Table A4, with x66 prefix */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_660F3A}, "" },	/* 0x660F3A  Table A5 with x66 prefix */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F3F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F40  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F41  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F42  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F43  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F44  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F45  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F46  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F47  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F4F  undefined opcode */

	{ 0x6001, WRITE | ADDRM_G | OPT_d, READ | ADDRM_U | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movmskpd" },	/* 0x660F50 MOVMSKPD reg128, reg32 */
	{ 0x2000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "sqrtpd" },	/* 0x660F51 SQRTPD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F52  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F53  undefined opcode */
	{ 0x3001, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "andpd" },	/* 0x660F54 ANDPD r/m128, reg128 */
	{ 0x3001, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "andnpd" },	/* 0x660F55 ANDNPD r/m128, reg128 */
	{ 0x3002, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "orpd" },	/* 0x660F56 ORPD r/m128, reg128 */
	{ 0x3003, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "xorpd" },	/* 0x660F57 XORPD r/m128, reg128 */

	{ 0x2001, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addpd" },	/* 0x660F58 ADDPD r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "mulpd" },	/* 0x660F59 MULPD r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtpd2ps" },	/* 0x660F5A CVTPD2PS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtps2dq" },	/* 0x660F5B CVTPS2DQ r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "subpd" },	/* 0x660F5C SUBPD r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "minpd" },	/* 0x660F5D MINPD r/m128, reg128 */
	{ 0x2004, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "divpd" },	/* 0x660F5E DIVPD r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maxpd" },	/* 0x660F5F MAXPD r/m128, reg128 */

	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpcklbw" },	/* 0x660F60 PUNPCKLBW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpcklwd" },	/* 0x660F61 PUNPCKLWD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckldq" },	/* 0x660F62 PUNPCKLDQ r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packsswb" },	/* 0x660F63 PACKSSWB r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtb" },	/* 0x660F64 PCMPGTB r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtw" },	/* 0x660F65 PCMPGTW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtd" },	/* 0x660F66 PCMPGTD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packuswb" },	/* 0x660F67 PACKUSWB r/m128, reg128 */

	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhbw" },	/* 0x660F68 PUNPCKHBW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhwd" },	/* 0x660F69 PUNPCKHWD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhdq" },	/* 0x660F6A PUNPCKHDQ r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packssdw" },	/* 0x660F6B PACKSSDW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpacklqdq" },	/* 0x660F6C PUNPACKLQDQ r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpackhqdq" },	/* 0x660F6D PUNPACKHQDQ r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_E | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movd" },	/* 0x660F6E MOVD r/m32, reg128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movdqa" },	/* 0x660F6F MOVDQA r/m128, reg128 */

	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pshufd" },	/* 0x660F70 PSHUFD r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_660F71_rm}, "" },	/* 0x660F71  group 12 (0xff prefix) */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_660F72_rm}, "" },	/* 0x660F72  group 13 (0xff prefix) */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_660F73_rm}, "" },	/* 0x660F73  group 14 (0xff prefix) */
	{ 0x5002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqb" },	/* 0x660F74 PCMPEQB r/m128, reg128 */
	{ 0x5002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqw" },	/* 0x660F75 PCMPEQW r/m128, reg128 */
	{ 0x5002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqd" },	/* 0x660F76 PCMPEQD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F77  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F78  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F79  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F7B  undefined opcode */
	{ 0x2001, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "haddpd" },	/* 0x660F7C HADDPD r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "hsubpd" },	/* 0x660F7D HSUBPD r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_E | OPT_d, READ | ADDRM_V | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movd" },	/* 0x660F7E MOVD reg128, r/m32 */
	{ 0x6001, WRITE | ADDRM_W | OPT_dq, READ | ADDRM_V | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq" },	/* 0x660F7F MOVQ reg128, r/m128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F80  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F81  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F82  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F83  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F84  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F85  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F86  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F87  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F8F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F90  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F91  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F92  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F93  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F94  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F95  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F96  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F97  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F98  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F99  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660F9F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FAF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FB9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FBF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC2  undefined opcode */
	{ 0x5002, READ | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cmppd" },	/* 0x660FC3 CMPPD r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC4  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_E | OPT_w, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pinsrw" },	/* 0x660FC5 PINSRW r/m16, imm8, reg128 */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_U | OPT_dq, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pextrw" },	/* 0x660FC6 PEXTRW reg128, imm8, reg32 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "shufpd" },	/* 0x660FC7 SHUFPD r/m128, imm8, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FCF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FD0  undefined opcode */
	{ 0x2000, MODIFY | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addsubpd" },	/* 0x660FD1 ADDSUBPD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlw" },	/* 0x660FD2 PSRLW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrld" },	/* 0x660FD3 PSRLD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlq" },	/* 0x660FD4 PSRLQ r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddq" },	/* 0x660FD5 PADDQ r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmullw" },	/* 0x660FD6 PMULLW r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_q, READ | ADDRM_V | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq" },	/* 0x660FD7 MOVQ reg64, r/m64 */

	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_U | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovmskb" },	/* 0x660FD8 PMOVMSKB reg128, reg32 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubusb" },	/* 0x660FD9 PSUBUSB r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubusw" },	/* 0x660FDA PSUBUSW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pminub" },	/* 0x660FDB PMINUB r/m128, reg128 */
	{ 0x3001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pand" },	/* 0x660FDC PAND r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddusb" },	/* 0x660FDD PADDUSB r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddusw" },	/* 0x660FDE PADDUSW r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaxub" },	/* 0x660FDF PMAXUB r/m128, reg128 */

	{ 0x3001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pandn" },	/* 0x660FE0 PANDN r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pavgb" },	/* 0x660FE1 PAVGB r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psraw" },	/* 0x660FE2 PSRAW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrad" },	/* 0x660FE3 PSRAD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pavgw" },	/* 0x660FE4 PAVGW r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmulhuw" },	/* 0x660FE5 PMULHUW r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmulhw" },	/* 0x660FE6 PMULHW r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttpd2dq" },	/* 0x660FE7 CVTTPD2DQ r/m128, reg128 */

	{ 0x6001, WRITE | ADDRM_M | OPT_dq, READ | ADDRM_V | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movntdq" },	/* 0x660FE8 MOVNTDQ reg128, m128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubsb" },	/* 0x660FE9 PSUBSB r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubsw" },	/* 0x660FEA PSUBSW r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pminsw" },	/* 0x660FEB PMINSW r/m128, reg128 */
	{ 0x3002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "por" },	/* 0x660FEC POR r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddsb" },	/* 0x660FED PADDSB r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddsw" },	/* 0x660FEE PADDSW r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaxsw" },	/* 0x660FEF PMAXSW r/m128, reg128 */

	{ 0x3003, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pxor" },	/* 0x660FF0 PXOR r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0x660FF1  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllw" },	/* 0x660FF2 PSLLW r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pslld" },	/* 0x660FF3 PSLLD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllq" },	/* 0x660FF4 PSLLQ r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmuludq" },	/* 0x660FF5 PMULUDQ r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaddwd" },	/* 0x660FF6 PMADDWD r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psadbw" },	/* 0x660FF7 PSADBW r/m128, reg128 */

	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_U | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maskmovdqu" },	/* 0x660FF8 MASKMOVDQU reg128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubb" },	/* 0x660FF9 PSUBB r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubw" },	/* 0x660FFA PSUBW r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubd" },	/* 0x660FFB PSUBD r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubq" },	/* 0x660FFC PSUBQ r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddb" },	/* 0x660FFD PADDB r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddw" },	/* 0x660FFE PADDW r/m128, reg128 */
	{ 0x2001, MODIFY | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddd" }	/* 0x660FFF PADDD r/m128, reg128 */
};


/** table for two byte opcodes with 0xF2 (REPZ override) PREFIX */
struct ia32_opcode opcode_table_F20F[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F00  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F01  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F02  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F03  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F05  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F06  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F07  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F0F  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movsd" },	/* 0xF20F10 MOVSD r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_sd, READ | ADDRM_V | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movsd" },	/* 0xF20F11 MOVSD reg128, r/m128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_q, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movddup" },	/* 0xF20F12 MOVDDUP r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F13  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F14  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F15  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F16  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F17  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F18  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F1F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F20  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F21  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F22  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F27  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F28  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F29  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_sd, READ | ADDRM_E | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtsi2sd" },	/* 0xF20F2A CVTSI2SD r/m32, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F2B  undefined opcode */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttsd2si" },	/* 0xF20F2C CVTTSD2SI r/m128, reg32 */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtsd2si" },	/* 0xF20F2D CVTSD2SI r/m128, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F2E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F2F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_F20F38}, "" },	/* 0xF20F38  Table A4, with xF2 prefix */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F3F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F40  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F41  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F42  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F43  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F44  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F45  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F46  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F47  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F4F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F50  undefined opcode */
	{ 0x2000, WRITE | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "sqrtsd" },	/* 0xF20F51 SQRTSD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F52  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F53  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F54  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F55  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F56  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F57  undefined opcode */

	{ 0x2001, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addsd" },	/* 0xF20F58 ADDSD r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "mulsd" },	/* 0xF20F59 MULSD r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtsd2ss" },	/* 0xF20F5A CVTSD2SS r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F5B  undefined opcode */
	{ 0x2002, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "subsd" },	/* 0xF20F5C SUBSD r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "minsd" },	/* 0xF20F5D MINSD r/m128, reg128 */
	{ 0x2004, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "divsd" },	/* 0xF20F5E DIVSD r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maxsd" },	/* 0xF20F5F MAXSD r/m128, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F60  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F61  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F62  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F63  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F64  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F65  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F66  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F67  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F68  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F69  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F6F  undefined opcode */

	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pshuflw" },	/* 0xF20F70 PSHUFLW r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F71  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F72  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F73  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F74  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F75  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F76  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F77  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F78  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F79  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F7B  undefined opcode */
	{ 0x2001, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "haddps" },	/* 0xF20F7C HADDPS r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "hsubps" },	/* 0xF20F7D HSUBPS r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F7E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F7F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F80  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F81  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F82  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F83  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F84  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F85  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F86  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F87  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F8F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F90  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F91  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F92  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F93  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F94  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F95  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F96  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F97  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F98  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F99  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20F9F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FAF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FB9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FBF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC1  undefined opcode */
	{ 0x5002, READ | ADDRM_V | OPT_sd, READ | ADDRM_W | OPT_sd, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cmpsd" },	/* 0xF20FC2 CMPSD r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FCF  undefined opcode */

	{ 0x2000, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addsubpd" },	/* 0xF20FD0 ADDSUBPD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD5  undefined opcode */
	{ 0x6001, WRITE | ADDRM_P | OPT_q, READ | ADDRM_U | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movdq2q" },	/* 0xF20FD6 MOVDQ2Q reg64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FDF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE5  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_pd, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtpd2dq" },	/* 0xF20FE6 CVTPD2DQ r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FE9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FEA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FEB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FEC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FEE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FEF  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_M | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "lddqu" },	/* 0xF20FF0 LDDQU m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF20FFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0xF20FFF  undefined opcode */
};


/** table for two byte opcodes with 0xF3 (REPZ override) PREFIX */
struct ia32_opcode opcode_table_F30F[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F00  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F01  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F02  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F03  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F05  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F06  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F07  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F08  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F09  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F0F  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movss" },	/* 0xF30F10 MOVSS r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_ss, READ | ADDRM_V | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movss" },	/* 0xF30F11 MOVSS reg128, r/m128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_q, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movsldup" },	/* 0xF30F12 MOVSLDUP r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F13  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F14  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F15  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_q, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movshdup" },	/* 0xF30F16 MOVSHDUP r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F17  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F18  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F1F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F20  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F21  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F22  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F23  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F27  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F28  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F29  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_E | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtsi2ss" },	/* 0xF30F2A CVTSI2SS r/m32, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F2B  undefined opcode */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttss2si" },	/* 0xF30F2C CVTTSS2SI r/m128, reg32 */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtss2si" },	/* 0xF30F2D CVTSS2SI r/m128, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F2E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F2F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F30  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F31  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F32  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F33  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F34  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F35  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F38  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F3F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F40  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F41  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F42  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F43  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F44  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F45  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F46  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F47  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F48  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F49  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F4F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F50  undefined opcode */
	{ 0x2000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "sqrtss" },	/* 0xF30F51 SQRTSS r/m128, reg128 */
	{ 0x2000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "rsqrtss" },	/* 0xF30F52 RSQRTSS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "rcpss" },	/* 0xF30F53 RCPSS r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F54  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F55  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F56  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F57  undefined opcode */

	{ 0x2001, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addss" },	/* 0xF30F58 ADDSS r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "mulss" },	/* 0xF30F59 MULSS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtss2sd" },	/* 0xF30F5A CVTSS2SD r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttps2dq" },	/* 0xF30F5B CVTTPS2DQ r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "subss" },	/* 0xF30F5C SUBSS r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "minss" },	/* 0xF30F5D MINSS r/m128, reg128 */
	{ 0x2004, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "divss" },	/* 0xF30F5E DIVSS r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maxss" },	/* 0xF30F5F MAXSS r/m128, reg128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F60  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F61  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F62  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F63  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F64  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F65  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F66  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F67  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F68  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F69  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F6A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F6B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F6D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F6E  undefined opcode */
	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movdqu" },	/* 0xF30F6F MOVDQU r/m128, reg128 */

	{ 0xf000, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_W | OPT_dq, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pshufhw" },	/* 0xF30F70 PSHUFHW r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F71  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F72  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F73  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F74  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F75  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F76  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F77  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F78  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F79  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F7B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F7C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F7D  undefined opcode */
	{ 0x6001, WRITE | ADDRM_V | OPT_q, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq" },	/* 0xF30F7E MOVQ r/m64, reg64 */
	{ 0x6001, WRITE | ADDRM_W | OPT_dq, READ | ADDRM_V | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movdqu" },	/* 0xF30F7F MOVDQU reg128, r/m128 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F80  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F81  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F82  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F83  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F84  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F85  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F86  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F87  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F88  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F89  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F8F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F90  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F91  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F92  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F93  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F94  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F95  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F96  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F97  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F98  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F99  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30F9F  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FA9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FAF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB7  undefined opcode */

	{ 0xf000, READ | ADDRM_G | OPT_v, WRITE | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "popcnt" },	/* 0xF30FB8 POPCNT r/m32, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FB9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FBF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC1  undefined opcode */
	{ 0x5002, READ | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cmpss" },	/* 0xF30FC2 CMPSS r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FC9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FCF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD5  undefined opcode */
	{ 0x6001, WRITE | ADDRM_V | OPT_dq, READ | ADDRM_N | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq2dq" },	/* 0xF30FD6 MOVQ2DQ reg64, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FD9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FDF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE5  undefined opcode */
	{ 0xf000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtd2pd" },	/* 0xF30FE6 CVTD2PD r/m128, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FE9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FEA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FEB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FEC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FED  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FEE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FEF  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF0  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF1  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF2  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF3  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF4  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF5  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF7  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FF9  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FFA  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FFB  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FFC  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FFD  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" },	/* 0xF30FFE  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = 0}, "" }	/* 0xF30FFF  undefined opcode */
};


/** table for two byte opcodes */
struct ia32_opcode opcode_table_twobyte[] = {
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F00_rm}, "" },	/* 0x0F00  group 6 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F01_rm}, "" },	/* 0x0F01  group 7 */
	{ 0xe000, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lar" },	/* 0x0F02 LAR r/m16, reg32 */
	{ 0xe000, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lsl" },	/* 0x0F03 LSL r/m16, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F04  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F05  undefined opcode */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "clts" },	/* 0x0F06 CLTS */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F07  undefined opcode */

	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "invd" },	/* 0x0F08 INVD */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "wbinvd" },	/* 0x0F09 WBINVD */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F0A  undefined opcode */
	{ 0xf000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "ud2" },	/* 0x0F0B UD2 illegal opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F0C  undefined opcode */
	{ 0xf000, READ | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "nop" },	/* 0x0F0D NOP, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F0E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F0F  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movups" },	/* 0x0F10 MOVUPS r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_ps, READ | ADDRM_V | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movups" },	/* 0x0F11 MOVUPS reg128, r/m128 */
	{ 0x6001, WRITE | ADDRM_V | OPT_q, READ | ADDRM_M | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movlps" },	/* 0x0F12 MOVLPS m64, reg64 */
	{ 0x6001, WRITE | ADDRM_M | OPT_q, READ | ADDRM_V | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movlps" },	/* 0x0F13 MOVLPS reg64, m64 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "unpcklps" },	/* 0x0F14 UNPCKLPS r/m64, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "unpckhps" },	/* 0x0F15 UNPCKHPS r/m64, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_q, READ | ADDRM_M | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movhps" },	/* 0x0F16 MOVHPS m64, reg64 */
	{ 0xf000, WRITE | ADDRM_M | OPT_q, READ | ADDRM_V | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movhps" },	/* 0x0F17 MOVHPS reg64, m64 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F18_rm}, "" },	/* 0x0F18  group 16 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F19  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F1A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F1B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F1C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F1D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F1E  undefined opcode */
	{ 0xf000, READ | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "nop" },	/* 0x0F1F NOP, r/m32 */

	{ 0x6001, WRITE | ADDRM_R | OPT_d, READ | ADDRM_C | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "mov" },	/* 0x0F20 MOV ring 0 priv. needed */
	{ 0x6001, WRITE | ADDRM_R | OPT_d, READ | ADDRM_D | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "mov" },	/* 0x0F21 MOV ring 0 priv. needed */
	{ 0x6001, WRITE | ADDRM_C | OPT_d, READ | ADDRM_R | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "mov" },	/* 0x0F22 MOV ring 0 priv. needed */
	{ 0x6001, WRITE | ADDRM_D | OPT_d, READ | ADDRM_R | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_fail}, "mov" },	/* 0x0F23 MOV ring 0 priv. needed */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F24  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F25  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F26  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F27  undefined opcode */

	{ 0x6001, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movaps" },	/* 0x0F28 MOVAPS r/m128, reg128 */
	{ 0x6001, WRITE | ADDRM_W | OPT_ps, READ | ADDRM_V | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movaps" },	/* 0x0F29 MOVAPS reg128, r/m128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_Q | OPT_pi, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtpi2ps" },	/* 0x0F2A CVTPI2PS r/m64, reg128 */
	{ 0x6001, WRITE | ADDRM_M | OPT_ps, READ | ADDRM_V | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movntps" },	/* 0x0F2B MOVNTPS reg128, m128 */
	{ 0xf000, WRITE | ADDRM_P | OPT_pi, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvttps2pi" },	/* 0x0F2C CVTTPS2PI r/m128, reg64 */
	{ 0xf000, WRITE | ADDRM_P | OPT_pi, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtps2pi" },	/* 0x0F2D CVTPS2PI r/m128, reg64 */
	{ 0xf000, READ | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "ucomiss" },	/* 0x0F2E UCOMISS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ss, READ | ADDRM_W | OPT_ss, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "comiss" },	/* 0x0F2F COMISS r/m128, reg128 */

	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "wrmsr" },	/* 0x0F30 WRMSR */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "rdtsc" },	/* 0x0F31 RDTSC */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "rdmsr" },	/* 0x0F32 RDMSR */
	{ 0xf000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "rdpmc" },	/* 0x0F33 RDPMC */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_sysenter}, "sysenter" },	/* 0x0F34 SYSENTER */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "sysexit" },	/* 0x0F35 SYSEXIT */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F36  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F37  undefined opcode */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_0F38}, "" },	/* 0x0F38  escape for three byte opcodes */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F39  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_0F3A}, "" },	/* 0x0F3A  escape for three byte opcodes */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F3B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F3C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F3D  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F3E  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F3F  undefined opcode */

	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovo" },	/* 0x0F40 CMOVO r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovno" },	/* 0x0F41 CMOVNO r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovc" },	/* 0x0F42 CMOVC r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovnc" },	/* 0x0F43 CMOVNC r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovz" },	/* 0x0F44 CMOVZ r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovnz" },	/* 0x0F45 CMOVNZ r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovbe" },	/* 0x0F46 CMOVBE r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmova" },	/* 0x0F47 CMOVA r/m32, reg32 */

	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovs" },	/* 0x0F48 CMOVS r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovns" },	/* 0x0F49 CMOVNS r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovpe" },	/* 0x0F4A CMOVPE r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovpo" },	/* 0x0F4B CMOVPO r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovl" },	/* 0x0F4C CMOVL r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovge" },	/* 0x0F4D CMOVGE r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovle" },	/* 0x0F4E CMOVLE r/m32, reg32 */
	{ 0x6002, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmovg" },	/* 0x0F4F CMOVG r/m32, reg32 */

	{ 0x6001, WRITE | ADDRM_G | OPT_d, READ | ADDRM_U | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movmskps" },	/* 0x0F50 MOVMSKPS reg128, reg32 */
	{ 0x2000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "sqrtps" },	/* 0x0F51 SQRTPS r/m128, reg128 */
	{ 0x2000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "rsqrtps" },	/* 0x0F52 RSQRTPS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "rcpps" },	/* 0x0F53 RCPPS r/m128, reg128 */
	{ 0x3001, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "andps" },	/* 0x0F54 ANDPS r/m128, reg128 */
	{ 0x3001, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "andnps" },	/* 0x0F55 ANDNPS r/m128, reg128 */
	{ 0x3002, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "orps" },	/* 0x0F56 ORPS r/m128, reg128 */
	{ 0x3003, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "xorps" },	/* 0x0F57 XORPS r/m128, reg128 */

	{ 0x2001, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addps" },	/* 0x0F58 ADDPS r/m128, reg128 */
	{ 0x2003, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "mulps" },	/* 0x0F59 MULPS r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_pd, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtps2pd" },	/* 0x0F5A CVTPS2PD r/m128, reg128 */
	{ 0xf000, WRITE | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_dq, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cvtdq2ps" },	/* 0x0F5B CVTDQ2PS r/m128, reg128 */
	{ 0x2002, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "subps" },	/* 0x0F5C SUBPS r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "minps" },	/* 0x0F5D MINPS r/m128, reg128 */
	{ 0x2004, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "divps" },	/* 0x0F5E DIVPS r/m128, reg128 */
	{ 0x2000, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maxps" },	/* 0x0F5F MAXPS r/m128, reg128 */

	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpcklbw" },	/* 0x0F60 PUNPCKLBW r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpcklwd" },	/* 0x0F61 PUNPCKLWD r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckldq" },	/* 0x0F62 PUNPCKLDQ r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packsswb" },	/* 0x0F63 PACKSSWB r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtb" },	/* 0x0F64 PCMPGTB r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtw" },	/* 0x0F65 PCMPGTW r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpgtd" },	/* 0x0F66 PCMPGTD r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packuswb" },	/* 0x0F67 PACKUSWB r/m32, reg64 */

	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhbw" },	/* 0x0F68 PUNPCKHBW r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhwd" },	/* 0x0F69 PUNPCKHWD r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "punpckhdq" },	/* 0x0F6A PUNPCKHDQ r/m32, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "packssdw" },	/* 0x0F6B PACKSSDW r/m32, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F6C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F6D  undefined opcode */
	{ 0x6001, WRITE | ADDRM_P | OPT_d, READ | ADDRM_E | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movd" },	/* 0x0F6E MOVD r/m32, reg32 */
	{ 0x6001, WRITE | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq" },	/* 0x0F6F MOVQ r/m64, reg64 */

	{ 0xf000, WRITE | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pshuf" },	/* 0x0F70 PSHUF r/m64, imm8, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F71_rm}, "" },	/* 0x0F71  group 12 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F72_rm}, "" },	/* 0x0F72  group 13 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0F73_rm}, "" },	/* 0x0F73  group 14 */
	{ 0x5002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqb" },	/* 0x0F74 PCMPEQB r/m64, reg64 */
	{ 0x5002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqw" },	/* 0x0F75 PCMPEQW r/m64, reg64 */
	{ 0x5002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pcmpeqd" },	/* 0x0F76 PCMPEQD r/m64, reg64 */
	{ 0xf000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "emms" },	/* 0x0F77 EMMS */

	{ 0xf000, WRITE | ADDRM_E | OPT_d, READ | ADDRM_G | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "vmread" },	/* 0x0F78 VMREAD reg32, r/m32 */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_E | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "vmwrite" },	/* 0x0F79 VMWRITE r/m32, reg32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F7A  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F7B  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F7C  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0F7D  undefined opcode */
	{ 0x6001, WRITE | ADDRM_E | OPT_d, READ | ADDRM_P | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movd" },	/* 0x0F7E MOVD reg32, r/m32 */
	{ 0x6001, WRITE | ADDRM_Q | OPT_q, READ | ADDRM_P | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movq" },	/* 0x0F7F MOVQ reg64, r/m64 */

	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jo" },	/* 0x0F80 JO, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jno" },	/* 0x0F81 JNO, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jc" },	/* 0x0F82 JC, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jnc" },	/* 0x0F83 JNC, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jz" },	/* 0x0F84 JZ, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jnz" },	/* 0x0F85 JNZ, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jbe" },	/* 0x0F86 JBE, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "ja" },	/* 0x0F87 JA, rel32 */

	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "js" },	/* 0x0F88 JS, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jns" },	/* 0x0F89 JNS, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jpe" },	/* 0x0F8A JPE, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jpo" },	/* 0x0F8B JPO, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jl" },	/* 0x0F8C JL, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jge" },	/* 0x0F8D JGE, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jle" },	/* 0x0F8E JLE, rel32 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jg" },	/* 0x0F8F JG, rel32 */

	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "seto" },	/* 0x0F90 SETO, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setno" },	/* 0x0F91 SETNO, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setc" },	/* 0x0F92 SETC, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setnc" },	/* 0x0F93 SETNC, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setz" },	/* 0x0F94 SETZ, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setnz" },	/* 0x0F95 SETNZ, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setbe" },	/* 0x0F96 SETBE, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "seta" },	/* 0x0F97 SETA, r/m8 */

	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sets" },	/* 0x0F98 SETS, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setns" },	/* 0x0F99 SETNS, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setpe" },	/* 0x0F9A SETPE, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setpo" },	/* 0x0F9B SETPO, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setl" },	/* 0x0F9C SETL, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setge" },	/* 0x0F9D SETGE, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setle" },	/* 0x0F9E SETLE, r/m8 */
	{ 0x6002, WRITE | ADDRM_E | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "setg" },	/* 0x0F9F SETG, r/m8 */

	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x63, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x0FA0 PUSH, DS */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x63, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x0FA1 POP, DS */
	{ 0xe004, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cpuid" },	/* 0x0FA2 CPUID */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bt" },	/* 0x0FA3 BT reg32, r/m32 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shld" },	/* 0x0FA4 SHLD reg32, imm8, r/m32 */
	{ 0x2007, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, READ |  IMPL , 0x0, 0x0, 0x11, HAS_MODRM, {.handler = action_copy}, "shld" },	/* 0x0FA5 SHLD reg32, CL, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FA6  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FA7  undefined opcode */

	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x64, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x0FA8 PUSH, FS */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x64, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x0FA9 POP, FS */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "rsm" },	/* 0x0FAA RSM */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bts" },	/* 0x0FAB BTS reg32, r/m32 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "shrd" },	/* 0x0FAC SHRD reg32, imm8, r/m32 */
	{ 0x2008, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, READ |  IMPL , 0x0, 0x0, 0x11, HAS_MODRM, {.handler = action_copy}, "shrd" },	/* 0x0FAD SHRD reg32, CL, r/m32 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0FAE_rm}, "" },	/* 0x0FAE  group 15 */
	{ 0x2003, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "imul" },	/* 0x0FAF IMUL r/m32, reg32 */

	{ 0x6004, MODIFY | ADDRM_E | OPT_b, WRITE | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmpxchg" },	/* 0x0FB0 CMPXCHG reg8, r/m8 */
	{ 0x6004, MODIFY | ADDRM_E | OPT_v, WRITE | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmpxchg" },	/* 0x0FB1 CMPXCHG reg32, r/m32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_M | OPT_p, WRITE |  IMPL , 0x0, 0x0, 0x65, HAS_MODRM, {.handler = action_copy}, "lss" },	/* 0x0FB2 LSS m48, GS, reg32 */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "btr" },	/* 0x0FB3 BTR reg32, r/m32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_M | OPT_p, WRITE |  IMPL , 0x0, 0x0, 0x63, HAS_MODRM, {.handler = action_copy}, "lfs" },	/* 0x0FB4 LFS m48, DS, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_M | OPT_p, WRITE |  IMPL , 0x0, 0x0, 0x64, HAS_MODRM, {.handler = action_copy}, "lgs" },	/* 0x0FB5 LGS m48, FS, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "movzx" },	/* 0x0FB6 MOVZX r/m8, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "movzx" },	/* 0x0FB7 MOVZX r/m16, reg32 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FB8  undefined opcode */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "ud1" },	/* 0x0FB9 UD1 undefined opcode? */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0FBA_rm}, "" },	/* 0x0FBA  group 8 */
	{ 0x8001, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "btc" },	/* 0x0FBB BTC reg32, r/m32 */
	{ 0x8001, READ | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bsf" },	/* 0x0FBC BSF r/m32, reg32 */
	{ 0x8001, READ | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bsr" },	/* 0x0FBD BSR r/m32, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "movsx" },	/* 0x0FBE MOVSX r/m8, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "movsx" },	/* 0x0FBF MOVSX r/m16, reg32 */

	{ 0x2001, MODIFY | ADDRM_E | OPT_b, MODIFY | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xadd" },	/* 0x0FC0 XADD reg8, r/m8 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, MODIFY | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xadd" },	/* 0x0FC1 XADD reg32, r/m32 */
	{ 0x5002, READ | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "cmpps" },	/* 0x0FC2 CMPPS r/m128, imm8, reg128 */
	{ 0x6001, WRITE | ADDRM_M | OPT_d, READ | ADDRM_G | OPT_d, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movnti" },	/* 0x0FC3 MOVNTI reg32, m32 */
	{ 0xf000, WRITE | ADDRM_P | OPT_q, READ | ADDRM_E | OPT_w, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pinsrw" },	/* 0x0FC4 PINSRW r/m16, imm8, reg64 */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_N | OPT_q, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pextrw" },	/* 0x0FC5 PEXTRW reg64, imm8, reg32 */
	{ 0xf000, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, READ | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "shufps" },	/* 0x0FC6 SHUFPS r/m128, imm8, reg128 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_0FC7_rm}, "" },	/* 0x0FC7  group 9 */

	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FC8 BSWAP, EAX */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FC9 BSWAP, ECX */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCA BSWAP, EDX */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCB BSWAP, EBX */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCC BSWAP, ESP */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCD BSWAP, EBP */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCE BSWAP, ESI */
	{ 0x6003, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "bswap" },	/* 0x0FCF BSWAP, EDI */

	{ 0x2000, MODIFY | ADDRM_V | OPT_ps, READ | ADDRM_W | OPT_ps, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "addsubps" },	/* 0x0FD0 ADDSUBPS r/m128, reg128 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlw" },	/* 0x0FD1 PSRLW r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrld" },	/* 0x0FD2 PSRLD r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrlq" },	/* 0x0FD3 PSRLQ r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddq" },	/* 0x0FD4 PADDQ r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmullw" },	/* 0x0FD5 PMULLW r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FD6  undefined opcode */
	{ 0xf000, WRITE | ADDRM_G | OPT_d, READ | ADDRM_N | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmovmskb" },	/* 0x0FD7 PMOVMSKB reg64, reg32 */

	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubusb" },	/* 0x0FD8 PSUBUSB r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubusw" },	/* 0x0FD9 PSUBUSW r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pminub" },	/* 0x0FDA PMINUB r/m64, reg64 */
	{ 0x3001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pand" },	/* 0x0FDB PAND r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddusb" },	/* 0x0FDC PADDUSB r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddusw" },	/* 0x0FDD PADDUSW r/m64, reg64 */
	{ 0x2000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaxub" },	/* 0x0FDE PMAXUB r/m64, reg64 */
	{ 0x3001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pandn" },	/* 0x0FDF PANDN r/m64, reg64 */

	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pavgb" },	/* 0x0FE0 PAVGB r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psraw" },	/* 0x0FE1 PSRAW r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psrad" },	/* 0x0FE2 PSRAD r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pavgw" },	/* 0x0FE3 PAVGW r/m64, reg64 */
	{ 0x2003, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmulhuw" },	/* 0x0FE4 PMULHUW r/m64, reg64 */
	{ 0x2003, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmulhw" },	/* 0x0FE5 PMULHW r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FE6  undefined opcode */
	{ 0x6001, WRITE | ADDRM_M | OPT_q, READ | ADDRM_P | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "movntq" },	/* 0x0FE7 MOVNTQ reg64, m64 */

	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubsb" },	/* 0x0FE8 PSUBSB r/m64, reg64 */
	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubsw" },	/* 0x0FE9 PSUBSW r/m64, reg64 */
	{ 0x2000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pminsw" },	/* 0x0FEA PMINSW r/m64, reg64 */
	{ 0x3002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "por" },	/* 0x0FEB POR r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddsb" },	/* 0x0FEC PADDSB r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddsw" },	/* 0x0FED PADDSW r/m64, reg64 */
	{ 0x2000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaxsw" },	/* 0x0FEE PMAXSW r/m64, reg64 */
	{ 0x3003, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pxor" },	/* 0x0FEF PXOR r/m64, reg64 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0x0FF0  undefined opcode */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllw" },	/* 0x0FF1 PSLLW r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pslld" },	/* 0x0FF2 PSLLD r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psllq" },	/* 0x0FF3 PSLLQ r/m64, reg64 */
	{ 0x2003, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmuludq" },	/* 0x0FF4 PMULUDQ r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "pmaddwd" },	/* 0x0FF5 PMADDWD r/m64, reg64 */
	{ 0xf000, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psadbw" },	/* 0x0FF6 PSADBW r/m64, reg64 */
	{ 0x6001, WRITE | ADDRM_P | OPT_q, READ | ADDRM_N | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "maskmovq" },	/* 0x0FF7 MASKMOVQ reg64, reg64 */

	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubb" },	/* 0x0FF8 PSUBB r/m64, reg64 */
	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubw" },	/* 0x0FF9 PSUBW r/m64, reg64 */
	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubd" },	/* 0x0FFA PSUBD r/m64, reg64 */
	{ 0x2002, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "psubq" },	/* 0x0FFB PSUBQ r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddb" },	/* 0x0FFC PADDB r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddw" },	/* 0x0FFD PADDW r/m64, reg64 */
	{ 0x2001, MODIFY | ADDRM_P | OPT_q, READ | ADDRM_Q | OPT_q, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_warn}, "paddd" },	/* 0x0FFE PADDD r/m64, reg64 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" }	/* 0x0FFF  undefined opcode */
};


/** table for one byte opcodes */
struct ia32_opcode opcode_table_onebyte[] = {
	{ 0x2001, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 0x00 ADD reg8, r/m8 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 0x01 ADD reg32, r/m32 */
	{ 0x2001, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 0x02 ADD r/m8, reg8 */
	{ 0x2001, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "add" },	/* 0x03 ADD r/m32, reg32 */
	{ 0x2001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "add" },	/* 0x04 ADD imm8, AL */
	{ 0x2001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "add" },	/* 0x05 ADD imm32, EAX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x62, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x06 PUSH, SS */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x62, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x07 POP, SS */

	{ 0x3002, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 0x08 OR reg8, r/m8 */
	{ 0x3002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 0x09 OR reg32, r/m32 */
	{ 0x3002, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 0x0A OR r/m8, reg8 */
	{ 0x3002, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "or" },	/* 0x0B OR r/m32, reg32 */
	{ 0x3002, MODIFY |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "or" },	/* 0x0C OR imm8, AL */
	{ 0x3002, MODIFY |  IMPL , READ | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "or" },	/* 0x0D OR imm32, EAX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x60, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x0E PUSH, ES */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_ESC, {.table = opcode_table_twobyte}, "" },	/* 0x0F  escape for two byte opcodes */

	{ 0x2001, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 0x10 ADC reg8, r/m8 */
	{ 0x2001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 0x11 ADC reg32, r/m32 */
	{ 0x2001, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 0x12 ADC r/m8, reg8 */
	{ 0x2001, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "adc" },	/* 0x13 ADC r/m32, reg32 */
	{ 0x2001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "adc" },	/* 0x14 ADC imm8, AL */
	{ 0x2001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "adc" },	/* 0x15 ADC imm32, EAX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x65, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x16 PUSH, GS */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x65, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x17 POP, GS */

	{ 0x2002, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 0x18 SBB reg8, r/m8 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 0x19 SBB reg32, r/m32 */
	{ 0x2002, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 0x1A SBB r/m8, reg8 */
	{ 0x2002, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sbb" },	/* 0x1B SBB r/m32, reg32 */
	{ 0x2002, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sbb" },	/* 0x1C SBB imm8, AL */
	{ 0x2002, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sbb" },	/* 0x1D SBB imm32, EAX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x61, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x1E PUSH, CS */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x61, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x1F POP, CS */

	{ 0x3001, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 0x20 AND reg8, r/m8 */
	{ 0x3001, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 0x21 AND reg32, r/m32 */
	{ 0x3001, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 0x22 AND r/m8, reg8 */
	{ 0x3001, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "and" },	/* 0x23 AND r/m32, reg32 */
	{ 0x3001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "and" },	/* 0x24 AND imm8, AL */
	{ 0x3001, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "and" },	/* 0x25 AND imm32, EAX */
	{ 0x4000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x26  prefix ES segment override */
	{ 0xf002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "daa" },	/* 0x27 DAA */

	{ 0x2002, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 0x28 SUB reg8, r/m8 */
	{ 0x2002, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 0x29 SUB reg32, r/m32 */
	{ 0x2002, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 0x2A SUB r/m8, reg8 */
	{ 0x2002, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "sub" },	/* 0x2B SUB r/m32, reg32 */
	{ 0x2002, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sub" },	/* 0x2C SUB imm8, AL */
	{ 0x2002, MODIFY |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sub" },	/* 0x2D SUB imm32, EAX */
	{ 0x1000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x2E  prefix CS segment override */
	{ 0xf002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "das" },	/* 0x2F DAS */

	{ 0x3003, MODIFY | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 0x30 XOR reg8, r/m8 */
	{ 0x3003, MODIFY | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 0x31 XOR reg32, r/m32 */
	{ 0x3003, MODIFY | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 0x32 XOR r/m8, reg8 */
	{ 0x3003, MODIFY | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xor" },	/* 0x33 XOR r/m32, reg32 */
	{ 0x3003, MODIFY |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "xor" },	/* 0x34 XOR imm8, AL */
	{ 0x3003, MODIFY |  IMPL , READ | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "xor" },	/* 0x35 XOR imm32, EAX */
	{ 0x2000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x36  prefix SS segment override */
	{ 0xf002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "aaa" },	/* 0x37 AAA */

	{ 0x5002, READ | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" },	/* 0x38 CMP reg8, r/m8 */
	{ 0x5002, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" },	/* 0x39 CMP reg32, r/m32 */
	{ 0x5002, READ | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" },	/* 0x3A CMP r/m8, reg8 */
	{ 0x5002, READ | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "cmp" },	/* 0x3B CMP r/m32, reg32 */
	{ 0x5002, READ |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cmp" },	/* 0x3C CMP imm8, AL */
	{ 0x5002, READ |  IMPL , READ |  SIGEND  | ADDRM_I | OPT_z, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cmp" },	/* 0x3D CMP imm32, EAX */
	{ 0x3000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x3E  prefix DS segment override */
	{ 0xf002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "aas" },	/* 0x3F AAS */

	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x40 INC, EAX */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x41 INC, ECX */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x42 INC, EDX */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x43 INC, EBX */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x44 INC, ESP */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x45 INC, EBP */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x46 INC, ESI */
	{ 0x2005, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_inc}, "inc" },	/* 0x47 INC, EDI */

	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x48 DEC, EAX */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x49 DEC, ECX */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4A DEC, EDX */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4B DEC, EBX */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4C DEC, ESP */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4D DEC, EBP */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4E DEC, ESI */
	{ 0x2006, MODIFY |  IMPL , ARG_NONE, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_dec}, "dec" },	/* 0x4F DEC, EDI */

	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x50 PUSH, EAX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x51 PUSH, ECX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x52 PUSH, EDX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x53 PUSH, EBX */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x54 PUSH, ESP */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x55 PUSH, EBP */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x56 PUSH, ESI */
	{ 0x4001, READ |  IMPL , ARG_NONE, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x57 PUSH, EDI */

	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x58 POP, EAX */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x59 POP, ECX */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5A POP, EDX */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5B POP, EBX */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5C POP, ESP */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5D POP, EBP */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5E POP, ESI */
	{ 0x4002, WRITE |  IMPL , ARG_NONE, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "pop" },	/* 0x5F POP, EDI */

	{ 0x4003, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "pushad" },	/* 0x60 PUSHAD */
	{ 0x4004, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "popad" },	/* 0x61 POPAD */
	{ 0xd004, READ | ADDRM_G | OPT_v, READ | ADDRM_M | OPT_a, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "bound" },	/* 0x62 BOUND m32, reg32 */
	{ 0xe000, MODIFY | ADDRM_E | OPT_w, READ | ADDRM_G | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "arpl" },	/* 0x63 ARPL reg16, r/m16 */
	{ 0x5000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x64  prefix FS segment override */
	{ 0x6000000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x65  prefix GS segment override */
	{ 0x100000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.table = opcode_table_660F}, "" },	/* 0x66  prefix operand size override */
	{ 0x200000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0x67  prefix address size override */

	{ 0x4001, READ | ADDRM_I | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x68 PUSH, imm32 */
	{ 0x2003, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_z, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "imul" },	/* 0x69 IMUL r/m32, imm32, reg32 */
	{ 0x4001, READ | ADDRM_I | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "push" },	/* 0x6A PUSH, imm8 */
	{ 0x2003, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, READ |  SIGEND  | ADDRM_I | OPT_b, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "imul" },	/* 0x6B IMUL r/m32, imm8, reg32 */
	{ 0xe002, WRITE | ADDRM_Y | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x32, 0x0, NO_MODRM, {.handler = action_copy}, "insb" },	/* 0x6C INSB EDX,  */
	{ 0xe002, WRITE | ADDRM_Y | OPT_z, READ |  IMPL , ARG_NONE, 0x0, 0x32, 0x0, NO_MODRM, {.handler = action_copy}, "insd" },	/* 0x6D INSD EDX,  */
	{ 0xe003, WRITE |  IMPL , READ | ADDRM_X | OPT_b, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "outsb" },	/* 0x6E OUTSB , EDX */
	{ 0xe003, WRITE |  IMPL , READ | ADDRM_X | OPT_z, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "outsb" },	/* 0x6F OUTSB , EDX */

	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jo" },	/* 0x70 JO, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jno" },	/* 0x71 JNO, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jc" },	/* 0x72 JC, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jnc" },	/* 0x73 JNC, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jz" },	/* 0x74 JZ, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jnz" },	/* 0x75 JNZ, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jbe" },	/* 0x76 JBE, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "ja" },	/* 0x77 JA, rel8 */

	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "js" },	/* 0x78 JS, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jns" },	/* 0x79 JNS, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jpe" },	/* 0x7A JPE, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jpo" },	/* 0x7B JPO, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jl" },	/* 0x7C JL, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jge" },	/* 0x7D JGE, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jle" },	/* 0x7E JLE, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jg" },	/* 0x7F JG, rel8 */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_80_rm}, "" },	/* 0x80  immediate group 1 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_81_rm}, "" },	/* 0x81  immediate group 1 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_82_rm}, "" },	/* 0x82  immediate group 1 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_83_rm}, "" },	/* 0x83  immediate group 1 */
	{ 0x5001, READ | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "test" },	/* 0x84 TEST reg8, r/m8 */
	{ 0x5001, READ | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "test" },	/* 0x85 TEST reg32, r/m32 */
	{ 0x6003, MODIFY | ADDRM_E | OPT_b, MODIFY | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xchg" },	/* 0x86 XCHG reg8, r/m8 */
	{ 0x6003, MODIFY | ADDRM_E | OPT_v, MODIFY | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "xchg" },	/* 0x87 XCHG reg32, r/m32 */

	{ 0x6001, WRITE | ADDRM_E | OPT_b, READ | ADDRM_G | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x88 MOV reg8, r/m8 */
	{ 0x6001, WRITE | ADDRM_E | OPT_v, READ | ADDRM_G | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x89 MOV reg32, r/m32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_b, READ | ADDRM_E | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x8A MOV r/m8, reg8 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, READ | ADDRM_E | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x8B MOV r/m32, reg32 */
	{ 0x6001, WRITE | ADDRM_E | OPT_v, READ | ADDRM_S | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x8C MOV reg16, r/m32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_v, ADDRM_M, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lea" },	/* 0x8D LEA m0, reg32 */
	{ 0x6001, WRITE | ADDRM_S | OPT_w, READ | ADDRM_E | OPT_w, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0x8E MOV r/m16, reg16 */
	{ 0x4002, WRITE | ADDRM_E | OPT_v, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_pop}, "pop" },	/* 0x8F POP, r/m32 */

	{ 0xf001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "nop" },	/* 0x90 NOP */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x31, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x91 XCHG ECX, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x32, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x92 XCHG EDX, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x33, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x93 XCHG EBX, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x34, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x94 XCHG ESP, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x35, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x95 XCHG EBP, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x36, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x96 XCHG ESI, EAX */
	{ 0x6003, MODIFY |  IMPL , MODIFY |  IMPL , ARG_NONE, 0x30, 0x37, 0x0, NO_MODRM, {.handler = action_copy}, "xchg" },	/* 0x97 XCHG EDI, EAX */

	{ 0xf003, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cwde" },	/* 0x98 CWDE */
	{ 0xf003, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cdq" },	/* 0x99 CDQ */
	{ 0x1003, EXECUTE | ADDRM_A | OPT_p, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "callf" },	/* 0x9A CALLF no far calls in current kernels */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "wait" },	/* 0x9B WAIT */
	{ 0x4005, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "pushfd" },	/* 0x9C PUSHFD */
	{ 0x4006, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "popfd" },	/* 0x9D POPFD */
	{ 0x6001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sahf" },	/* 0x9E SAHF */
	{ 0x6001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "lahf" },	/* 0x9F LAHF */

	{ 0x6001, WRITE |  IMPL , READ | ADDRM_O | OPT_v, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xA0 MOV only one byte is read, but location addr is 2 or 4 byte */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_O | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xA1 MOV (imm32), EAX */
	{ 0x6001, WRITE | ADDRM_O | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x10, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xA2 MOV AL, (imm32) */
	{ 0x6001, WRITE | ADDRM_O | OPT_v, READ |  IMPL , ARG_NONE, 0x0, 0x30, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xA3 MOV EAX, (imm32) */
	{ 0x7003, WRITE | ADDRM_X | OPT_b, READ | ADDRM_Y | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "movsb" },	/* 0xA4 MOVSB ,  */
	{ 0x7003, WRITE | ADDRM_X | OPT_v, READ | ADDRM_Y | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "movsd" },	/* 0xA5 MOVSD ,  */
	{ 0x7001, WRITE | ADDRM_X | OPT_b, READ | ADDRM_Y | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cmpsb" },	/* 0xA6 CMPSB ,  */
	{ 0x7001, WRITE | ADDRM_X | OPT_v, READ | ADDRM_Y | OPT_v, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cmpsd" },	/* 0xA7 CMPSD ,  */

	{ 0x5001, READ |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "test" },	/* 0xA8 TEST imm8, AL */
	{ 0x5001, READ |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "test" },	/* 0xA9 TEST imm32, EAX */
	{ 0x7004, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "stosb" },	/* 0xAA STOSB */
	{ 0x7004, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "stosd" },	/* 0xAB STOSD */
	{ 0x7002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "lodsb" },	/* 0xAC LODSB */
	{ 0x7002, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "lodsd" },	/* 0xAD LODSD */
	{ 0x7001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "scasb" },	/* 0xAE SCASB */
	{ 0x7001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "scasd" },	/* 0xAF SCASD */

	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB0 MOV imm8, AL */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x11, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB1 MOV imm8, CL */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x12, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB2 MOV imm8, DL */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x13, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB3 MOV imm8, BL */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x14, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB4 MOV imm8, AH */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x15, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB5 MOV imm8, CH */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x16, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB6 MOV imm8, DH */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x17, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB7 MOV imm8, BH */

	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB8 MOV imm32, EAX */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x31, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xB9 MOV imm32, ECX */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x32, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBA MOV imm32, EDX */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x33, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBB MOV imm32, EBX */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x34, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBC MOV imm32, ESP */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x35, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBD MOV imm32, EBP */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x36, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBE MOV imm32, ESI */
	{ 0x6001, WRITE |  IMPL , READ | ADDRM_I | OPT_v, ARG_NONE, 0x37, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "mov" },	/* 0xBF MOV imm32, EDI */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_C0_rm}, "" },	/* 0xC0  shift group 2 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_C1_rm}, "" },	/* 0xC1  shift group 2 */
	{ 0x1005, READ | ADDRM_I | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_ret}, "ret" },	/* 0xC2 RET near return, pop imm16 bytes from stack */
	{ 0x1005, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_ret}, "ret" },	/* 0xC3 RET near return */
	{ 0x6001, WRITE | ADDRM_G | OPT_z, READ | ADDRM_M | OPT_p, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "les" },	/* 0xC4 LES m48, reg32 */
	{ 0x6001, WRITE | ADDRM_G | OPT_z, READ | ADDRM_M | OPT_p, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "lds" },	/* 0xC5 LDS m48, reg32 */
	{ 0x6001, WRITE | ADDRM_E | OPT_b, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0xC6 MOV imm8, r/m8 */
	{ 0x6001, WRITE | ADDRM_E | OPT_v, READ | ADDRM_I | OPT_z, ARG_NONE, 0x0, 0x0, 0x0, HAS_MODRM, {.handler = action_copy}, "mov" },	/* 0xC7 MOV imm32, r/m32 */

	{ 0x4007, READ | ADDRM_I | OPT_w, READ | ADDRM_I | OPT_b, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_push}, "enter" },	/* 0xC8 ENTER imm8, imm16 */
	{ 0x4008, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_pop}, "leave" },	/* 0xC9 LEAVE */
	{ 0x1005, READ | ADDRM_I | OPT_w, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "retf" },	/* 0xCA RETF far return - should not be used in our context */
	{ 0x1005, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "retf" },	/* 0xCB RETF far return - should not be used in our context */
	{ 0xd005, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "int3" },	/* 0xCC INT3 trap to debugger - we copy debugger traps (best effort) */
	{ 0xd001, READ | ADDRM_I | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "int" },	/* 0xCD INT imm8 - interrupt vector */
	{ 0xd008, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "into" },	/* 0xCE INTO trap to debugger */
	{ 0xd003, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "iret" },	/* 0xCF IRET interrupt return - we should not see this */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_D0_rm}, "" },	/* 0xD0  shift group 2 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_D1_rm}, "" },	/* 0xD1  shift group 2 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_D2_rm}, "" },	/* 0xD2  shift group 2 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_D3_rm}, "" },	/* 0xD3  shift group 2 */
	{ 0xf002, WRITE | ADDRM_I | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "aam" },	/* 0xD4 AAM, imm8 */
	{ 0xf002, WRITE | ADDRM_I | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "aad" },	/* 0xD5 AAD, imm8 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xD6  undefined opcode */
	{ 0x7005, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "xlat" },	/* 0xD7 XLAT %al = (%ds:%ebx[%al]) */

	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_D8_fpu}, "" },	/* 0xD8  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_D9_fpu}, "" },	/* 0xD9  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DA_fpu}, "" },	/* 0xDA  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DB_fpu}, "" },	/* 0xDB  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DC_fpu}, "" },	/* 0xDC  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DD_fpu}, "" },	/* 0xDD  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DE_fpu}, "" },	/* 0xDE  escape for floating point instructions */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_FPU_ESC, {.table = opcode_table_DF_fpu}, "" },	/* 0xDF  escape for floating point instructions */

	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "loopnz" },	/* 0xE0 LOOPNZ, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "loopz" },	/* 0xE1 LOOPZ, rel8 */
	{ 0x1001, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "loop" },	/* 0xE2 LOOP, rel8 */
	{ 0x1002, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jcc}, "jcxz" },	/* 0xE3 JCXZ, rel8 */
	{ 0xe002, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x10, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "in" },	/* 0xE4 IN port[imm8] to %al */
	{ 0xe002, WRITE |  IMPL , READ | ADDRM_I | OPT_b, ARG_NONE, 0x30, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "in" },	/* 0xE5 IN port[imm8] to %eax */
	{ 0xe003, WRITE | ADDRM_I | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x10, 0x0, NO_MODRM, {.handler = action_copy}, "out" },	/* 0xE6 OUT %al to port[imm8] */
	{ 0xe003, WRITE | ADDRM_I | OPT_b, READ |  IMPL , ARG_NONE, 0x0, 0x30, 0x0, NO_MODRM, {.handler = action_copy}, "out" },	/* 0xE7 OUT %eax to port[imm8] */

	{ 0x1003, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_call}, "call" },	/* 0xE8 CALL near relative */
	{ 0x1001, EXECUTE | ADDRM_J | OPT_z, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jmp}, "jmp" },	/* 0xE9 JMP near relative */
	{ 0x1001, EXECUTE | ADDRM_A | OPT_p, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_warn}, "jmp" },	/* 0xEA JMP far absolute */
	{ 0x1001, EXECUTE | ADDRM_J | OPT_b, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_jmp}, "jmp" },	/* 0xEB JMP short */
	{ 0xe002, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x10, 0x22, 0x0, NO_MODRM, {.handler = action_copy}, "in" },	/* 0xEC IN port[%dx] to %al */
	{ 0xe002, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x30, 0x22, 0x0, NO_MODRM, {.handler = action_copy}, "in" },	/* 0xED IN port[%dx] to %eax */
	{ 0xe003, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x22, 0x10, 0x0, NO_MODRM, {.handler = action_copy}, "out" },	/* 0xEE OUT %al to port[%dx] */
	{ 0xe003, WRITE |  IMPL , READ |  IMPL , ARG_NONE, 0x22, 0x30, 0x0, NO_MODRM, {.handler = action_copy}, "out" },	/* 0xEF OUT %eax to port[%dx] */

	{ 0x10000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.handler = NO_ACTION_CALLED}, "" },	/* 0xF0  lock prefix */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_fail}, "" },	/* 0xF1  undefined opcode */
	{ 0x40000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.table = opcode_table_F20F}, "" },	/* 0xF2   repne prefix */
	{ 0x20000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_PREFIX_ESC, {.table = opcode_table_F30F}, "" },	/* 0xF3  rep prefix */
	{ 0xe001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "hlt" },	/* 0xF4 HLT */
	{ 0x9010, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cmc" },	/* 0xF5 CMC */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_F6_rm}, "" },	/* 0xF6  group 3 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_F7_rm}, "" },	/* 0xF7  group 3 */

	{ 0x9001, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "clc" },	/* 0xF8 CLC */
	{ 0x9007, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "stc" },	/* 0xF9 STC */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cli" },	/* 0xFA CLI */
	{ 0xe000, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "sti" },	/* 0xFB STI */
	{ 0x9004, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "cld" },	/* 0xFC CLD */
	{ 0x900a, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, NO_MODRM, {.handler = action_copy}, "std" },	/* 0xFD STD */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_FE_rm}, "" },	/* 0xFE  group 4 */
	{ 0x0, ARG_NONE, ARG_NONE, ARG_NONE, 0x0, 0x0, 0x0, OPCODE_MODRM_ESC, {.table = opcode_table_FF_rm}, "" }	/* 0xFF  group 5 */
};


#endif  /* FBT_OPCODE_TABLES_H */

