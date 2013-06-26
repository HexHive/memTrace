#ifndef I386_OPCODE_H
#define I386_OPCODE_H

#define MAX_INSTRUCTION_SIZE 20

/*
 * This struct is used to store all information which is
 * given by an opcode. Basically anything which does not
 * depend on a prefix byte or an argument byte
 */
typedef struct instr {
	/*
	 * if there follows another opcode byte after this one
	 * table specifies the place to continue the lookup
	 */
	struct instr *table;

	/* the information for the opcode */
	std::string mnemonic;
	unsigned int opcodeFlags;

	/* the following hold flags for the operands */
	/* the value NONE means the opcode does not make use of this operand */
	unsigned int destFlags;
	unsigned int srcFlags;
	unsigned int auxFlags;

	/* the following hold flags for the implizit operands */
	/* do not reley on the these values if an argument is not implizit */
	unsigned int implDestFlags;
	unsigned int implSrcFlags;
	unsigned int implAuxFlags;

	/* the following is specific to the table generator */
	std::string defaultAction;
	std::string comment;

} instr_t;




/*******************************************************\
 * operand flags                                       *
\*******************************************************/
/* operand not used by this instruction */
#define		NONE					0x00000000

/* operand masks */
#define		OP_USE_MASK				0x0000000F		/* how is this operand used */
#define		OP_SPECIAL_MASK			0x000000F0		/* special flags for this operand */
#define		OP_ADDRM_MASK			0x00001F00		/* addressing method */
#define		OPT_MASK				0x00FF0000		/* type of operand */



/* how is the opeand used in this instruction */
#define		RWX					  0x00000007
#define		READ					0x00000001		/* operand is read */
#define		WRITE					0x00000002		/* operand is written */
#define		MODIFY					READ | WRITE	/* operand is modified */
#define		EXECUTE					0x00000004		/* operand is executed */

/* special operands and flags */
#define   SPECIAL_ALL   0x00000070
#define		IMPL					0x00000010		/* implizit register */
#define		CONST					0x00000020		/* implizit constant value */
#define		SIGEND				0x00000040		/* operand is signed */

/* addresing methods - taken from intel manual */
#define		ADDRM_ALL			  0x00001F00
#define		ADDRM_A					0x00000100
#define		ADDRM_C					0x00000200
#define		ADDRM_D					0x00000300
#define		ADDRM_E					0x00000400
#define		ADDRM_F					0x00000500
#define		ADDRM_G					0x00000600
#define		ADDRM_I					0x00000700
#define		ADDRM_J					0x00000800
#define		ADDRM_M					0x00000900
#define		ADDRM_N					0x00000A00
#define		ADDRM_O					0x00000B00
#define		ADDRM_P					0x00000C00
#define		ADDRM_Q					0x00000D00
#define		ADDRM_R					0x00000E00
#define		ADDRM_S					0x00000F00
#define		ADDRM_U					0x00001000
#define		ADDRM_V					0x00001100
#define		ADDRM_W					0x00001200
#define		ADDRM_X					0x00001300
#define		ADDRM_Y					0x00001400
#define		ADDRM_RM				0x00001500
#define		ADDRM_UM				0x00001600

/* operand types - taken from intel manual */
#define		OPT_ALL				0x003F0000
#define		OPT_a					0x00010000
#define		OPT_b					0x00020000
#define		OPT_c					0x00030000
#define		OPT_d					0x00040000
#define		OPT_dq				0x00050000
#define		OPT_p					0x00060000
#define		OPT_pd				0x00070000
#define		OPT_pi				0x00080000
#define		OPT_ps				0x00090000
#define		OPT_q					0x000A0000
#define		OPT_s					0x000B0000
#define		OPT_ss				0x000C0000
#define		OPT_sd				0x000D0000 /* this one is not in the intel manual! */
#define		OPT_si				0x000E0000
#define		OPT_v					0x000F0000
#define		OPT_w					0x00100000
#define		OPT_z					0x00110000
/* operand types for FPU - these are not found in the intel manual */
#define		OPT_fs				0x00200000		/* single-real*/
#define		OPT_fd				0x00210000		/* double-real */
#define		OPT_fe				0x00220000		/* extended-real */
#define		OPT_fp				0x00230000		/* packed-BCD */
#define		OPT_fv				0x00240000		/* FPU env (14/28 bytes) */
#define		OPT_fst				0x00250000		/* FPU state (98/108 bytes) */


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
#define		INS_TYPE_MASK			0x0000FFFF
#define		INS_GROUP_MASK			0x0000F000
#define		INS_PREFIX_MASK			0x0FFF0000


/* prefixes */
#define		PREFIX_LOCK				0x00010000
#define		PREFIX_REP				0x00020000
#define		PREFIX_REPNZ			0x00040000
#define		PREFIX_OP_SIZE			0x00100000
#define		PREFIX_ADDR_SIZE		0x00200000

#define		PREFIX_CS				0x01000000
#define		PREFIX_SS				0x02000000
#define		PREFIX_DS				0x03000000
#define		PREFIX_ES				0x04000000
#define		PREFIX_FS				0x05000000
#define		PREFIX_GS				0x06000000



/* instruction types [groups] */
#define		EXEC					0x00001000
#define		ARITH					0x00002000
#define		LOGIC					0x00003000
#define		STACK					0x00004000
#define		COND					0x00005000
#define		LOAD					0x00006000
#define		ARRAY					0x00007000
#define		BIT						0x00008000
#define		FLAG					0x00009000
#define		FPU						0x0000A000
#define		TRAPS					0x0000D000
#define		SYSTEM				0x0000E000
#define		OTHER					0x0000F000

/* EXEC group */
#define		BRANCH					EXEC | 0x01			/* Unconditional branch */
#define		BRANCHCC				EXEC | 0x02			/* Conditional branch */
#define		CALL					EXEC | 0x03			/* Jump to subroutine */
#define		CALLCC					EXEC | 0x04			/* Jump to subroutine */
#define		RET						EXEC | 0x05			/* Return from subroutine */
#define		LOOP					EXEC | 0x06			/* loop to local label */

/* ARITH group */
#define		ADD						ARITH | 0x01
#define		SUB						ARITH | 0x02
#define		MUL						ARITH | 0x03
#define		DIV						ARITH | 0x04
#define		INC						(ARITH | 0x05)		/* increment */
#define		DEC						ARITH | 0x06		/* decrement */
#define		SHL						ARITH | 0x07		/* shift right */
#define		SHR						ARITH | 0x08		/* shift left */
#define		ROL						ARITH | 0x09		/* rotate left */
#define		ROR						ARITH | 0x0A		/* rotate right */

/* LOGIC group */
#define		AND						LOGIC | 0x01
#define		OR						LOGIC | 0x02
#define		XOR						LOGIC | 0x03
#define		NOT						LOGIC | 0x04
#define		NEG						LOGIC | 0x05

/* STACK group */
#define		PUSH					STACK | 0x01
#define		POP						STACK | 0x02
#define		PUSHREGS				STACK | 0x03		/* push register context */
#define		POPREGS					STACK | 0x04		/* pop register context */
#define		PUSHFLAGS				STACK | 0x05		/* push all flags */
#define		POPFLAGS				STACK | 0x06		/* pop all flags */
#define		ENTER					STACK | 0x07		/* enter stack frame */
#define		LEAVE					STACK | 0x08		/* leave stack frame */

/* COND group */
#define		TEST					COND | 0x01
#define		CMP						COND | 0x02

/* LOAD group */
#define		MOV						LOAD | 0x01
#define		MOVCC					LOAD | 0x02
#define		XCHG					LOAD | 0x03
#define		XCHGCC					LOAD | 0x04

/* ARRAY group */
#define		STRCMP					ARRAY | 0x01
#define		STRLOAD					ARRAY | 0x02
#define		STRMOV					ARRAY | 0x03
#define		STRSTOR					ARRAY | 0x04
#define		XLAT					ARRAY | 0x05

/* BIT group */
#define		BITTEST					BIT | 0x01
#define		BITSET					BIT | 0x02
#define		BITCLR					BIT | 0x03

/* FLAG group */
#define		CLEARCF					FLAG | 0x01			/* clear Carry flag */
#define		CLEARZF					FLAG | 0x02			/* clear Zero flag */
#define		CLEAROF					FLAG | 0x03			/* clear Overflow flag */
#define		CLEARDF					FLAG | 0x04			/* clear Direction flag */
#define		CLEARSF					FLAG | 0x05			/* clear Sign flag */
#define		CLEARPF					FLAG | 0x06			/* clear Parity flag */
#define		SETCF					FLAG | 0x07
#define		SETZF					FLAG | 0x08
#define		SETOF					FLAG | 0x09
#define		SETDF					FLAG | 0x0A
#define		SETSF					FLAG | 0x0B
#define		SETPF					FLAG | 0x0C
#define		TOGCF					FLAG | 0x10			/* toggle */
#define		TOGZF					FLAG | 0x20
#define		TOGOF					FLAG | 0x30
#define		TOGDF					FLAG | 0x40
#define		TOGSF					FLAG | 0x50
#define		TOGPF					FLAG | 0x60

/* TRAP */
#define		TRAP					TRAPS | 0x01		/* generate trap */
#define		TRAPCC					TRAPS | 0x02		/* conditional trap gen */
#define		TRET					TRAPS | 0x03		/* return from trap */
#define		BOUNDS					TRAPS | 0x04		/* gen bounds trap */
#define		DEBUG					TRAPS | 0x05		/* gen breakpoint trap */
#define		TRACE					TRAPS | 0x06		/* gen single step trap */
#define		INVALIDOP				TRAPS | 0x07		/* gen invalid instruction */
#define		OFLOW					TRAPS | 0x08		/* gen overflow trap */

/* SYSTEM */
#define		HALT					SYSTEM | 0x01		/* halt machine */
#define		IN						SYSTEM | 0x02		/* input form port */
#define		OUT						SYSTEM | 0x03		/* output to port */
#define		CPUID					SYSTEM | 0x04		/* identify cpu */

/* OTHER */
#define		NOP						OTHER | 0x01
#define		BCDCONV					OTHER | 0x02		/* convert to/from BCD */
#define		SZCONV					OTHER | 0x03		/* convert size of operand */





/* these are defined in i386_opcode.map */
extern instr_t table_opcode_onebyte[], table_opcode_twobytes[];

extern instr_t table_opcode_0f38[];
extern instr_t table_opcode_0f3a[];

extern instr_t table_opcode_660f[];
extern instr_t table_opcode_f20f[];
extern instr_t table_opcode_f30f[];
extern instr_t table_opcode_660f38[];
extern instr_t table_opcode_660f3a[];
extern instr_t table_opcode_f20f38[];

extern instr_t table_opcode_80_rm[], table_opcode_81_rm[], table_opcode_82_rm[], table_opcode_83_rm[];
extern instr_t table_opcode_C0_rm[], table_opcode_C1_rm[];
extern instr_t table_opcode_D0_rm[], table_opcode_D1_rm[], table_opcode_D2_rm[], table_opcode_D3_rm[];
extern instr_t table_opcode_F6_rm[], table_opcode_F7_rm[], table_opcode_FE_rm[], table_opcode_FF_rm[];
extern instr_t table_opcode_0F00_rm[], table_opcode_0F01_rm[], table_opcode_0F18_rm[];
extern instr_t table_opcode_0F71_rm[], table_opcode_0F72_rm[], table_opcode_0F73_rm[];
extern instr_t table_opcode_0FAE_rm[], table_opcode_0FBA_rm[], table_opcode_0FC7_rm[];  /* group 12, 13, 14 */
extern instr_t table_opcode_660F71_rm[], table_opcode_660F72_rm[], table_opcode_660F73_rm[];  /* 0x66 extension to former groups */

extern instr_t table_opcode_D8_fpu_rm[], table_opcode_D8_fpu_others[], table_opcode_D9_fpu_rm[], table_opcode_D9_fpu_others[];
extern instr_t table_opcode_DA_fpu_rm[], table_opcode_DA_fpu_others[], table_opcode_DB_fpu_rm[], table_opcode_DB_fpu_others[];
extern instr_t table_opcode_DC_fpu_rm[], table_opcode_DC_fpu_others[], table_opcode_DD_fpu_rm[], table_opcode_DD_fpu_others[];
extern instr_t table_opcode_DE_fpu_rm[], table_opcode_DE_fpu_others[], table_opcode_DF_fpu_rm[], table_opcode_DF_fpu_others[];


#endif
