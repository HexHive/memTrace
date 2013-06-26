#include "table_generator.h"

/*
 * A lot of helper functions which should ease the use of the table generator
 * see "table_generator.h" for documentation of the following functions
 *
 * feel free to add more functions if you think they might be handy
 */

bool mayOperandAccessMemory (unsigned int operandFlags) {
	switch (operandFlags & OP_ADDRM_MASK) {
		case ADDRM_A:
		case ADDRM_E:
		case ADDRM_J:
		case ADDRM_M:
		case ADDRM_O:
		case ADDRM_Q:
		case ADDRM_W:
		case ADDRM_X:
		case ADDRM_Y:
			return true;
	}

	return false;
}


bool mayOperandAccessRegister (unsigned int operandFlags) {
	switch (operandFlags & OP_ADDRM_MASK) {
		case ADDRM_C:
		case ADDRM_D:
		case ADDRM_E:
		case ADDRM_G:
		case ADDRM_N:
		case ADDRM_P:
		case ADDRM_Q:
		case ADDRM_R:
		case ADDRM_S:
		case ADDRM_U:
		case ADDRM_V:
		case ADDRM_W:
			return true;
	}

	if ((operandFlags & IMPL) != 0) {
		return true;
	}

	return false;
}


bool isModRMOperand (unsigned int operandFlags) {

	switch (operandFlags & OP_ADDRM_MASK) {
		case ADDRM_C:
		case ADDRM_D:
		case ADDRM_E:
		case ADDRM_G:
		case ADDRM_M:
		case ADDRM_N:
		case ADDRM_P:
		case ADDRM_Q:
		case ADDRM_R:
		case ADDRM_S:
		case ADDRM_U:
		case ADDRM_V:
		case ADDRM_W:
			return true;
	}

	return false;
}


bool isImmediateOperand (unsigned int operandFlags) {

	switch (operandFlags & OP_ADDRM_MASK) {
		case ADDRM_A:
		case ADDRM_I:
		case ADDRM_J:
		case ADDRM_O:
			return true;
	}

	return false;
}


bool isImplizitOperand (unsigned int operandFlags) {

	switch (operandFlags & OP_SPECIAL_MASK) {
		case IMPL:
		case CONST:
			return true;
	}

	return false;
}


bool isReadOperand (unsigned int operandFlags) {
	return operandFlags & READ;
}


bool isWriteOperand (unsigned int operandFlags) {
	return operandFlags & WRITE;
}

unsigned int operandSize (unsigned int operandFlags) {
	switch (operandFlags & OPT_MASK) {
		case OPT_b:
			return 1;
		case OPT_c:
		case OPT_w:
			return 2;
		case OPT_a:
		case OPT_d:
		case OPT_si:
		case OPT_v:
		case OPT_z:
		case OPT_fs:
			return 4;
		case OPT_p:
			return 6;
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
	}
	return 0;
}


bool isPushOpcode (unsigned int opcodeFlags) {
	switch (opcodeFlags & INS_TYPE_MASK) {
		case PUSH:
		case PUSHREGS:
		case PUSHFLAGS:
		case ENTER:
			return true;
	}
	return false;
}


bool isPopOpcode (unsigned int opcodeFlags) {
	switch (opcodeFlags & INS_TYPE_MASK) {
		case POP:
		case POPREGS:
		case POPFLAGS:
		case LEAVE:
			return true;
	}
	return false;
}

bool isIncOpcode (unsigned int opcodeFlags) {
	switch (opcodeFlags & INS_TYPE_MASK) {
		case INC:	return true;
	}
	return false;
}

bool isDecOpcode (unsigned int opcodeFlags) {
	switch (opcodeFlags & INS_TYPE_MASK) {
		case DEC:	return true;
	}
	return false;
}

bool isImmediateMemAddr (unsigned int operandFlags)
{
	return mayOperandAccessMemory(operandFlags) && isImmediateOperand(operandFlags);
}


bool isMemAddrInModRM   (unsigned int operandFlags)
{
	return mayOperandAccessMemory(operandFlags) && isModRMOperand(operandFlags);
}



