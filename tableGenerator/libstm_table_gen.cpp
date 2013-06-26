
#include <iostream>
#include <fstream>
#include <sstream>

#include "table_generator.h"

std::string int2string (int n) {
	std::stringstream ss;
	ss << n;
	return ss.str();
}


bool isLegalOp (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	// TODO: ensure that illegal operations return false...
	switch (disasmInfo.opcodeFlags & INS_TYPE_MASK) {
		case IN:
		case OUT:
			return false;
	}

	// TODO: is the following correct??
	if (action == "action_warn") {
		return false;
	}

	return true;
}

bool handlePushAndPop (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if (isPushOpcode(disasmInfo.opcodeFlags) || isPopOpcode(disasmInfo.opcodeFlags)) {
		action = "action_copy";
		return false;
	}

	return true;
}

bool handleFPU (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if ((disasmInfo.opcodeFlags & INS_GROUP_MASK) == FPU) {
		action = "action_fail";
		return false;
	}

	return true;
}

bool isMemOp (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	bool result = false;
	result |= mayOperandAccessMemory(disasmInfo.destFlags) && !(disasmInfo.destFlags & EXECUTE);
	result |= mayOperandAccessMemory(disasmInfo.srcFlags)  && !(disasmInfo.srcFlags & EXECUTE);
	result |= mayOperandAccessMemory(disasmInfo.auxFlags)  && !(disasmInfo.auxFlags & EXECUTE);

	if (result) {
		result = *opcode != 0x8D; /* 0x8D = lea - the operand looks like but does no access the memory */
	}

	return result;
}

bool handleDIVandMUL (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if (*opcode == 0xF6 || *opcode == 0xF7) {
		if (*(opcode+1) >= 0x30) {
			action = "handleDIV_" + int2string(operandSize(disasmInfo.srcFlags));
			return false;
		} else if (*(opcode+1) >= 0x20) {
			action = "handleMUL_" + int2string(operandSize(disasmInfo.srcFlags));
			return false;
		}
	}

	return true;
}

bool handleCMPXCHGandCMPXCHG8B (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if (*opcode == 0x0F) {
		if ((*(opcode+1) == 0xB0) || (*(opcode+1) == 0xB1)) {
			unsigned int flags = 0;
			if (isMemAddrInModRM(disasmInfo.destFlags)) flags = disasmInfo.destFlags;
			if (isMemAddrInModRM(disasmInfo.srcFlags))  flags = disasmInfo.srcFlags;
			if (isMemAddrInModRM(disasmInfo.auxFlags))  flags = disasmInfo.auxFlags;

			action = "handleCMPXCHG";
			action += "_" + int2string(operandSize(flags));
			return false;
		}
		if ((*(opcode+1) == 0xC7) && (((*(opcode+2) >>3) & 0x7) == 0x01)) {
			action = "handleCMPXCHG8B";
			return false;
		}
	}
	return true;
}

bool handleMOVSetc (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if (*opcode == 0xA4) {
		action = "handleMOVS_1";
		return false;
	}
	if (*opcode == 0xA5) {
		action = "handleMOVS_4";
		return false;
	}
	if (*opcode == 0xA6) {
		action = "handleCMPS_1";
		return false;
	}
	if (*opcode == 0xA7) {
		action = "handleCMPS_4";
		return false;
	}
	if (*opcode == 0xAA) {
		action = "handleSTOS_1";
		return false;
	}
	if (*opcode == 0xAB) {
		action = "handleSTOS_4";
		return false;
	}
	if (*opcode == 0xAC) {
		action = "action_fail"; // LODSB
		return false;
	}
	if (*opcode == 0xAD) {
		action = "action_fail"; // LODSD
		return false;
	}
	if (*opcode == 0xAE) {
		action = "action_fail"; // SCASB
		return false;
	}
	if (*opcode == 0xAF) {
		action = "action_fail"; // SCASD
		return false;
	}
	if (*opcode == 0x6C) {
		action = "action_fail"; // INSB
		return false;
	}
	if (*opcode == 0x6D) {
		action = "action_fail"; // INSD
		return false;
	}
	if (*opcode == 0x6E) {
		action = "action_fail"; // OUTSB
		return false;
	}
	if (*opcode == 0x6F) {
		action = "action_fail"; // OUTSD
		return false;
	}
	return true;
}


bool handleIndirectCALLandJMP (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	if (*opcode == 0xFF) {
		if ((*(opcode+1) & 0x38) == 0x10) {
			action = "handleIndirectCALL";
			return false;
		}
		if ((*(opcode+1) & 0x38) == 0x20) {
			action = "handleIndirectJMP";
			return false;
		}
	}

	return true;
}

bool handleModRMAddress (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	unsigned int flags = 0;
	if (isMemAddrInModRM(disasmInfo.destFlags)) flags = disasmInfo.destFlags;
	if (isMemAddrInModRM(disasmInfo.srcFlags))  flags = disasmInfo.srcFlags;
	if (isMemAddrInModRM(disasmInfo.auxFlags))  flags = disasmInfo.auxFlags;

	if (flags == 0) return true;

	action = "handleModRMAddr_";
	if (isReadOperand(flags))  action += "R";
	if (isWriteOperand(flags)) action += "W";

	action += "_" + int2string(operandSize(flags));

	flags = 0;
	if (isImmediateOperand(disasmInfo.destFlags)) flags = disasmInfo.destFlags;
	if (isImmediateOperand(disasmInfo.srcFlags))  flags = disasmInfo.srcFlags;
	if (isImmediateOperand(disasmInfo.auxFlags))  flags = disasmInfo.auxFlags;

	if (flags != 0) {
		action += "_I_" + int2string(operandSize(flags));
	}


	return false;
}

bool handleImmediateAddress (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
	unsigned int flags = 0;
	if (isImmediateMemAddr(disasmInfo.destFlags)) flags = disasmInfo.destFlags;
	if (isImmediateMemAddr(disasmInfo.srcFlags))  flags = disasmInfo.srcFlags;
	if (isImmediateMemAddr(disasmInfo.auxFlags))  flags = disasmInfo.auxFlags;

	if (flags == 0) return true;

	action = "handleImmediateAddr_";
	if (isReadOperand(flags))  action += "R";
	if (isWriteOperand(flags)) action += "W";

	action += "_" + int2string(operandSize(flags));

	return false;
}

int main () {

	/* define the output file */
	std::ofstream outputFile ("libstm_opcode_tables.h");

	/* add the analysise functions to the generator */
	addAnalysFunction(handleIndirectCALLandJMP);
	addAnalysFunction(handleMOVSetc);
	addAnalysFunction(isLegalOp);
	addAnalysFunction(handlePushAndPop);

	/* Uncomment this line to disable FPU instructions */
/*  	addAnalysFunction(handleFPU); */

	addAnalysFunction(isMemOp);
	addAnalysFunction(handleDIVandMUL);
	addAnalysFunction(handleCMPXCHGandCMPXCHG8B);
	addAnalysFunction(handleModRMAddress);
	addAnalysFunction(handleImmediateAddress);

	/* generate the tables */
	if (outputFile.is_open()) {
		generateTables(outputFile, "stm");
	}
}

