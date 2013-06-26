
#include <iostream>
#include <fstream>

#include "table_generator.h"

bool handlePushAndPop (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
        if (isPushOpcode(disasmInfo.opcodeFlags)){
                action = "action_push";
                return false;
        }
        if (isPopOpcode(disasmInfo.opcodeFlags)){
                action = "action_pop";
                return false;
        }
        return true;
}

bool handleIncAndDec (const unsigned char* opcode, const instr& disasmInfo, std::string& action) {
        if (isIncOpcode(disasmInfo.opcodeFlags)){
                action = "action_inc";
                return false;
        }
        if (isDecOpcode(disasmInfo.opcodeFlags)){
                action = "action_dec";
                return false;
        }
        return true;
}

int main () {

	std::ofstream outputFile ("fbt_opcode_tables.h");

	addAnalysFunction(handlePushAndPop);
	addAnalysFunction(handleIncAndDec);

	if (outputFile.is_open()) {
		generateTables(outputFile, "");
	}
}

