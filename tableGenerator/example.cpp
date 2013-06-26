
#include <iostream>
#include <fstream>

#include "table_generator.h"


int main () {

	std::ofstream outputFile ("fbt_opcode_tables.h");

	if (outputFile.is_open()) {
		generateTables(outputFile, "");
	}
}

