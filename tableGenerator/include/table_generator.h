#ifndef TABLE_GENERATOR_H
#define TABLE_GENERATOR_H

#include <string>

#include "i386_opcode.h"


#define BUF_SIZE 20


/**
 * Call back function type:
 * @param opcode is a byte buffer holding the opcode for which the action should be defined
 * @param disasmInfo is a struct with the informations of the disasm library
 * @param action is the current action which is inserted into the jump table. modify to change the action which is inserted
 * @return false if no more analysis functions should be called for this opcode
 */
typedef bool(*analysFunction)(const unsigned char* opcode, const instr& disasmInfo, std::string& action);


/**
 * Adds an analysis function. The functions are called in the order they were added.
 * @param f is a function pointer to an analysis function
 */
void addAnalysFunction(analysFunction f);

/**
 * Generates the opcode jump table
 * @param out is the stream where the generated file is outputted to
 * @param prefix is a string which is prepended to any variable in the generated output to preven name colisions
 */
void generateTables(std::ofstream& out, std::string prefix);


/*****\
| *** |  The following functions are ment to aied you in
| *** |  analyzing the disasm information for an opcode
\*****/

/**
 * returns the size of the operand
 */
unsigned int operandSize(unsigned int operandFlags);

/**
 * may this operand access memory
 */
bool mayOperandAccessMemory(unsigned int operandFlags);

/**
 * may this operand access a register
 */
bool mayOperandAccessRegister(unsigned int operandFlags);

/**
 * is this operand an immediate value
 */
bool isImmediateOperand(unsigned int operandFlags);

/**
 * is this operand in the modRM byte
 */
bool isModRMOperand(unsigned int operandFlags);

/**
 * is this operand implizitly given
 */
bool isImplizitOperand(unsigned int operandFlags);

/**
 * is this operand read
 */
bool isReadOperand(unsigned int operandFlags);

/**
 * is this operand written
 */
bool isWriteOperand(unsigned int operandFlags);

/**
 * is this a push operand
 */
bool isPushOpcode(unsigned int opcodeFlags);

/**
 * is this a pop operand
 */
bool isPopOpcode(unsigned int opcodeFlags);

bool isIncOpcode (unsigned int opcodeFlags);
bool isDecOpcode (unsigned int opcodeFlags);

/**
 * is this an immediate memory address
 */
bool isImmediateMemAddr(unsigned int operandFlags);

/**
 * is this a memory address which is given by a modRM field
 */
bool isMemAddrInModRM(unsigned int operandFlags);


#endif
