/**
 * @file fbt_actions.h
 * This module defines some generic default actions that are used to translate
 * specific machine codes.
 *
 * Copyright (c) 2011 ETH Zurich
 *
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 * $Date: 2011-12-30 14:24:05 +0100 (ven, 30 dic 2011) $
 * $LastChangedDate: 2011-12-30 14:24:05 +0100 (ven, 30 dic 2011) $
 * $LastChangedBy: payerm $
 * $Revision: 1134 $
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
#ifndef FBT_ACTIONS_H
#define FBT_ACTIONS_H

#include "fbt_datatypes.h"
/**
 * This instruction drops/removes the current instruction.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_none(struct translate *ts, BOOL lock);

/**
 * Copies the current instruction verbatim from the original code region to the
 * code cache.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_copy(struct translate *ts, BOOL lock);

/**
 * Copies the current instruction verbatim from the original code region to the
 * code cache. This method additional emits a warning in the logs for unsafe
 * instructions.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_warn(struct translate *ts, BOOL lock);

/**
 * This action fails and terminates the program. This action is used for illegal
 * instructions.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_fail(struct translate *ts, BOOL lock);

enum translation_state action_push(struct translate *ts, BOOL lock);

enum translation_state action_pop(struct translate *ts, BOOL lock);

enum translation_state action_inc(struct translate *ts, BOOL lock);

enum translation_state action_dec(struct translate *ts, BOOL lock);

/**
 * Handles relative jump instructions.
 * Rewrites relative jump instructions such that the jump is relative to the
 * translated code. Short jumps are rewritten to near jumps, as we cannot
 * guarantee that the offset for the translated version can fit into 8 bit.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_jmp(struct translate *ts, BOOL lock);

/**
 * Handles indirect jumps.
 * Indirect jumps are translated into a PUSH of the addr and a call to the
 * function "ind_jump"
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction.
 */
enum translation_state action_jmp_indirect(struct translate *ts, BOOL lock);

/**
 * This function handles a jump conditional (Jcc).
 * Short jumps are rewritten to near jumps, as we cannot guarantee that the
 * offset for the translated version can fit into 8 bit.
 * JECXZ are handled separately (within this function), as there exists only a
 * short jump version.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_jcc(struct translate *ts, BOOL lock);

/**
 * Handles call instructions to relative memory addresses.
 * Copies the call instruction, but changes the target address such that the
 * translated version of the function is called. If the function is not already
 * translated, the function translate_function is invoked.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_call(struct translate *ts, BOOL lock);

/**
 * Handles near indirect calls.
 * If the function is not already translated, the function translate_function is
 * invoked.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_call_indirect(struct translate *ts, BOOL lock);

/**
 * This function translates a sysenter instruction.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction
 */
enum translation_state action_sysenter(struct translate *ts, BOOL lock);

/**
 * Handles ret instructions.
 * @param ts is a pointer to the translation struct of the current thread
 * @return enum that determines if the TU shall be finalized after this
 * instruction (in this case: YES).
 */
enum translation_state action_ret(struct translate *ts, BOOL lock);
#endif  /* FBT_ACTIONS_H */
