/**
 * @file fbt_translate.h
 * This module is used to translate basic blocks.
 *
 * Copyright (c) 2012 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedDate: 2012-01-18 12:17:00 +0100 (mer, 18 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1184 $
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

#ifndef FBT_TRANSLATE_H
#define FBT_TRANSLATE_H

#include "fbt_datatypes.h"
#include "fbt_config.h"

/**
 * By commenting and uncommenting one can play with alignment rules.
 */
#define ENFORCE_ALIGNMENT(x) //while (((uint64_t)x) & ((uint64_t)0xFF)){x++;}

/*
 * In practice the 'flags' register is never used
 * throughout function boundaries. That is, no one
 * uses it as some sort of implicit parameter or
 * some sort of implicit return value. This switch
 * says that lmem can make this assumption to
 * get better performance. This makes sense since
 * lmem is meant mainly to debug and not for security.
 * A malicious program may detect the sandbox by
 * making a function that changes flags in a specific
 * way and let the caller check if this change has
 * been preserved.
 */
enum{LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_CALL=TRUE};
enum{LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_RET=TRUE};
enum{LMEM_DO_NOT_PRESERVE_EFLAGS_OVER_CALL_INDIRECT=TRUE};

/**
 * This artificial syscall takes two arguments.
 * Watchpoints have size one byte.
 * @param arg1 0 means set watchpoint, 1 means delete watchpoint
 * @param arg2 the address of the watchpoint.
 */
enum syscall_auth_response lmem_syscall(struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t *arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)));

/* forward declare struct */
struct trampoline;
struct translate;
struct thread_local_data;

/** Maximum size for a translated code block  */
#define MAX_BLOCK_SIZE (2048*8)

/** the translation can be in these states. */
enum translation_state {
  /** translation must not stop after this instruction but must continue */
  OPEN,
  /** translation may stop after this instruction */
  NEUTRAL,
  /** translation must stop after this instruction */
  CLOSE,
  /** translation must stop after this instruction and fixup code must be
     inserted as if the instruction limit is reached */
  CLOSE_GLUE
};

/** Function definition for action functions. */
typedef enum translation_state (*actionFunP_t)(struct translate *ts, BOOL lock);

/**
 * Translate a given code region located at orig_address and put the
 * translated code fragment into the code cache.
 * Translates a translation unit without jumping to the translated code.
 * If the translation unit (TU) has already been translated and is in the
 * code cache, the function returns immediately. Otherwise, the TU is
 * translated first and stored in the code cache.
 * @param tld pointer to thread local data.
 * @param orig_address the address where the TU begins
 * @return pointer to the translated code that corresponds to this TU
 */
void *fbt_translate_noexecute(struct thread_local_data *tld,
    guestptr_t orig_address, BOOL lock);

#ifndef REGISTER_FOR_ARFLAGS
#define ARFLAGS_TO_RAX_CLO_R8 movabs_to_r8 {&tld->saved_arith_flags}; \
                              movl (%r8), %eax;
#define ARFLAGS_TO_RAX_CLO_R10 movabs_to_r10 {&tld->saved_arith_flags}; \
                               movl (%r10), %eax;
#define RAX_TO_ARFLAGS_CLO_R8 movabs_to_r8 {&tld->saved_arith_flags}; \
                              movl %eax, (%r8);
#else

#ifdef FAST_RET
#error "incompatible options: register for arflags incopat with fastret"
#endif

#define ARFLAGSREG %r13d
#define ARFLAGS_TO_RAX_CLO_R8 movl ARFLAGSREG, %eax;
#define ARFLAGS_TO_RAX_CLO_R10 movl ARFLAGSREG, %eax;
#define RAX_TO_ARFLAGS_CLO_R8 movl %eax, ARFLAGSREG;

#endif

/**
 * Saves the arighmetic flags *only*
 */
#define SAVE_FLAGS \
    movl %eax, %r9d; \
    lahf; \
    seto %al; \
    RAX_TO_ARFLAGS_CLO_R8 \
    movl %r9d, %eax;

/**
 * Restores the arighmetic flags *only* (clobbering some regs)
 */
#define RESTORE_FLAGS_CLOBBERING_R8_R9 \
    movl %eax, %r9d; \
    ARFLAGS_TO_RAX_CLO_R8 \
    addb $0x7f, %al;  \
    sahf; \
    movl %r9d, %eax;

/**
 * Restores the arighmetic flags *only* (clobbering some regs)
 */
#define RESTORE_FLAGS_CLOBBERING_R8_R10 \
    movl %eax, %r10d; \
    ARFLAGS_TO_RAX_CLO_R8 \
    addb $0x7f, %al;  \
    sahf; \
    movl %r10d, %eax;

/**
 * Restores the arighmetic flags *only* (clobbering some regs)
 */
#define RESTORE_FLAGS_CLOBBERING_R9_R10 \
    movl %eax, %r9d; \
    ARFLAGS_TO_RAX_CLO_R10 \
    addb $0x7f, %al;  \
    sahf; \
    movl %r9d, %eax;

#if 0
/* For debugging purposes this macro might be handy. */
#define CHECK_THAT_SAVED_FLAGS_EQUAL_EFLAGS \
        movl %eax, %r9d; \
        lahf; \
        seto %al; \
        #error "note: adjust when REGISTER_FOR_ARFLAGS is set"
        movabs_to_r8 {&tld->saved_arith_flags}; \
        movl (%r8), %r10d; \
        cmpw %r10w, %ax;  \
        je ok; \
        hlt;  \
        ok: \
        movw %ax, %r13w; \
        movw %ax, %r14w; \
        movl %r9d, %eax;
#endif

#endif

