/**
 * @file fbt_datatypes.h
 * Datatypes used in the BT
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-21 13:23:02 +0100 (sab, 21 gen 2012) $
 * $LastChangedDate: 2012-01-21 13:23:02 +0100 (sab, 21 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1201 $
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
#ifndef FBT_DATATYPES_H
#define FBT_DATATYPES_H

#include "fbt_config.h"

/* for uint_64 and the like */
#include <stdint.h>

typedef uint32_t guestptr_t;
typedef unsigned char uchar;

typedef uint64_t size_t;

typedef uchar BOOL;
enum{FALSE=0, TRUE=1};

/* forward declare these structs */
struct mem_info;
struct trampoline;
struct ia32_opcode;
struct dso_chain;
struct shared_data;

#include "fbt_mutex.h"

struct signal_call_runtime_data
{
  guestptr_t handler_to_call;
  void* saved_rip;
  void* saved_rsp;
};

/**
 * This struct is used when a new instruction is parsed and translated.
 * The struct gets updated through the disassembling function and the
 * information is then consumed by the action function (that handles the
 * opcode).
 */
struct translate {

  /** pointer to the instruction that is currently being translated */
  guestptr_t cur_instr;

  /** information about the current instruction (or NULL) */
  const struct ia32_opcode *cur_instr_info;

  /** pointer into the instruction to the first byte of the data/imm values */
  unsigned char *first_byte_after_opcode;

  /** number of prefixes for this instruction */
  unsigned char num_prefixes;

  /** operand sizes (dest, src, and aux) for this instruction */
  unsigned char dest_operand_size;
  unsigned char src_operand_size;
  unsigned char aux_operand_size;

  /** pointer to the next instruction (only valid after decoding) */
  guestptr_t next_instr;

  /** pointer back to tld (for action functions) */
  struct thread_local_data *tld;
};

#define MAX_NR_SIGNALS 64 /**< max number of signals */

struct fbt_sigaction_32bit {
  uint32_t sigaction;
  uint32_t flags;
  uint32_t restorer;
  uint32_t mask;
};

typedef signed int fbt_pid_t;
typedef unsigned int fbt_uid_t;

/**
 * Possible values for the system call authorization.
 */
enum syscall_auth_response {
  /** syscall authorization granted, execute syscall */
  SYSCALL_AUTH_GRANTED,
  /** syscall execution denied, return fake value */
  SYSCALL_AUTH_FAKE,
  /** syscall rejected */
  SYSCALL_AUTH_DENIED
} __attribute__((packed));


/**
 * This struct defines thread local data that is needed inside the BT.
 * These fields are set during the startup of the BT and then used whenever
 * a new block of code is translated.
 */
struct thread_local_data {
  /* nonzero if the current thread is in the 
     bt context (i.e. in translate_noexecute() and friends  */
  int32_t in_bt_context;

  /* information used for thread creation...
     see usage for details */
  guestptr_t thread_start_instr;
  guestptr_t thread_start_stack;

  /* state that is saved 
     when a watchpoint is hit and
     that can be used to resume execution */
  uint32_t wp_saved_pc;
  uint32_t wp_saved_eax;
  uint32_t wp_saved_ebx;
  uint32_t wp_saved_ecx;
  uint32_t wp_saved_edx;
  uint32_t wp_saved_esi;
  uint32_t wp_saved_edi;
  uint32_t wp_saved_ebp;
  uint32_t wp_saved_esp;
  uint32_t wp_saved_arflagsreg;
  uint64_t wp_saved_next_trans_instr;

  /* state to be preserved across
     thread creation */
  uint32_t thread_saved_eax;
  uint32_t thread_saved_ebx;
  uint32_t thread_saved_ecx;
  uint32_t thread_saved_edx;
  uint32_t thread_saved_esi;
  uint32_t thread_saved_edi;
  uint32_t thread_saved_ebp;
  uint32_t new_wanted_tls_base;

  /** mapping table between code cache and program */
  void *mappingtable;
  /** this pointer points to a target in the code cache. optimizations and
      stack guards use this variable to hide locations from the translated
      program. trampolines use this value as a branch target */
  void *ind_target;
  /** this trampoline dereferences ind_target and transfers the control flow to
     the specified code */
  void *ret2app_trampoline;
  /** trampolines set up the secure stack and the unmanaged_code_trampoline
      handles the translation and lookup of the code and transfer the control
      back to the newly translated code */
  void *unmanaged_code_trampoline;
  /** this trampoline points to a fast, thread-local version of the indirect
      jump optimization that looks up a given PC in the mapping table and
      transfers control to the translated fragment. */
  void *opt_ijump_trampoline;
  /** same as opt_ijump_trampoline but for indirect calls */
  void *opt_icall_trampoline;
  /** this trampoline is used for plain return instructions */
  void *opt_ret_trampoline;

  /** used by clone() to communicate locations of stacks */
  guestptr_t new_app_stack;

  /** this is a memory location where temporary values may be
      stored when there are not enough registers */
  uint32_t tmps[8];

  /** the table with pointers to syscall authorization handlers */
  enum syscall_auth_response (**syscall_table)(
      struct thread_local_data*,
      uint32_t, uint32_t, uint32_t,
      uint32_t, uint32_t, uint32_t,
      uint32_t, uint32_t, uint32_t*);

  /** location of the system call in the original program */
  guestptr_t syscall_location;

  /** Trampoline used as handler for signals that might be both user signals
      or internal signals (used by libdetox to communicate) */
  void *signal_trampoline;

  /** trampoline to handle sysenter instructions in a safe manner */
  void *sysenter_trampoline;
  /** trampoline to handle int80 instructions in a safe manner. This trampoline
     is only needed if we authorize system calls */
  void *int80_trampoline;

  /** Trampoline used when starting a new thread so we can execute code in
   * the libdetox context before starting thread execution */
  void *bootstrap_thread_trampoline;

  /** lightweight memory tracing tool */
  void *watchpoint_trampoline;

  /** safe stack for the BT */
  uint64_t *stack;
  /** all allocated memory */
  struct mem_info *chunk;
  /** pointer to memory that can be used through the fbt_smalloc allocator */
  void *smalloc;
  /** amount of memory left available at smalloc above */
  long smalloc_size;  

  /** Data that is shared between all threads */

  /** List of locations that should be translated 
      (and corresponding locations backpatched) before
      giving execution back to the translated program */
  int totranslate_stacktop;
  uint32_t totrans[256];
  void** topatch[256];

  /** Thread identifier as returned by gettid syscall */
  uint32_t tid;

  /** points to the current position in the code cache */
  uchar *transl_instr;
  /** points to the end of the code cache */
  uchar *code_cache_end;
  /** list of unused trampolines */
  struct trampoline *trampos;

  /** The eflags saving restoring code saves the 
      arithmetic condition codes here (really, only the
      arithmetic bits, not interrupt, direction or the like)! */
  uint64_t saved_arith_flags;

  /** data used by by signal trampoline to know what handler to call
      and where to return when the call is done */
  struct signal_call_runtime_data sigcall_data;
};

/**
 * Different types of origins for trampolines.
 * Depending on the origin type we use different backpatch locations and
 * backpatch techniques. For more information about the different origins and
 * their translations see translate_execute in fbt_trampoline.c
 */
enum origin_type {
  /** origin is somewhere on the applications stack, we must clear
      it when the data is translated */
  ORIGIN_CLEAR,
  /** use relative address */
  ORIGIN_RELATIVE,
  /** use an absolute address */
  ORIGIN_ABSOLUTE,
};

/**
 * An entry in the Mapping Table.
 * The layout of this must not be changed without changing the assembly too.
 */
struct ccache_entry {
  guestptr_t src;
  void* dst;
};


#define MAX_SHM_ENTRIES 10000
typedef struct shm_entry {
  uint32_t id;
  guestptr_t size;
} shm_entry;

/**
 * A trampoline as a placeholder of an untranslated code block.
 * These trampolines contain two locations (origin and target) and some code to
 * branch from the translated code into the binary translator.

 * The code cache contains a JMP to the trampoline, this JMP will be fixed after
 * the translation of the code block and will then directly point to the
 * translated code in the code cache.
 *
 * [ mov %esp, (tld->stack) ] <- pointer to trampoline
 * [ mov stack+4/8, %esp    ]
 * [ call trampo            ]
 * [ origin                 ]
 * [ target                 ]
 * The call to trampo then leaves the RIP on the stack with whom we can
 * construct a pointer to origin and target.
 */
struct trampoline {
  /** placeholder for code */
  uint32_t code[8];  // a bit less would suffice I think
  /** either a pointer to the next free trampoline (if used in the free list) or
      the tail of the code to jump into the BT */
  struct trampoline *next;
  /** origin in the code cache (to fix/backpatch the jump location) */
  unsigned char *origin;
  /** target in the untranslated code */
  guestptr_t target;
  /** type of origin */
  enum origin_type origin_t;
};

struct thread_entry;

/**
 * For now the limit of possible mmapped locations for a given process
 * is hardcoded.
 */
#define MAX_ADDRESS_SPACE_ENTRIES 10000

enum address_space_entry_type
{
  ASET_LMEMINTERNAL,
  ASET_FIXED,
  ASET_FREE
};

/**
 * Describes basically a mmap entry
 */
struct address_space_entry
{
  enum address_space_entry_type type;
  guestptr_t begin;
  uint32_t size;
  char* description;
};

/**
 * Completely describes what is allocated memory and what is not.
 */
struct address_space{
  struct address_space_entry entries[MAX_ADDRESS_SPACE_ENTRIES];
  int num_entries;
};

#define MAX_INTERNAL_MEMORY_ENTRIES 1024

struct internal_memory_entry
{
  uint64_t begin;
  uint64_t size;
};

struct internal_memory
{
  int num_entries;
  struct internal_memory_entry entries[MAX_INTERNAL_MEMORY_ENTRIES];  
};

/** 
 * Structure that contains all the data that is shared among all threads. It
 * is only alloated once and then passed on when a new thread is generated. 
 */
struct shared_data {

  /** just for enforce preconditions */
  int is_initialized;

  struct internal_memory intmem;

  /** Fake brk (used by fbt_syscall.c to implement a fake brk) */
  guestptr_t fake_brk_begin;
  guestptr_t fake_brk_current_brk;
  guestptr_t fake_brk_end;

  struct address_space address_space;


  /**
   * signal handling data
   */
  guestptr_t signal_stack_area;
  guestptr_t sighandler_wrapper32;

  /** specifies an array of handlers that take care of application signals. The
     pointers either point to an abort routine, to a trampoline or to a
     translated code region */
  struct fbt_sigaction_32bit signals[MAX_NR_SIGNALS];

  /** statistic */
  uint64_t total_internal_allocated_data;

  int num_shm_entries;
  struct shm_entry shmentries[MAX_SHM_ENTRIES];
};

/** Stores information about a list of threads. Each node should be allocated
 * in the thread local storage of the thread itself. */
struct thread_entry {
  /** Internal thread local data for this thread */
  struct thread_local_data *tld;
  /** Pointer to next thread in linked list or NULL if end of list */
  struct thread_entry *next;

  /** Can be used as temporary storage for thread-specific data */
  long user;  
};

struct user_desc_32
{
  unsigned int  entry_number;
  unsigned int  base_addr;
  unsigned int  limit;
  unsigned int  seg_32bit:1;
  unsigned int  contents:2;
  unsigned int  read_exec_only:1;
  unsigned int  limit_in_pages:1;
  unsigned int  seg_not_present:1;
  unsigned int  useable:1;
};

#endif  /* FBT_DATATYPES_H */
