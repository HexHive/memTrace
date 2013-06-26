/**
 * @file lmem.c
 * This module contains the main() function which is called
 * by a helper assembly routine.
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-22 21:05:54 +0100 (dom, 22 gen 2012) $
 * $LastChangedDate: 2012-01-22 21:05:54 +0100 (dom, 22 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1206 $
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

#include "fbt_translate.h"
#include "fbt_code_cache.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_mem_mgmt.h"
#include "fbt_syscall.h"
#include "fbt_disas.h"
#include "fbt_trampoline.h"
#include "fbt_x86_opcode.h"
#include "fbt_loader.h"
#include "fbt_address_space.h"
#include "fbt_signals.h"
#include "fbt_shared_data.h"

/* mmap constants */
#include <asm-generic/mman.h>

#define PATH_OF_LOADER "/lib32/ld-linux.so.2"

#define MAX_GUEST_ARGS 512

#define ARG_LEN_LIMIT 1024
#define ENV_LEN_LIMIT (1024*4)

/* forward declaration for the default opcode table */
extern struct ia32_opcode opcode_table_onebyte[];

struct user_desc_64 {
    unsigned int  entry_number;
    unsigned int  base_addr;
    unsigned int  limit;
    unsigned int  seg_32bit:1;
    unsigned int  contents:2;
    unsigned int  read_exec_only:1;
    unsigned int  limit_in_pages:1;
    unsigned int  seg_not_present:1;
    unsigned int  useable:1;
    unsigned int  lm:1; // only for 64 bit...
};

/**
 * Helper function needed to align the stack.
 */
static int round_up_by_four(int n)
{
  return 4*((n+3)/4);
}

/**
 * Creates a fresh thread local data. New threads
 * call this function.
 */
struct thread_local_data* fbt_init(BOOL lock) 
{
  struct thread_local_data *tld = fbt_init_tls(lock);
  fbt_initialize_trampolines(tld);
  fbt_init_syscalls(tld);
  return tld;
}


/*
 * Auxiliary vector entries for passing information to the interpreter.
 *
 * The i386 supplement to the SVR4 ABI specification names this "auxv_t",
 * but POSIX lays claim to all symbols ending with "_t".
 */

typedef struct {
	uint32_t type;
	uint32_t value;
} Elf32_Auxinfo;

typedef struct {
	uint64_t type;
	uint64_t value;
} Elf64_Auxinfo;

/* Values for a_type. */
#define AT_NULL		0	/* Terminates the vector. */
#define AT_IGNORE	1	/* Ignored entry. */
#define AT_EXECFD	2	/* File descriptor of program to load. */
#define AT_PHDR		3	/* Program header of program already loaded. */
#define AT_PHENT	4	/* Size of each program header entry. */
#define AT_PHNUM	5	/* Number of program header entries. */
#define AT_PAGESZ	6	/* Page size in bytes. */
#define AT_BASE		7	/* Interpreter's base address. */
#define AT_FLAGS	8	/* Flags (unused for i386). */
#define AT_ENTRY	9	/* Where interpreter should transfer control. */
#define AT_NOTELF	10	/* Program is not ELF ?? */
#define AT_UID		11	/* Real uid. */
#define AT_EUID		12	/* Effective uid. */
#define AT_GID		13	/* Real gid. */
#define AT_EGID		14	/* Effective gid. */
#define AT_PLATFORM     15
#define AT_HWCAP        16
#define AT_CLKTCK       17
#define AT_SECURE       23
#define AT_RANDOM       25
#define AT_EXECFN       31
#define AT_SYSINFO_EHDR 33

/**
 * This is where the execution really starts. The loader
 * is loaded with the right parameters. All subsystems are
 * initialized and the first basic block of the loader
 * is executed.
 */
int main(int argc, char** argv, char** envi)
{

  /* first thing!
     this ensures that lmem allocates at high addresses when
     using mmap (and doesn't rely on mmap(0,...) providing high addresses) */
  shared_data.intmem.num_entries = 0;
  shared_data.total_internal_allocated_data = 0;

  DEBUG_START();

  guestptr_t guest_args[MAX_GUEST_ARGS];
  guestptr_t env_vars[MAX_GUEST_ARGS];
  int num_env_vars = 0;

  if (argc < 2){
    llprintf("Program to run not specified\n");
    return 1;
  }
  if (argc >= MAX_GUEST_ARGS-1){
    llprintf("Too many args (arbitrary limit exceeded)!!\n");
    return 1;
  }

  PRINT_DEBUG("lMem started with: ");
  for (int i=0; i<argc; i++){
    PRINT_DEBUG("%s ", argv[i]);
  }
  PRINT_DEBUG("\n");

  {
    char cwdbuf[2048];
    fbt_syscall2(SYS64_getcwd, cwdbuf, sizeof(cwdbuf));
    PRINT_DEBUG("cwd is %s\n", cwdbuf);
  }

  // Create the thread local data for the thread
  struct thread_local_data *tld = fbt_init(TRUE);

  // Since it is the first thread, the shared data
  // must be initialized
  fbt_init_shared_data(tld);

  // Needs shared data
  fbt_signals_init();

  // load the static elf file into memory
  guestptr_t startaddr = lmem_load_loader(tld);

  // allocate the stack
#ifndef NDEBUG
  guestptr_t stk =
#endif
      do_guest_mmap(tld,
          STACK_BOTTOM,
          STACK_SIZE,
          PROT_READ|PROT_WRITE,
          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0,
          "stack");
  assert(stk != 0);
  guestptr_t stacktop = STACK_TOP;
  assert((uint32_t)stacktop == (uint64_t)stacktop);
  assert(((uint32_t)stacktop % 16) == 0);

  // put the strings that we need on the stack's memory
  // (may be somewhere else too, but it's convenient)
  stacktop -= round_up_by_four(fbt_strlen(PATH_OF_LOADER)+1);
  assert(fbt_strlen(PATH_OF_LOADER) < ARG_LEN_LIMIT-1)
  fbt_strncpy((char*)(uint64_t)stacktop, PATH_OF_LOADER, ARG_LEN_LIMIT);
  guest_args[0] = stacktop;

  char* sixteenrandombytes = "supercalifragili";
  stacktop -= round_up_by_four(fbt_strlen(sixteenrandombytes)+1);
  fbt_strncpy((char*)(uint64_t)stacktop, sixteenrandombytes, 256);
  guestptr_t at_rand = stacktop;

  for (int i=1; i<argc; i++){
    assert(fbt_strlen(argv[i]) < ARG_LEN_LIMIT-1);
    stacktop -= round_up_by_four(fbt_strlen(argv[i])+1);
    fbt_strncpy((char*)(uint64_t)stacktop, argv[i], ARG_LEN_LIMIT);
    guest_args[i] = stacktop;
  }

  num_env_vars = 0;
  while (*envi){
    stacktop -= round_up_by_four(fbt_strlen(*envi)+1);
    fbt_strncpy((char*)(uint64_t)stacktop, *envi, ENV_LEN_LIMIT);
    env_vars[num_env_vars] = stacktop;
    num_env_vars++;
    envi++;
  }

  envi++;
  Elf64_Auxinfo* aux = (Elf64_Auxinfo*)envi;
  
/**
   INFO: Meanings of the aux vector

Breakpoint 1, 0x0000002000010128 in _start ()
(gdb) info auxv
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7ffe000
16   AT_HWCAP             Machine-dependent CPU capability hints 0xbfebfbff
6    AT_PAGESZ            System page size               4096
17   AT_CLKTCK            Frequency of times()           100
3    AT_PHDR              Program headers for program    0x400040
4    AT_PHENT             Size of program header entry   56
5    AT_PHNUM             Number of program headers      6
7    AT_BASE              Base address of interpreter    0x0
8    AT_FLAGS             Flags                          0x0
9    AT_ENTRY             Entry point of program         0x2000010128
11   AT_UID               Real user ID                   1000
12   AT_EUID              Effective user ID              1000
13   AT_GID               Real group ID                  1000
14   AT_EGID              Effective group ID             1000
23   AT_SECURE            Boolean, was exec setuid-like? 0
25   AT_RANDOM            Address of 16 random bytes     0x7fffffffe5c9
31   AT_EXECFN            File name of executable        0x7fffffffefdc "/home/enkrav/lmem/lMem/lMem"
15   AT_PLATFORM          String identifying platform    0x7fffffffe5d9 "x86_64"
0    AT_NULL              End of vector                  0x0

 */

  /*
   * NOTE TO THE READER:
   *       The following code that puts args, env, and aux
   *       vector on the stack should probably be read
   *       from bottom to top.
   */

  /*  Some additional zeros don't hurt */
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;

  /* Empty auxiliary vector... */
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;


  /* copy only the auxiliary vector entries
     that make sense to copy. The order is 
     reversed for convenience of coding, but
     this is no problem, as they are key->value pairs*/
  while (aux->type){
    //llprintf("aux of type %d\n", aux->type);
    switch (aux->type){
    
    /* DO NOT PROVIDE */
    case AT_SYSINFO_EHDR: /* System-supplied DSO's ELF header */
    case AT_PLATFORM:     /* String identifying platform */ 
    case AT_HWCAP:        /* Machine-dependent CPU capability hints */ 
    case AT_PHDR:         /* Program headers for program */
    case AT_PHENT:        /* Size of program header entry */
    case AT_PHNUM:        /* Number of program headers */
    case AT_RANDOM:       /* Address of 16 random bytes */
      stacktop -= 4;
      *((guestptr_t*)(uint64_t)stacktop) = at_rand;
      stacktop -= 4;
      *((guestptr_t*)(uint64_t)stacktop) = AT_RANDOM;
      break;
    case AT_FLAGS:        /* Flags */
    case AT_ENTRY:        /* Entry point of program */
      break;

    /* ADAPT */
    case AT_BASE:         /* Base address of interpreter */
    case AT_EXECFN:       /* File name of executable */
      break;

    /* KEEP */
    case AT_PAGESZ:       /* System page size */
    case AT_CLKTCK:       /* Frequency of times() */
    case AT_UID:          /* Real user ID */
    case AT_EUID:         /* Effective user ID */
    case AT_GID:          /* Real group ID */
    case AT_EGID:         /* Effective group ID */
    case AT_SECURE:       /* Boolean, was exec setuid-like? */
      stacktop -= 4;
      *((guestptr_t*)(uint64_t)stacktop) = aux->value;
      stacktop -= 4;
      *((guestptr_t*)(uint64_t)stacktop) = aux->type;
      break;

    /* IGNORE UNKNOWN */
    default:
      break;
    }
    aux++;
  }

  /* Terminalting NULL of envvars list */
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;

  /* Pointers to envvars stings */
  for (int i=num_env_vars-1; i>=0; i--){
    stacktop -= 4;
    *((guestptr_t*)(uint64_t)stacktop) = env_vars[i];
  }

  /* Terminalting NULL of argument list */
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = 0;

  /* Pointers to argument stings */
  for (int i=argc-1; i>=0; i--){
    stacktop -= 4;
    *((guestptr_t*)(uint64_t)stacktop) = guest_args[i];
  }

  /* number of arguments */
  stacktop -= 4;
  *((guestptr_t*)(uint64_t)stacktop) = argc;

  /* translate the first basic block */
  char *transl_begin = fbt_translate_noexecute(tld, (guestptr_t)(uint64_t)startaddr, TRUE);

  /* we switch to application context */
  tld->in_bt_context = 0;

  /* start the execution of translated code */
  uint64_t xitcd;
  __asm__ __volatile__(
      "mov $0x100000000, %%r15;"
      "mov $0, %%r12;"
      "mov $0, %%r13;"
      "mov $0, %%r14;"
      "movl %%ecx, %%esp;"
      "jmp *%%rax;"
      : "=a" (xitcd)
      : "a"(transl_begin), "c"(stacktop));

  for (int i=0; i<xitcd; i++){
    fbt_syscall3q(SYS64_write, 0, (uint64_t)".", 4, "err in writ");
  }
  fbt_syscall3q(SYS64_write, 0, (uint64_t)"\nend\n", 4, "err in writ");
  fbt_syscall1q(SYS64_exit, 0, "err in xit");

  return 0;
}

