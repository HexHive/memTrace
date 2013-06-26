/**
 * @file fbt_syscall.c
 * Implementation of special system call handlers.
 *
 * Copyright (c) 2011 ETH Zurich
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 * @author Enrico Kravina <enrico.kravina@gmail.com>
 *
 * $Date: 2012-01-18 16:44:48 +0100 (mer, 18 gen 2012) $
 * $LastChangedDate: 2012-01-18 16:44:48 +0100 (mer, 18 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1189 $
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

#define _GNU_SOURCE

#include <asm-generic/mman-common.h>
#include <sys/mman.h>

#include <elf.h>
#include <asm-generic/mman-common.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "fbt_syscall.h"
#include "fbt_syscalls_64.h"
#include "fbt_syscall_numbers_32.h"
#include "fbt_code_cache.h"
#include "fbt_datatypes.h"
#include "fbt_debug.h"
#include "fbt_libc.h"
#include "fbt_llio.h"
#include "fbt_mem_mgmt.h"
#include "fbt_disas.h"
#include "fbt_address_space.h"
#include "fbt_translate.h"
#include "fbt_signals.h"
#include "fbt_shared_data.h"

#include "../lmempath.h"

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004


#define CSIGNAL         0x000000ff      /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000      /* Same thread group? */
#define CLONE_NEWNS     0x00020000      /* New namespace group? */
#define CLONE_SYSVSEM   0x00040000      /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS    0x00080000      /* create a new TLS for the child */
#define CLONE_PARENT_SETTID     0x00100000      /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID    0x00200000      /* clear the TID in the child */
#define CLONE_DETACHED          0x00400000      /* Unused, ignored */
#define CLONE_UNTRACED          0x00800000      /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID      0x01000000      /* set the TID in the child */
#define CLONE_STOPPED           0x02000000      /* Start in stopped state */
#define CLONE_NEWUTS            0x04000000      /* New utsname group? */
#define CLONE_NEWIPC            0x08000000      /* New ipcs */
#define CLONE_NEWUSER           0x10000000      /* New user namespace */
#define CLONE_NEWPID            0x20000000      /* New pid namespace */
#define CLONE_NEWNET            0x40000000      /* New network namespace */
#define CLONE_IO                0x80000000      /* Clone io context */

struct thread_local_data* fbt_init();

static char* syscall_names[1024];
static char* syscall_parstrings[1024];

#ifdef DEBUG
static void printuserdesc(struct user_desc_32* udp)
{
  PRINT_DEBUG_SYSCALL("  entry_number = %d\n", udp->entry_number);
  PRINT_DEBUG_SYSCALL("  base_addr = %x\n", udp->base_addr);
  PRINT_DEBUG_SYSCALL("  limit = %x\n", udp->limit);
  PRINT_DEBUG_SYSCALL("  seg_32bit = %d\n", (int)udp->seg_32bit);
  PRINT_DEBUG_SYSCALL("  contents = %d\n", (int)udp->contents);
  PRINT_DEBUG_SYSCALL("  read_exec_only = %d\n", (int)udp->read_exec_only);
  PRINT_DEBUG_SYSCALL("  limit_in_pages = %d\n", (int)udp->limit_in_pages);
  PRINT_DEBUG_SYSCALL("  seg_not_present = %d\n", (int)udp->seg_not_present);
  PRINT_DEBUG_SYSCALL("  useable = %d\n", (int)udp->useable);
}
#endif

/*
 * System call authorization functions must ensure a couple of things:
 * - First of all they may not change or write any of their arguments
 * - Second they must verify that the syscall_nr is correct (even if they assume
 *   that they are only called from one syscall number)
 *
 * These functions are called by asm-magic and include all possible
 * parameters. If you change any parameters then they will be propagated back
 * and the changed parameters will be used for the system call if it is allowed.
 */

static enum syscall_auth_response auth_signal(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2, uint32_t arg3,
    uint32_t arg4, uint32_t arg5,
    uint32_t arg6,
    uint32_t is_sysenter,
    uint32_t *retval)
{
  if (syscall_nr != SYS32_signal) {
    fbt_suicide_str("Unexpected syscall number (expected signal)"
        " (fbt_syscall.c).");
  }
  fbt_mutex_lock(&shared_data_mutex);

  PRINT_DEBUG_SYSCALL("SYSCALL: auth signal (%d)\n", (int)syscall_nr);

  fbt_suicide_str("'signal' not implemented");

  /* to implement it recall: guestptr_t oldfunction = shared_data.signals[arg1].sigaction; */
  shared_data.signals[arg1].mask = 0x0;
  shared_data.signals[arg1].flags = 0x0;
  shared_data.signals[arg1].restorer = 0x0;
  shared_data.signals[arg1].sigaction = arg2;
  if (arg2 == (uint32_t)(uint64_t)SIG_IGN || 
      arg2 == (uint32_t)(uint64_t)SIG_DFL) {
    fbt_suicide_str("sig ign/dfl not implemented");
  } else {
    fbt_suicide_str("remaining signals not implemented");
  }
  fbt_mutex_unlock(&shared_data_mutex);

  return SYSCALL_AUTH_FAKE;
}

/**
 * This function should emulate the sigaction system call.
 * Currently the signal implementation is not finished.
 */
static enum syscall_auth_response auth_sigaction(struct thread_local_data *tld,
    uint32_t syscall_nr, uint32_t arg1,
    uint32_t arg2, uint32_t arg3,
    uint32_t arg4, uint32_t arg5,
    uint32_t arg6,
    uint32_t is_sysenter,
    uint32_t *retval)
{
  if (syscall_nr != SYS32_sigaction && syscall_nr != SYS32_rt_sigaction) {
    fbt_suicide_str("Invalid system call number (expected (rt_)sigaction) (fbt_syscall.c).");
  }
  PRINT_DEBUG_SYSCALL("SYSCALL: sigaction(...)\n");
  fbt_mutex_lock(&shared_data_mutex);


  *retval = 0x0;

  /* store the _old_ target for this signal */
  if (arg3 != 0x0) {
    struct fbt_sigaction_32bit*
    sigaction = (struct fbt_sigaction_32bit*)(uint64_t)arg3;
    sigaction->sigaction = shared_data.signals[arg1].sigaction;
    sigaction->mask = shared_data.signals[arg1].mask;
    sigaction->flags = shared_data.signals[arg1].flags;
    sigaction->restorer = shared_data.signals[arg1].restorer;
  }
  /* interpret the _new_ sigaction struct */
  if (arg2 != 0x0) {
    struct fbt_sigaction_32bit*
    sigaction = (struct fbt_sigaction_32bit*)(uint64_t)arg2;

    shared_data.signals[arg1].mask = sigaction->mask;
    shared_data.signals[arg1].flags = sigaction->flags;
    shared_data.signals[arg1].restorer = sigaction->restorer;
    shared_data.signals[arg1].sigaction = sigaction->sigaction;

    //llprintf("trans app signal handler for %d added\n", arg1);

    PRINT_DEBUG_SYSCALL("Translated app installed signal handler for signal %d at %x\n",
                arg1, (int)sigaction->sigaction);

    /* Say that we were successful */
    *retval = 0;
  }
  fbt_mutex_unlock(&shared_data_mutex);
  return SYSCALL_AUTH_FAKE;
}

#define CLONE_PARENT_SETTID     0x00100000
#define CLONE_CHILD_CLEARTID    0x00200000
#define CLONE_CHILD_SETTID      0x01000000

int ekrclone64(int (*fun)(void*),
                void* childstack,
                int flags,
                void* parameter,
                void* parenttidptr,
                void* childtidptr,
                void* tlsptr);

int mythreadstarter(void* transbeg,
                       guestptr_t stack,
                       uint32_t* regs);

int mythread(void* param)
{
  struct thread_local_data* tld = param;

  void* transl_begin = fbt_translate_noexecute(tld, tld->thread_start_instr, TRUE);
  guestptr_t stacktop = tld->thread_start_stack;

  uint32_t t[8];
  t[0] = tld->thread_saved_eax;
  t[1] = tld->thread_saved_ebx;
  t[2] = tld->thread_saved_ecx;
  t[3] = tld->thread_saved_edx;
  t[4] = tld->thread_saved_esi;
  t[5] = tld->thread_saved_edi;
  t[6] = tld->thread_saved_ebp;

  PRINT_DEBUG_SYSCALL("mythread registers = %x %x %x %x %x %x %x\n", t[0],t[1],t[2],t[3],t[4],t[5],t[6]);

  if (tld->new_wanted_tls_base != 0xffffffff)
  {
    PRINT_DEBUG_SYSCALL("SETTING NEW BASE OF CHLD TO %x\n", tld->new_wanted_tls_base);
    fbt_syscall2(SYS64_arch_prctl, ARCH_SET_GS, tld->new_wanted_tls_base);
  }

  /* assembly routine */
  mythreadstarter(transl_begin, stacktop, &t[0]);

  return 0;
}

/**
 * The clone() to start a thread works.
 * The fork through clone case still needs a little work.
 */
static enum syscall_auth_response auth_clone(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t cloneflags,
    uint32_t clonestack,
    uint32_t parenttidptr,
    uint32_t tlsptr,
    uint32_t childtidptr,
    uint32_t arg6,
    uint32_t is_sysenter,
    uint32_t *retval)
{
  if (syscall_nr != SYS32_clone) {
    fbt_suicide_str("Invalid system call number in clone auth "
                    "(fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("SYSCALL: clone (flags = %x, stack = %x, parenttidptr = %x, tlsptr = %x, childtidptr = %x arg6=%x)\n",
              cloneflags, clonestack, parenttidptr, tlsptr, childtidptr, arg6);

  if (cloneflags & CLONE_VM) PRINT_DEBUG_SYSCALL("  CLONE_VM\n");
  if (cloneflags & CLONE_FS) PRINT_DEBUG_SYSCALL("  CLONE_FS\n");
  if (cloneflags & CLONE_FILES) PRINT_DEBUG_SYSCALL("  CLONE_FILES\n");
  if (cloneflags & CLONE_SIGHAND) PRINT_DEBUG_SYSCALL("  CLONE_SIGHAND\n");
  if (cloneflags & CLONE_PTRACE) PRINT_DEBUG_SYSCALL("  CLONE_PTRACE\n");
  if (cloneflags & CLONE_VFORK) PRINT_DEBUG_SYSCALL("  CLONE_VFORK\n");
  if (cloneflags & CLONE_PARENT) PRINT_DEBUG_SYSCALL("  CLONE_PARENT\n");
  if (cloneflags & CLONE_THREAD) PRINT_DEBUG_SYSCALL("  CLONE_THREAD\n");
  if (cloneflags & CLONE_NEWNS) PRINT_DEBUG_SYSCALL("  CLONE_NEWNS\n");
  if (cloneflags & CLONE_SYSVSEM) PRINT_DEBUG_SYSCALL("  CLONE_SYSVSEM\n");
  if (cloneflags & CLONE_SETTLS) PRINT_DEBUG_SYSCALL("  CLONE_SETTLS\n");
  if (cloneflags & CLONE_PARENT_SETTID) PRINT_DEBUG_SYSCALL("  CLONE_SETTID\n");
  if (cloneflags & CLONE_CHILD_CLEARTID) PRINT_DEBUG_SYSCALL("  CLONE_CHILD_CLEARTID\n");
  if (cloneflags & CLONE_DETACHED) PRINT_DEBUG_SYSCALL("  CLONE_DETACHED\n");
  if (cloneflags & CLONE_UNTRACED) PRINT_DEBUG_SYSCALL("  CLONE_UNTRACED\n");
  if (cloneflags & CLONE_CHILD_SETTID) PRINT_DEBUG_SYSCALL("  CLONE_CHILD_SETTID\n");
  if (cloneflags & CLONE_STOPPED) PRINT_DEBUG_SYSCALL("  CLONE_STOPPED\n");
  if (cloneflags & CLONE_NEWUTS) PRINT_DEBUG_SYSCALL("  CLONE_NEWUTS\n");
  if (cloneflags & CLONE_NEWIPC) PRINT_DEBUG_SYSCALL("  CLONE_NEWIPC\n");
  if (cloneflags & CLONE_NEWUSER) PRINT_DEBUG_SYSCALL("  CLONE_NEWUSER\n");
  if (cloneflags & CLONE_NEWPID) PRINT_DEBUG_SYSCALL("  CLONE_NEWPID\n");
  if (cloneflags & CLONE_NEWNET) PRINT_DEBUG_SYSCALL("  CLONE_NEWNET\n");

  if (cloneflags & CLONE_VM) {

    struct user_desc_32* udesc = (struct user_desc_32*)(uint64_t)tlsptr;

    /* jump over that int 0x80 or sysenter instruction (both are 2bytes long) */
    guestptr_t where_to_continue = tld->syscall_location+2;

    /* initialize new BT data structures for the new thread */
    struct thread_local_data *new_threads_tld = fbt_init();
    new_threads_tld->thread_start_instr = where_to_continue;
    new_threads_tld->thread_start_stack = clonestack;
    new_threads_tld->thread_saved_eax = tld->thread_saved_eax;
    new_threads_tld->thread_saved_ebx = tld->thread_saved_ebx;
    new_threads_tld->thread_saved_ecx = tld->thread_saved_ecx;
    new_threads_tld->thread_saved_edx = tld->thread_saved_edx;
    new_threads_tld->thread_saved_esi = tld->thread_saved_esi;
    new_threads_tld->thread_saved_edi = tld->thread_saved_edi;
    new_threads_tld->thread_saved_ebp = tld->thread_saved_ebp;

    if (cloneflags & CLONE_SETTLS){
      new_threads_tld->new_wanted_tls_base = udesc->base_addr;
    } else {
      new_threads_tld->new_wanted_tls_base = 0xffffffff;
    }

    PRINT_DEBUG_SYSCALL("New threads tld=%p\n", new_threads_tld);

    PRINT_DEBUG_SYSCALL("\n");
    PRINT_DEBUG64(mythread);
    PRINT_DEBUG64(new_threads_tld->stack);
    PRINT_DEBUG64(cloneflags);
    PRINT_DEBUG64(new_threads_tld);
    PRINT_DEBUG64(parenttidptr);
    PRINT_DEBUG64(childtidptr);
    PRINT_DEBUG64(tlsptr);
    PRINT_DEBUG_SYSCALL("\n");

#ifdef DEBUG
    if (cloneflags & CLONE_SETTLS){
      printuserdesc(udesc);
    }
#endif

    /* Note that we set up the thread local storage
       explicitly, hence we clear the CLONE_SETTLS bit */
    *retval = ekrclone64(mythread, 
                         new_threads_tld->stack, 
                         cloneflags&(~CLONE_SETTLS), 
                         new_threads_tld, 
                         (void*)(uint64_t)parenttidptr, 
                         (void*)(uint64_t)childtidptr, 
                         0);

    if (*retval == 0){
      fbt_suicide_str("impossible... the zero is executed by the function\n");
    }

    PRINT_DEBUG_SYSCALL("ekrclone64 returns %d\n", (int)*retval);

    PRINT_DEBUG_SYSCALL("Parent!\n");

    /* we are the parent thread, let's return the result from the clone syscall */
    PRINT_DEBUG_SYSCALL("New thread (pid: %d)\n", *retval);
    PRINT_DEBUG_SYSCALL("args = [%x, %x, %x, %x, %x]\n", 
                        cloneflags, 
                        clonestack, 
                        parenttidptr, 
                        tlsptr, 
                        childtidptr);

    return SYSCALL_AUTH_FAKE;
  } else {
    PRINT_DEBUG_SYSCALL("clone copies virtual memory\n");
    if (clonestack != 0){
      fbt_suicide_str("stack argument must be zero in fork by clone");
    }
    int r = fbt_syscall5(SYS64_clone,
                         cloneflags,
                         clonestack,
                         parenttidptr,
                         childtidptr,
                         tlsptr);
    *retval = r;
    return SYSCALL_AUTH_FAKE;
  }

  fbt_suicide_str("impoooosiibiooooooll!!!\n");
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response auth_set_thread_area(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter
    __attribute__((unused)),
    uint32_t *retval
    __attribute__((unused)))
{
  if (syscall_nr != SYS32_set_thread_area) {
    fbt_suicide_str("Invalid system call number in set_thread_area auth (fbt_syscall.c).");
  }
  PRINT_DEBUG_SYSCALL("SYSCALL: set_thread_area(...)\n");

  struct user_desc_32* udp = (struct user_desc_32*)(uint64_t)arg1;
#ifdef DEBUG
  printuserdesc(udp);
#endif

  fbt_syscall2(SYS64_arch_prctl, ARCH_SET_GS, udp->base_addr);

  unsigned thegs;
  __asm__("xor %0,%0; movw %%gs, %w0": "=r"(thegs));
  unsigned sele = (thegs>>3);
  udp->entry_number = sele;
  *retval = 0;
  PRINT_DEBUG_SYSCALL("FAKE SET_THREAD_AREA SET GS TO %d AND SELECTOR TO %d\n", thegs, sele);

  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response auth_rt_sigprocmask(
    struct thread_local_data *tld,
    uint32_t syscall_nr, uint32_t arg1,
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter
    __attribute__((unused)),
    uint32_t *retval
    __attribute__((unused)))
{
  if (syscall_nr != SYS32_rt_sigprocmask){
    fbt_suicide_str("Invalid system call number in exit auth (fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("auth rt_sigprocmask doing nothin'\n");

  *retval = 0;
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response auth_exit(struct thread_local_data *tld,
    uint32_t syscall_nr, uint32_t arg1,
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter
    __attribute__((unused)),
    uint32_t *retval
    __attribute__((unused)))
{
  if ((syscall_nr != SYS32_exit) && (syscall_nr != SYS32_exit_group)) {
    fbt_suicide_str("Invalid system call number in exit auth (fbt_syscall.c).");
  }
  if (syscall_nr == SYS32_exit){
    PRINT_DEBUG_SYSCALL("SYSCALL: exit(...)\n");
  } else if (syscall_nr == SYS32_exit_group){
    PRINT_DEBUG_SYSCALL("SYSCALL: exit_group(...)\n");
  } else {
    fbt_suicide_str("lmem: impossibol in xit\n");
  }

  uint32_t dbgtid;
  dbgtid = fbt_syscall(SYS64_gettid);

  //llprintf("on exit: total alloc internal data: ");
  //print64(2, shared_data.total_internal_allocated_data);
  //llprintf("\n");


  /* we are shutting down this thread -> clean up BT */
  PRINT_DEBUG_SYSCALL(
      "thread/process exit (%p, retval: %d) %s\n",
      tld,
      arg1,
      (syscall_nr == SYS32_exit ? "exit" : "exit_group"));

#ifdef DEBUG
  write_ps_address_space();
#endif

  //llprintf("freeing tld\n");
  fbt_mem_free(tld, TRUE);
  //llprintf("done freeing tld\n");

  //llprintf("now, total alloc internal data: ");
  //print64(2, shared_data.total_internal_allocated_data);
  //llprintf("\n");

  /* an improvement might be to make a routine in assembly that frees the
     bt stack and calls the right exit function in one go. */
  if (syscall_nr == SYS32_exit){
    //llprintf("SYSCALL: exit(...)\n");
    fbt_syscall1(SYS64_exit, arg1);
  } else if (syscall_nr == SYS32_exit_group){
    //llprintf("SYSCALL: exit_group(...)\n");
    fbt_syscall1(SYS64_exit_group, arg1);
  } else {
    fbt_suicide_str("lmem: impossibol in xit\n");
  }

  /* fbt_exit unmaps all memory except the last and final pages for the tld.
     we need this storage because we are currently running on this stack.
     So we need a careful trick to get rid of that last memory. We therefore
     call munmap directly in an assembler sequence. After the munmap call the
     stack is no longer valid, so we need to keep all data that we need after
     that syscall in registers. */
  /* this system call will never return, so don't bother about a clean stack */
  if (syscall_nr == SYS32_exit) {
    __asm__ __volatile__("movl %0, %%eax\n"
        "movl %1, %%esi\n"
        "movl %2, %%edi\n"
        "syscall\n"
        "movl %3, %%eax\n"
        "movl %4, %%edi\n"
        "syscall\n"
        "hlt\n"
        : /* no return value */
        : "i"(SYS64_munmap), "m"(tld->chunk->ptr),
          "m"(tld->chunk->size), "i"(SYS64_exit), "r"(arg1)
          : "memory", "rdi", "rsi", "rax");
  } else {
    __asm__ __volatile__("movl %0, %%eax\n"
        "movl %1, %%edi\n"
        "movl %2, %%esi\n"
        "syscall\n"
        "movl %3, %%eax\n"
        "movl %4, %%edi\n"
        "syscall\n"
        "hlt\n"
        : /* no return value */
        : "i"(SYS64_munmap), "m"(tld->chunk->ptr),
          "m"(tld->chunk->size), "i"(SYS64_exit_group), "r"(arg1)
          : "memory", "rdi", "rsi", "rax");
  }


  fbt_suicide_str("Failed to exit thread/process (fbt_syscall.c)\n");
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
deny_syscall(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr, uint32_t arg1, uint32_t arg2, uint32_t arg3,
    uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t is_sysenter,
    uint32_t *retval)
{
  if (is_sysenter) {
    PRINT_DEBUG_SYSCALL("Syscall: %d (arguments: 0x%x 0x%x 0x%x 0x%x 0x%x, ebp: %p, from "
        "sysenter)\n", syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
  } else {
    PRINT_DEBUG_SYSCALL("Syscall: %d (arguments: 0x%x 0x%x 0x%x 0x%x 0x%x, ebp: %p, from "
        "int)\n", syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
  }
  PRINT_DEBUG_SYSCALL("denied %d\n", syscall_nr);
  fllprintf(2, "lMem denied syscall %d\n", syscall_nr);
  fbt_suicide_str("This system call is illegal!!!!: (fbt_syscall.c).\n");
  while(1){/* attach debugger... */}
  *retval = -1;
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
allow_syscall(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr __attribute__((unused)),
    uint32_t arg1 __attribute__((unused)),
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
#ifdef DEBUG
  if (syscall_nr == SYS32_close){
    if (arg1 == debugStream){
      PRINT_DEBUG_SYSCALL("not closing debug stream!\n"); 
      return SYSCALL_AUTH_FAKE;
    }
  }
#endif


  if (syscall_nr == 195 || syscall_nr == 196 || syscall_nr==197){
    PRINT_DEBUG_SYSCALL("SYSCALL: (L)STAT64 sysnr=%d (%x, %x)\n",
        (int)syscall_nr,  (int)arg1, (int)arg2);
    if (syscall_nr == 195 || syscall_nr == 196){
      PRINT_DEBUG_SYSCALL("  arg1=%s\n", (int)arg1);
    }
  } else {
    PRINT_DEBUG_SYSCALL("SYSCALL: %s ", syscall_names[syscall_nr], syscall_nr);
    PRINT_DEBUG_SYSCALL(syscall_parstrings[syscall_nr], arg1, arg2, arg3, arg4, arg5, arg6);
  }

  *retval = _fbt_traditional_32bit_syscall(
      arg1, arg2, arg3, arg4, arg5, arg6, syscall_nr);
  PRINT_DEBUG_SYSCALL("...... %s returned %d\n", syscall_names[syscall_nr], *retval);
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
auth_still_to_implement(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr __attribute__((unused)),
    uint32_t arg1 __attribute__((unused)),
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  PRINT_DEBUG_SYSCALL("SYSCALL: %s ", syscall_names[syscall_nr], syscall_nr);
  PRINT_DEBUG_SYSCALL(syscall_parstrings[syscall_nr], arg1, arg2, arg3, arg4, arg5, arg6);
  fllprintf(2, "syscall %s still to implement\n", syscall_names[syscall_nr]);
  fbt_suicide_str("exiting due to syscall not impl yet by lmem\n");
  return SYSCALL_AUTH_FAKE;
}


static enum syscall_auth_response
auth_old_mmap(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t unused2 __attribute__((unused)),
    uint32_t unused3 __attribute__((unused)),
    uint32_t unused4 __attribute__((unused)),
    uint32_t unused5 __attribute__((unused)),
    uint32_t unused6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_old_mmap) {
    fbt_suicide_str("Invalid system call number in mmap (fbt_syscall.c).");
  }

  uint32_t* arg1_as_ptr = (uint32_t*)(uint64_t)arg1;

  uint32_t a1 = arg1_as_ptr[0];
  uint32_t a2 = arg1_as_ptr[1];
  uint32_t a3 = arg1_as_ptr[2];
  uint32_t a4 = arg1_as_ptr[3];
  int32_t a5 = ((int32_t*)arg1_as_ptr)[4];
  uint32_t a6 = arg1_as_ptr[5];

  PRINT_DEBUG_SYSCALL("SYSCALL: old_mmap(%x, %d, %d, %d, %d, %d)\n",
              a1, a2, a3, a4, a5, a6);

  *retval = do_guest_mmap(tld, a1, a2, a3, a4, a5, a6, "oldmmap");

  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
auth_execve(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2,
    uint32_t arg3,
    uint32_t arg4,
    uint32_t arg5,
    uint32_t arg6,
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_execve) {
    fbt_suicide_str("Invalid system call number in execve (fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("SYSCALL: execve(%s, %x, %x, %x, %x)\n", (char*)arg1, arg2, arg3, arg4, arg5);

  char* newargs[500];
  newargs[0] = LMEMPATH "/lMem." CONFIG_NAME;
  newargs[1] = (char*)(uint64_t)arg1;        /* room for improvement: the program name and 
                                                first argument do not necessarily coincide! */
  int numnewargs = 2;
  guestptr_t* it = (guestptr_t*)(uint64_t)arg2;
  if (*it) it++;                        /* skip one... not fully clean ... see comment above */
  while (*it){
    newargs[numnewargs] = (char*)(uint64_t)(*it);
    numnewargs++;
    it++;
  }
  newargs[numnewargs] = 0;

  char* newenv[500];
  int numnewenv = 0;
  it = (guestptr_t*)(uint64_t)arg3;
  while (*it){
    newenv[numnewenv] = (char*)(uint64_t)(*it);
    numnewenv++;
    it++;
  }
  newenv[numnewenv] = 0;

  /* Here we would need to check if newargs[0] is a valid executable!
     for now we are happy if the file exists */
  struct stat file_info;
  int64_t rr = fbt_syscall2(SYS64_stat, (uint64_t)newargs[1], (uint64_t)&file_info);

  PRINT_DEBUG_SYSCALL("...... execve fakely returned %d\n", rr);

  if (valid_result(rr)) {
    fbt_syscall3(SYS64_execve, (uint64_t)newargs[0], (uint64_t)newargs, (uint64_t)newenv);
    llprintf("could not exec '%s'", newargs[0]);
    fbt_suicide_str("lmem: execve failed... should never be reached");
    return SYSCALL_AUTH_FAKE; /* shut up gcc */
  } else {
    *retval = rr; /* possible improvement: this error should not be hardcoded */
    return SYSCALL_AUTH_FAKE;
  }
}

static enum syscall_auth_response
auth_mmap2(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2,
    uint32_t arg3,
    uint32_t arg4,
    uint32_t arg5,
    uint32_t arg6,
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_mmap2) {
    fbt_suicide_str("Invalid system call number in mmap (fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("SYSCALL: mmap2(%x, %d, %d, %d, %d, %d)\n",
              arg1, arg2, arg3, arg4, arg5, arg6);

  // convert to signed...
  union {
    uint32_t l;
    int32_t li;
  } h;
  h.l = arg5;
  int64_t a5 = h.li;

  *retval = do_guest_mmap(tld, arg1, arg2, arg3, arg4, a5, arg6*4096, "mmap");

  PRINT_DEBUG_SYSCALL("SYSCALL: mmap2 returning %x\n", (uint32_t)(*retval));

  return SYSCALL_AUTH_FAKE;
}


static enum syscall_auth_response
auth_ipc(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t callnr,
    uint32_t first,
    uint32_t second,
    uint32_t third,
    uint32_t pointer,
    uint32_t fifth,
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_ipc) {
    fbt_suicide_str("Invalid system call number in mmap (fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("SYSCALL: ipc(%x, %d, %d, %d, %d, %d)\n",
                      callnr, first, second, third, pointer, fifth);


  const int shmat = 21;   // first<-ipc_private, second<-length, third<-ipc_creat
  const int shmgetnr = 23;
  const int shmctl = 24;

  if (callnr == shmat){
    PRINT_DEBUG_SYSCALL("SYS: shmat()\n");

    int size = 0x100000; // default
    int found = 0;
    fbt_mutex_lock(&shared_data_mutex);
      for (int k=0; k<shared_data.shmentries; k++){
        shm_entry e = shared_data.shmentries[k];
        if (e.id == first){
          size = e.size;
          found = 1;
          break; 
        } 
      }
    fbt_mutex_unlock(&shared_data_mutex);

    if (found == 0){
      PRINT_DEBUG_SYSCALL("fffuuu\n");
      fbt_suicide_str("fffuuu\n");
    }

    guestptr_t where = reserve_address_chunk(tld, 0, size);
    PRINT_DEBUG_SYSCALL("SYS: where = %x\n", where);
    // Tell *explicitly* where to put it
    int res = _fbt_traditional_32bit_syscall(
      callnr, first, second, third, where, fifth, SYS32_ipc);
    // here we should check for error
    *retval = where;
    PRINT_DEBUG_SYSCALL("SYS: shmat returning 0x%x\n", *retval);
    return SYSCALL_AUTH_FAKE;
  } else if (callnr == shmgetnr) {
    PRINT_DEBUG_SYSCALL("SYS: shmget()\n");
    *retval = _fbt_traditional_32bit_syscall(
      callnr, first, second, third, pointer, fifth, SYS32_ipc);
    fbt_mutex_lock(&shared_data_mutex);
      if (shared_data.num_shm_entries >= MAX_SHM_ENTRIES){
        PRINT_DEBUG_SYSCALL("SYS: terminating due to exhaustion of shared memory entries");
        fbt_suicide_str("SYS: terminating due to exhaustion of shared memory entries");
      }
      shm_entry entry;
      entry.id = *retval;
      entry.size = second;
      shared_data.shmentries[shared_data.num_shm_entries++] = entry;
    fbt_mutex_unlock(&shared_data_mutex);
    PRINT_DEBUG_SYSCALL("SYS: ...returning 0x%x\n", *retval);
    return SYSCALL_AUTH_FAKE;
  } else if (callnr == shmctl) {
    // These don't need special treatement
    PRINT_DEBUG_SYSCALL("SYS: shmctl()\n");
    *retval = _fbt_traditional_32bit_syscall(
      callnr, first, second, third, pointer, fifth, SYS32_ipc);
    PRINT_DEBUG_SYSCALL("SYS: ...returning 0x%x\n", *retval);
    return SYSCALL_AUTH_FAKE;
  } else {
    // Those we don't support yet
    PRINT_DEBUG_SYSCALL("SYS: unknown ipc call %d\n", callnr);
    fbt_suicide_str("SYS: unknown ipc call\n");
  }
}



/**
 * The signal implementation is not done yet. We would
 * have to implement this function properly.
 */
static enum syscall_auth_response
auth_tgkill(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1 __attribute__((unused)),
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  PRINT_DEBUG_SYSCALL("SYSCALL: tgkill(...)\n");

  uint32_t dbgtid;
  dbgtid = fbt_syscall(SYS64_gettid);
  llprintf("lmem: auth tgkill from tid %d\n", dbgtid);
  //fbt_suicide_str("Signal support not finished yet.\n");

  //*retval = 0;
  return SYSCALL_AUTH_GRANTED;
}


static enum syscall_auth_response
auth_munmap(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2,
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_munmap) {
    fbt_suicide_str("Invalid system call number in munmap (fbt_syscall.c).");
  }
  PRINT_DEBUG_SYSCALL("SYSCALL: munmap(%x, %x)\n", (int)arg1, (int)arg2);
  *retval = do_guest_munmap(tld, arg1, arg2);
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
auth_mremap(struct thread_local_data *tld __attribute__((unused)),
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2,
    uint32_t arg3,
    uint32_t arg4,
    uint32_t arg5,
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_mremap) {
    fbt_suicide_str("Invalid system call number in mremap (fbt_syscall.c).");
  }

  PRINT_DEBUG_SYSCALL("SYSCALL: mremap(old addr = %x, old size = %d, new size = %d, flags = %d)\n",
      (int)arg1,
      (int)arg2,
      (int)arg3,
      (int)arg4);
  *retval = do_guest_mremap(tld, arg1, arg2, arg3, arg4, arg5);

  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
auth_brk(struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1,
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval)
{
  if (syscall_nr != SYS32_brk) {
    fbt_suicide_str("Invalid system call number in brk (fbt_syscall.c).");
  }
  fbt_mutex_lock(&shared_data_mutex);
  PRINT_DEBUG_SYSCALL("SYSCALL: brk(%x) (begin is %x)\n", arg1, shared_data.fake_brk_begin);
  if (arg1 == 0){
    *retval = shared_data.fake_brk_current_brk;
  } else {
    if (arg1 < shared_data.fake_brk_begin){
      fbt_suicide_str("want to set brk too low!!!");
    }
    if (arg1 > shared_data.fake_brk_end){
      fbt_suicide_str("brk space exhausted!!!");
    }
    uint32_t i;
    for (i=shared_data.fake_brk_current_brk; i<arg1; i++){
      *((char*)(uint64_t)(i)) = 0;
    }
    shared_data.fake_brk_current_brk = arg1;
    *retval = shared_data.fake_brk_current_brk;
  }
  fbt_mutex_unlock(&shared_data_mutex);
  return SYSCALL_AUTH_FAKE;
}

static enum syscall_auth_response
auth_mprotect(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1 __attribute__((unused)),
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  if (syscall_nr != SYS32_mprotect) {
    fbt_suicide_str("Invalid system call number in mprotect (fbt_syscall.c).");    
  }
  PRINT_DEBUG_SYSCALL("SYSCALL: mprotect()\n");
  return SYSCALL_AUTH_GRANTED;
}

static enum syscall_auth_response
auth_write(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t fd,
    uint32_t buf,
    uint32_t cnt,
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  if (syscall_nr != SYS32_write) {
    fbt_suicide_str("Invalid system call number in open (fbt_syscall.c).");
  }
  uchar* bf = (uchar*)(uint64_t)buf;
  BOOL isstring = TRUE;
  for (int i=0; i<cnt; i++){
    uchar c = bf[i];
    if (c < 32){
      isstring = FALSE;
      break;
    }
  }
  if (isstring){
    PRINT_DEBUG_SYSCALL("SYSCALL: write(fd=%d, dataptr=%x, count=%d)\n", fd, buf, cnt);
  } else {
    PRINT_DEBUG_SYSCALL("SYSCALL: write(fd=%d, string=%s, count=%d)\n", fd, buf, cnt);
  }

  *retval = _fbt_traditional_32bit_syscall(
      fd, buf, cnt, arg4, arg5, arg6, syscall_nr);
  PRINT_DEBUG_SYSCALL("...... %s returned %d\n", syscall_names[syscall_nr], *retval);
  return SYSCALL_AUTH_FAKE;
  //return SYSCALL_AUTH_GRANTED;
}

static enum syscall_auth_response
auth_read(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t fd,
    uint32_t buf,
    uint32_t cnt,
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  if (syscall_nr != SYS32_read) {
    fbt_suicide_str("Invalid system call number in open (fbt_syscall.c).");
  }
  PRINT_DEBUG_SYSCALL("SYSCALL: read(fd=%d, buffer=%x, count='%d')\n", fd, buf, cnt);
  return SYSCALL_AUTH_GRANTED;
}

#ifdef LMEM_WATCHPOINT_SYSCALL_NR
enum syscall_auth_response lmem_watchpoint_syscall(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t set_or_unset,
    uint32_t orig_address,
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  if (syscall_nr != LMEM_WATCHPOINT_SYSCALL_NR) {
    fbt_suicide_str("fbt_sdbg.c: wrong syscall number in "
                    "lmem_watchpoint_syscall\n");
  }
  char* shadow_addr = ((char*)(uint64_t)orig_address) + LMEM_SHIFT_OFFSET;
  if (set_or_unset == 0) {
    PRINT_DEBUG_SYSCALL("Protecting memory at %x!\n",  orig_address);
    *shadow_addr=1;
  } else if (set_or_unset == 1) {
    PRINT_DEBUG_SYSCALL("Unprotecting memory at %x!\n", orig_address);
    *shadow_addr=0;
  } else {
    fbt_suicide_str("fbt_sdbg.c: invalid first parameter in lmem_syscall\n");
  }
  return SYSCALL_AUTH_FAKE;
}
#endif

#ifdef LMEM_SPECIAL_SIGRET_SYSCALL_NR

void sigreturner(void** wheresavedstack,
                   void** wheresavedip);

enum syscall_auth_response lmem_special_sigret_syscall(
    struct thread_local_data *tld,
    uint32_t syscall_nr,
    uint32_t arg1 __attribute__((unused)),
    uint32_t arg2 __attribute__((unused)),
    uint32_t arg3 __attribute__((unused)),
    uint32_t arg4 __attribute__((unused)),
    uint32_t arg5 __attribute__((unused)),
    uint32_t arg6 __attribute__((unused)),
    uint32_t is_sysenter __attribute__((unused)),
    uint32_t *retval __attribute__((unused)))
{
  if (syscall_nr != LMEM_SPECIAL_SIGRET_SYSCALL_NR) {
    fbt_suicide_str("fbt_sdbg.c: wrong syscall number in "
        "lmem_return_from_syscall\n");
  }
  sigreturner(&tld->sigcall_data.saved_rsp,
              &tld->sigcall_data.saved_rip);
  fbt_suicide_str("should never be reached");
  return SYSCALL_AUTH_FAKE;
}
#endif

static void init_names();
static void init_parstrings();

void fbt_init_syscalls(struct thread_local_data *tld)
{
  uint32_t i;

  /* most syscalls are allowed */
  for (i = 0; i <= I386_NR_SYSCALLS_32; ++i) {
    tld->syscall_table[i] = &allow_syscall;
  }

  /* these do net even exist*/
  for (; i < MAX_SYSCALLS_TABLE; ++i) {
    tld->syscall_table[i] = &deny_syscall;
  }

  /* deny a couple of system calls */
  tld->syscall_table[SYS32_ptrace] = &deny_syscall;
  tld->syscall_table[SYS32_sigreturn] = &deny_syscall;
  tld->syscall_table[SYS32_rt_sigreturn] = &deny_syscall;
  tld->syscall_table[SYS32_unused1] = &deny_syscall;
  tld->syscall_table[SYS32_unused2] = &deny_syscall;
  tld->syscall_table[SYS32_unused3] = &deny_syscall;
  tld->syscall_table[SYS32_sys_setaltroot] = &deny_syscall;

  /* special handling for special system calls */
  tld->syscall_table[SYS32_execve] = &auth_execve;
  tld->syscall_table[SYS32_old_mmap] = &auth_old_mmap;
  tld->syscall_table[SYS32_mmap2] = &auth_mmap2;
  tld->syscall_table[SYS32_munmap] = &auth_munmap;
  tld->syscall_table[SYS32_mremap] = &auth_mremap;
  tld->syscall_table[SYS32_mprotect] = &auth_mprotect;
  tld->syscall_table[SYS32_brk] = &auth_brk;

  tld->syscall_table[SYS32_tgkill] = &auth_tgkill;

  /* redirect system calls that change the system call handlers to our
     validation functions */
  tld->syscall_table[SYS32_signal] = &auth_signal;
  tld->syscall_table[SYS32_sigaction] = &auth_sigaction;
  tld->syscall_table[SYS32_rt_sigaction] = &auth_sigaction;

  /* used to change the signal mask of the current
     thread (of the translated application). Emulated
     since we need to do our custom signal blocking. */
  tld->syscall_table[SYS32_rt_sigprocmask] = &auth_rt_sigprocmask;

  tld->syscall_table[SYS32_sigprocmask] = &auth_still_to_implement;
  tld->syscall_table[SYS32_sigsuspend] = &auth_still_to_implement;
  tld->syscall_table[SYS32_sigpending] = &auth_still_to_implement;

  tld->syscall_table[SYS32_clone] = &auth_clone;
  tld->syscall_table[SYS32_exit] = &auth_exit;
  tld->syscall_table[SYS32_exit_group] = &auth_exit;

  tld->syscall_table[SYS32_fork] = &deny_syscall;

  tld->syscall_table[SYS32_set_thread_area] = &auth_set_thread_area;

  tld->syscall_table[SYS32_read] = &auth_read;
  tld->syscall_table[SYS32_write] = &auth_write;

  tld->syscall_table[SYS32_ipc] = &auth_ipc;

#ifdef LMEM_WATCHPOINT_SYSCALL_NR
  tld->syscall_table[LMEM_WATCHPOINT_SYSCALL_NR] = &lmem_watchpoint_syscall;
#endif
#ifdef LMEM_SPECIAL_SIGRET_SYSCALL_NR
  tld->syscall_table[LMEM_SPECIAL_SIGRET_SYSCALL_NR] = &lmem_special_sigret_syscall;
#endif

  init_names();
  init_parstrings();
}

void init_names()
{
  syscall_names[SYS32_restart_syscall]="restart_syscall";
  syscall_names[SYS32_exit]="exit";
  syscall_names[SYS32_fork]="fork";
  syscall_names[SYS32_read]="read";
  syscall_names[SYS32_write]="write";
  syscall_names[SYS32_open]="open";
  syscall_names[SYS32_close]="close";
  syscall_names[SYS32_waitpid]="waitpid";
  syscall_names[SYS32_creat]="creat";
  syscall_names[SYS32_link]="link";
  syscall_names[SYS32_unlink]="unlink";
  syscall_names[SYS32_execve]="execve";
  syscall_names[SYS32_chdir]="chdir";
  syscall_names[SYS32_time]="time";
  syscall_names[SYS32_mknod]="mknod";
  syscall_names[SYS32_chmod]="chmod";
  syscall_names[SYS32_lchown]="lchown";
  syscall_names[SYS32_break]="break";
  syscall_names[SYS32_oldstat]="oldstat";
  syscall_names[SYS32_lseek]="lseek";
  syscall_names[SYS32_getpid]="getpid";
  syscall_names[SYS32_mount]="mount";
  syscall_names[SYS32_umount]="umount";
  syscall_names[SYS32_setuid]="setuid";
  syscall_names[SYS32_getuid]="getuid";
  syscall_names[SYS32_stime]="stime";
  syscall_names[SYS32_ptrace]="ptrace";
  syscall_names[SYS32_alarm]="alarm";
  syscall_names[SYS32_oldfstat]="oldfstat";
  syscall_names[SYS32_pause]="pause";
  syscall_names[SYS32_utime]="utime";
  syscall_names[SYS32_stty]="stty";
  syscall_names[SYS32_gtty]="gtty";
  syscall_names[SYS32_access]="access";
  syscall_names[SYS32_nice]="nice";
  syscall_names[SYS32_ftime]="ftime";
  syscall_names[SYS32_sync]="sync";
  syscall_names[SYS32_kill]="kill";
  syscall_names[SYS32_rename]="rename";
  syscall_names[SYS32_mkdir]="mkdir";
  syscall_names[SYS32_rmdir]="rmdir";
  syscall_names[SYS32_dup]="dup";
  syscall_names[SYS32_pipe]="pipe";
  syscall_names[SYS32_times]="times";
  syscall_names[SYS32_prof]="prof";
  syscall_names[SYS32_brk]="brk";
  syscall_names[SYS32_setgid]="setgid";
  syscall_names[SYS32_getgid]="getgid";
  syscall_names[SYS32_signal]="signal";
  syscall_names[SYS32_geteuid]="geteuid";
  syscall_names[SYS32_getegid]="getegid";
  syscall_names[SYS32_acct]="acct";
  syscall_names[SYS32_umount2]="umount2";
  syscall_names[SYS32_lock]="lock";
  syscall_names[SYS32_ioctl]="ioctl";
  syscall_names[SYS32_fcntl]="fcntl";
  syscall_names[SYS32_mpx]="mpx";
  syscall_names[SYS32_setpgid]="setpgid";
  syscall_names[SYS32_ulimit]="ulimit";
  syscall_names[SYS32_oldolduname]="oldolduname";
  syscall_names[SYS32_umask]="umask";
  syscall_names[SYS32_chroot]="chroot";
  syscall_names[SYS32_ustat]="ustat";
  syscall_names[SYS32_dup2]="dup2";
  syscall_names[SYS32_getppid]="getppid";
  syscall_names[SYS32_getpgrp]="getpgrp";
  syscall_names[SYS32_setsid]="setsid";
  syscall_names[SYS32_sigaction]="sigaction";
  syscall_names[SYS32_sgetmask]="sgetmask";
  syscall_names[SYS32_ssetmask]="ssetmask";
  syscall_names[SYS32_setreuid]="setreuid";
  syscall_names[SYS32_setregid]="setregid";
  syscall_names[SYS32_sigsuspend]="sigsuspend";
  syscall_names[SYS32_sigpending]="sigpending";
  syscall_names[SYS32_sethostname]="sethostname";
  syscall_names[SYS32_setrlimit]="setrlimit";
  syscall_names[SYS32_getrlimit]="getrlimit";
  syscall_names[SYS32_getrusage]="getrusage";
  syscall_names[SYS32_gettimeofday]="gettimeofday";
  syscall_names[SYS32_settimeofday]="settimeofday";
  syscall_names[SYS32_getgroups]="getgroups";
  syscall_names[SYS32_setgroups]="setgroups";
  syscall_names[SYS32_select]="select";
  syscall_names[SYS32_symlink]="symlink";
  syscall_names[SYS32_oldlstat]="oldlstat";
  syscall_names[SYS32_readlink]="readlink";
  syscall_names[SYS32_uselib]="uselib";
  syscall_names[SYS32_swapon]="swapon";
  syscall_names[SYS32_reboot]="reboot";
  syscall_names[SYS32_readdir]="readdir";
  syscall_names[SYS32_old_mmap]="old_mmap";
  syscall_names[SYS32_munmap]="munmap";
  syscall_names[SYS32_truncate]="truncate";
  syscall_names[SYS32_ftruncate]="ftruncate";
  syscall_names[SYS32_fchmod]="fchmod";
  syscall_names[SYS32_fchown]="fchown";
  syscall_names[SYS32_getpriority]="getpriority";
  syscall_names[SYS32_setpriority]="setpriority";
  syscall_names[SYS32_profil]="profil";
  syscall_names[SYS32_statfs]="statfs";
  syscall_names[SYS32_fstatfs]="fstatfs";
  syscall_names[SYS32_ioperm]="ioperm";
  syscall_names[SYS32_socketcall]="socketcall";
  syscall_names[SYS32_syslog]="syslog";
  syscall_names[SYS32_setitimer]="setitimer";
  syscall_names[SYS32_getitimer]="getitimer";
  syscall_names[SYS32_stat]="stat";
  syscall_names[SYS32_lstat]="lstat";
  syscall_names[SYS32_fstat]="fstat";
  syscall_names[SYS32_olduname]="olduname";
  syscall_names[SYS32_iopl]="iopl";
  syscall_names[SYS32_vhangup]="vhangup";
  syscall_names[SYS32_idle]="idle";
  syscall_names[SYS32_vm86old]="vm86old";
  syscall_names[SYS32_wait4]="wait4";
  syscall_names[SYS32_swapoff]="swapoff";
  syscall_names[SYS32_sysinfo]="sysinfo";
  syscall_names[SYS32_ipc]="ipc";
  syscall_names[SYS32_fsync]="fsync";
  syscall_names[SYS32_sigreturn]="sigreturn";
  syscall_names[SYS32_clone]="clone";
  syscall_names[SYS32_setdomainname]="setdomainname";
  syscall_names[SYS32_uname]="uname";
  syscall_names[SYS32_modify_ldt]="modify_ldt";
  syscall_names[SYS32_adjtimex]="adjtimex";
  syscall_names[SYS32_mprotect]="mprotect";
  syscall_names[SYS32_sigprocmask]="sigprocmask";
  syscall_names[SYS32_create_module]="create_module";
  syscall_names[SYS32_init_module]="init_module";
  syscall_names[SYS32_delete_module]="delete_module";
  syscall_names[SYS32_get_kernel_syms]="get_kernel_syms";
  syscall_names[SYS32_quotactl]="quotactl";
  syscall_names[SYS32_getpgid]="getpgid";
  syscall_names[SYS32_fchdir]="fchdir";
  syscall_names[SYS32_bdflush]="bdflush";
  syscall_names[SYS32_sysfs]="sysfs";
  syscall_names[SYS32_personality]="personality";
  syscall_names[SYS32_afs_syscall]="afs_syscall";
  syscall_names[SYS32_setfsuid]="setfsuid";
  syscall_names[SYS32_setfsgid]="setfsgid";
  syscall_names[SYS32__llseek]="_llseek";
  syscall_names[SYS32_getdents]="getdents";
  syscall_names[SYS32__newselect]="_newselect";
  syscall_names[SYS32_flock]="flock";
  syscall_names[SYS32_msync]="msync";
  syscall_names[SYS32_readv]="readv";
  syscall_names[SYS32_writev]="writev";
  syscall_names[SYS32_getsid]="getsid";
  syscall_names[SYS32_fdatasync]="fdatasync";
  syscall_names[SYS32__sysctl]="_sysctl";
  syscall_names[SYS32_mlock]="mlock";
  syscall_names[SYS32_munlock]="munlock";
  syscall_names[SYS32_mlockall]="mlockall";
  syscall_names[SYS32_munlockall]="munlockall";
  syscall_names[SYS32_sched_setparam]="sched_setparam";
  syscall_names[SYS32_sched_getparam]="sched_getparam";
  syscall_names[SYS32_sched_setscheduler]="sched_setscheduler";
  syscall_names[SYS32_sched_getscheduler]="sched_getscheduler";
  syscall_names[SYS32_sched_yield]="sched_yield";
  syscall_names[SYS32_sched_get_priority_max]="sched_get_priority_max";
  syscall_names[SYS32_sched_get_priority_min]="sched_get_priority_min";
  syscall_names[SYS32_sched_rr_get_interval]="sched_rr_get_interval";
  syscall_names[SYS32_nanosleep]="nanosleep";
  syscall_names[SYS32_mremap]="mremap";
  syscall_names[SYS32_setresuid]="setresuid";
  syscall_names[SYS32_getresuid]="getresuid";
  syscall_names[SYS32_vm86]="vm86";
  syscall_names[SYS32_query_module]="query_module";
  syscall_names[SYS32_poll]="poll";
  syscall_names[SYS32_nfsservctl]="nfsservctl";
  syscall_names[SYS32_setresgid]="setresgid";
  syscall_names[SYS32_getresgid]="getresgid";
  syscall_names[SYS32_prctl]="prctl";
  syscall_names[SYS32_rt_sigreturn]="rt_sigreturn";
  syscall_names[SYS32_rt_sigaction]="rt_sigaction";
  syscall_names[SYS32_rt_sigprocmask]="rt_sigprocmask";
  syscall_names[SYS32_rt_sigpending]="rt_sigpending";
  syscall_names[SYS32_rt_sigtimedwait]="rt_sigtimedwait";
  syscall_names[SYS32_rt_sigqueueinfo]="rt_sigqueueinfo";
  syscall_names[SYS32_rt_sigsuspend]="rt_sigsuspend";
  syscall_names[SYS32_pread64]="pread64";
  syscall_names[SYS32_pwrite64]="pwrite64";
  syscall_names[SYS32_chown]="chown";
  syscall_names[SYS32_getcwd]="getcwd";
  syscall_names[SYS32_capget]="capget";
  syscall_names[SYS32_capset]="capset";
  syscall_names[SYS32_sigaltstack]="sigaltstack";
  syscall_names[SYS32_sendfile]="sendfile";
  syscall_names[SYS32_getpmsg]="getpmsg";
  syscall_names[SYS32_putpmsg]="putpmsg";
  syscall_names[SYS32_vfork]="vfork";
  syscall_names[SYS32_ugetrlimit]="ugetrlimit";
  syscall_names[SYS32_mmap2]="mmap2";
  syscall_names[SYS32_truncate64]="truncate64";
  syscall_names[SYS32_ftruncate64]="ftruncate64";
  syscall_names[SYS32_stat64]="stat64";
  syscall_names[SYS32_lstat64]="lstat64";
  syscall_names[SYS32_fstat64]="fstat64";
  syscall_names[SYS32_lchown32]="lchown32";
  syscall_names[SYS32_getuid32]="getuid32";
  syscall_names[SYS32_getgid32]="getgid32";
  syscall_names[SYS32_geteuid32]="geteuid32";
  syscall_names[SYS32_getegid32]="getegid32";
  syscall_names[SYS32_setreuid32]="setreuid32";
  syscall_names[SYS32_setregid32]="setregid32";
  syscall_names[SYS32_getgroups32]="getgroups32";
  syscall_names[SYS32_setgroups32]="setgroups32";
  syscall_names[SYS32_fchown32]="fchown32";
  syscall_names[SYS32_setresuid32]="setresuid32";
  syscall_names[SYS32_getresuid32]="getresuid32";
  syscall_names[SYS32_setresgid32]="setresgid32";
  syscall_names[SYS32_getresgid32]="getresgid32";
  syscall_names[SYS32_chown32]="chown32";
  syscall_names[SYS32_setuid32]="setuid32";
  syscall_names[SYS32_setgid32]="setgid32";
  syscall_names[SYS32_setfsuid32]="setfsuid32";
  syscall_names[SYS32_setfsgid32]="setfsgid32";
  syscall_names[SYS32_pivot_root]="pivot_root";
  syscall_names[SYS32_mincore]="mincore";
  syscall_names[SYS32_madvise]="madvise";
  syscall_names[SYS32_madvise1]="madvise1";
  syscall_names[SYS32_getdents64]="getdents64";
  syscall_names[SYS32_fcntl64]="fcntl64";
  syscall_names[SYS32_unused1]="unused1";
  syscall_names[SYS32_unused2]="unused2";
  syscall_names[SYS32_gettid]="gettid";
  syscall_names[SYS32_readahead]="readahead";
  syscall_names[SYS32_setxattr]="setxattr";
  syscall_names[SYS32_lsetxattr]="lsetxattr";
  syscall_names[SYS32_fsetxattr]="fsetxattr";
  syscall_names[SYS32_getxattr]="getxattr";
  syscall_names[SYS32_lgetxattr]="lgetxattr";
  syscall_names[SYS32_fgetxattr]="fgetxattr";
  syscall_names[SYS32_listxattr]="listxattr";
  syscall_names[SYS32_llistxattr]="llistxattr";
  syscall_names[SYS32_flistxattr]="flistxattr";
  syscall_names[SYS32_removexattr]="removexattr";
  syscall_names[SYS32_lremovexattr]="lremovexattr";
  syscall_names[SYS32_fremovexattr]="fremovexattr";
  syscall_names[SYS32_tkill]="tkill";
  syscall_names[SYS32_sendfile64]="sendfile64";
  syscall_names[SYS32_futex]="futex";
  syscall_names[SYS32_sched_setaffinity]="sched_setaffinity";
  syscall_names[SYS32_sched_getaffinity]="sched_getaffinity";
  syscall_names[SYS32_set_thread_area]="set_thread_area";
  syscall_names[SYS32_get_thread_area]="get_thread_area";
  syscall_names[SYS32_io_setup]="io_setup";
  syscall_names[SYS32_io_destroy]="io_destroy";
  syscall_names[SYS32_io_getevents]="io_getevents";
  syscall_names[SYS32_io_submit]="io_submit";
  syscall_names[SYS32_io_cancel]="io_cancel";
  syscall_names[SYS32_fadvise64]="fadvise64";
  syscall_names[SYS32_unused3]="unused3";
  syscall_names[SYS32_exit_group]="exit_group";
  syscall_names[SYS32_lookup_dcookie]="lookup_dcookie";
  syscall_names[SYS32_epoll_create]="epoll_create";
  syscall_names[SYS32_epoll_ctl]="epoll_ctl";
  syscall_names[SYS32_epoll_wait]="epoll_wait";
  syscall_names[SYS32_remap_file_pages]="remap_file_pages";
  syscall_names[SYS32_set_tid_address]="set_tid_address";
  syscall_names[SYS32_timer_create]="timer_create";
  syscall_names[SYS32_timer_settime]="timer_settime";
  syscall_names[SYS32_timer_gettime]="timer_gettime";
  syscall_names[SYS32_timer_getoverrun]="timer_getoverrun";
  syscall_names[SYS32_timer_delete]="timer_delete";
  syscall_names[SYS32_clock_settime]="clock_settime";
  syscall_names[SYS32_clock_gettime]="clock_gettime";
  syscall_names[SYS32_clock_getres]="clock_getres";
  syscall_names[SYS32_clock_nanosleep]="clock_nanosleep";
  syscall_names[SYS32_statfs64]="statfs64";
  syscall_names[SYS32_fstatfs64]="fstatfs64";
  syscall_names[SYS32_tgkill]="tgkill";
  syscall_names[SYS32_utimes]="utimes";
  syscall_names[SYS32_fadvise64_64]="fadvise64_64";
  syscall_names[SYS32_vserver]="vserver";
  syscall_names[SYS32_mbind]="mbind";
  syscall_names[SYS32_get_mempolicy]="get_mempolicy";
  syscall_names[SYS32_set_mempolicy]="set_mempolicy";
  syscall_names[SYS32_mq_open]="mq_open";
  syscall_names[SYS32_mq_unlink]="mq_unlink";
  syscall_names[SYS32_mq_timedsend]="mq_timedsend";
  syscall_names[SYS32_mq_timedreceive]="mq_timedreceive";
  syscall_names[SYS32_mq_notify]="mq_notify";
  syscall_names[SYS32_mq_getsetattr]="mq_getsetattr";
  syscall_names[SYS32_kexec_load]="kexec_load";
  syscall_names[SYS32_waitid]="waitid";
  syscall_names[SYS32_sys_setaltroot]="sys_setaltroot";
  syscall_names[SYS32_add_key]="add_key";
  syscall_names[SYS32_request_key]="request_key";
  syscall_names[SYS32_keyctl]="keyctl";
  syscall_names[SYS32_ioprio_set]="ioprio_set";
  syscall_names[SYS32_ioprio_get]="ioprio_get";
  syscall_names[SYS32_inotify_init]="inotify_init";
  syscall_names[SYS32_inotify_add_watch]="inotify_add_watch";
  syscall_names[SYS32_inotify_rm_watch]="inotify_rm_watch";
  syscall_names[SYS32_migrate_pages]="migrate_pages";
  syscall_names[SYS32_openat]="openat";
  syscall_names[SYS32_mkdirat]="mkdirat";
  syscall_names[SYS32_mknodat]="mknodat";
  syscall_names[SYS32_fchownat]="fchownat";
  syscall_names[SYS32_futimesat]="futimesat";
  syscall_names[SYS32_fstatat64]="fstatat64";
  syscall_names[SYS32_unlinkat]="unlinkat";
  syscall_names[SYS32_renameat]="renameat";
  syscall_names[SYS32_linkat]="linkat";
  syscall_names[SYS32_symlinkat]="symlinkat";
  syscall_names[SYS32_readlinkat]="readlinkat";
  syscall_names[SYS32_fchmodat]="fchmodat";
  syscall_names[SYS32_faccessat]="faccessat";
  syscall_names[SYS32_pselect6]="pselect6";
  syscall_names[SYS32_ppoll]="ppoll";
  syscall_names[SYS32_unshare]="unshare";
  syscall_names[SYS32_set_robust_list]="set_robust_list";
  syscall_names[SYS32_get_robust_list]="get_robust_list";
  syscall_names[SYS32_splice]="splice";
  syscall_names[SYS32_sync_file_range]="sync_file_range";
  syscall_names[SYS32_tee]="tee";
  syscall_names[SYS32_vmsplice]="vmsplice";
  syscall_names[SYS32_move_pages]="move_pages";
  syscall_names[SYS32_getcpu]="getcpu";
  syscall_names[SYS32_epoll_pwait]="epoll_pwait";
  syscall_names[SYS32_utimensat]="utimensat";
  syscall_names[SYS32_signalfd]="signalfd";
  syscall_names[SYS32_timerfd_create]="timerfd_create";
  syscall_names[SYS32_eventfd]="eventfd";
  syscall_names[SYS32_fallocate]="fallocate";
  syscall_names[SYS32_timerfd_settime]="timerfd_settime";
  syscall_names[SYS32_timerfd_gettime]="timerfd_gettime";
  syscall_names[SYS32_signalfd4]="signalfd4";
  syscall_names[SYS32_eventfd2]="eventfd2";
  syscall_names[SYS32_epoll_create1]="epoll_create1";
  syscall_names[SYS32_dup3]="dup3";
  syscall_names[SYS32_pipe2]="pipe2";
  syscall_names[SYS32_inotify_init1]="inotify_init1";
  syscall_names[SYS32_preadv]="preadv";
  syscall_names[SYS32_pwritev]="pwritev";
  syscall_names[SYS32_rt_tgsigqueueinfo]="rt_tgsigqueueinfo";
  syscall_names[SYS32_perf_event_open]="perf_event_open";
  syscall_names[SYS32_recvmmsg]="recvmmsg";
  syscall_names[SYS32_fanotify_init]="fanotify_init";
  syscall_names[SYS32_fanotify_mark]="fanotify_mark";
  syscall_names[SYS32_prlimit64]="prlimit64";
  syscall_names[SYS32_name_to_handle_at]="name_to_handle_at";
  syscall_names[SYS32_open_by_handle_at]="open_by_handle_at";
  syscall_names[SYS32_clock_adjtime]="clock_adjtime";
  syscall_names[SYS32_syncfs]="syncfs";
  syscall_names[SYS32_sendmmsg]="sendmmsg";
  syscall_names[SYS32_setns]="setns";
  syscall_names[SYS32_process_vm_readv]="process_vm_readv";
  syscall_names[SYS32_process_vm_writev]="process_vm_writev";
}

void init_parstrings()
{
  syscall_parstrings[SYS32_restart_syscall]="-disallowed-";
  syscall_parstrings[SYS32_exit]="-handled-";
  syscall_parstrings[SYS32_fork]="-disallowed-";
  syscall_parstrings[SYS32_read]="-handled-";
  syscall_parstrings[SYS32_write]="-handled-";
  syscall_parstrings[SYS32_open]="(path='%s', %x, %x)";
  syscall_parstrings[SYS32_close]="(fd=%d)";
  syscall_parstrings[SYS32_waitpid]="(pid=%d, statusptr=%x, options=%x)";
  syscall_parstrings[SYS32_creat]="(pathname='%s', mode=%x)";
  syscall_parstrings[SYS32_link]="?";
  syscall_parstrings[SYS32_unlink]="?";
  syscall_parstrings[SYS32_execve]="-handled-";
  syscall_parstrings[SYS32_chdir]="(path='%s')";
  syscall_parstrings[SYS32_time]="?";
  syscall_parstrings[SYS32_mknod]="?";
  syscall_parstrings[SYS32_chmod]="?";
  syscall_parstrings[SYS32_lchown]="?";
  syscall_parstrings[SYS32_break]="?";
  syscall_parstrings[SYS32_oldstat]="?";
  syscall_parstrings[SYS32_lseek]="?";
  syscall_parstrings[SYS32_getpid]="?";
  syscall_parstrings[SYS32_mount]="?";
  syscall_parstrings[SYS32_umount]="?";
  syscall_parstrings[SYS32_setuid]="?";
  syscall_parstrings[SYS32_getuid]="?";
  syscall_parstrings[SYS32_stime]="?";
  syscall_parstrings[SYS32_ptrace]="?";
  syscall_parstrings[SYS32_alarm]="?";
  syscall_parstrings[SYS32_oldfstat]="?";
  syscall_parstrings[SYS32_pause]="?";
  syscall_parstrings[SYS32_utime]="?";
  syscall_parstrings[SYS32_stty]="?";
  syscall_parstrings[SYS32_gtty]="?";
  syscall_parstrings[SYS32_access]="(pathname='%s', mode=%x)";
  syscall_parstrings[SYS32_nice]="?";
  syscall_parstrings[SYS32_ftime]="?";
  syscall_parstrings[SYS32_sync]="?";
  syscall_parstrings[SYS32_kill]="?";
  syscall_parstrings[SYS32_rename]="?";
  syscall_parstrings[SYS32_mkdir]="?";
  syscall_parstrings[SYS32_rmdir]="?";
  syscall_parstrings[SYS32_dup]="(oldfd=%d)";
  syscall_parstrings[SYS32_pipe]="?";
  syscall_parstrings[SYS32_times]="?";
  syscall_parstrings[SYS32_prof]="?";
  syscall_parstrings[SYS32_brk]="?";
  syscall_parstrings[SYS32_setgid]="?";
  syscall_parstrings[SYS32_getgid]="?";
  syscall_parstrings[SYS32_signal]="?";
  syscall_parstrings[SYS32_geteuid]="?";
  syscall_parstrings[SYS32_getegid]="?";
  syscall_parstrings[SYS32_acct]="?";
  syscall_parstrings[SYS32_umount2]="?";
  syscall_parstrings[SYS32_lock]="?";
  syscall_parstrings[SYS32_ioctl]="()";
  syscall_parstrings[SYS32_fcntl]="?";
  syscall_parstrings[SYS32_mpx]="?";
  syscall_parstrings[SYS32_setpgid]="?";
  syscall_parstrings[SYS32_ulimit]="?";
  syscall_parstrings[SYS32_oldolduname]="?";
  syscall_parstrings[SYS32_umask]="?";
  syscall_parstrings[SYS32_chroot]="?";
  syscall_parstrings[SYS32_ustat]="?";
  syscall_parstrings[SYS32_dup2]="(oldfd=%d, newfd=%d)";
  syscall_parstrings[SYS32_getppid]="?";
  syscall_parstrings[SYS32_getpgrp]="?";
  syscall_parstrings[SYS32_setsid]="?";
  syscall_parstrings[SYS32_sigaction]="?";
  syscall_parstrings[SYS32_sgetmask]="?";
  syscall_parstrings[SYS32_ssetmask]="?";
  syscall_parstrings[SYS32_setreuid]="?";
  syscall_parstrings[SYS32_setregid]="?";
  syscall_parstrings[SYS32_sigsuspend]="?";
  syscall_parstrings[SYS32_sigpending]="?";
  syscall_parstrings[SYS32_sethostname]="?";
  syscall_parstrings[SYS32_setrlimit]="?";
  syscall_parstrings[SYS32_getrlimit]="?";
  syscall_parstrings[SYS32_getrusage]="?";
  syscall_parstrings[SYS32_gettimeofday]="?";
  syscall_parstrings[SYS32_settimeofday]="?";
  syscall_parstrings[SYS32_getgroups]="?";
  syscall_parstrings[SYS32_setgroups]="?";
  syscall_parstrings[SYS32_select]="?";
  syscall_parstrings[SYS32_symlink]="?";
  syscall_parstrings[SYS32_oldlstat]="?";
  syscall_parstrings[SYS32_readlink]="?";
  syscall_parstrings[SYS32_uselib]="?";
  syscall_parstrings[SYS32_swapon]="?";
  syscall_parstrings[SYS32_reboot]="?";
  syscall_parstrings[SYS32_readdir]="?";
  syscall_parstrings[SYS32_old_mmap]="?";
  syscall_parstrings[SYS32_munmap]="?";
  syscall_parstrings[SYS32_truncate]="?";
  syscall_parstrings[SYS32_ftruncate]="?";
  syscall_parstrings[SYS32_fchmod]="?";
  syscall_parstrings[SYS32_fchown]="?";
  syscall_parstrings[SYS32_getpriority]="?";
  syscall_parstrings[SYS32_setpriority]="?";
  syscall_parstrings[SYS32_profil]="?";
  syscall_parstrings[SYS32_statfs]="?";
  syscall_parstrings[SYS32_fstatfs]="?";
  syscall_parstrings[SYS32_ioperm]="?";
  syscall_parstrings[SYS32_socketcall]="?";
  syscall_parstrings[SYS32_syslog]="?";
  syscall_parstrings[SYS32_setitimer]="?";
  syscall_parstrings[SYS32_getitimer]="?";
  syscall_parstrings[SYS32_stat]="?";
  syscall_parstrings[SYS32_lstat]="?";
  syscall_parstrings[SYS32_fstat]="?";
  syscall_parstrings[SYS32_olduname]="?";
  syscall_parstrings[SYS32_iopl]="?";
  syscall_parstrings[SYS32_vhangup]="?";
  syscall_parstrings[SYS32_idle]="?";
  syscall_parstrings[SYS32_vm86old]="?";
  syscall_parstrings[SYS32_wait4]="?";
  syscall_parstrings[SYS32_swapoff]="?";
  syscall_parstrings[SYS32_sysinfo]="?";
  syscall_parstrings[SYS32_ipc]="(call=%d, first=%d, second=%d, third=%d, ptr=%x, fifth=%x)";
  syscall_parstrings[SYS32_fsync]="?";
  syscall_parstrings[SYS32_sigreturn]="?";
  syscall_parstrings[SYS32_clone]="?";
  syscall_parstrings[SYS32_setdomainname]="?";
  syscall_parstrings[SYS32_uname]="(buf=%x)";
  syscall_parstrings[SYS32_modify_ldt]="?";
  syscall_parstrings[SYS32_adjtimex]="?";
  syscall_parstrings[SYS32_mprotect]="?";
  syscall_parstrings[SYS32_sigprocmask]="?";
  syscall_parstrings[SYS32_create_module]="?";
  syscall_parstrings[SYS32_init_module]="?";
  syscall_parstrings[SYS32_delete_module]="?";
  syscall_parstrings[SYS32_get_kernel_syms]="?";
  syscall_parstrings[SYS32_quotactl]="?";
  syscall_parstrings[SYS32_getpgid]="?";
  syscall_parstrings[SYS32_fchdir]="?";
  syscall_parstrings[SYS32_bdflush]="?";
  syscall_parstrings[SYS32_sysfs]="?";
  syscall_parstrings[SYS32_personality]="?";
  syscall_parstrings[SYS32_afs_syscall]="?";
  syscall_parstrings[SYS32_setfsuid]="?";
  syscall_parstrings[SYS32_setfsgid]="?";
  syscall_parstrings[SYS32__llseek]="?";
  syscall_parstrings[SYS32_getdents]="?";
  syscall_parstrings[SYS32__newselect]="?";
  syscall_parstrings[SYS32_flock]="?";
  syscall_parstrings[SYS32_msync]="?";
  syscall_parstrings[SYS32_readv]="?";
  syscall_parstrings[SYS32_writev]="?";
  syscall_parstrings[SYS32_getsid]="?";
  syscall_parstrings[SYS32_fdatasync]="?";
  syscall_parstrings[SYS32__sysctl]="?";
  syscall_parstrings[SYS32_mlock]="?";
  syscall_parstrings[SYS32_munlock]="?";
  syscall_parstrings[SYS32_mlockall]="?";
  syscall_parstrings[SYS32_munlockall]="?";
  syscall_parstrings[SYS32_sched_setparam]="?";
  syscall_parstrings[SYS32_sched_getparam]="?";
  syscall_parstrings[SYS32_sched_setscheduler]="?";
  syscall_parstrings[SYS32_sched_getscheduler]="?";
  syscall_parstrings[SYS32_sched_yield]="?";
  syscall_parstrings[SYS32_sched_get_priority_max]="?";
  syscall_parstrings[SYS32_sched_get_priority_min]="?";
  syscall_parstrings[SYS32_sched_rr_get_interval]="?";
  syscall_parstrings[SYS32_nanosleep]="?";
  syscall_parstrings[SYS32_mremap]="?";
  syscall_parstrings[SYS32_setresuid]="?";
  syscall_parstrings[SYS32_getresuid]="?";
  syscall_parstrings[SYS32_vm86]="?";
  syscall_parstrings[SYS32_query_module]="?";
  syscall_parstrings[SYS32_poll]="?";
  syscall_parstrings[SYS32_nfsservctl]="?";
  syscall_parstrings[SYS32_setresgid]="?";
  syscall_parstrings[SYS32_getresgid]="?";
  syscall_parstrings[SYS32_prctl]="?";
  syscall_parstrings[SYS32_rt_sigreturn]="?";
  syscall_parstrings[SYS32_rt_sigaction]="?";
  syscall_parstrings[SYS32_rt_sigprocmask]="(how=%d, sigsetptr=%x, oldsigsetptr=%x)";
  syscall_parstrings[SYS32_rt_sigpending]="?";
  syscall_parstrings[SYS32_rt_sigtimedwait]="?";
  syscall_parstrings[SYS32_rt_sigqueueinfo]="?";
  syscall_parstrings[SYS32_rt_sigsuspend]="?";
  syscall_parstrings[SYS32_pread64]="?";
  syscall_parstrings[SYS32_pwrite64]="?";
  syscall_parstrings[SYS32_chown]="?";
  syscall_parstrings[SYS32_getcwd]="(buf=%x, size=%d)";
  syscall_parstrings[SYS32_capget]="?";
  syscall_parstrings[SYS32_capset]="?";
  syscall_parstrings[SYS32_sigaltstack]="?";
  syscall_parstrings[SYS32_sendfile]="?";
  syscall_parstrings[SYS32_getpmsg]="?";
  syscall_parstrings[SYS32_putpmsg]="?";
  syscall_parstrings[SYS32_vfork]="?";
  syscall_parstrings[SYS32_ugetrlimit]="?";
  syscall_parstrings[SYS32_mmap2]="?";
  syscall_parstrings[SYS32_truncate64]="?";
  syscall_parstrings[SYS32_ftruncate64]="?";
  syscall_parstrings[SYS32_stat64]="?";
  syscall_parstrings[SYS32_lstat64]="?";
  syscall_parstrings[SYS32_fstat64]="?";
  syscall_parstrings[SYS32_lchown32]="?";
  syscall_parstrings[SYS32_getuid32]="?";
  syscall_parstrings[SYS32_getgid32]="?";
  syscall_parstrings[SYS32_geteuid32]="?";
  syscall_parstrings[SYS32_getegid32]="?";
  syscall_parstrings[SYS32_setreuid32]="?";
  syscall_parstrings[SYS32_setregid32]="?";
  syscall_parstrings[SYS32_getgroups32]="?";
  syscall_parstrings[SYS32_setgroups32]="?";
  syscall_parstrings[SYS32_fchown32]="?";
  syscall_parstrings[SYS32_setresuid32]="?";
  syscall_parstrings[SYS32_getresuid32]="?";
  syscall_parstrings[SYS32_setresgid32]="?";
  syscall_parstrings[SYS32_getresgid32]="?";
  syscall_parstrings[SYS32_chown32]="?";
  syscall_parstrings[SYS32_setuid32]="?";
  syscall_parstrings[SYS32_setgid32]="?";
  syscall_parstrings[SYS32_setfsuid32]="?";
  syscall_parstrings[SYS32_setfsgid32]="?";
  syscall_parstrings[SYS32_pivot_root]="?";
  syscall_parstrings[SYS32_mincore]="?";
  syscall_parstrings[SYS32_madvise]="?";
  syscall_parstrings[SYS32_madvise1]="?";
  syscall_parstrings[SYS32_getdents64]="?";
  syscall_parstrings[SYS32_fcntl64]="?";
  syscall_parstrings[SYS32_unused1]="?";
  syscall_parstrings[SYS32_unused2]="?";
  syscall_parstrings[SYS32_gettid]="?";
  syscall_parstrings[SYS32_readahead]="?";
  syscall_parstrings[SYS32_setxattr]="?";
  syscall_parstrings[SYS32_lsetxattr]="?";
  syscall_parstrings[SYS32_fsetxattr]="?";
  syscall_parstrings[SYS32_getxattr]="?";
  syscall_parstrings[SYS32_lgetxattr]="?";
  syscall_parstrings[SYS32_fgetxattr]="?";
  syscall_parstrings[SYS32_listxattr]="?";
  syscall_parstrings[SYS32_llistxattr]="?";
  syscall_parstrings[SYS32_flistxattr]="?";
  syscall_parstrings[SYS32_removexattr]="?";
  syscall_parstrings[SYS32_lremovexattr]="?";
  syscall_parstrings[SYS32_fremovexattr]="?";
  syscall_parstrings[SYS32_tkill]="?";
  syscall_parstrings[SYS32_sendfile64]="?";
  syscall_parstrings[SYS32_futex]="?";
  syscall_parstrings[SYS32_sched_setaffinity]="?";
  syscall_parstrings[SYS32_sched_getaffinity]="?";
  syscall_parstrings[SYS32_set_thread_area]="?";
  syscall_parstrings[SYS32_get_thread_area]="?";
  syscall_parstrings[SYS32_io_setup]="?";
  syscall_parstrings[SYS32_io_destroy]="?";
  syscall_parstrings[SYS32_io_getevents]="?";
  syscall_parstrings[SYS32_io_submit]="?";
  syscall_parstrings[SYS32_io_cancel]="?";
  syscall_parstrings[SYS32_fadvise64]="?";
  syscall_parstrings[SYS32_unused3]="?";
  syscall_parstrings[SYS32_exit_group]="?";
  syscall_parstrings[SYS32_lookup_dcookie]="?";
  syscall_parstrings[SYS32_epoll_create]="?";
  syscall_parstrings[SYS32_epoll_ctl]="?";
  syscall_parstrings[SYS32_epoll_wait]="?";
  syscall_parstrings[SYS32_remap_file_pages]="?";
  syscall_parstrings[SYS32_set_tid_address]="(tidptr=%x)";
  syscall_parstrings[SYS32_timer_create]="?";
  syscall_parstrings[SYS32_timer_settime]="?";
  syscall_parstrings[SYS32_timer_gettime]="?";
  syscall_parstrings[SYS32_timer_getoverrun]="?";
  syscall_parstrings[SYS32_timer_delete]="?";
  syscall_parstrings[SYS32_clock_settime]="?";
  syscall_parstrings[SYS32_clock_gettime]="?";
  syscall_parstrings[SYS32_clock_getres]="?";
  syscall_parstrings[SYS32_clock_nanosleep]="?";
  syscall_parstrings[SYS32_statfs64]="?";
  syscall_parstrings[SYS32_fstatfs64]="?";
  syscall_parstrings[SYS32_tgkill]="?";
  syscall_parstrings[SYS32_utimes]="?";
  syscall_parstrings[SYS32_fadvise64_64]="?";
  syscall_parstrings[SYS32_vserver]="?";
  syscall_parstrings[SYS32_mbind]="?";
  syscall_parstrings[SYS32_get_mempolicy]="?";
  syscall_parstrings[SYS32_set_mempolicy]="?";
  syscall_parstrings[SYS32_mq_open]="?";
  syscall_parstrings[SYS32_mq_unlink]="?";
  syscall_parstrings[SYS32_mq_timedsend]="?";
  syscall_parstrings[SYS32_mq_timedreceive]="?";
  syscall_parstrings[SYS32_mq_notify]="?";
  syscall_parstrings[SYS32_mq_getsetattr]="?";
  syscall_parstrings[SYS32_kexec_load]="?";
  syscall_parstrings[SYS32_waitid]="?";
  syscall_parstrings[SYS32_sys_setaltroot]="?";
  syscall_parstrings[SYS32_add_key]="?";
  syscall_parstrings[SYS32_request_key]="?";
  syscall_parstrings[SYS32_keyctl]="?";
  syscall_parstrings[SYS32_ioprio_set]="?";
  syscall_parstrings[SYS32_ioprio_get]="?";
  syscall_parstrings[SYS32_inotify_init]="?";
  syscall_parstrings[SYS32_inotify_add_watch]="?";
  syscall_parstrings[SYS32_inotify_rm_watch]="?";
  syscall_parstrings[SYS32_migrate_pages]="?";
  syscall_parstrings[SYS32_openat]="?";
  syscall_parstrings[SYS32_mkdirat]="?";
  syscall_parstrings[SYS32_mknodat]="?";
  syscall_parstrings[SYS32_fchownat]="?";
  syscall_parstrings[SYS32_futimesat]="?";
  syscall_parstrings[SYS32_fstatat64]="?";
  syscall_parstrings[SYS32_unlinkat]="?";
  syscall_parstrings[SYS32_renameat]="?";
  syscall_parstrings[SYS32_linkat]="?";
  syscall_parstrings[SYS32_symlinkat]="?";
  syscall_parstrings[SYS32_readlinkat]="?";
  syscall_parstrings[SYS32_fchmodat]="?";
  syscall_parstrings[SYS32_faccessat]="?";
  syscall_parstrings[SYS32_pselect6]="?";
  syscall_parstrings[SYS32_ppoll]="?";
  syscall_parstrings[SYS32_unshare]="?";
  syscall_parstrings[SYS32_set_robust_list]="?";
  syscall_parstrings[SYS32_get_robust_list]="?";
  syscall_parstrings[SYS32_splice]="?";
  syscall_parstrings[SYS32_sync_file_range]="?";
  syscall_parstrings[SYS32_tee]="?";
  syscall_parstrings[SYS32_vmsplice]="?";
  syscall_parstrings[SYS32_move_pages]="?";
  syscall_parstrings[SYS32_getcpu]="?";
  syscall_parstrings[SYS32_epoll_pwait]="?";
  syscall_parstrings[SYS32_utimensat]="?";
  syscall_parstrings[SYS32_signalfd]="?";
  syscall_parstrings[SYS32_timerfd_create]="?";
  syscall_parstrings[SYS32_eventfd]="?";
  syscall_parstrings[SYS32_fallocate]="?";
  syscall_parstrings[SYS32_timerfd_settime]="?";
  syscall_parstrings[SYS32_timerfd_gettime]="?";
  syscall_parstrings[SYS32_signalfd4]="?";
  syscall_parstrings[SYS32_eventfd2]="?";
  syscall_parstrings[SYS32_epoll_create1]="?";
  syscall_parstrings[SYS32_dup3]="?";
  syscall_parstrings[SYS32_pipe2]="?";
  syscall_parstrings[SYS32_inotify_init1]="?";
  syscall_parstrings[SYS32_preadv]="?";
  syscall_parstrings[SYS32_pwritev]="?";
  syscall_parstrings[SYS32_rt_tgsigqueueinfo]="?";
  syscall_parstrings[SYS32_perf_event_open]="?";
  syscall_parstrings[SYS32_recvmmsg]="?";
  syscall_parstrings[SYS32_fanotify_init]="?";
  syscall_parstrings[SYS32_fanotify_mark]="?";
  syscall_parstrings[SYS32_prlimit64]="?";
  syscall_parstrings[SYS32_name_to_handle_at]="?";
  syscall_parstrings[SYS32_open_by_handle_at]="?";
  syscall_parstrings[SYS32_clock_adjtime]="?";
  syscall_parstrings[SYS32_syncfs]="?";
  syscall_parstrings[SYS32_sendmmsg]="?";
  syscall_parstrings[SYS32_setns]="?";
  syscall_parstrings[SYS32_process_vm_readv]="?";
  syscall_parstrings[SYS32_process_vm_writev]="?";
}


