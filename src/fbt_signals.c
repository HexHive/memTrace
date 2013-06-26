/**
 * @file fbt_signals.c
 * Implementation of signal wrapping.
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
#include "fbt_signals.h"
#include "fbt_libc.h"
#include "fbt_datatypes.h"
#include "fbt_shared_data.h"
#include "fbt_translate.h"
#include "fbt_address_space.h"
#include "fbt_debug.h"

#include <asm-generic/mman-common.h>

/* implemented in assembly (start.s) */
void restorefun();

/**
 * Lets us catch signals.
 * @param signr for what signal to install the handler
 * @handler the handler
 */
void fbt_add_signal_handler(int signr, __sighandler_t handler)
{
  struct kernel_sigaction act;
  fbt_memset(&act, 0, sizeof(act));
  act.k_sa_handler = handler;
  act.sa_mask = 0xFFFFFFFFFFFFFFFF;
  act.sa_flags = SA_RESTORER;
  act.restorer = restorefun;
  int retval = fbt_rt_sigaction(signr, (uint64_t)&act, 0, 8);
  if (retval < 0 && retval >= (-128)){
    fbt_suicide_str("failed to install sighandler\n");
  }
}

struct thread_local_data* fbt_init(BOOL lck);

void sighelper(void* where,
                 void* stackarea,
                 void** wheretosavestack,
                 void** wheretosaveip,
                 void* sighandleraddr);

/**
 * For now we just exit when we get a signal.
 * @param signal the signal number
 */
static void fbt_generic_signal_handler(int signal)
{
  //llprintf("got signal %d\n", signal);

  PRINT_DEBUG("lmem: we got signal %d\n", signal);
  uint32_t tid = fbt_syscall(SYS64_gettid);
  PRINT_DEBUG("lmem: sig fom tid %d\n", tid);

  /* There is room for improvement in this locking scheme */
  fbt_mutex_lock(&shared_data_mutex);

  struct fbt_sigaction_32bit s = shared_data.signals[signal];
  if (s.sigaction == (uint64_t)SIG_IGN){
    PRINT_DEBUG("ignoring signal %d\n", signal);
    fbt_mutex_unlock(&shared_data_mutex);
  } else if (s.sigaction == (uint64_t)SIG_DFL) {
    PRINT_DEBUG("performing default action of signal %d, which is...\n", signal);
    switch (signal){
    case SIGWINCH:
    case SIGIO:
    case SIGURG:
    case SIGCHLD:
      PRINT_DEBUG("...ignoring it\n");
      break;
    default:
      llprintf("...killing everything\n");
      PRINT_DEBUG("exiting due to some signal\n");
      fbt_syscall1(SYS64_exit_group, 1);      }
    fbt_mutex_unlock(&shared_data_mutex);
  } else if (s.sigaction == (uint64_t)SIG_ERR) {
    fbt_mutex_unlock(&shared_data_mutex);
    fbt_suicide_str("dunno how to handle sig_err handler???\n");
  } else {

    /* Call the signal handler (translated) */

    struct thread_local_data* tld = fbt_init(FALSE);
    void* where = fbt_translate_noexecute(tld, 
                                          shared_data.sighandler_wrapper32,
                                          FALSE);

    PRINT_DEBUG("calling sighelper");
    fbt_mutex_unlock(&shared_data_mutex);
    sighelper(where, /* the translated signal handler where
                        sighelper should jump to, after having saved all
                        the context that allows the translated code to
                        jump back to 'sighelper' when the lmem sigreturn
                        special system call is issued */
              (void**)(uint64_t)shared_data.signal_stack_area,  /* read only:
                       the stack that should be used by the lmem_sigreturn 
                       routine and the signal handler */
              &tld->sigcall_data.saved_rsp, /* place where sighelper can
                                               store context that is then used
                                               to return to sighelper */
              &tld->sigcall_data.saved_rip, /* analogously */
              (void*)(uint64_t)s.sigaction); /* the actual handler */
    PRINT_DEBUG("returned from sighelper");
  }
}

/**
 * Initializes all signal handlers.
 */
void fbt_signals_init()
{
  if (!shared_data.is_initialized){
    fbt_suicide_str("signals init function needs shared data.\n");
  }

  for (int i = 1; i < MAX_NR_SIGNALS; ++i) {
    if (i==11) continue; /* we want to let sigsegv crash for now */

    /* for convenience: we like to break in the debugger when 
       the translated application issues signal 3 */
    if (i==3) continue; 

    if (i==9) continue;  /* kill cannot be overridden */
    if (i==19) continue; /* stop cannot be overridden */

    fbt_add_signal_handler(i, fbt_generic_signal_handler);
  }
}

