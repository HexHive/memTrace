/**
 * @file fbt_signal.h
 * Implementation of signal wrapping. Unfinished!
 *
 * Copyright (c) 2012 ETH Zurich
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

#ifndef FBT_SIGNALS_H
#define FBT_SIGNALS_H

#include "fbt_datatypes.h"


/*****************************************
   This is taken from the linux kernel
   include/asm-generic/signal-defs.h    */
typedef void __signalfn_t(int);
typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t *__sigrestore_t;

#define SIG_DFL ((__sighandler_t)0)     /* default signal handling */
#define SIG_IGN ((__sighandler_t)1)     /* ignore signal */
#define SIG_ERR ((__sighandler_t)-1)    /* error return from signal */
/********************************** (end copypaste) */

/***********************************************
 * The following is taken from the linux kernel
 * arch/ia64
 */
#define SIGHUP     1
#define SIGINT     2
#define SIGQUIT    3
#define SIGILL     4
#define SIGTRAP    5
#define SIGABRT    6
#define SIGIOT     6
#define SIGBUS     7
#define SIGFPE     8
#define SIGKILL    9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO   29
#define SIGPOLL   SIGIO
/*
#define SIGLOST   29
 */
#define SIGPWR    30
#define SIGSYS    31
/* signal 31 is no longer "unused", but the SIGUNUSED macro remains for backwards compatibility */
#define SIGUNUSED 31

/* These should not be considered constants from userland.  */
#define SIGRTMIN  32
#define SIGRTMAX  _NSIG

/*
 * SA_FLAGS values:
 *
 * SA_ONSTACK indicates that a registered stack_t will be used.
 * SA_RESTART flag to get restarting signals (which were the default long ago)
 * SA_NOCLDSTOP flag to turn off SIGCHLD when children stop.
 * SA_RESETHAND clears the handler when the signal is delivered.
 * SA_NOCLDWAIT flag on SIGCHLD to inhibit zombies.
 * SA_NODEFER prevents the current signal from being masked in the handler.
 *
 * SA_ONESHOT and SA_NOMASK are the historical Linux names for the Single
 * Unix names RESETHAND and NODEFER respectively.
 */
#define SA_NOCLDSTOP  0x00000001
#define SA_NOCLDWAIT  0x00000002
#define SA_SIGINFO  0x00000004
#define SA_ONSTACK  0x08000000
#define SA_RESTART  0x10000000
#define SA_NODEFER  0x40000000
#define SA_RESETHAND  0x80000000

#define SA_NOMASK SA_NODEFER
#define SA_ONESHOT  SA_RESETHAND

#define SA_RESTORER 0x04000000

/*
 * sigaltstack controls
 */
#define SS_ONSTACK  1
#define SS_DISABLE  2
/**************************************************/


struct kernel_sigaction {
  __sighandler_t k_sa_handler;
  uint64_t sa_flags;
  __sighandler_t restorer;
  uint64_t sa_mask;
};

void fbt_add_signal_handler(int signr, __sighandler_t handler);

void fbt_signals_init();

/*
extern int __syscall_rt_sigaction (
    int,
    const struct kernel_sigaction *__unbounded,
    struct kernel_sigaction *__unbounded,
    size_t);
 */

#endif
