/**
 * @file fbt_syscalls_64.h
 * This file implements system calls. The main syscall function
 * is implemented in assembly.
 *
 * Copyright (c) 2011 ETH Zurich
 *
 * @author Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * $Date: 2012-01-12 16:45:01 +0100 (gio, 12 gen 2012) $
 * $LastChangedDate: 2012-01-12 16:45:01 +0100 (gio, 12 gen 2012) $
 * $LastChangedBy: kravinae $
 * $Revision: 1167 $
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

#ifndef FBT_SYSCALLS_H
#define FBT_SYSCALLS_H

#include "fbt_syscall_numbers_64.h"
#include "fbt_datatypes.h"
#include "fbt_llio.h"
#include "fbt_libc.h"
#include "fbt_util.h"

/*
 * The _generic_64bit_syscall() routine is implemented in
 * assembly
 */
int64_t _fbt_generic_64bit_syscall(uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6,
    uint64_t nr);

static inline int64_t fbt_syscall(uint64_t nr)
{
  return _fbt_generic_64bit_syscall(0,0,0,0,0,0, nr);
}

static inline int64_t fbt_syscall1(uint64_t nr,
    uint64_t arg1)
{
  return _fbt_generic_64bit_syscall(arg1,0,0,0,0,0, nr);
}

static inline int64_t fbt_syscall2(uint64_t nr,
    uint64_t arg1,
    uint64_t arg2)
{
  return _fbt_generic_64bit_syscall(arg1, arg2, 0,0,0,0, nr);
}

static inline int64_t fbt_syscall3(uint64_t nr,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3)
{
  return _fbt_generic_64bit_syscall(arg1,arg2,arg3,0,0,0, nr);
}

static inline int64_t fbt_syscall4(uint64_t nr,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4)
{
  return _fbt_generic_64bit_syscall(arg1,arg2,arg3,arg4,0,0, nr);
}

static inline int64_t fbt_syscall5(uint64_t nr,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5)
{
  return _fbt_generic_64bit_syscall(arg1,arg2,arg3,arg4,arg5,0, nr);
}

static inline int64_t fbt_syscall6(uint64_t nr,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6)
{
  return _fbt_generic_64bit_syscall(arg1,arg2,arg3,arg4,arg5,arg6,nr);
}

static inline BOOL valid_result(int64_t r)
{
  return !(r<0 && r>=(-128));
}

static inline int64_t fbt_syscallq(int64_t number,
    const char* errstr)
{
  int64_t res = fbt_syscall(number);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall1q(uint64_t number,
    uint64_t arg1,
    const char* errstr)
{
  int64_t res = fbt_syscall1(number, arg1);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall2q(uint64_t number,
    uint64_t arg1,
    uint64_t arg2,
    const char* errstr)
{
  int64_t res = fbt_syscall2(number, arg1, arg2);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall3q(uint64_t number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    const char* errstr)
{
  int64_t res = fbt_syscall3(number, arg1, arg2, arg3);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall4q(uint64_t number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    const char* errstr)
{
  int64_t res = fbt_syscall4(number, arg1, arg2, arg3, arg4);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall5q(uint64_t number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    const char* errstr)
{
  int64_t res = fbt_syscall5(number, arg1, arg2, arg3, arg4, arg5);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

static inline int64_t fbt_syscall6q(uint64_t number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6,
    const char* errstr)
{
  int64_t res = fbt_syscall6(number, arg1, arg2, arg3, arg4, arg5, arg6);
  if (!valid_result(res)) {
    fbt_suicide_str(errstr);
  }
  return res;
}

/* Possible endings for syscalls:
   K: program will be killed with (int)err
   E: syscall executes, errors are ignored
   nothing: program is killed with given error string
 */

#define fbt_clone2(flags, stack) fbt_syscall2(SYS64_clone, flags, stack)
#define fbt_read(fd, buf, count) fbt_syscall3(SYS64_read, fd, buf, count)
#define fbt_write(fd, buf, count, errstr)          \
    fbt_syscall3q(SYS64_write, fd, buf, count, errstr)
#define fbt_writeK(fd, buf, count, err)    \
    fbt_syscall3s(SYS64_write, fd, buf, count, err)
#define fbt_open(pathname, flags, mode, errstr)    \
    fbt_syscall3q(SYS64_open, pathname, flags, mode, errstr)
#define fbt_openE(pathname, flags, mode)    \
    fbt_syscall3(SYS64_open, pathname, flags, mode)
#define fbt_openat(fd, pathname, flags, mode, errstr)      \
    fbt_syscall4q(SYS64_openat, fd, pathname, flags,  mode, errstr)
#define fbt_openatE(fd, pathname, flags, mode)      \
    fbt_syscall4(SYS64_openat, fd, pathname, flags,  mode)
#define fbt_faccessatE(fd, file, flags, mode)       \
    fbt_syscall4(SYS64_faccessat, fd, file, flags, mode)
#define fbt_accessE(path, mode)     \
    fbt_syscall2(SYS64_access, path, mode)
#define fbt_close(fd, errstr) fbt_syscall1q(SYS64_close, fd, errstr)
#define fbt_closeE(fd) fbt_syscall1(SYS64_close, fd)
#define fbt_lseek(fd, offset, whence, errstr)      \
    fbt_syscall3q(SYS64_lseek, fd, offset, whence, errstr)
#define fbt_getpid(errstr) fbt_syscallq(SYS64_getpid, errstr)
#define fbt_gettid() fbt_syscall(SYS64_gettid)
#define fbt_fstat64(fd, stat, errstr) \
    fbt_syscall2q(SYS64_fstat64, fd, stat, errstr)
#define fbt_fstat64E(fd, stat) \
    fbt_syscall2(SYS64_fstat64, fd, stat)
#define fbt_stat64(path, stat, errstr) \
    fbt_syscall2q(SYS64_stat64, path, stat, errstr)
#define fbt_stat64E(path, stat) \
    fbt_syscall2(SYS64_stat64, path, stat)
#define fbt_fstat(fd, stat, errstr) \
    fbt_syscall2q(SYS64_fstat, fd, stat, errstr)
#define fbt_mmap(addr, length, prot, flags, fd, offset, errstr)    \
    fbt_syscall6q(SYS64_mmap, addr, length, prot, flags, fd, offset, errstr)
#define fbt_mremap(addr, oldsize, newsize, flags, errstr)    \
    fbt_syscall4q(SYS64_mremap, addr, oldsize, newsize, flags, errstr)
#define fbt_munmap(addr, length, errstr)   \
    fbt_syscall2q(SYS64_munmap, addr, length, errstr)
#define fbt_mprotect(addr, len, prot, errstr)              \
    fbt_syscall3q(SYS64_mprotect, addr, len, prot, errstr)
#define fbt_signalE(sig, handler)   \
    fbt_syscall2(SYS64_signal, sig, handler)
#define fbt_sigactionE(sig, act, oldact)    \
    fbt_syscall3(SYS64_sigaction, sig, act, oldact)
#define fbt_sigaction(sig, act, oldact, errstr)   \
    fbt_syscall3q(SYS64_sigaction, sig, act, oldact, errstr)
#define fbt_clone(flags, stack, ptid, newtls, ctid, errstr)        \
    fbt_syscall5q(SYS64_clone, flags, stack, ptid, newtls, ctid, errstr)
#define fbt_rt_sigactionE(sig, act, oldact) \
    fbt_syscall3(SYS64_rt_sigaction, sig, act, oldact)
#define fbt_getcwd(str, len, errstr)       \
    fbt_syscall2q(SYS64_getcwd, str, len, errstr)
#define fbt_readlink(src, dest, len) \
    fbt_syscall3(SYS64_readlink, src, dest, len)
#define fbt_set_thread_area(uinfo) \
    fbt_syscall1(SYS64_set_thread_area, uinfo)

/* Warning: to check if this makes sense */

#define fbt_rt_sigaction(sig, act, oldact, number)    \
    fbt_syscall4(SYS64_rt_sigaction, sig, act, oldact, number)
#define fbt_rt_signal(sig, handler)   \
    fbt_syscall2(SYS64_rt_signal, sig, handler)
#endif  /* FBT_SYSCALLS_H */
