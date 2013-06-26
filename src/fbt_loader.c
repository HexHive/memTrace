/**
 * @file fbt_loader.c
 * A bootstrap module that implements a very simple loader
 * that loads the real loader.
 *
 * Copyright (c) 2012 ETH Zurich
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

#include "fbt_loader.h"
#include "fbt_syscalls_64.h"
#include "fbt_llio.h"
#include "fbt_libc.h"
#include "fbt_address_space.h"
#include "fbt_debug.h"

#include <elf.h>
#include <asm-generic/mman-common.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/**
 * Loads the loader!
 * @param tld the thread local data.
 */
guestptr_t lmem_load_loader(struct thread_local_data* tld)
{
  struct stat file_info;

  char* PATH_OF_LOADER="/lib32/ld-linux.so.2";
  {
    int ret = fbt_syscall2(SYS64_stat, (uint64_t)PATH_OF_LOADER, (uint64_t)&file_info);
    if (!valid_result(ret)){
      PATH_OF_LOADER="/lib/ld-linux.so.2";
      ret = fbt_syscall2(SYS64_stat, (uint64_t)PATH_OF_LOADER, (uint64_t)&file_info);
      if (!valid_result(ret)){
        llprintf("did not find loader, try to adjust it to your loader's path\n");
        fbt_suicide_str("stat of loader failed");
      }
    }
  }

  const int LOADOFF = LOADER_BASE_ADDRESS;
  const char* PNAME = PATH_OF_LOADER;

  unsigned siz = file_info.st_size;
  if (siz == 0){
    fbt_suicide_str("loader is empty file!!!\n");
  }

  int fd = fbt_syscall3(SYS64_open, (uint64_t)PNAME, O_RDONLY, 0);
  if (!valid_result(fd)){
    fbt_suicide_str("could not open loader\n");
  }

  uchar* buf = NULL;
  buf =  (uchar*)(uint64_t)do_guest_mmap(
      tld,
      0xA000000,
      siz,
      PROT_READ,
      MAP_SHARED,
      fd,
      0,
      "loader");

  if (!valid_result((uint64_t)buf)){
    fbt_suicide_str("mmapping loader failed\n");
  }

  Elf32_Ehdr* header = (Elf32_Ehdr*)buf;
  char* startaddr = (char*)(uint64_t)(header->e_entry + LOADOFF);

  for (int i=0; i<header->e_phnum; i++) {
    Elf32_Phdr* phdr = (Elf32_Phdr*)(buf + header->e_phoff + i * header->e_phentsize);

    if (phdr->p_type != PT_LOAD){
      continue;
    }

    char* wanted = (char*)(uint64_t)(phdr->p_vaddr + LOADOFF);
    char* rounded = (char*)(uint64_t)round_down_to_guest_pagesize((uint64_t)wanted);
    int required_size = phdr->p_memsz + (wanted-rounded);

    int hh = wanted-rounded;
    if (hh<0){
      fbt_suicide_str("problem in rounding in load loader\n");
    }

    uint64_t whrr;
    whrr = (uint64_t)rounded;

    char* res = (char*)(uint64_t)do_guest_mmap(
        tld,
        (guestptr_t)(uint64_t)rounded,
        required_size,
        PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
        -1,
        0,
        "some loader section");

    PRINT_DEBUG("mapped loadable segment at ");
    PRINT_DEBUG64((uint64_t)res);

    if (res != rounded){
      fbt_suicide_str("while loading loader mmap did not give desired address\n");
    }

    int j;
    for (j=0; j<phdr->p_filesz+hh; j++){
      ((char*)(uint64_t)(whrr))[j] = buf[phdr->p_offset - hh + j];
    }
  }

  fbt_syscall1(SYS64_close, fd);

  return (guestptr_t)(uint64_t)startaddr;
}


