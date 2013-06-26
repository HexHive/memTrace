/**
 * Unit tests for the memory management unit
 *
 * Copyright (c) 2010 ETH Zurich
 *   Mathias Payer <mathias.payer@nebelwelt.net>
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
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "gtest/gtest.h"

#include "libfastbt.h"

TEST(DynaraceDeathTest, Fileracecondition)
{
#if defined(AUTHORIZE_SYSCALLS) && defined(DYNARACE)
  /* prepare file */
  int fd = open("file", O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  int foo;
  char buf[16];
  strcpy(buf, "foobar");
  foo = write(fd, &buf, strlen(buf));
  close(fd);

  if (fork() == 0) {
    /* child process */
    sleep(1);
    printf("changing file");
    unlink("file");
    fd = open("file", O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
    strcpy(buf, "raced");
    foo = write(fd, &buf, strlen(buf));
    close(fd);
    _exit(0);
  }
  /* test process */
  ASSERT_EXIT({
      struct thread_local_data *tld = fbt_init(NULL);
      fbt_start_transaction(tld, fbt_commit_transaction);
      char buf[16];
      int fd;
      if (access("file", R_OK) != 0) {
        printf("Something is wrong!\n");
      }
      /* race opportunity */
      sleep(3);
      
      fd = open("file", O_RDONLY);
      int len = read(fd, buf, 16);
      buf[len] = 0x0;
      printf("read: '%s' (%d), expected: 'foobar'\n", buf, len);
      fflush(0);
      fbt_commit_transaction();
      fbt_exit(tld);
#if defined(DEBUG)
    }, ::testing::ExitedWithCode(255), "");
#else
    }, ::testing::KilledBySignal(11), "");
#endif  /* DEBUG */
#else   /* AUTHORIZE_SYSCALLS && DYNARACE */
  printf("Race detection support missing\n");
#endif  /* AUTHORIZE_SYSCALLS && DYNARACE */
}
