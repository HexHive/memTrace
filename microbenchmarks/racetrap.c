#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

int main() {
  char buf[16];
  int fd;
  if (access("file", R_OK) != 0) {
    return 1;
  }
  /* race opportunity */
  sleep(1);
  
  fd = open("file", O_RDONLY);
  int len = read(fd, buf, 16);
  buf[len] = 0x0;
  printf("read: '%s' (%d), expected: 'foo'\n", buf, len);
  fflush(0);
  return 0;
}
