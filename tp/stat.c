#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

struct stat buffer;
struct stat buffer2;

int main()
{
  int status;

  status = stat("tp/testfile.txt", &buffer);
  if (status == -1){
    return 250;
  }
  assert(status == 0);
  assert(buffer.st_size == 23);

  status = lstat("tp/testfile.txt", &buffer2);
  if (status == -1){
    return 250;
  }
  assert(status == 0);
  assert(buffer2.st_size == 23);

  status = fstat(1, &buffer2); // stat stdout
  if (status == -1){
    assert(0);
    return 250;
  }
  assert(status == 0);

  return buffer.st_size;
}

