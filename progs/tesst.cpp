#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <unistd.h>
#include <dlfcn.h>

#include <errno.h>

using namespace std;

char xx[15];

void test() {
  cout << "inside test" << endl;
}

int main(int argc, char** argv)
{
  xx[0] = 15;
  
  test();
  xx[1] = 13;
  cout << "HALLO" << endl;
  xx[2] = 14;
  test();

  xx[3] = xx[0];

  cout << xx[0] << endl;
  
  return 0;
}
