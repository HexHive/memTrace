
#include "lib2.h"

int global2;
int global3 = 41;

void func() {
  if (global2 == 42)
    global2 = 42;
}

const char *method(int a) {
  /* This adds a relocation entry of type R_386_RELATIVE and therefore
     test the loaders ability to handle this */
  static const char *msg = "\n\nTest \"relocations\" successful.\n\n";

  if (global2 == 42)
    return msg;
  else
    return "Error\n";
}
