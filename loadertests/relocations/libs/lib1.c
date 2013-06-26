
#include "lib1.h"

extern void func();

/* This adds an R_386_GLOB_DAT entry in the relocation section. 
   This checks if the loader updates the GOT entry to point to 
   the object in the application memory. */
int global = 42;

/* This is only referenced in this library */
int local = 10;

/* This adds an DT_INIT entry to the dynamic section, should
   be called after loading of shared library. */
void _init (void) {
  local = 9;
}

void _fini (void) {
  // TODO
}

const char *get_string (int param) {

  /* This adds an R_386_32 entry in the relocation section. Global2
     is defined in lib2. This checks if the loader updates the 
     memory address. */
  static int *p = &global2;
  *p = 42;

  func();

  global3 = 42;

  if (global3 == 42 &&  global == 43 && local == 9) {
    const char *ret = method(global);
        
    return ret;
  }  else {
    return "Error\n";
  }
}

