#include <exception>
#include <new>
#include <memory>
#include <cstdlib>
#include <cstdio>

#include "fbt_lmem_api.h"

static void* lmem_allocate(size_t size) {
  std::printf("New of library called\n");
  char* block=(char*)std::malloc(size+12);
  if (block == 0) // did malloc succeed?
    throw std::bad_alloc(); // ANSI/ISO compliant behavior

  char* res_begin = block + 8;
  char* res_end = block + 8 + size;

  // store the size of the block in the first four bytes
  *((unsigned*)block) = 0xdeadbeef;
  *(((unsigned*)block)+1) = size;

  lmem_protect(block+0);
  lmem_protect(block+1);
  lmem_protect(block+2);
  lmem_protect(block+3);
  lmem_protect(block+4);
  lmem_protect(block+5);
  lmem_protect(block+6);
  lmem_protect(block+7);
  lmem_protect(res_end);
  lmem_protect(res_end+1);
  lmem_protect(res_end+2);
  lmem_protect(res_end+3);

  return res_begin;
}

static void lmem_deallocate(void* addr) {
  std::printf("Deallocate called\n");
  std::fflush(stdout);


  if (addr == 0){
    return;
  }

  char* block = (char*)addr-8;

  std::printf("Unprotecting\n");
  std::fflush(stdout);

  /* to be able to read the tag*/
  lmem_unprotect(block+0);
  lmem_unprotect(block+1);
  lmem_unprotect(block+2);
  lmem_unprotect(block+3);
  lmem_unprotect(block+4);
  lmem_unprotect(block+5);
  lmem_unprotect(block+6);
  lmem_unprotect(block+7);

  std::printf("Unprotected\n");
  std::fflush(stdout);


  unsigned tag = *((unsigned*)block);
  if (tag != 0xdeadbeef){
    std::printf("WARNING: WAS NOT ALLOCATED BY US: IGNORING\n");
    return;
  }

  size_t size = *(((unsigned*)block)+1);
  char* res_end = block + 8 + size;


  lmem_unprotect(res_end);
  lmem_unprotect(res_end+1);
  lmem_unprotect(res_end+2);
  lmem_unprotect(res_end+3);

  std::free(block);
}

__attribute__((visibility("default")))
void* operator new(size_t size) {
  return lmem_allocate(size);
}

__attribute__((visibility("default")))
void operator delete(void* addr) {
  return lmem_deallocate(addr);
}

__attribute__((visibility("default")))
void* operator new[](size_t size) {
  return lmem_allocate(size);
}

__attribute__((visibility("default")))
void operator delete[](void* addr) {
  return lmem_deallocate(addr);
}
