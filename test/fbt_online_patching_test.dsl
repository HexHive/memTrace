#include "gtest/gtest.h"

#if defined(ONLINE_PATCHING)

#include <sys/mman.h>

#include "libfastbt.h"
#include "patching/fbt_patching.h"

/** Function taking no arguments and returning an integer */
typedef int (*int_func)(void);

/** Function taking no arguments and returning no value */
typedef void (*void_func)(void);

/** Needed for call_abs / jmp_abs macros */
void fllwrite(...) {}

/* == Patch generation macros ==
 * The following contains macros to generate patches, which will automatically
 * fill in all the data in the change instances. 
 */

/** Begins a new list of <code>changes</code> which will be available at
  * <code>base_addr</code> and has code generated at <code>transl</code>
  */
#define BEGIN_PATCH_GENERATION(base_addr, changes, transl) \
  { \
  int _changes_counter = 0; \
  struct change *_changes = changes; \
  long _addr = base_addr; \
  char *_transl = transl; \
  char *_old_transl; \

#define BEGIN_INSTR \
  _old_transl = _transl; \
  _changes[_changes_counter].machine_code = _transl;

#define END_INSTR \
  _changes[_changes_counter].offset = _addr; \
  _changes[_changes_counter].generation_addr = (unsigned)_old_transl; \
  _changes[_changes_counter].original_instr_len = (_transl - _old_transl); \
  _changes[_changes_counter].num_bytes = (_transl - _old_transl); \
  _addr += (_transl - _old_transl); \
  ++_changes_counter; \
  
#define END_PATCH_GENERATION \
  }  \


/** Allocates memory that with read-write-execute permissions that can be used
  * to generate code at runtime
  *
  * @param size Number of bytes to allocate
  * @return Pointer to start of allocated memory black
  */
static char *allocate_code_memory(long size) {
  /* We need space to store size of memory area */
  size += sizeof(long);

  char *result = (char *)mmap(
    0,
    size,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  );

  /* Store size */
  *((long *)result) = size;

  /* Return memory not used for internal management */
  return result + sizeof(long);
}

/** Frees memory previously allocated by <code>allocate_code_memory</code>
  *
  * @param Pointer to start of  memory region returned from <code>allocate_code_memory</code> 
  */
static void free_code_memory(char *mem) {
  /* retrieve stored size */
  long *start = ((long *)mem) - 1;
  long size = *start;

  /* free memory */
  munmap(start, size);
}
  
/** Generates a very simple function and introduces it using a patch and
 then calls it */
TEST(OnlinePatching, Return)
{
  /* Create the pach that we will apply */
  char *codemem = allocate_code_memory(1024);
  char *target = codemem;
  
  long base_addr = 0x1337;
  
  struct change changes[2] = {
    { base_addr, 0, 5, 5, NULL},
    { base_addr+5, 0, 1, 1, NULL}   
  };

  struct patching_information pi;
  pi.version = 1;
  pi.mem_pool = NULL;
  pi.changes = changes;
  pi.num_changes = 2;
  
  changes[0].machine_code = target;
  BEGIN_ASM(target)
    movl $0xC0FFEE, %eax
  END_ASM

  changes[1].machine_code = target;  
  BEGIN_ASM(target)
    ret
  END_ASM
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);
  
  int_func f = (int_func)base_addr;

  fbt_start_transaction(tld, fbt_commit_transaction);
  int result = f();
  fbt_commit_transaction();
  
  EXPECT_EQ(0xC0FFEE, result);
  
  fbt_exit(tld);
  
  free_code_memory(codemem);
} 

/** Tests generated indirect jump */
TEST(OnlinePatching, IndirectJump)
{
  
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[4];

  struct patching_information pi;
  pi.version = 1;
  pi.mem_pool = NULL;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  long jump_target = (long)target;
  
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  void_func f = (void_func)base_addr;
  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      jmp *{&jump_target}
    END_ASM
    END_INSTR
  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);

  free_code_memory(orig_target);
}

/** Tests generated indirect call */
TEST(OnlinePatching, IndirectCall)
{
  
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[3];

  struct patching_information pi;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  long jump_target = (long)target;
  
  BEGIN_ASM(target)
    movl 4(%esp), %eax
    addl $0x4000, %eax
    movl %eax, {&flag}
    leal 8(%esp), %esp
    ret
  END_ASM

  void_func f = (void_func)base_addr;
  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      pushl $0x024f
    END_ASM
    END_INSTR

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      call *{&jump_target}
    END_ASM
    END_INSTR

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      ret
    END_ASM
    END_INSTR

  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(0x424f, flag);
  
  fbt_exit(tld);

  free_code_memory(orig_target);
}
  
/** Tests generated relative jump */
TEST(OnlinePatching, RelativeJump)
{
  /* Create the pach that we will apply */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[1] = {
    { base_addr, 0, 0, 0, NULL } 
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  long jump_target = (long)target;
  
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  void_func f = (void_func)base_addr;
  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      jmp_abs {jump_target}
    END_ASM
    END_INSTR
  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);
  
  free_code_memory(orig_target);
}

/** Tests generated relative jump (relocated) */
TEST(OnlinePatching, RelativeJumpRelocated)
{
  /* Create the pach that we will apply */

  char *gen_target = allocate_code_memory(1024);  
  char *target = allocate_code_memory(1024);

  char *orig_gen_target = gen_target;

  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[] = {
    { base_addr, (long)gen_target, 5, 5, NULL } 
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  /* Create return trampoline that is not part of the patch */
  long jump_target = (long)target;
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  /* Generate code for patch */
  BEGIN_ASM(gen_target)
    jmp_abs {jump_target}
  END_ASM

  /* Copy generated code */
  char *offset = target;
  changes[0].machine_code = offset;
  memcpy(offset, orig_gen_target, 5);
  free_code_memory(orig_gen_target);


  /* Start libdetox, call patched function in a transaction */
  void_func f = (void_func)base_addr;
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);

  free_code_memory(target);
}

/** Retrieve EIP in patched instructions */
TEST(OnlinePatching, RetrieveEIP)
{
  /* Create the pach that we will apply */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  
  struct change changes[3];

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);
  
  BEGIN_ASM(target)
    movl $100, %eax
    ret
  END_ASM

  char *patch_target = target;

  int_func f = (int_func)base_addr;
  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      call_abs {patch_target + 5}
    END_ASM
    END_INSTR

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      popl %eax
    END_ASM
    END_INSTR 

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      ret
    END_ASM
    END_INSTR    
  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  long eip = f();
  fbt_commit_transaction();
  
  EXPECT_EQ(base_addr + 5, eip);
  
  fbt_exit(tld);
  
  free_code_memory(orig_target);
}

/** Retrieve EIP in patched instructions with indirect call*/
TEST(OnlinePatching, RetrieveEIPWithIndirectCall)
{
  /* Create the pach that we will apply */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  
  struct change changes[3];

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  long jump_target = base_addr + 6;

  int_func f = (int_func)base_addr;

  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      call *{&jump_target}
    END_ASM
    END_INSTR

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      popl %eax
    END_ASM
    END_INSTR 

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      ret
    END_ASM
    END_INSTR    
  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  long eip = f();
  fbt_commit_transaction();
  
  EXPECT_EQ(base_addr + 6, eip);
  
  fbt_exit(tld);
  
  free_code_memory(orig_target);
}


/** Tests generated relative call */
TEST(OnlinePatching, RelativeCall)
{
  /* Create the pach that we will apply */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[4];

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  long jump_target = (long)target;
  
  BEGIN_ASM(target)
    movl $100, %eax
    ret
  END_ASM

  void_func f = (void_func)base_addr;
  BEGIN_PATCH_GENERATION(base_addr, changes, target)
    BEGIN_INSTR
    BEGIN_ASM(_transl)
      call_abs {jump_target}
    END_ASM
    END_INSTR

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      addl $10, %eax
    END_ASM
    END_INSTR 

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      movl %eax, {&flag}
    END_ASM
    END_INSTR 

    BEGIN_INSTR
    BEGIN_ASM(_transl)
      ret
    END_ASM
    END_INSTR    
  END_PATCH_GENERATION
  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(110, flag);
  
  fbt_exit(tld);
  
  free_code_memory(orig_target);
}

/** Tests generated relative call (relocated) */
TEST(OnlinePatching, RelativeCallRelocated)
{
  /* Create the pach that we will apply */

  char *gen_target = allocate_code_memory(1024);  
  char *target = allocate_code_memory(1024);

  char *orig_gen_target = gen_target;

  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[] = {
    { base_addr, (long)gen_target, 1, 5, NULL },
    { base_addr+1, (long)gen_target+5, 1, 1, NULL },
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  /* Create return trampoline that is not part of the patch */
  long jump_target = (long)target;
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  /* Generate code for patch */
  BEGIN_ASM(gen_target)
    call_abs {jump_target} // offset: 0
    ret // offset: 5
  END_ASM

  /* Copy generated code */
  char *offset = target;
  changes[0].machine_code = offset;
  changes[1].machine_code = offset + 5;
  memcpy(offset, orig_gen_target, gen_target - orig_gen_target);
  free_code_memory(orig_gen_target);


  /* Start libdetox, call patched function in a transaction */
  void_func f = (void_func)base_addr;
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);

  free_code_memory(target);
}

/** Tests generated indirect call (relocated) */
TEST(OnlinePatching, IndirectCallRelocated)
{
  /* Create the pach that we will apply */

  char *gen_target = allocate_code_memory(1024);  
  char *target = allocate_code_memory(1024);

  char *orig_gen_target = gen_target;
  char *orig_target = target;

  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[] = {
    { base_addr, (long)gen_target, 1, 5, NULL },
    { base_addr+1, (long)gen_target+6, 1, 1, NULL },
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  /* Create return trampoline that is not part of the patch */
  long jump_target = (long)target;
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  /* Generate code for patch */
  BEGIN_ASM(gen_target)
    call *{&jump_target} // offset: 0
    ret // offset: 6
  END_ASM

  /* Copy generated code */
  char *offset = target;
  changes[0].machine_code = offset;
  changes[1].machine_code = offset + 6;
  memcpy(offset, orig_gen_target, gen_target - orig_gen_target);
  free_code_memory(orig_gen_target);


  /* Start libdetox, call patched function in a transaction */
  void_func f = (void_func)base_addr;
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);

  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);

  free_code_memory(orig_target);
}


/** Tests generated relative jump to label */
TEST(OnlinePatching, RelativeLocalJump)
{
  /* This is where we will generate our code */
  char *gen_target = allocate_code_memory(1024);
  char *orig_gen_target = gen_target;

  /* This is where we will copy the generated code to test that online patching
  correctly retranslates relative locations based on the original_addr */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;
  
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[] = {
    { base_addr,   (unsigned)gen_target, 5, 5, target },
    { base_addr+2, (unsigned)gen_target+2, 2, 2, target + 2},
    { base_addr+4, (unsigned)gen_target+4, 1, 1, target + 4},    
    { base_addr+5, (unsigned)gen_target+5, 10, 10, target + 5},    
    { base_addr+15, (unsigned)gen_target+15, 1, 1, target + 15},      
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);
  
  /* objdump of assembly code
  00000000 <after-0x5>:
     0: 39 c0                 cmp    %eax,%eax
     2: 74 01                 je     5 <after>
     4: c3                    ret    

  00000005 <after>:
     5: c7 05 37 13 37 13 01  movl   $0x1,0x13371337
     c: 00 00 00 
     f: c3
  */  

  changes[0].machine_code = target;
  BEGIN_ASM(target)
    cmpl %eax, %eax
    jmp after
    ret
  after:
    movl $1, {&flag}
    ret
  END_ASM  

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);
  
  void_func f = (void_func)base_addr;

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(1, flag);
  
  fbt_exit(tld);
  
  free_code_memory(orig_gen_target);
  free_code_memory(orig_target);
}
  
/** Tests generated conditional jump */
TEST(OnlinePatching, ConditionalLocalJump)
{
  /* This is where we will generate our code */
  char *gen_target = allocate_code_memory(1024);
  char *orig_gen_target = gen_target;
  void_func f = (void_func)gen_target;

  /* This is where we will copy the generated code to test that online patching
  correctly retranslates relative locations based on the original_addr */
  char *target = allocate_code_memory(1024);
  char *orig_target = target;

  long flag = 0;
  
  struct change changes[] = {
    // offset / original_addr / num_original / num_bytes / data
    { (unsigned)gen_target, (unsigned)gen_target, 2, 2, target },
    { (unsigned)gen_target+2, (unsigned)gen_target+2, 2, 2, target + 2},
    { (unsigned)gen_target+4, (unsigned)gen_target+4, 1, 1, target + 4},    
    { (unsigned)gen_target+5, (unsigned)gen_target+5, 10, 10, target + 5},    
    { (unsigned)gen_target+15, (unsigned)gen_target+15, 1, 1, target + 15},      
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);
  
  /* objdump of assembly code
  00000000 <after-0x5>:
     0: 39 c0                 cmp    %eax,%eax
     2: 74 01                 je     5 <after>
     4: c3                    ret    

  00000005 <after>:
     5: c7 05 37 13 37 13 01  movl   $0x1,0x13371337
     c: 00 00 00 
     f: c3
  */  

  char *original_gen_target = gen_target;
  BEGIN_ASM(gen_target)
    cmpl %eax, %eax
    je after
    ret
  after:
    movl $1, {&flag}
    ret
  END_ASM  

  /* Run code without binary translator */
  f();
  EXPECT_EQ(1, flag);
  flag = 0;

  /* Copy code to target, remove gen_target */
  memcpy(target, original_gen_target, 1024);
  memset(original_gen_target, 0xc3, 1024);

  /* Start libdetox, call patched function in a transaction */
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  fbt_exit(tld);

  EXPECT_EQ(1, flag);  
  
  free_code_memory(orig_gen_target);
  free_code_memory(orig_target);
}

/** Tests generated conditional jump (relocated) */
TEST(OnlinePatching, ConditionalJumpRelocated)
{
  char *gen_target = allocate_code_memory(1024);  
  char *orig_gen_target = gen_target;
  
  char *target = allocate_code_memory(1024);
 
  long base_addr = 0x1337;
  long flag = 0;
  
  struct change changes[5] = {
    { base_addr, (long)gen_target, 3, 3, NULL },
    { base_addr+3, base_addr+3, 2, 2, NULL },
    { base_addr+5, (long)gen_target+5, 5, 5, NULL },
    { base_addr+10, (long)gen_target+10, 10, 10, NULL },
    { base_addr+20, (long)gen_target+20, 1, 1, NULL } 
  };

  struct patching_information pi;
  pi.mem_pool = NULL;
  pi.version = 1;
  pi.changes = changes;
  pi.num_changes = sizeof(changes) / sizeof(changes[0]);

  /* Create return trampoline that is not part of the patch */
  long jump_target = (long)target;
  BEGIN_ASM(target)
    movl $1, {&flag}
    ret
  END_ASM

  /* Generate code for patch */
  BEGIN_ASM(gen_target)
      cmpl $0, %esp    // offset 0
      jne after         // offset 3
      jmp_abs {jump_target}  // offset 5
    after:
      movl $2, {&flag} // offset 10
      ret              // offset 20
  END_ASM

  /* Copy generated code */
  char *offset = target;
  changes[0].machine_code = offset;
  changes[1].machine_code = offset+3;
  changes[2].machine_code = offset+5;
  changes[3].machine_code = offset+10;
  changes[4].machine_code = offset+20;
  memcpy(offset, orig_gen_target, gen_target - orig_gen_target);
  free_code_memory(orig_gen_target);


  /* Start libdetox, call patched function in a transaction */
  void_func f = (void_func)base_addr;
  struct thread_local_data *tld = fbt_init(NULL);
  fbt_apply_patch(tld, &pi, OP_ONLINE);

  fbt_start_transaction(tld, fbt_commit_transaction);
  f();
  fbt_commit_transaction();
  
  EXPECT_EQ(2, flag);
  
  fbt_exit(tld);

  free_code_memory(target);
}
  
#endif /* ONLINE_PATCHING */