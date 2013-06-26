/**
 * The entry point of the program.
 * Calls main passing argc and argv to it.
 */
.globl _start
_start:
  popq    %rdi                         /* this is argc, must be 2 for one argument */
  movq    %rsp, %rsi                  /* second argument (char** argv) */
  leaq    8(%rsi, %rdi, 8), %rdx      /* first environment variable */
  call    main
  movq    %rax, %rbx
  movq    $1,%rax   # system call 1
  int     $0x80

/**
 * This very simple function is
 * needed as the restore function
 * for installing signal handlers.
 * (see the musl C library)
 */
.global restorefun
restorefun:
  movl $15, %eax
  syscall

/*
   Linux x64 calling convention passes parameters in
   RDI, RSI, RDX, RCX, R8, and R9

   void sighelper(void* where,
                  void* stackarea,
                  void** wheretosavestack,
                  void** wheretosaveip,
                  void* sighandleraddr,
                  BOOL lock);
   */
.global sighelper
sighelper:

  push %rax
  push %rbx
  push %rcx
  push %rdx
  push %rsi
  push %rdi
  push %rbp

  push %r8
  push %r9
  push %r10
  push %r11
  push %r12
  push %r13
  push %r14
  push %r15

  /* the lMem constants... important to keep in synch with C-code.
     an improvement would surely be to use the #defines also here 
     in the assembly code */
  mov $0x100000000, %r15
  mov $0, %r12

  /* save the current stack */
  mov %rsp, (%rdx)

  /* switch to stack given in second parameter */
  mov %rsi, %rsp;

  /* save the ip where we want to return
     (somewhare in the middle of the many nops below) */
  lea 100(%rip), %rax
  mov %rax, (%rcx)

  /* jump to the first already translated block of the
     lmem_sigreturn routine, which expects the signal
     handler address (untranslated) in the eax register */
  mov %r8, %rax
  jmp *%rdi

  /* hundred nops */
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;
  nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;

  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %r11
  pop %r10
  pop %r9
  pop %r8

  pop %rbp
  pop %rdi
  pop %rsi
  pop %rdx
  pop %rcx
  pop %rbx
  pop %rax

  ret




/*
   Linux x64 calling convention passes parameters in
   RDI, RSI, RDX, RCX, R8, and R9

   void sigreturner(void** wheresavedstack,
                    void** wheresavedip);
   */
.global sigreturner
sigreturner:
  mov (%rdi), %rsp;  /* switch back stack  */
  jmp *(%rsi)         /* jump to saved rip */

/*
 The linux 64 function calling convention uses
 rdi, rsi, rdx, rcx, r8, r9

 The linux64 syscall convention uses
 rdi, rsi, rdx, r10, r8, r9 

 ekrclone64 mimicks the glibc clone() wrapper
*/
.globl ekrclone64
ekrclone64:
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

//    int3

    /* put arguments of function in r8, r9, ...*/

    mov %r8, %r12   /* parent tid ptr */
    mov %r9, %r13   /* child tid ptr  */
    mov 72(%rsp), %r14 /* tls pointer: seventh parameter is on the stack */

    mov %rdi, %r8    /* function address */
    mov %rsi, %r9    /* child stack */
    mov %rdx, %r10   /* flags */
    mov %rcx, %r11   /* argument for function */

//int3;
    /* kernel destroys rcs and r11 so lets keep
       the value in r10 */
    mov %r11, %r15

    /* fill in syscall arguments */
    mov %r10, %rdi   /* flags is first syscall param */
    mov %r9, %rsi    /* child stack is second syscall param */
    mov %r12, %rdx   /* */
    mov %r13, %r10   /* */
    xchg %r14, %r8    /* */
    mov $56, %rax     /* clone system call number */

// DEBUG
//mov $0xdadada01, %rbx
//mov $0xdadada02, %rcx
//mov $0xdadada03, %rdx
//mov $0xdadada04, %rsi
//mov $0xdadada05, %rdi
//mov $0xdadada06, %rbp
//mov $0xdadada07, %r8
//mov $0xdadada08, %r9
//mov $0xdadada09, %r10
//mov $0xdadada0a, %r11
//mov $0xdadada0b, %r12
//mov $0xdadada0c, %r13
//mov $0xdadada0d, %r14
//mov $0xdadada0e, %r15

//    int3
    syscall

    cmp $-1, %eax
    jne oook
    int3
    int3
    int3
oook:

    cmp $0, %eax
    jne return
  
    /* call function */
    mov %r15, %rdi
    call *%r14

    /* exit */
    mov $60, %rax  /* exit system call number */
    mov $0, %rdi  /* return code */
    syscall

return:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    ret





/*
 The linux 64 function calling convention uses
 rdi, rsi, rdx, rcx, r8, r9

 The linux64 syscall convention uses
 rdi, rsi, rdx, r10, r8, r9

 ekrclone64 mimicks the glibc clone() wrapper
*/
.globl mythreadstarter
mythreadstarter:

    /* put arguments of function in r8, r9, ...*/
    mov %rdi, %r8    /* transbeg */
    mov %rsi, %r9    /* stack */
    mov %rdx, %r10   /* regs */

    /* restore gp registers */
    mov   (%r10), %eax
    mov  4(%r10), %ebx
    mov  8(%r10), %ecx
    mov 12(%r10), %edx
    mov 16(%r10), %esi
    mov 20(%r10), %edi
    mov 24(%r10), %ebp

	/* set stack */
	mov %r9, %rsp

	/* set standard constants */
	mov $0x100000000, %r15
    mov $0, %r12

    /* THE RETURN VALUE IS ZERO */
    mov $0, %eax

	/* go! */
	jmp *%r8


