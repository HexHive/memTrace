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





