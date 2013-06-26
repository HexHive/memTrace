
/*
 The linux 64 function calling convention uses
 rdi, rsi, rdx, rcx, r8, r9

 The linux64 syscall convention uses
 rdi, rsi, rdx, r10, r8, r9
*/
.globl _fbt_generic_64bit_syscall
_fbt_generic_64bit_syscall:
	push   %rbp
	mov    %rsp,%rbp

	push %r10

	# the only mismatch is the fourth arg
	mov %rcx, %r10

	# syscall number in rax
	mov    0x10(%rbp),%rax
	syscall

	pop %r10

	leaveq
	retq

/*
 The linux 64 function calling convention uses
 rdi, rsi, rdx, rcx, r8, r9

 The linux32 syscall convention uses
 %ebx, %ecx, %edx, %esi, %edi, %ebp
*/
.globl _fbt_traditional_32bit_syscall
_fbt_traditional_32bit_syscall:
	push   %rbp
	mov    %rsp,%rbp

	/* syscall number in rax (seventh parameter) */
    mov    0x10(%rbp),%rax

    /* save registers that we will modify */
    push %rbx
    push %rcx
    push %rdi
    push %rbp

    mov %edi, %ebx  /* first param */
    xchg %esi, %ecx  /* second param and fourth param must get swapped */
    /* third already in edx */
    mov %r8d, %edi
    mov %r9d, %ebp

    /* traditional call (with 32 bit syscall numbers!) */
    int $0x80

    /* restore registers that we modified */
    pop %rbp
    pop %rdi
    pop %rcx
    pop %rbx

	leaveq
	retq


