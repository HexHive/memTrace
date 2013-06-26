.globl _fbt_generic_64bit_syscall

# The linux 64 function calling convention uses
# rdi, rsi, rdx, rcx, r8, r9

# The linux64 syscall convention uses
# rdi, rsi, rdx, r10, r8, r9

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

