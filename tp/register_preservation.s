/*

Unittest used by test.sh

Do not modify (or if you do, alter test.sh accordingly)

*/

        .text

# DATA
successstring:
        .ascii "SUCCESS\12\0"
teststring:
        .ascii "teststring\12\0"
failstring:
        .ascii "FAIL\12\0"

fail:
	movl $4, %eax
	movl $1, %ebx
	movl $failstring, %ecx
	movl $5, %edx
	int $0x80

	movl $1, %eax
	movl $1, %ebx
	int $0x80
	hlt

# Function that writes a characteristic pattern in gp registers
write_pattern:
	movl $0xdeadbeef, %eax
	movl $0xc0ffeeee, %ebx
	movl $0x13371337, %ecx
	movl $0xf00df00d, %edx
	movl $0xfa1affe1, %ebp
	movl $0xabbaabba, %esi
	movl $0xdadafafa, %edi
	#int3
	ret

# Function that writes a characteristic pattern in gp registers
check_pattern:
	cmp $0xdeadbeef, %eax
	jne fail
	cmp $0xc0ffeeee, %ebx
	jne fail
	cmp $0x13371337, %ecx
	jne fail
	cmp $0xf00df00d, %edx
	jne fail
	cmp $0xfa1affe1, %ebp
	jne fail
	cmp $0xabbaabba, %esi
	jne fail
	cmp $0xdadafafa, %edi
	jne fail
	ret

testfun:
	nop
	ret

carabas1:
	nop
	jmp contit1

carabas2:
	nop
	jmp contit2

dosyscall_write:
	pushl %eax
	pushl %ebx
	pushl %ecx
	pushl %edx
	movl $4, %eax
	movl $1, %ebx
	movl $teststring, %ecx
	movl $11, %edx
	int $0x80
        # eax has the return value, the others should be preserved
	cmpl $1, %ebx
	jne fail
	cmpl $teststring, %ecx
	jne fail
	cmpl $11, %edx
	jne fail
	popl %edx
	popl %ecx
	popl %ebx
	popl %eax
	ret

.globl _start
_start:
	call write_pattern

# test if pattern same after doing nothing
	call check_pattern


# test if pattern same after conditional jump
	cmp %eax, %eax
	jne foo
	nop
foo:
	call check_pattern

# test if pattern same after indirect jump (eax untested)
	#jmp contit
	push %eax
	mov  $carabas1, %eax
	jmp *%eax
contit1:
	pop %eax
	call check_pattern

# test if pattern same after indirect jump (eax tested)
	#jmp contit
	push %ebx
	mov  $carabas2, %ebx
	jmp *%ebx
contit2:
	pop %ebx
	call check_pattern

# test if pattern same after indirect call (eax untested)
	#jmp contit
	push %eax
	mov  $testfun, %eax
	call *%eax
	pop %eax
	call check_pattern

# test if pattern same after indirect call (eax tested)
	#jmp contit
	push %ebx
	mov  $testfun, %ebx
	call *%ebx
	pop %ebx
	call check_pattern

# test if pattern same after doing a syscall call
	#jmp contit
	call dosyscall_write
	call check_pattern

# test pushf and popf
        mov %esp, %ebx
	mov $4, %eax
        cmp $4, %eax
        pushf
        cmp $5, %eax
        popf
	jne fail
        cmp %esp, %ebx
	jne fail

        mov %esp, %ebx
	mov $4, %eax
        cmp $4, %eax
        cmp $5, %eax
	je fail
        cmp %esp, %ebx
	jne fail

# test push with esp
       # TODO
        

	# if we have not failed yet we may 
	# write that we were successful
	movl $4, %eax
	movl $1, %ebx
	movl $successstring, %ecx
	movl $8, %edx
	int $0x80

	# and exit
	movl $1, %eax
	movl $0, %ebx
	int $0x80

