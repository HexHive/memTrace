	.bss
gugus:
	.byte 64,0
	

        .text

.globl _start
_start:
	movw $0xffff, %bx
	movzxw %bx, %eax
	cmpl $0xffff, %eax
	jne fail

	leal gugus, %edi
	movl $0xffff, (%edi)
	movzxw (%edi), %eax
	cmpl $0xffff, %eax
	jne fail

	leal gugus, %edi
	movl $0xff, (%edi)
	movzxb (%edi), %eax
	cmpl $0xff, %eax
	jne fail

	# successful exit
	movl $1, %eax
	movl $0, %ebx
	int $0x80

fail:
	# failing exit
	movl $1, %eax
	movl $1, %ebx
	int $0x80
