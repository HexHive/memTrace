        .bss
gugus:
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0

gaga:
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0

dada:
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0

stk:
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0
        .byte 0,0,0,0,0,0,0,0

.text

# DATA
successstring:
        .ascii "SUCCESS\12\0"
teststring:
        .ascii "teststring\12\0"
failstring:
        .ascii "FAIL\12\0"


.globl _start
_start:
        mov $stk, %rsp # setup stack

        mov    %rsp,%r9
   	movabs $gugus,%r8
   	lea    0x8(%r8),%rsp
   	pushfq 
   	mov    %r9,%rsp

	mov    %rsp,%r9
	movabs $gugus,%r8
	mov    %r8,%rsp
	popfq  
	mov    %r9,%rsp

	mov    $gaga,%ebx
	mov    %edi,0x8(%esp)
	mov    (%ebx),%eax
	mov    %esi,(%esp)

	mov    %rsp,%r9
	movabs $dada,%r8
	lea    0x8(%r8),%rsp
	pushfq 
	movabs $gugus,%r8
	mov    (%r8),%r13
	movabs $dada,%r8
	mov    (%r8),%r14
	cmp    %r13,%r14
	je     pass
	int3   
pass:
	mov    %r9,%rsp

	# and exit
	movl $1, %eax
	movl $0, %ebx
	int $0x80

