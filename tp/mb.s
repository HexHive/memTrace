	.data
# DATA
astring:
        .ascii "tic\12\0"


	.bss
gugus:
	.byte 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	

        .text

tic:
        movl $4, %eax
        movl $1, %ebx
        movl $astring, %ecx
        movl $4, %edx
        int $0x80
	ret

.globl _start
_start:

	movl $1, %eax
	movl $0xFFFFFFFF, %ecx
lp1:
	dec %ecx
	cmp %ecx, %eax
	mov %ecx, gugus
	jnz lp1

	call tic


	mov $1, %edx
	movl $1, %eax
	movl $0x24000000, %ecx
	#movl $0x7FFFFFFF, %ecx
lp2:
	dec %ecx
	cmp %ecx, %eax
	mov %ecx, gugus(%edx)
	jnz lp2

	call tic


	mov $1, %edx
	movl $1, %eax
	movl $0x24000000, %ecx
	#movl $0x7FFFFFFF, %ecx
lp3:
	dec %ecx
	cmp %ecx, %eax
	mov %ecx, gugus(%edx)
	jnz lp3

	call tic

	#mov $1, %edx
	#movl $1, %eax
	#movl $0xFFFFFFFF, %ecx
#lp3:
	#dec %ecx
	#cmp %ecx, %eax
	#mov %ecx, gugus(%edx, %edx, 1)
	#jnz lp3

	call tic


	# and exit
	movl $1, %eax
	movl $0, %ebx
	int $0x80






















