	.data
# DATA
astring:
        .ascii "string\12\0"
gugusstring:
        .ascii "gugus_gugus_gugus_gugus\12\0"


	.bss
gugus:
	.byte 64,0
	

        .text

.globl _start
_start:

	# copy string
	cld
	leal gugus, %edi
	movl $8, %ecx
 	movl $73, %eax # ascii for 'I'		
	rep stosb

	# output it
	movl $4, %eax
	movl $1, %ebx
	movl $gugus, %ecx
	movl $8, %edx
	int $0x80

        leal astring, %edi # Starting address
        movb $0, %al    # Byte to search for (NUL)
        movl $-1, %ecx  # no limit
        cld               
        repne scasb
        mov $-2, %eax   # ECX will be -2 for length 0, -3 for length 1, ...
        sub %ecx, %eax  # Length in EAX

	cmp $7, %eax
        je pass
	hlt
pass:

	# and exit
	movl $1, %eax
	movl $0, %ebx
	int $0x80

        jmp *%eax # never reached 

