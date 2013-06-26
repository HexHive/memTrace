/* syscall parameters go to: EBX, ECX, EDX, ESI, EDI, EBP */
.globl ekrclone
ekrclone:
    push %ebx
    push %ecx
    push %edx
    push %esi
    push %edi
    push %ebp

    /* first parameter is at 28(%esp) */

    mov 28(%esp), %ebp   /* save functiona addr in reg as we'll loose stack */

    mov $120, %eax       /* clone system call number */
    mov 36(%esp), %ebx   /* flags -> param 1 of system call*/
    mov 32(%esp), %ecx   /* stack -> param 2 of system call */
    mov 40(%esp), %edx   /* ptid -> param 3 of system call */
    mov 44(%esp), %esi   /* tls -> param 4 of system call */
    mov 48(%esp), %edi   /* ctid -> param 5 of system call */
    /*int3*/
    int $0x80

    cmp $0, %eax
    jne return
  
    /* call function */
    call *%ebp

    /* exit */
    mov $1, %eax  /* exit system call number */
    mov $0, %ebx  /* return code */
    int $0x80

return:

    pop %ebp
    pop %edi
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx

    ret

