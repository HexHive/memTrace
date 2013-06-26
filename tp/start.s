// This very simple function is
// needed as the restore function
// for signal handling
.global restorefun
restorefun:
        movl $15, %eax
        syscall
