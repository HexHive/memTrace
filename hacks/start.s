.globl _start
_start:
  popq    %rdi
  movq    %rsp, %rsi
  leaq    8(%rsi, %rdi, 8), %rdx
  call    mymain
  movq    %rax, %rbx
  movq    $60, %rax
  syscall
