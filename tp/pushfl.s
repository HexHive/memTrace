.globl _start
_start:
  mov $300000000, %rdx
loop:
  pushf #to see difference
  popf #to see difference
  dec %rdx
  jne loop
  # exit syscall
  mov $0, %rdi
  mov $60, %eax
  syscall

