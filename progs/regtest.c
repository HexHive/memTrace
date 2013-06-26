
int main()
{
  __asm__("movl $0x20, %eax\n"
	  "movl $0x21, %ecx\n"
	  "movl $0x22, %edx\n"
	  "movl $0x23, %ebx\n"
	  "movl $0x24, %esp\n"
	  "movl $0x25, %ebp\n"
	  "movl $0x26, %esi\n"
	  "movl $0x27, %edi\n");
}
