char c[256];

int gargoil();

int _start(){
c[0]='S';
c[1]='h';
c[2]='a';
c[3]='r';
c[4]='\n';
asm("movl $5, %%edx;" // msg len
    "mov %%eax,%%ecx;" // the message
    "movl $1, %%ebx;" // file desc
    "mov $4, %%eax;" // syscall nr
    "int $0x80;" // call kernel
    : :"a"(&c[0]));

//asm("int3");
int rs = gargoil();

asm("movl %%eax, %%ebx;" // exit code
    "mov $1, %%eax;" // syscall nr
    "int $0x80;"
    : :"a"(rs));
}

