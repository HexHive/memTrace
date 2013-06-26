#include <string.h>

char c[256];

int foo(){
asm("movl $5, %%edx;" // msg len
    "mov %%eax,%%ecx;" // the message
    "movl $1, %%ebx;" // file desc
    "mov $4, %%eax;" // syscall nr
    "int $0x80;" // call kernel
    : :"a"(&c[0]));
}

int _start(){
c[0]='H';
c[1]='e';
c[2]='l';
c[3]='l';
c[4]='\n';
asm("movl $5, %%edx;" // msg len
    "mov %%eax,%%ecx;" // the message
    "movl $1, %%ebx;" // file desc
    "mov $4, %%eax;" // syscall nr
    "int $0x80;" // call kernel
    : :"a"(&c[0]));

//asm("int3");
void* th = &strlen;
asm("nop");
int tehlen = strlen(&c[0]);

int (*f)();
f = foo;

while (1){
f();
}


asm("movl %%eax, %%ebx;" // exit code
    "mov $1, %%eax;" // syscall nr
    "int $0x80;"
    : :"a"(42));
}

