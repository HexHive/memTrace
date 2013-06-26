#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

char c[256];
char q[256];
char r[256];

int main(){
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
strcpy(q,c);
int tehlen = strlen(&q[0]);
write(1, "gugus\n", 6);
sleep(1);
write(1, "hahaha!!\n", 9);
memset(&r[0], 0xfa, 256);
asm("movl %%eax, %%ebx;" // exit code
    "mov $1, %%eax;" // syscall nr
    "int $0x80;"
    : :"a"(tehlen));
}

