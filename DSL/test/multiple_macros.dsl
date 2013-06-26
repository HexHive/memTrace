#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>

typedef void (*void_func)(void);
typedef int (*int_func)(void);

typedef unsigned long ulong_t;

void a() {
    printf("a()\n");
}

void b() {
    printf("b()\n");
}

int main(int argc, char *argv) {
    char *target = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    void_func f = (void_func)target;
    
    // Start a shell
    BEGIN_ASM(target)
        call_abs {&a}
        call_abs {&b}
        ret
    END_ASM()

    f();
    

    munmap(target, 4096);    

    return 0;
}
