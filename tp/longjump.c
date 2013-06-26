/*

Unittest used by test.sh

Do not modify (or if you do, alter test.sh accordingly)

*/

#include <stdio.h>
#include <setjmp.h>
 
static jmp_buf buf;

static int result = 0;
 
void second(void) {
  //  printf("second\n");         // prints
    result += 3;
    longjmp(buf,1);             // jumps back to where setjmp was called - making setjmp now return 1
}
 
void first(void) {
    second();
 //   printf("first\n");          // does not print
    result += 7;
}
 
int main() {   
    if ( ! setjmp(buf) ) {
        first();                // when executed, setjmp returns 0
    } else {                    // when longjmp jumps back, setjmp returns 1
//        printf("main\n");       // prints
	result += 5;
    }
 
    return result;
}

