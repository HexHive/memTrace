#define _GNU_SOURCE   

#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>

int execute_clone(void *arg)

{
int i;
//	for (i=1;i<1000; i++)
{
        printf("\nclone function Executed....Sleeping\n");
        fflush(stdout);}
        return 0;
}

int main()

{
int i;
        void *ptr;

        int rc;
        void *start =(void *) 0x000001000000;
        size_t len = 0x000000000020000;

        ptr = mmap(start, len, PROT_WRITE,    
                      MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED|MAP_GROWSDOWN, 0, 0);
        if(ptr == (void *)-1) {
                perror("\nmmap failed");
        }

        rc = clone(&execute_clone, ptr + len, CLONE_VM, NULL);


        if(rc <= 0) {
                perror("\nClone() failed");
        }

//	for (i=1;i<1000; i++)
        	printf("\nmain\n");
        sleep(3);
}

