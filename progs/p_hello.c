/*
 * p_hello.c -- a hello program (in pthread)
 */
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

#define MAX_THREAD 1000

typedef struct {
	int id;
} parm;

void *hello(void *arg)
{
	parm *p=(parm *)arg;
	printf("Hello from node %d\n", p->id);
	return (NULL);
}

void main(int argc, char* argv[]) {
	int n,i;
	pthread_t *threads;
	pthread_attr_t pthread_custom_attr;
	parm *p;

	if (argc != 2)
	{
		printf ("Usage: %s n\n  where n is no. of threads\n",argv[0]);
		exit(1);
	}

	n=atoi(argv[1]);

	if ((n < 1) || (n > MAX_THREAD))
	{
		printf ("The no of thread should between 1 and %d.\n",MAX_THREAD);
		exit(1);
	}

	threads=(pthread_t *)malloc(n*sizeof(*threads));
	pthread_attr_init(&pthread_custom_attr);

	p=(parm *)malloc(sizeof(parm)*n);
	/* Start up thread */

	for (i=0; i<n; i++)
	{
		p[i].id=i;
		pthread_create(&threads[i], &pthread_custom_attr, hello, (void *)(p+i));
	}

	/* Synchronize the completion of each thread. */

	for (i=0; i<n; i++)
	{
		pthread_join(threads[i],NULL);
	}
	free(p);
}
