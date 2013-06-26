#include <stdio.h>
#include <math.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>

#define MAX_THREAD 20
#define SOLARIS 1
#define ORIGIN  2

#define OS		SOLARIS

typedef struct
{
	int          id;
	int          noproc;
	int          dim;
}              parm;

typedef struct
{
	int             cur_count;
	pthread_mutex_t barrier_mutex;
	pthread_cond_t barrier_cond;
}               barrier_t;

barrier_t barrier1;

double         *finals;
int rootn;

/* barrier */
void barrier_init(barrier_t * mybarrier)
{
	/* must run before spawning the thread */
	pthread_mutexattr_t attr;

# if (OS==ORIGIN)
	pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
	pthread_mutexattr_setprioceiling(&attr, 0); 

	pthread_mutex_init(&(mybarrier->barrier_mutex), &attr);
# elif (OS==SOLARIS)
	pthread_mutex_init(&(mybarrier->barrier_mutex), NULL);
# else
# error "undefined OS"
# endif
	pthread_cond_init(&(mybarrier->barrier_cond), NULL);
	mybarrier->cur_count = 0;
}

void barrier(int numproc, barrier_t * mybarrier)
{
	pthread_mutex_lock(&(mybarrier->barrier_mutex));
	mybarrier->cur_count++;
	if (mybarrier->cur_count!=numproc) {
		pthread_cond_wait(&(mybarrier->barrier_cond), &(mybarrier->barrier_mutex));
	}
	else
	{
		mybarrier->cur_count=0;
		pthread_cond_broadcast(&(mybarrier->barrier_cond));
	}
	pthread_mutex_unlock(&(mybarrier->barrier_mutex));
}

double f(a)
double          a;
{
	return (4.0 / (1.0 + a * a));
}

void * cpi(void *arg)
{
	parm           *p = (parm *) arg;
	int             myid = p->id;
	int             numprocs = p->noproc;
	int             i;
	double          PI25DT = 3.141592653589793238462643;
	double          mypi, pi, h, sum, x, a;
	double          startwtime, endwtime;

	if (myid == 0)
	{
		startwtime = clock();
	}
	barrier(numprocs, &barrier1);
	if (rootn==0)
		finals[myid]=0;
	else {
		h = 1.0 / (double) rootn;
		sum = 0.0;
		for (i = myid + 1; i <=rootn; i += numprocs)
		{
			x = h * ((double) i - 0.5);
			sum += f(x);
		}
		mypi = h * sum;
	}
	finals[myid] = mypi;

	barrier(numprocs, &barrier1);

	if (myid == 0)
	{
		pi = 0.0;
		for (i =0; i < numprocs; i++)
			pi += finals[i];
		endwtime = clock();
		printf("pi is approximately %.16f, Error is %.16f\n",
		    pi, fabs(pi - PI25DT));
		printf("wall clock time = %f\n",
		    (endwtime - startwtime) / CLOCKS_PER_SEC);
	}
	return NULL;
}

int main(argc, argv)
int             argc;
char           *argv[];
{
	int             done = 0, n, myid, numprocs, i, rc;
	double          startwtime, endwtime;
	parm           *arg;

	pthread_t      *threads;
	pthread_attr_t  pthread_custom_attr;

	if (argc != 2)
	{
		printf("Usage: %s n\n  where n is no. of thread\n", argv[0]);
		exit(1);
	}
	n = atoi(argv[1]);

	if ((n < 1) || (n > MAX_THREAD))
	{
		printf("The no of thread should between 1 and %d.\n", MAX_THREAD);
		exit(1);
	}
	threads = (pthread_t *) malloc(n * sizeof(*threads));
	pthread_attr_init(&pthread_custom_attr);

	/* setup barrier */
	barrier_init(&barrier1);

	/* allocate space for final result */
	finals = (double *) malloc(n * sizeof(double));

	rootn = 10000000;

	arg=(parm *)malloc(sizeof(parm)*n);
	/* Spawn thread */
	for (i = 0; i < n; i++)
	{
		arg[i].id = i;
		arg[i].noproc = n;
		pthread_create(&threads[i], &pthread_custom_attr, cpi, (void *)(arg+i));
	}

	/* Synchronize the completion of each thread. */

	for (i = 0; i < n; i++)
	{
		pthread_join(threads[i], NULL);
	}

	free(arg);

}
