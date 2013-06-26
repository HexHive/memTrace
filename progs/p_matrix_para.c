/********************************************
 * Unoptimized matrix matrix multiplication *
 ********************************************/

#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

#define MAX_THREAD 20

#define NDIM 200

double          a[NDIM][NDIM];
double          b[NDIM][NDIM];
double          c[NDIM][NDIM];

typedef struct
{
	int             id;
	int             noproc;
	int             dim;
	double	(*a)[NDIM][NDIM],(*b)[NDIM][NDIM],(*c)[NDIM][NDIM];
}               parm;

void mm(int me_no, int noproc, int n, double a[NDIM][NDIM], double b[NDIM][NDIM], double c[NDIM][NDIM])
{
	int             i,j,k;
	double sum;
	i=me_no;
	while (i<n) {

		for (j = 0; j < n; j++) {
			sum = 0.0;
			for (k = 0; k < n; k++) {
				sum = sum + a[i][k] * b[k][j];
			}
			c[i][j] = sum;

		}
		i+=noproc;
	}
}

void * worker(void *arg)
{
	parm           *p = (parm *) arg;
	mm(p->id, p->noproc, p->dim, *(p->a), *(p->b), *(p->c));
	return NULL;
}


void main(int argc, char *argv[])
{
	int             j, k, noproc, me_no;
	double          sum;
	double          t1, t2;

	pthread_t      *threads;
	pthread_attr_t  pthread_custom_attr;

	parm           *arg;
	int             n, i;

	for (i = 0; i < NDIM; i++)
		for (j = 0; j < NDIM; j++)
		{
			a[i][j] = i + j;
			b[i][j] = i + j;
		}

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
	threads = (pthread_t *) malloc(n * sizeof(pthread_t));
	pthread_attr_init(&pthread_custom_attr);

	arg=(parm *)malloc(sizeof(parm)*n);
	/* setup barrier */

	/* Start up thread */

	/* Spawn thread */
	for (i = 0; i < n; i++)
	{
		arg[i].id = i;
		arg[i].noproc = n;
		arg[i].dim = NDIM;
		arg[i].a = &a;
		arg[i].b = &b;
		arg[i].c = &c;
		pthread_create(&threads[i], &pthread_custom_attr, worker, (void *)(arg+i));
	}

	for (i = 0; i < n; i++)
	{
		pthread_join(threads[i], NULL);

	}
	/* print_matrix(NDIM); */
	check_matrix(NDIM);
	free(arg);
}

print_matrix(dim)
int dim;
{
	int i,j;

	printf("The %d * %d matrix is\n", dim,dim);
	for(i=0;i<dim;i++){
		for(j=0;j<dim;j++)
			printf("%lf ",  c[i][j]);
		printf("\n");
	}
}

check_matrix(dim)
int dim;
{
	int i,j,k;
	int error=0;

	printf("Now checking the results\n");
	for(i=0;i<dim;i++)
		for(j=0;j<dim;j++) {
			double e=0.0;

			for (k=0;k<dim;k++)
				e+=a[i][k]*b[k][j];

			if (e!=c[i][j]) {
				printf("(%d,%d) error\n",i,j);
				error++;
			}
		}
	if (error)
		printf("%d elements error\n",error);
		else
		printf("success\n");
}
