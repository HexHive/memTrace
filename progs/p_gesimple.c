/************************************************************************
 * lutest.c : unoptimized GE column-oriented test prorgam	        *
 * machine: meiko 2 							*
 * Date: 9/10/95, Tao Yang                     				*
 * Let the right hand  vector be the n+1-th column of A			*
 * Forward Elimination:							* 
 *									*
 *									*
 *     For k=1 to n							*
 *               T(k,k)							*
 *               for j=k+1 to n+1					*
 *                       do T(k,j);					*
 *									*
 * Task  definition:							*
 *	T(k,k):								*
 *		do i=k+1:n    a(i,k) = a(i,k)/a(k,k)			*
 *	T(k,j):								*
 *		do i=k+1 to n  a(i,j) = a(i,j)- a(i,k)*a(k,j); 		*
 *									*
 * Backward substitution 						*
 *  For k = n to 1							*
 *      Do   S(k, n+1)							*
 *									*
 * Task definition of  S(k,n+1), uses column k to modify column n+1     *
 *       a(k,n+1)=a(k,n+1)/a(k,k)                                       *
 *       For i = k-1 to 1                                               *
 *           a(i,n+1)= a(i,n+1) - a(i,k)* a(k,n+1)                      *
 ***********************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

#define MAX_THREAD 20

#define SOLARIS 1
#define ORIGIN  2

#define OS	SOLARIS

typedef struct
{
	int             id;
	int             noproc;
	int             dim;
}               parm;

typedef struct
{
	int             cur_count;
	pthread_mutex_t barrier_mutex;
	pthread_cond_t barrier_cond;
}               barrier_t;

barrier_t mybarrier;

#define NDIM 45

typedef struct  dataitem{
	double row[NDIM];
} DATAITEM;


DATAITEM column[NDIM+1];

int NO_PROC;
#define isodd(x)    ( x%2 == 1)
#define WHICHMAP 2
#define  BLOCK 1
#define CYCLIC 2


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


/***********************************
 * GE simple    		   *
 ***********************************/
void *gesimple(void *arg)
{
	parm           *p = (parm *) arg;

	int me_no=p->id;
	int k,j,bcastno;

	if (me_no==0) { /* change here */
		begin_userprog();
	}
	barrier(NO_PROC, &mybarrier);
	for(k=0; k<NDIM; k++){
		if((bcastno=get_location(k,NDIM+1,WHICHMAP))== me_no){
			task_Tkk(k, &column[k]);
		}
		/* broadcast(k,&column[k], sizeof(column[k]), bcastno, NO_PROC); */
		barrier(NO_PROC, &mybarrier);
		for(j=k+1; j<=NDIM; j++)
			if(get_location(j,NDIM+1,WHICHMAP)== me_no)
				task_Tkj(k,j, &column[k],&column[j]);
	}
	if(get_location(NDIM,NDIM+1,WHICHMAP)== me_no){
		/*print_matrix(NDIM);*/
		for(k=NDIM-1; k>= 0; k--)
			task_S(k,&column[k], &column[NDIM]);
	}
	barrier(NO_PROC, &mybarrier);
	end_userprog(me_no);

	return NULL;
}



/***********************************
 * Main control 		   *
 ***********************************/
main(argc,argv)
int argc;
char *argv[];
{
	int i;
	parm *arg;
	pthread_t      *threads;
	pthread_attr_t  pthread_custom_attr;

	if (argc != 2)
	{
		printf("Usage: %s n\n  where n is no. of thread\n", argv[0]);
		exit(1);
	}
	NO_PROC = atoi(argv[1]);

	if ((NO_PROC < 1) || (NO_PROC > MAX_THREAD))
	{
		printf("The no of thread should between 1 and %d.\n", MAX_THREAD);
		exit(1);
	}
	threads = (pthread_t *) malloc(NO_PROC * sizeof(*threads));
	pthread_attr_init(&pthread_custom_attr);

	arg=(parm *)malloc(sizeof(parm)*NO_PROC);

	/* setup barrier */
	barrier_init(&mybarrier);

	/* Spawn thread */
	for (i = 0; i < NO_PROC; i++)
	{
		arg[i].id = i;
		arg[i].noproc = NO_PROC;
		pthread_create(&threads[i], &pthread_custom_attr, gesimple, (void *)(arg+i));
	}

	for (i = 0; i < NO_PROC; i++)
	{
		pthread_join(threads[i], NULL);
	}
	free(arg);


	exit(0);
}


/************************************************
 * Data initialization and postprocessing	*
 ************************************************/
begin_userprog()
{
	gen_test_data(NDIM);
	/*      if(me_no==0) print_matrix(NDIM);*/
}
end_userprog(int me_no)
{
	if(get_location(NDIM,NDIM+1,WHICHMAP)== me_no)
		print_solution(NDIM);
}

gen_test_data(n)
int n;
{
	int i,j;

	for(j=0;j<n;j++)
		for(i=0;i<n; i++)
			column[j].row[i] =1;

	for(i=0;i<n;i++)
		column[i].row[i]=n;
	for(i=0;i<n;i++)
		column[n].row[i]=2*n-1;

}

print_matrix(n)
int n;
{
	register int i,j;

	printf("The %d * %d matrix is\n", n,n+1);
	for(i=0;i<n;i++){
		for(j=0;j<n+1;j++)
			printf("%lf ",  column[j].row[i]);
		printf("\n");
	}
}
print_solution(n)
int n;
{
	register int i;

	printf("The solution is :\n");
	for(i=0;i<NDIM;i++){
		printf("%lf ",  column[n].row[i]);
	}
	printf("\n");
}


/************************************************
 * Task specification 	 	       		*
 ************************************************/

task_Tkk(k, colk)
int k;
DATAITEM *colk;
{
	int i;
	double temp;

	/*	do i=k+1:n a(i,k) = a(i,k)/a(k,k)   for L matrix */
	temp = colk->row[k];
	for(i=k+1;i<NDIM;i++)
		colk->row[i] /= temp; /* dangerous, what if temp==0? Hong Tang */
}
task_Tkj(k,j, colk, colj)
int k,j;
DATAITEM *colk, *colj;
{
	int i;
	/*
		do i=k+1 to N
	             a(i,j) = a(ij)- a(i,k)*a(k,j); 
	 */

	for(i=k+1;i<NDIM;i++)
		colj->row[i] -=  colk->row[i]*colj->row[k];
}

/*
 * Task definition of  S(k,n+1), uses column k to modify column n+1     *
 *       a(k,n+1)=a(k,n+1)/a(k,k)
 *       For i = k-1 to 1
 *           a(i,n+1)= a(i,n+1) - a(i,k)* a(k,n+1)
*/

task_S(k,colk,colb)
int k;
DATAITEM *colk,*colb;
{
	int i;
	double temp;
	colb->row[k]  /=  colk->row[k];
	temp= colb->row[k];
	for (i=k-1;i>=0; i--)
		colb->row[i]  -=  colk->row[i]*temp;
}

/****************************************************
 * broadcasting from node x,  mapping stuff	    *
 ****************************************************/
broadcast( type,msgbuf,size, x)
char *msgbuf ;
int type,size, x;
{
	/* MPI_Bcast(msgbuf, size, MPI_UNSIGNED_CHAR, x, MPI_COMM_WORLD); */
}

/**************************************************
 *  Get the real proc location of dat item j      *
 **************************************************/


int get_location(j, n,selemap)
int j,n,selemap;
{
	return(mapproc(j, selemap, n, NO_PROC));
}

/*******************************
 *Vitural architecture mapping *
 *proc no is from 0 np-1       *
 *data no is from 1 to n       *
 *******************************/


int mapproc(j, selemap, n, p)
int j, selemap, n, p; /* Cluster Mj */
{
	int r;
	double ceil(),floor();

	switch(selemap){
	case BLOCK: /*
		                         map(j) = floor(j/r)
		    		                    */
		r = (int) ceil( (double) n/ (double) p);
		return((int) floor((double) j/ (double)r));
	case CYCLIC: /*
		                         map(j) = j mod p
		    		                    */
		return( j%p);
	}
}
