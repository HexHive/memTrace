#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>


#define ROWS 10000
#define COLS 10000
#define THREADS 10

double initial_matrix[ROWS][COLS];
double final_matrix[ROWS][COLS];
// Barrier variable
pthread_barrier_t barr;

extern void DotProduct(int row, int col,
                       double source[ROWS][COLS],
                       double destination[ROWS][COLS]);
extern double determinant(double matrix[ROWS][COLS]);

void * entry_point(void *arg)
{
    int rank = (int)arg;
    for(int row = rank * ROWS / THREADS; row < (rank + 1) * THREADS; ++row)
        for(int col = 0; col < COLS; ++col)
            DotProduct(row, col, initial_matrix, final_matrix);

    // Synchronization point
    int rc = pthread_barrier_wait(&barr);
    if(rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD)
    {
        printf("Could not wait on barrier\n");
        exit(-1);
    }

    for(int row = rank * ROWS / THREADS; row < (rank + 1) * THREADS; ++row)
        for(int col = 0; col < COLS; ++col)
            DotProduct(row, col, final_matrix, initial_matrix);
}

int main(int argc, char **argv)
{
    pthread_t thr[THREADS];

    // Barrier initialization
    if(pthread_barrier_init(&barr, NULL, THREADS))
    {
        printf("Could not create a barrier\n");
        return -1;
    }

    for(int i = 0; i < THREADS; ++i)
    {
        if(pthread_create(&thr[i], NULL, &entry_point, (void*)i))
        {
            printf("Could not create thread %d\n", i);
            return -1;
        }
    }

    for(int i = 0; i < THREADS; ++i)
    {
        if(pthread_join(thr[i], NULL))
        {
            printf("Could not join thread %d\n", i);
            return -1;
        }
    }

    double det = Determinant(initial_matrix);
    printf("The determinant of M^4 = %f\n", det);

    return 0;
}
