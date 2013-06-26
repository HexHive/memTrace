/*
 * #include <signal.h>
 *
 * void (*signal(int sig, void (*func)(int)))(int);
 *
 *      Or in the equivalent but easier to read typedef'd version:
 *
 * typedef void (*sig_t) (int);
 * sig_t signal(int sig, sig_t func);
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

void
handler(int value)
{
        fprintf(stderr, "SIGINT caught");
}

int
main(int argc, char *argv[] )
{
        size_t infile;
        char buffer[2048];

        if(argc < 3)
        {
                fprintf(stderr,"Usage:%s filename \n",*argv);
                exit(-1);
        }

        int c;
        while ((c = getopt (argc, argv, "Cf:")) != -1)
        {
                switch(c)
                {
                        case 'C':
                                if( (signal (SIGINT, handler)) == SIG_IGN )
                                        signal (SIGINT,SIG_IGN);
                                break;
                        case 'f':
                                if( ( infile = open(optarg, O_RDONLY)) == -1 )
                               if( ( infile = open(optarg, O_RDONLY)) == -1 )
                                {
                                        perror("Unable to open file");
                                }
                                break;

                        default:
                                break; //eat-it

                }
        }

        int count=0;
        while( (count = read(infile,buffer,sizeof(buffer))) > 0 )
        {
                write(STDOUT_FILENO,buffer,count);
        }

        return EXIT_SUCCESS;

}

