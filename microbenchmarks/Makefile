# use g++ compiler
CC=gcc
CFLAGS= -m32 -O2

INCLUDEDIR=../src/
LIBPATH=../lib

.PHONY: runtest build clean

all: microbenchmark iotest racetrap

microbenchmark: microbenchmark.c
	$(CC) $(CFLAGS) -O microbenchmark.c -o microbenchmark

iotest: iotest.c
	$(CC) $(CFLAGS) -O iotest.c -o iotest
	
racetrap: racetrap.c	
	$(CC) $(CFLAGS) -O racetrap.c -o racetrap

clean:
	rm -f *.o microbenchmark racetrap iotest

