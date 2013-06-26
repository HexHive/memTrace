CC = gcc 
CFLAGS = -Wall -g -pthread -m32 -L. -Wl,--hash-style=both -Wl,-rpath=./

.PHONY: all clean test

all: main

test: main
	./main

main:
	$(CC) $(CFLAGS) -o main main.c

clean: 
	rm -f main main.o 


