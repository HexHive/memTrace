CC = gcc 
CFLAGS = -nostartfiles -nostdlib -m32 -Wl,--hash-style=both -Wl,-rpath=$(CURDIR)
LIBCFLAGS = -nostartfiles -nostdlib -Wall -m32 -fPIC -shared
LD = ld
LIBLDFLAGS = -m elf_i386 -shared 

.PHONY: all clean test

all: main

test: main
	./main

main: lib1.so lib2.so
	$(CC) $(CFLAGS) -o main main.c  lib1.so

lib1.so: lib1.o lib2.so
	$(LD) $(LIBLDFLAGS) -soname lib1.so -o lib1.so lib1.o lib2.so

lib2.so: lib2.o
	$(LD) $(LIBLDFLAGS) -soname lib2.so -o lib2.so lib2.o

%.o: %.c 
	$(CC) $(LIBCFLAGS) -c $<

clean: 
	rm -f *.so *.o main

