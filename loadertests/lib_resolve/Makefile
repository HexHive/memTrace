CC = gcc 
CFLAGS = -ldl -rdynamic -g -m32 -Wl,--hash-style=both -Wl,-rpath=$(CURDIR)
LIBCFLAGS = -Wall -m32 -fPIC -shared
LD = ld
LIBLDFLAGS = -m elf_i386 -shared 

.PHONY: all clean test

all: main

test: main
	./main

main: lib1.so lib2.so lib3.so
	$(CC) $(CFLAGS) -o main main.c lib1.so

lib1.so: lib1.o
	$(LD) $(LIBLDFLAGS) -ldl -soname lib1.so -o lib1.so lib1.o

lib2.so: lib2.o lib3.so
	$(LD) $(LIBLDFLAGS) lib3.so -ldl -soname lib2.so -o lib2.so lib2.o

lib3.so: lib3.o
	$(LD) $(LIBLDFLAGS) -ldl -soname lib3.so -o lib3.so lib3.o

%.o: %.c 
	$(CC) $(LIBCFLAGS) -c $<

clean: 
	rm -f main *.so *.o

