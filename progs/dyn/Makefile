CC = gcc 
CFLAGS = -ldl -rdynamic -g -m32 -L. lib1.so -Wl,--hash-style=both -Wl,-rpath=$(CURDIR)
FILES = main.c
LIBCFLAGS = -Wall -m32 -fPIC -shared
LD = ld
LIBLDFLAGS = -m elf_i386 -shared -z relro

.PHONY: all clean test

all: main

test: main
	./main

main: $(FILES) lib1.so lib2.so lib_tls.so lib_tls_dynamic.so
	$(CC) $(CFLAGS) -o main $(FILES) 

lib1.so: lib1.o
	$(LD) $(LIBLDFLAGS) -ldl -soname lib1.so -o lib1.so lib1.o

lib2.so: lib2.o
	$(LD) $(LIBLDFLAGS) -ldl -soname lib2.so -o lib2.so lib2.o

lib_tls.so: lib_tls.o
	$(LD) $(LIBLDFLAGS) -soname lib_tls.so -o lib_tls.so lib_tls.o

lib_tls_dynamic.so: lib_tls_dynamic.o
	$(LD) $(LIBLDFLAGS) -soname lib_tls_dynamic.so -o lib_tls_dynamic.so lib_tls_dynamic.o

%.o: %.c 
	$(CC) $(LIBCFLAGS) -c $<

clean:
	rm -f main *.o *~ *.so
