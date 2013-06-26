CC = gcc 
CFLAGS = -nostartfiles -nostdlib -Wall -m32 -fPIC -shared
LD = ld
LDFLAGS = -m elf_i386 -shared 

all: lib1.so lib2.so

lib1.so: lib1.o lib2.so
	$(LD) $(LDFLAGS) -soname lib1.so -o lib1.so lib1.o lib2.so

lib2.so: lib2.o
	$(LD) $(LDFLAGS) -soname lib2.so -o lib2.so lib2.o

clean: 
	rm -f *.so *.o

%.o: %.c 
	$(CC) $(CFLAGS) -c $<
