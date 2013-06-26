all: hello simple indir shar register_preservation qsort longjump brk print stat malloc stresstest tls empty strings ex extend sig forever simsig hits wrap new push pushfl sprintf fork sfork clone sclone hi execve myecho futex clone2 pip mmap mmapII segops

CFLAGS = -m32 -O0 -ggdb
CC = gcc 
CXX = g++

hits: hits.c
	$(CC) $(CFLAGS) hits.c -o hits -I../lib/

hi: hi.c
	$(CC) $(CFLAGS) hi.c -o hi

uname: uname.c
	$(CC) $(CFLAGS) uname.c -o uname

mmap: mmap.c
	$(CC) $(CFLAGS) mmap.c -o mmap

mmapII: mmapII.c
	$(CC) $(CFLAGS) mmapII.c -o mmapII

futex: futex.c
	$(CC) $(CFLAGS) futex.c -o futex -Wall

fuwait: fuwait.c
	$(CC) $(CFLAGS) fuwait.c -o fuwait -Wall

myecho: myecho.c
	$(CC) $(CFLAGS) myecho.c -o myecho

segops: segops.c
	$(CC) $(CFLAGS) segops.c -o segops -fno-stack-protector -w

execve: execve.c hi 
	$(CC) $(CFLAGS) execve.c -o execve

forever: forever.c
	$(CC) $(CFLAGS) -o forever forever.c

fork: fork.c
	$(CC) $(CFLAGS) -o fork fork.c

sfork: sfork.c
	$(CC) $(CFLAGS) -o sfork sfork.c

clone: clone.c
	$(CC) $(CFLAGS) -o clone clone.c

clone2: clone2.c 
	$(CC) $(CFLAGS) -o clone2 clone2.c 

sclone: sclone.c ekrclone.s
	$(CC) $(CFLAGS) -o sclone sclone.c ekrclone.s

sprintf: sprintf.c
	$(CC) $(CFLAGS) -o sprintf sprintf.c

register_preservation: register_preservation.s
	as --32 register_preservation.s -o register_preservation.o
	$(CC) $(CFLAGS) -o register_preservation register_preservation.o -nostartfiles

push: push.s
	as push.s -o push.o
	gcc -o push push.o -nostartfiles

pushfl: pushfl.s
	as pushfl.s -o pushfl.o
	gcc -o pushfl pushfl.o -nostartfiles

new: new.cpp
	$(CXX) $(CFLAGS) new.cpp ../lib/newdelete.o -o new 

wrap: wrap.c
	$(CC) $(CFLAGS) wrap.c ../lib/lmem_malloc.o -o wrap

strings: strings.s
	as --32 strings.s -o strings.o
	$(CC) $(CFLAGS) -o strings strings.o -nostartfiles

extend: extend.s
	as --32 extend.s -o extend.o
	$(CC) $(CFLAGS) -o extend extend.o -nostartfiles

empty: empty.c
	$(CC) $(CFLAGS) empty.c -o empty -m32

simsig: simsig.c
	$(CC) $(CFLAGS) simsig.c -o simsig -m32

tls: tls.c
	$(CC)  $(CFLAGS) tls.c -o tls -m32

sig: sig.c
	$(CC)  $(CFLAGS) sig.c -o sig 

ex: ex.cpp
	$(CXX)  $(CFLAGS) ex.cpp -o ex -m32

malloc: malloc.c
	$(CC)  $(CFLAGS) malloc.c -o malloc -m32

stresstest: stresstest.c
	$(CC)  $(CFLAGS) stresstest.c -o stresstest -m32 -ggdb

print: print.c
	$(CC)  $(CFLAGS) print.c -o print -m32

stat: stat.c
	$(CC)  $(CFLAGS) stat.c -o stat -m32

brk: brk.c
	$(CC)  $(CFLAGS) brk.c -o brk -m32

qsort: qsort.c
	$(CC)  $(CFLAGS) qsort.c -o qsort -m32

longjump: longjump.c
	$(CC)  $(CFLAGS) longjump.c -o longjump -m32

hello: hello.c
	$(CC)  $(CFLAGS) hello.c -o hello -m32

simple: simple.c
	$(CC)  $(CFLAGS) simple.c -o simple -m32 -ggdb

pip: pip.c
	$(CC)  $(CFLAGS) pip.c -o pip -m32 -ggdb

indir: indir.c
	$(CC)  $(CFLAGS) indir.c -o indir -m32 -nostartfiles

shar: shar.c sl.c
	$(CC) $(CFLAGS) sl.c -c -fPIC -m32
	ld -soname sl.so -o sl.so sl.o  -fPIC -m elf_i386 -shared
	$(CC) $(CFLAGS) -o shar shar.c -m32 sl.so -nodefaultlibs -nostartfiles

clean:
	rm -f segops hello simple sl.so shar indir sl.o register_preservation qsort longjump brk print stat malloc stresstest tls empty strings ex extend sig forever simsig hits pushfl push m mb fib wrap new sprintf fork sfork clone sclone hi execve myecho futex clone2

