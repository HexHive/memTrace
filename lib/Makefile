all: newdelete.o lmem_malloc.o

lmem_malloc.o: lmem_malloc.c
	gcc -c -m32 lmem_malloc.c 

newdelete.o: newdelete.cpp 
	g++ -c -m32 newdelete.cpp

clean:
	rm -f *.o
