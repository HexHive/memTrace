CC = gcc 
CFLAGS =  -g -m32 -L. -Wl,--hash-style=both

.PHONY: all clean test

all: main

test: main
	./main

main: $(FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o main main.c 

clean:
	rm -f main *.o *~
