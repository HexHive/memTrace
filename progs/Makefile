all:       prog primes test regtest thtest tt correct sigac fork thtest64 p_gesimple p_hello p_matrix_para p_greetings2 p_cpi

CFLAGS = -ggdb -O2 -m32

clean: 
	rm -f prog primes test regtest thtest tt hello sdl gtk leak mem intro flt correct sigac cln fork thtest64 p_gesimple p_hello p_matrix_para p_greetings2 p_cpi
	make -C dyn clean

intro: intro.c
	gcc -o intro intro.c $(CFLAGS)

p_hello: p_hello.c
	gcc -o p_hello p_hello.c $(CFLAGS) -lpthread

p_gesimple: p_gesimple.c
	gcc -o p_gesimple p_gesimple.c $(CFLAGS) -lpthread -lm

p_matrix_para: p_matrix_para.c
	gcc -o p_matrix_para p_matrix_para.c $(CFLAGS) -lpthread

p_greetings2: p_greetings2.c
	gcc -o p_greetings2 p_greetings2.c $(CFLAGS) -lpthread

p_cpi: p_cpi.c
	gcc -o p_cpi p_cpi.c $(CFLAGS) -lpthread

flt: flt.c
	gcc -o flt flt.c $(CFLAGS)

sigac: sigac.c
	gcc -o sigac sigac.c $(CFLAGS)

correct: correct.c
	gcc -o correct correct.c $(CFLAGS)

leak: leak.c
	gcc -o leak leak.c $(CFLAGS)

mem: mem.c
	gcc -o mem mem.c $(CFLAGS)

prog: prog.c
	gcc -o prog prog.c $(CFLAGS)

fork: fork.c
	gcc -o fork fork.c $(CFLAGS)

primes: primes.cpp
	g++ -o primes primes.cpp $(CFLAGS)

test: test.cpp
	g++ -o test test.cpp $(CFLAGS)

regtest: regtest.c
	gcc -o regtest regtest.c $(CFLAGS)

thtest: thtest.c
	gcc -o thtest thtest.c $(CFLAGS) -lpthread

thtest64: thtest.c
	gcc -o thtest64 thtest.c -lpthread

tt: tt.c
	gcc -o tt tt.c  $(CFLAGS) -lpthread

hello: hello.c
	gcc -o hello.o -Wall -I/usr/X11R6/include -c hello.c -m32
	gcc -o hello -Wall -L/usr/X11R6/lib -lX11 hello.o -m32

sdl: sdl.c
	gcc -o sdl sdl.c -ggdb `sdl-config --cflags --libs` -m32

alleg: alleg.c
	gcc -o alleg alleg.c -ggdb `allegro-config --cflags --libs` -m32

gtk: gtk.c
	gcc -Wall -g gtk.c -o gtk `pkg-config --cflags gtk+-2.0` `pkg-config --libs gtk+-2.0` -m32

