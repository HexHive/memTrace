# have a look at CONFIGURATION and the different Makedefs to configure the BT

.PHONY: all clean build test documentation microbenchmarks progs testprogs

all:
	sh makecurrdirh.sh
	make -C src
	make -C lib
	make -C progs
	make -C hacks
	make -C tp
	make -C microbenchmarks
	make -C progs 

test:
	make -C test

documentation:
	doxygen doxygen.config

clean:
	rm -f lMem
	rm -f lMem.*
	make -C tp clean
	make -C src clean
	make -C lib clean
	make -C progs clean
	make -C hacks clean
	make -C test clean
	make -C microbenchmarks clean
	rm -rf documentation

