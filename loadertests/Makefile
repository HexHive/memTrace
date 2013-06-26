.PHONY: all clean test compile

all: compile

compile:
	make -C relocations
	make -C threads
	make -C exceptions
	make -C tls_relocations
	make -C dynamic_loading
	make -C libc_basic
	make -C versioning
	make -C lib_resolve

test: compile
	make -C relocations test
	make -C threads test
	make -C tls_relocations test
	make -C dynamic_loading test
	make -C libc_basic test
	make -C versioning test
	make -C lib_resolve test
	make -C exceptions test
	
clean: 
	make -C relocations clean
	make -C threads clean
	make -C tls_relocations clean
	make -C dynamic_loading clean
	make -C libc_basic clean
	make -C versioning clean
	make -C lib_resolve clean
	make -C exceptions clean
