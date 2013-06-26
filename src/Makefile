include ../Makedefs

.PHONY: clean all

all: lMem

CFLAGS += $(OPTFLAGS) -fno-stack-protector -mcmodel=small -msoft-float -fpic -std=c99
LDFLAGS += -Wl,-z,relro,-z,now,-z,initfirst
LIBFLAGS = -fpic -c

CFILES = $(wildcard *.c)
ASMFILES = $(wildcard *.s)
HEADERS = $(wildcard *.h)
COBJS = ${CFILES:.c=.o}
ASMOBJS = ${ASMFILES:.s=.o}
OBJS = $(COBJS) $(ASMOBJS)

# pull in dependency info for existing .o files
-include $(OBJS:.o=.d)

%.o : %.c
	$(CC) $(CFLAGS) -MM $*.c > $*.d
	$(CC) $(CFLAGS) -E $*.c > $*.prep
	$(DSL_PATH) $*.prep $*.dsl
	$(CC) -x c -c $(CFLAGS) $(CPPFLAGS) $*.dsl -o $*.o 
	rm -f $*.prep $*.dsl

%.o : %.s
	as $< -o $@

lMem: $(OBJS) 
	$(CC) -o lMem -static $(OBJS) -Ttext=0x2000000000 $(LDFLAGS)
	ar rcs lmem.a *.o
	cp -f lMem ../lMem.$(CONFIG_NAME)
	# cp -f lMem /home/libdetox/pre32/home/enkrav/lmem/lMem/lMem.$(CONFIG_NAME)

clean:
	rm -f *.o *.prep *.dsl lMem lmem.a *.d

