all: sta hk

sta: set_thread_area.c
	gcc -m32 set_thread_area.c ekrclone.s -o sta -ggdb -nodefaultlibs -nostartfiles  -fno-stack-protector

hk: hk.c ekrclone64.s
	gcc -ggdb -o hk hk.c ekrclone64.s 

clean:
	rm -f sta hk
