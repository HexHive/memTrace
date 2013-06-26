all: runtest

runtest: 
	sh test_transform.sh
	sh test_action_indjmp.sh
	sh test_action_pushpop.sh
	sh test_action_copy.sh

clean:
	rm -f action_copy_test
	rm -f action_pushpop_test
	rm -f action_indjmp_test
	rm -f test_llio
	rm -f *.o generated/* file debug.txt
	rm -f transform_test 

tio:
	gcc test_llio.c -o test_llio -I ../src/  ../src/libfastbt.a
	./test_llio

