# Tests action_pushpop
rm action_pushpop_test
rm generated/*.c 
gcc -E test_action_pushpop.c -o generated/test_action_pushpop_preprocessed.c -I ../src/ 
python ../DSL/src/parse.py generated/test_action_pushpop_preprocessed.c generated/test_action_pushpop_preprocessed_dsld.c
gcc -O0 -fno-strict-aliasing -ggdb -o action_pushpop_test generated/test_action_pushpop_preprocessed_dsld.c ../src/lmem.a
./action_pushpop_test
exit $?
