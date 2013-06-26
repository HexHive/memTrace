# Tests action_indjmp
rm action_indjmp_test
rm generated/*.c 
gcc -E test_action_indjmp.c -o generated/test_action_indjmp_preprocessed.c -I ../src/ 
python ../DSL/src/parse.py generated/test_action_indjmp_preprocessed.c generated/test_action_indjmp_preprocessed_dsld.c
gcc -O0 -fno-strict-aliasing -ggdb -o action_indjmp_test generated/test_action_indjmp_preprocessed_dsld.c ../src/lmem.a
./action_indjmp_test
exit $?
