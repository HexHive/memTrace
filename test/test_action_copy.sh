# Tests action_copy
rm action_copy_test
rm generated/*.c 
python gen_action_copy_test.py > generated/action_copy_test.c
gcc -E generated/action_copy_test.c -o generated/action_copy_test_preprocessed.c -I ../src/ 
python ../DSL/src/parse.py generated/action_copy_test_preprocessed.c generated/action_copy_test_preprocessed_dsld.c
gcc  -O0 -fno-strict-aliasing -ggdb -o action_copy_test generated/action_copy_test_preprocessed_dsld.c ../src/lmem.a
./action_copy_test
exit $?
