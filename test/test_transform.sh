# Tests
rm transform_test
rm generated/*.c 
gcc -E test_transform.c -o generated/test_transform_preprocessed.c -I ../src/ 
python ../DSL/src/parse.py generated/test_transform_preprocessed.c generated/test_transform_preprocessed_dsld.c
gcc -O0 -fno-strict-aliasing -ggdb -o transform_test generated/test_transform_preprocessed_dsld.c ../src/lmem.a
./transform_test
exit $?
