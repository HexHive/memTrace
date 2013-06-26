#include "gtest/gtest.h"

#if defined(TEST_FBT_ALGORITHMS)

#include "fbt_algorithms.h"

int compare(int a, int b) {
  if (a == b) {
    return 0;
  } else if (a < b) {
    return -1;
  } else {
    return +1;
  }
}

int int_comparator(const void *a, const void *b) {
  return compare(*(int *)a, *(int *)b);
}

int compare_to(const void *a, const void *context) {
  return compare((int)context, *((int *)a));
}

int array[] = {1, 10, 100, 1000};

#define TEST_IN_ARRAY(name, query, expected) \
  TEST(BinarySearch, name) \
  { \
    EXPECT_EQ(array+expected, fbt_binary_search(array, LEN(array), sizeof(int), &compare_to, (void *)query));\
  }

TEST_IN_ARRAY(Simple1, 0, 0)
TEST_IN_ARRAY(Simple2, 1, 0)
TEST_IN_ARRAY(Simple3, 9, 1)
TEST_IN_ARRAY(Simple4, 10, 1)
TEST_IN_ARRAY(Simple5, 99, 2)
TEST_IN_ARRAY(Simple6, 100, 2)
TEST_IN_ARRAY(Simple7, 999, 3)
TEST_IN_ARRAY(Simple8, 1000, 3)
TEST_IN_ARRAY(Simple9, 1001, 4)

TEST(fbt_swap_mem, NoBytes) {
  int32_t a, b;
  a = 0xaabbccdd;
  b = 0x11002233;
  fbt_swap_mem(&a, &b, 0);
  EXPECT_EQ(0xaabbccdd, a);
  EXPECT_EQ(0x11002233, b);
}

TEST(fbt_swap_mem, Int32) {
  int32_t a, b;
  a = 0xaabbccdd;
  b = 0x11002233;
  fbt_swap_mem(&a, &b, sizeof(a));
  EXPECT_EQ(0xaabbccdd, b);
  EXPECT_EQ(0x11002233, a);
}

TEST(fbt_swap_mem, Int64) {
  int64_t a, b;
  a = 0x0011223344556677;
  b = 0x8899aabbccddeeff;
  fbt_swap_mem(&a, &b, sizeof(a));
  EXPECT_EQ(0x0011223344556677, b);
  EXPECT_EQ(0x8899aabbccddeeff, a);
}

TEST(fbt_swap_mem, Char5) {
  char as[] = { 'a', 'b', 'c', 'd', 'e', 'z' };
  char bs[] = { 'f', 'g', 'h', 'i', 'j', 'z' };  

  fbt_swap_mem(as, bs, 5);
  
  EXPECT_EQ(as[0], 'f');
  EXPECT_EQ(as[1], 'g');
  EXPECT_EQ(as[2], 'h');  
  EXPECT_EQ(as[3], 'i');
  EXPECT_EQ(as[4], 'j');
  EXPECT_EQ(as[5], 'z');          

  EXPECT_EQ(bs[0], 'a');
  EXPECT_EQ(bs[1], 'b');
  EXPECT_EQ(bs[2], 'c');  
  EXPECT_EQ(bs[3], 'd');
  EXPECT_EQ(bs[4], 'e');
  EXPECT_EQ(bs[5], 'z');
}

void EXPECT_CHAR_ARRAY_EQ(char *a, char *b, size_t size) { 
  for (size_t i = 0; i < size; ++i) {
    EXPECT_EQ(*a++, *b++);
  }
}

void EXPECT_INT_ARRAY_EQ(int *a, int *b, size_t size) { 
  for (size_t i = 0; i < size; ++i) {
    EXPECT_EQ(*a++, *b++);
  }
}

void expect_partitioned(void *begin, size_t num, void *pivot, size_t size, int (*comparator)(const void *, const void *)) { 
  void *cur = begin;
  for (size_t i = 0; i < num; ++i) {
    int comp = comparator(cur, pivot);
    
    if (cur < pivot) {
      EXPECT_GE(0, comp);
    } else if (cur > pivot) {
      EXPECT_LE(0, comp);
    }
  
    cur = (char *)cur + size;
  }
}

TEST(fbt_partition, AlreadyPartitioned) {  
  int xs[] = { 2, 1, 3, 3, 3, 5, 4 };
  size_t length = LEN(xs);

  void *pivot = fbt_partition(xs, length, 3, sizeof(int), &int_comparator);
  
  expect_partitioned(xs, length, pivot, sizeof(int), &int_comparator);
}

TEST(fbt_partition, IncreasingLowPivot) {  
  int xs[] = { 1, 2, 3, 4, 5, 6, 7 };
  void *pivot = fbt_partition(xs, LEN(xs), 0, sizeof(int), &int_comparator);
  expect_partitioned(xs, LEN(xs), pivot, sizeof(int), &int_comparator);
}

TEST(fbt_partition, IncreasingMidPivot) {  
  int xs[] = { 1, 2, 3, 4, 5, 6, 7 };
  void *pivot = fbt_partition(xs, LEN(xs), 3, sizeof(int), &int_comparator);
  expect_partitioned(xs, LEN(xs), pivot, sizeof(int), &int_comparator);
}

TEST(fbt_partition, IncreasingHighPivot) {  
  int xs[] = { 1, 2, 3, 4, 5, 6, 7 };
  void *pivot = fbt_partition(xs, LEN(xs), 6, sizeof(int), &int_comparator);
  expect_partitioned(xs, LEN(xs), pivot, sizeof(int), &int_comparator);
}

TEST(fbt_qsort, AlreadySorted) {
  int xs[] = { 1, 2, 3, 4, 5, 6, 7 };
  int ys[] = { 1, 2, 3, 4, 5, 6, 7 };  
  fbt_qsort(xs, LEN(xs), sizeof(xs[0]), &int_comparator);
  EXPECT_INT_ARRAY_EQ(ys, xs, LEN(xs));
}

TEST(fbt_qsort, Reversed) {
  int xs[] = { 7, 6, 5, 4, 3, 2, 1 };
  int ys[] = { 1, 2, 3, 4, 5, 6, 7 };  
  fbt_qsort(xs, LEN(xs), sizeof(xs[0]), &int_comparator);
  fbt_print_int_array(xs, LEN(xs), NULL);   
  EXPECT_INT_ARRAY_EQ(ys, xs, LEN(xs));
}

TEST(fbt_qsort, Fill) {
  int xs[] = { 1, 1, 1, 1, 1 };
  int ys[] = { 1, 1, 1, 1, 1 };  
  fbt_qsort(xs, LEN(xs), sizeof(xs[0]), &int_comparator); 
  EXPECT_INT_ARRAY_EQ(ys, xs, LEN(xs));
}

TEST(fbt_qsort, Random1) {
  int xs[] = { 235, 130, 435, 340, 123, 355 };
  int ys[] = { 123, 130, 235, 340, 355, 435 };  
  fbt_qsort(xs, LEN(xs), sizeof(xs[0]), &int_comparator);
  fbt_print_int_array(xs, LEN(xs), NULL);
  EXPECT_INT_ARRAY_EQ(ys, xs, LEN(xs));
}

#define QSORT_TEST(name, xs_val, ys_val) \
  TEST(fbt_qsort, name) { \
    int xs[] = xs_val; \
    int ys[] = ys_val; \
    fbt_qsort(xs, LEN(xs), sizeof(xs[0]), &int_comparator); \
    fbt_print_int_array(xs, LEN(xs), NULL); \
    EXPECT_INT_ARRAY_EQ(ys, xs, LEN(xs)); \
  }
  
#define ARRAY(...) __VA_ARGS__
  
#include "fbt_algorithms_generated_qsort_tests.h"

#else /* TEST_FBT_ALGORITHMS */
TEST(fbt_algorithms, NotTesting) {
  printf("Not testing fbt_algorithms because TEST_FBT_ALGORITHMS is not set (test/Makefile).");
}
#endif /* TEST_FBT_ALGORITHMS */