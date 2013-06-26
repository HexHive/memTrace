#!/usr/bin/env bash

failed=0

echo -n "tls test: "
./lMem tp/tls &> /dev/null
if test 35 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "register preservation test: "
./lMem tp/register_preservation &> /dev/null
if test 0 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "longjmp test: "
./lMem tp/longjump &> /dev/null
if test 8 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "qsort test: "
./lMem tp/qsort &> /dev/null
if test 37 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "brk test: "
./lMem tp/brk &> /dev/null
if test 15 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "printf test: "
./lMem tp/print &> /dev/null
if test 0 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "stat test: "
./lMem tp/stat &> /dev/null
if test 23 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "malloc test: "
./lMem tp/malloc &> /dev/null
if test 0 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "strings test: "
./lMem tp/strings &> /dev/null
if test 0 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "sprintf test: "
./lMem tp/sprintf &> /dev/null
if test 42 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

# FOR NOW WE DISABLE FORK
#echo -n "syscall fork test: "
#./lMem tp/sfork &> /dev/null
#if test 3 -eq $?; then
  #echo -e "\e[1;32mSUCCESS\e[0m"
#else
  #echo -e "\e[1;31mFAIL\e[0m"
  #failed=1
#fi

echo -n "glibc fork test: "
./lMem tp/fork &> /dev/null
if test 3 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "execve test: "
./lMem tp/execve &> /dev/null
if test 42 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "sclone test: "
./lMem tp/sclone &> /dev/null
if test 42 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "clone test: "
./lMem tp/clone &> /dev/null
if test 42 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "futex test: "
./lMem tp/futex &> /dev/null
if test 42 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo -n "segops test: "
./lMem tp/segops &> /dev/null
if test 21 -eq $?; then
  echo -e "\e[1;32mSUCCESS\e[0m"
else
  echo -e "\e[1;31mFAIL\e[0m"
  failed=1
fi

echo "number of failures: $failed"
exit $failed

