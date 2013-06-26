#!/usr/bin/env bash

ln -s -f lMem.id lMem
./testsing.sh
ln -s -f lMem.idfr lMem
./testsing.sh
ln -s -f lMem.eflags lMem
./testsing.sh
ln -s -f lMem.memacc lMem
./testsing.sh
ln -s -f lMem.full lMem
./testsing.sh
