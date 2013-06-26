#!/usr/bin/env bash
make clean

ln -s -f id.config current.config
make -C src clean
make -C src

ln -s -f idfr.config current.config
make -C src clean
make -C src -j4

ln -s -f eflags.config current.config
make -C src clean
make -C src -j4

ln -s -f memacc.config current.config
make -C src clean
make -C src -j4

ln -s -f full.config current.config
make -C src clean
make -C src -j4

make -C lib -j4
make -C tp -j4

