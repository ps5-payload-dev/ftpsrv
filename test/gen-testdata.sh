#!/usr/bin/env bash

LARGE_NUMBER=5000
SMALL_NUMBER=1


echo "testdata1: large number of folders with a single small text file"
rm -rf testdata1
mkdir -p testdata1
for i in $(seq 1 $LARGE_NUMBER); do
    mkdir -p "testdata1/folder$i"
    echo "hello, world" > "testdata1/folder$i/hello_world.txt"
done


echo "testdata2: single folder with a large number of small text files"
rm -rf testdata2
mkdir -p testdata2
for i in $(seq 1 $LARGE_NUMBER); do
    echo "hello, world" > "testdata2/file$i.txt"
done

exit 0

echo "testdata3: large number of folders with a large number of small text files"
rm -rf testdata3
mkdir -p testdata3
for i in $(seq 1 $LARGE_NUMBER); do
    mkdir -p "testdata3/folder$i"
    for j in $(seq 1 $LARGE_NUMBER); do
	echo "hello, world" > "testdata3/folder$i/file$j.txt"
    done
done

echo "testdata4: a single large binary file"
rm -rf testdata4
mkdir -p testdata4
head -c 1G /dev/urandom > testdata4/1GB.bin
