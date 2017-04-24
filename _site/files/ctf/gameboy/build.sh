#!/bin/sh
echo rgbasm -v -o $1.o $1.asm
./rgbasm -v -o $1.o $1.asm
echo rgblink -o $1.gb $1.o
./rgblink -t -o $1.gb $1.o
echo rgbfix -v -p 0xff -t "AAAAAAAAAAAAAAAA" $1.gb
./rgbfix -v -p 0xff -t "AAAAAAAAAAAAAAAA" $1.gb
