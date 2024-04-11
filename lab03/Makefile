PWD := $(shell pwd)

all:
	gcc -shared -fPIC -o libmaze.so libmaze.c -ldl
	LD_LIBRARY_PATH=. ./maze

asm:
	gcc main.c -o main
	objdump -D -M intel main > main.S
	vim main.S
ldd:
	gcc main.c -o main
	ldd main

clean:
	rm libmaze.so mazetest