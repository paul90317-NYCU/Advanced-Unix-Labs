all:
	gcc -o mazetest maze.c libmaze.c
	gcc -shared -fPIC -o libmaze.so libmaze.c -ldl
	LD_PRELOAD=libmaze.so ./mazetest

asm:
	gcc main.c -o main
	objdump -D -M intel main > main.S
	vim main.S
ldd:
	gcc main.c -o main
	ldd main

clean:
	rm libmaze.so mazetest