
all:
	gcc main.c -g -o main
	gcc -shared -fPIC -o hello_printf.so hello_printf.c -ldl
	LD_PRELOAD=/home/paul90317/data/GOT/hello_printf.so gdb ./main

asm:
	gcc main.c -o main
	objdump -D -M intel main > main.S
	vim main.S
ldd:
	gcc main.c -o main
	ldd main