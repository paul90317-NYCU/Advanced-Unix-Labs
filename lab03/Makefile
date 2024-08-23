PWD := $(shell pwd)

test:
	gcc -shared -fPIC -o libmaze.so libmaze.c -ldl
	gcc -shared -fPIC -o libmaze_dummy.so libmaze_dummy.c -ldl
	gcc -L. -fPIC -o mazetest maze.c -lmaze -lmaze_dummy 
	python ./see_elf.py mazetest > elf.h
	gcc -shared -fPIC -o libmaze.so libmaze.c -ldl
	LD_LIBRARY_PATH=. ./mazetest

submit:
	python ./see_elf.py maze > elf.h
	gcc -shared -fPIC -o libmaze.so libmaze.c -ldl
	python submit.py ./libmaze.so

asm:
	objdump -D -M intel maze > maze.S
ldd:
	ldd maze

clean:
	rm libmaze.so libmaze_dummy.so mazetest