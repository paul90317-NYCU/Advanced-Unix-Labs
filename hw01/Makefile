CC := gcc
CFLAGS := -g -fpic
LDLIBS := -shared -ldl

all: logger logger.so

test: all
	-./test.sh answers/ex1-1.txt examples/ex1-1
	-./test.sh answers/ex1-2.txt examples/ex1-2
	-./test.sh answers/ex2.txt examples/ex2
	-./test.sh answers/ex3-1.txt examples/ex3-1
	-./test.sh answers/ex3-2.txt examples/ex3-2
	-./test.sh answers/ex4-1.txt examples/ex4 www.cs.nycu.edu.tw
	-./test.sh answers/ex4-2.txt examples/ex4 www.google.com
	-./test.sh answers/ex5-1.txt examples/ex5 172.217.160.100
	-./test.sh answers/ex5-2.txt examples/ex5 20.27.177.113
	-./test.sh answers/ex6.txt examples/ex6

hiddencase/: all
	rm -rf ./hiddencase
	cp -r ./hw1_hiddencase ./hiddencase
	cp logger.so ./hiddencase/logger.so
	cp logger ./hiddencase/logger
	
logger.so: liblogger.c common.h api.h hijack.h
	$(CC) $(CFLAGS) $(LDLIBS) $(filter %.c, $^) -o $@

logger: logger.c common.h
	$(CC) $(CFLAGS) $(filter %.c, $^) -o $@

.PHONY: clean
clean:
	rm -f *.o logger logger.so *.log *.html
