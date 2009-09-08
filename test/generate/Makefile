
LOADLIBES=-lmcrypt
CFLAGS=-O2

CPPFLAGS=-I/opt/local/include
LDFLAGS=-L/opt/local/lib

generate_testcases: generate_testcases.c

memcheck: generate_testcases
	valgrind --leak-check=yes ./generate_testcases > /dev/null
