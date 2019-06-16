CC=gcc -std=gnu99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native -g

.PHONY: all library static-library dynamic-library \
        check test vectors speed \
        clean

all: monokex.o

check: test
test: test.out
	./test.out
vectors: vectors.out
	./vectors.out
speed: speed.out
	./speed.out

clean:
	rm -rf *.out *.o

monocypher.o: monocypher.c    monocypher.h
monokex.o   : monokex.c       monokex.h monocypher.h
vectors.o   : vectors.c       vectors.h monocypher.h
test.o      : test.c  utils.h monokex.h monocypher.h
speed.o     : speed.c utils.h monokex.h monocypher.h
monokex.o test.o speed.o vectors.o:
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

test.out   : test.o    monokex.o monocypher.o
speed.out  : speed.o   monokex.o monocypher.o
test.out vectors.out speed.out:
	$(CC) $(CFLAGS) -fPIC -o $@ $^
