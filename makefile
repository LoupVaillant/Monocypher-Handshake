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

monokex.o  : monokex.c     monokex.h
test.o     : test.c  utils.h monokex.h
speed.o    : speed.c utils.h monokex.h
monokex.o test.o speed.o:
	$(CC) $(CFLAGS) -c -o $@ $< \
            $$(pkg-config --cflags monocypher)

test.out   : test.o    monokex.o
vectors.out: vectors.o monokex.o
speed.out  : speed.o   monokex.o
test.out vectors.out speed.out:
	$(CC) $(CFLAGS) -o $@ $^               \
            $$(pkg-config --cflags monocypher) \
            $$(pkg-config --libs   monocypher)
