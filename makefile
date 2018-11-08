CC=gcc -std=gnu99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native -g

.PHONY: all library static-library dynamic-library \
        check test vectors speed \
        clean

all: handshake.o

check: test
test: test.out
	./test.out
vectors: vectors.out
	./vectors.out
speed: speed.out
	./speed.out

clean:
	rm -rf *.out *.o

handshake.o: handshake.c     handshake.h
test.o     : test.c  utils.h handshake.h
speed.o    : speed.c utils.h handshake.h
handshake.o test.o speed.o:
	$(CC) $(CFLAGS) -c -o $@ $< \
            $$(pkg-config --cflags monocypher)

test.out   : test.o    handshake.o
vectors.out: vectors.o handshake.o
speed.out  : speed.o   handshake.o
test.out vectors.out speed.out:
	$(CC) $(CFLAGS) -o $@ $^               \
            $$(pkg-config --cflags monocypher) \
            $$(pkg-config --libs   monocypher)
