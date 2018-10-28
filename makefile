CC=gcc -std=c99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native -g

.PHONY: all library static-library dynamic-library \
        check test \
        clean

all: handshake.o

clean:
	rm -rf *.out *.o

handshake.o: handshake.c handshake.h
	$(CC) $(CFLAGS) -c -o $@ $< \
            $$(pkg-config --cflags monocypher)

test.o: test.c utils.h handshake.h
	$(CC) $(CFLAGS) -c -o $@ $< \
            $$(pkg-config --cflags monocypher)

test.out: test.o handshake.o
	$(CC) $(CFLAGS) -o $@ $^               \
            $$(pkg-config --cflags monocypher) \
            $$(pkg-config --libs   monocypher)

test: test.out
	./test.out
