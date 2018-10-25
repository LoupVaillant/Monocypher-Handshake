CC=gcc -std=c99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native

.PHONY: all library static-library dynamic-library \
        check test \
        clean

all: handshake.o

handshake.o: handshake.c handshake.h
	$(CC) $(CFLAGS) -c -o $@ $< \
            $$(pkg-config --cflags monocypher)
