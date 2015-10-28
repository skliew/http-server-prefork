CC=gcc
CFLAGS=-Wall -I.

all: run_server

clean:
	rm -rf run_server *.o

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

run_server: run_server.o server.o
	gcc -o $@ $^

