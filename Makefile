CC=gcc
CFLAGS=-Wall -I.
OBJS := server.o run_server.o picohttpparser.o

all: run_server

clean:
	rm -rf run_server *.o

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

picohttpparser.o: picohttpparser/picohttpparser.c
	$(CC) -c $(CFLAGS) $< -o $@

run_server: $(OBJS)
	gcc -o $@ $^

