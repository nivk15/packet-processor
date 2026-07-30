CC = gcc
CFLAGS = -Wall -Wextra -g

sniffer: main.o flow.o
	$(CC) main.o flow.o -o sniffer

main.o: main.c flow.h
	$(CC) $(CFLAGS) -c main.c

flow.o: flow.c flow.h
	$(CC) $(CFLAGS) -c flow.c

clean:
	rm -f sniffer *.o
