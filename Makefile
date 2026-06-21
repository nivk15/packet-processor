CC = gcc
CFLAGS = -Wall -Wextra -g

sniffer: main.c
	$(CC) $(CFLAGS) main.c -o sniffer

clean:
	rm -f sniffer