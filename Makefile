CC = gcc
CFLAGS = -Wall -Wextra -g

sniffer: main.o flow.o
	$(CC) main.o flow.o -o sniffer

main.o: main.c flow.h
	$(CC) $(CFLAGS) -c main.c

flow.o: flow.c flow.h
	$(CC) $(CFLAGS) -c flow.c

# test_runner links flow.o but not main.o - test.c has its own main()
test: test.o flow.o
	$(CC) test.o flow.o -o test_runner
	./test_runner

test.o: test.c flow.h
	$(CC) $(CFLAGS) -c test.c

clean:
	rm -f sniffer test_runner *.o
