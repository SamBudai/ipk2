CC=gcc
CFLAGS=-g -Wall -pedantic -Wno-unused-parameter -Wall -Werror

ipk-sniffer: main.c
	$(CC) $(CFLAGS) main.c -lpcap -o ipk-sniffer
clean:
	rm -f *.o *~