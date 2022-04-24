CC=gcc
CFLAGS=-g -pedantic -Wno-unused-parameter

ipk-sniffer: main.c
	$(CC) $(CFLAGS) main.c -lpcap -o ipk-sniffer
clean:
	rm -f *.o *~
