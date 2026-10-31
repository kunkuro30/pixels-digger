CC ?= gcc
CFLAGS ?= -O3 -march=native -pthread

digger: digger.c
	$(CC) $(CFLAGS) -o digger digger.c

portable: digger.c
	$(CC) -O3 -pthread -o digger digger.c

clean:
	rm -f digger found.txt
