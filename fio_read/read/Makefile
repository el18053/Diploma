CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic

all: readfile #mmap_readfile

readfile: readfile.c
	$(CC) $(CFLAGS) -o readfile readfile.c

clean:
	rm -f readfile
