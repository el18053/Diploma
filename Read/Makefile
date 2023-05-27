CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic

all: readfile rreadfile mmap_readfile

readfile: readfile.c
	$(CC) $(CFLAGS) -o readfile readfile.c

rreadfile: readfilereverse.c
	$(CC) $(CFLAGS) -o rreadfile readfilereverse.c

mmap_readfile: mmap_read.c
	$(CC) $(CFLAGS) -o mmap_readfile mmap_read.c

clean:
	rm -f readfile rreadfile mmap_readfile
