#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024*1024

int main(int argc, char **argv) {
	const char* file_path = argv[1];
	int file_descriptor;
	char buffer[BUFFER_SIZE];

	// Open the file
	file_descriptor = open(file_path, O_RDONLY);
	if (file_descriptor == -1) {
		perror("Failed to open the file");
		exit(1);
	}

	//mmap the file
	struct stat st;
	fstat(file_descriptor, &st); //obtain file size

	void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, file_descriptor, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	char* file_data = (char*)addr;

	for (off_t i = 0; i < st.st_size; i++) {
		printf("%c", file_data[i]);
	}

	// Don't forget to unmap the file after you're done
	munmap(addr, st.st_size);

	// Close the file
	close(file_descriptor);

	return 0;
}
