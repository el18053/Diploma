#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024

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

	struct stat st;
	fstat(file_descriptor, &st);
	printf("File size is %ld\n", st.st_size);

	// Read from the file using pread64 in a loop
	ssize_t offset = 1024; // Starting offset
	ssize_t bytes_read;

	//bytes_read = pread(file_descriptor, buffer, BUFFER_SIZE, offset);

	while ((bytes_read = pread(file_descriptor, buffer, BUFFER_SIZE, st.st_size - offset)) > 0 && (st.st_size - offset) > 0) {
		// Print the content read from the file
		//printf("Read %zd bytes: %.*s\n", bytes_read, (int)bytes_read, buffer);

		offset += bytes_read; // Update the offset
	}

	if (bytes_read == -1) {
		perror("Failed to read the file");
		close(file_descriptor);
		exit(1);
	}

	// Close the file
	close(file_descriptor);

	return 0;
}
