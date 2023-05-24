#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define BUFFER_SIZE 4096

int main() {
    const char* file_path = "example.txt";
    int file_descriptor;
    char buffer[BUFFER_SIZE];

    // Open the file
    file_descriptor = open(file_path, O_RDONLY);
    if (file_descriptor == -1) {
        perror("Failed to open the file");
        exit(1);
    }

    // Read from the file using pread64 in a loop
    off64_t offset = 0; // Starting offset
    ssize_t bytes_read;

    while ((bytes_read = pread64(file_descriptor, buffer, BUFFER_SIZE, offset)) > 0) {
        // Print the content read from the file
        printf("Read %zd bytes: %.*s\n", bytes_read, (int)bytes_read, buffer);

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
