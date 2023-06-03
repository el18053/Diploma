#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

#define BUFFER_SIZE 1024*1024

typedef __u64 u64;
typedef char stringkey[64];


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct helloworld_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = helloworld_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = helloworld_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	stringkey pid_key = "pid";
	u64 v = getpid();
	err = bpf_map__update_elem(skel->maps.execve_counter, &pid_key, sizeof(pid_key), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}
	
	stringkey access_key = "accessed";
	v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &access_key, sizeof(access_key), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}

	stringkey access_key_1 = "sync_accessed";
	v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &access_key_1, sizeof(access_key_1), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}

	stringkey access_key_2 = "async_accessed";
	v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &access_key_2, sizeof(access_key_2), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}




	/* Attach tracepoint handler */
	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	//for (;;) {
		/* trigger our BPF program */
		const char* file_path = "output.txt";
		int file_descriptor;
		char buffer[BUFFER_SIZE];

		// Open the file
		file_descriptor = open(file_path, O_RDONLY);
		if (file_descriptor == -1) {
			fprintf(stderr, "Failed to open the file");
			err = file_descriptor;
			goto cleanup;
		}

		// Read from the file using pread64 in a loop
		ssize_t offset = 0; // Starting offset
		ssize_t bytes_read;

		//bytes_read = pread(file_descriptor, buffer, BUFFER_SIZE, offset);

		while ((bytes_read = pread(file_descriptor, buffer, BUFFER_SIZE, offset)) > 0) {
			// Print the content read from the file
			//printf("Read %zd bytes\n", bytes_read);

			offset += bytes_read; // Update the offset
		}

		if (bytes_read == -1) {
			fprintf(stderr, "Failed to read the file");
			close(file_descriptor);
			err = bytes_read;
			goto cleanup;
		}

		// Close the file
		close(file_descriptor);

		u64 accesses, sync_accesses, async_accesses;
		
		err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key, sizeof(access_key), &accesses, sizeof(accesses), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		}
		else {
			printf("Number page accesses : %lld\n", accesses);
		}

		err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key_1, sizeof(access_key_1), &sync_accesses, sizeof(sync_accesses), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		}
		else {
			printf("Number page cache misses : %lld\n", sync_accesses);
		}

		err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key_2, sizeof(access_key_2), &async_accesses, sizeof(async_accesses), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		}
		else {
			printf("Number of prefetched pages : %lld\n", async_accesses);
		}

		if (sync_accesses > 0 || async_accesses > 0) 
		{
			if ( accesses != sync_accesses + async_accesses )
			{
				fprintf(stderr, "Error in page cache accesses!!!\n");
				goto cleanup;
			}
		}


		sleep(1);
	//}

cleanup:
	helloworld_bpf__destroy(skel);
	return -err;
}
