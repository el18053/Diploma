#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "final.skel.h"
#include <fcntl.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024*1024

typedef __u64 u64;
typedef char stringkey[64];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct final_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = final_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = final_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}


	/* init the counter */
	stringkey key = "execve_counter";
	u64 v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the counter, %d\n", err);
		goto cleanup;
	}

	stringkey pid_key = "pid";
	v = getpid();
	err = bpf_map__update_elem(skel->maps.execve_counter, &pid_key, sizeof(pid_key), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}


	/* Attach tracepoint handler */
	err = final_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		//fprintf(stderr, ".");
		//sleep(1);
		// read counter value from map
		//
		//LIBBPF_API int bpf_map__lookup_elem(const struct bpf_map *map,
		//        const void *key, size_t key_sz,
		//        void *value, size_t value_sz, __u64 flags);
		//        /usr/local/bpf/include/bpf/libbpf.h
		err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		} 
		else {
			;//printf("execve_counter is %llu\n", v);
		}
		const char* file_path = "hello.c";
		int file_descriptor;
		char buffer[BUFFER_SIZE];

		// Open the file
		file_descriptor = open(file_path, O_RDONLY);
		if (file_descriptor == -1) {
			perror("Failed to open the file");
			exit(1);
		}

		// Read from the file using pread64 in a loop
		ssize_t offset = 0; // Starting offset
		ssize_t bytes_read;

		bytes_read = pread(file_descriptor, buffer, BUFFER_SIZE, offset);

		if (bytes_read == -1) {
			perror("Failed to read the file");
			close(file_descriptor);
			exit(1);
		}

		// Close the file
		close(file_descriptor);


		sleep(5);
	}

cleanup:
	final_bpf__destroy(skel);
	return -err;
}
