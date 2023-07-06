#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "trace_read_tracepoint.skel.h"
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
	struct trace_read_tracepoint_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace_read_tracepoint_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = trace_read_tracepoint_bpf__load(skel);
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
	err = trace_read_tracepoint_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Lookup key from map error: %d\n", err);
		goto cleanup;
	} 
	const char* file_path = "output.txt";
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

cleanup:
	trace_read_tracepoint_bpf__destroy(skel);
	return -err;
}
