#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "trace_read_kprobe.skel.h"
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
	struct trace_read_kprobe_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace_read_kprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = trace_read_kprobe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}


	/* init the counter */
	stringkey key = "bytes_read";
	u64 v = 0;
	err = bpf_map__update_elem(skel->maps.read_map, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the counter, %d\n", err);
		goto cleanup;
	}

	stringkey pid_key = "pid";
	v = getpid();
	err = bpf_map__update_elem(skel->maps.read_map, &pid_key, sizeof(pid_key), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}


	/* Attach tracepoint handler */
	err = trace_read_kprobe_bpf__attach(skel);
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
		const char* file_path = "output.txt";
		int file_descriptor;
		char buffer[BUFFER_SIZE];

		// Open the file
		file_descriptor = open(file_path, O_RDONLY);
		if (file_descriptor == -1) {
			fprintf(stderr, "Failed to open the file");
			goto cleanup;
		}
		else
			printf("fd is : %d\n", file_descriptor);

		// Read from the file using read
		ssize_t bytes_read;

		bytes_read = read(file_descriptor, buffer, BUFFER_SIZE);

		if (bytes_read == -1) {
			fprintf(stderr, "Failed to read the file");
			close(file_descriptor);
			goto cleanup;
		}

		// Close the file
		close(file_descriptor);

		err = bpf_map__lookup_elem(skel->maps.read_map, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		}
		else 
		{
			printf("Total bytes read : %lld\n", v);
		}

		sleep(5);
	}

cleanup:
	trace_read_kprobe_bpf__destroy(skel);
	return -err;
}
