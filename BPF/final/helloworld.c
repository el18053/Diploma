#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

#define BUFFER_SIZE 4096

typedef __u64 u64;
typedef __u32 u32;
typedef char stringkey[64];
typedef char stringinput[128];

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

	/* Attach tracepoint handler */
	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	stringkey key = "key";
	int init_key = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &init_key, sizeof(init_key),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to save key %d\n", err);
		goto cleanup;
	}

	int bs = 4; //bs stands for block size
	int fs = 128; //fs stands for file size
	int rs = 24; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)

	//Empty Cache
	int result = system("echo 1 > /proc/sys/vm/drop_caches");

	if (result == -1) {
		printf("Failed to empty cache.\n");
		goto cleanup;
	}

	char fioCommand[100];
	sprintf(fioCommand, "FILESIZE=%dk BLOCK_SIZE=%dk READSIZE=%dK fio readfile.fio", fs, bs, rs);

	// Execute the FIO command
	result = system(fioCommand);

	if (result == -1) {
		printf("Failed to execute FIO command.\n");
		goto cleanup;
	}

	int key_size;
	err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key),  &key_size, sizeof(key_size), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to retreive key_size, err= %d\n", err);
		goto cleanup;
	}

	FILE* file = fopen("log.txt", "w");
	if (file == NULL) {
		printf("Failed to open the file.\n");
		goto cleanup;
	}

	for (int i=0; i < key_size; i++) {
		stringinput message;
		err = bpf_map__lookup_elem(skel->maps.log_file, &i, sizeof(i), message, sizeof(message), BPF_ANY);
		fprintf(file, "%s\n", message);
	}	       

	fclose(file);

	sleep(1);

cleanup:
	helloworld_bpf__destroy(skel);
	return -err;
}
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

#define BUFFER_SIZE 4096

typedef __u64 u64;
typedef __u32 u32;
typedef char stringkey[64];
typedef char stringinput[128];

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

	/* Attach tracepoint handler */
	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	stringkey key = "key";
	int init_key = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &init_key, sizeof(init_key),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to save key %d\n", err);
		goto cleanup;
	}

	int bs = 4; //bs stands for block size
	int fs = 128; //fs stands for file size
	int rs = 24; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)

	//Empty Cache
	int result = system("echo 1 > /proc/sys/vm/drop_caches");

	if (result == -1) {
		printf("Failed to empty cache.\n");
		goto cleanup;
	}

	char fioCommand[100];
	sprintf(fioCommand, "FILESIZE=%dk BLOCK_SIZE=%dk READSIZE=%dK fio readfile.fio", fs, bs, rs);

	// Execute the FIO command
	result = system(fioCommand);

	if (result == -1) {
		printf("Failed to execute FIO command.\n");
		goto cleanup;
	}

	int key_size;
	err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key),  &key_size, sizeof(key_size), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to retreive key_size, err= %d\n", err);
		goto cleanup;
	}

	FILE* file = fopen("log.txt", "w");
	if (file == NULL) {
		printf("Failed to open the file.\n");
		goto cleanup;
	}

	for (int i=0; i < key_size; i++) {
		stringinput message;
		err = bpf_map__lookup_elem(skel->maps.log_file, &i, sizeof(i), message, sizeof(message), BPF_ANY);
		fprintf(file, "%s\n", message);
	}	       

	fclose(file);

	sleep(1);

cleanup:
	helloworld_bpf__destroy(skel);
	return -err;
}