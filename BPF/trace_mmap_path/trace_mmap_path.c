#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "trace_mmap_path.skel.h"

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
	struct trace_mmap_path_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace_mmap_path_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = trace_mmap_path_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = trace_mmap_path_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	pid_t child_pid = fork();

	if (child_pid == -1) {
		fprintf(stderr, "Fork failed");
		goto cleanup;
	}

	if( child_pid == 0)
	{
		sleep(1);

		int file_size = 20;
		int bs = 4; //bs stands for block size
		int fs = file_size; //fs stands for file size
		int rs = fs; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)

		stringkey key = "key";
		int init_key = 0;
		err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &init_key, sizeof(init_key),  BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Failed to save key %d\n", err);
			goto cleanup;
		}

		stringkey bring_page_key = "bring_page";
		int bring_page = 1;
		err = bpf_map__update_elem(skel->maps.execve_counter, &bring_page_key, sizeof(bring_page_key), &bring_page, sizeof(bring_page),  BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Failed to save key %d\n", err);
			goto cleanup;
		}

		int i = 0, nr_pages = file_size / 4;

		err = bpf_map__update_elem(skel->maps.index_map, &i, sizeof(i), &nr_pages, sizeof(nr_pages), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Failed to create indexes array err=%d", err);
			goto cleanup;
		}

		for(i = 0; i < nr_pages; i++) 
		{
			int j = i + 1;
			err = bpf_map__update_elem(skel->maps.index_map, &j, sizeof(j), &i, sizeof(i), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to create indexes array err=%d", err);
				goto cleanup;
			}
		}

		//Empty Cache
		int result = system("echo 1 > /proc/sys/vm/drop_caches");

		if (result == -1) {
			printf("Failed to empty cache.\n");
			goto cleanup;
		}

		char *engine = "mmap";
		char fioCommand[100];
		sprintf(fioCommand, "FILESIZE=%dk BLOCK_SIZE=%dk ENGINE=%s READSIZE=%dK fio readfile.fio", fs, bs, engine, rs);

		// Execute the FIO command
		result = system(fioCommand);

		if (result == -1) {
			printf("Failed to execute FIO command.\n");
			goto cleanup;
		}

		//Delete test file created by fio (it creates future hazzards)
		result = system("rm test");

		if (result == -1) {
			printf("Failed to empty cache.\n");
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
	}
	else
	{
		printf("child Process ID: %d\n", child_pid);

		int status;
		waitpid(child_pid, &status, 0);

		if (WIFEXITED(status)) {
			printf("Child process exited with status: %d\n", WEXITSTATUS(status));
		}


		sleep(1);
	}

cleanup:
	trace_mmap_path_bpf__destroy(skel);
	return -err;
}
