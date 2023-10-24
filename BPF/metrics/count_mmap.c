#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include "count_mmap.skel.h"

typedef __u32 u32;
typedef char stringkey[64];


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct count_mmap_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = count_mmap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = count_mmap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = count_mmap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
			"to see output of the BPF programs.\n");

	pid_t pid = fork();

	if (pid == -1) {
		perror("Failed to fork process");
		goto cleanup;
	}

	else if (pid == 0) {
		sleep(1);

		//child process
		printf("Child process started\n");

		//Init Counters to Zero
		stringkey access_key_1 = "sync_accessed";
		stringkey access_key_2 = "async_accessed";
		u32 v;

		int file_size = 256;
		{
			v = 0;
			err = bpf_map__update_elem(skel->maps.execve_counter, &access_key_1, sizeof(access_key_1), &v, sizeof(v),  BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to init the process pid, %d\n", err);
				goto cleanup;
			}

			v = 0;
			err = bpf_map__update_elem(skel->maps.execve_counter, &access_key_2, sizeof(access_key_2), &v, sizeof(v),  BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to init the process pid, %d\n", err);
				goto cleanup;
			}

			int bs = 4; //bs stands for block size
			int fs = file_size; //fs stands for file size
			int rs = fs; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)
			char *engine = "mmap";
			
			//Empty Cache
			int result = system("echo 1 > /proc/sys/vm/drop_caches");

			if (result == -1) {
				printf("Failed to empty cache.\n");
				goto cleanup;
			}


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


			u32 sync_accesses, async_accesses;

			err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key_1, sizeof(access_key_1), &sync_accesses, sizeof(sync_accesses), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Lookup key from map error: %d\n", err);
				goto cleanup;
			}

			err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key_2, sizeof(access_key_2), &async_accesses, sizeof(async_accesses), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Lookup key from map error: %d\n", err);
				goto cleanup;
			}

			printf("FILE SIZE = %d KBytes\n", file_size);
			printf("Number of Sync fetcted page(s) : %d\n", sync_accesses);
			printf("Number of Async fetched page(s) : %d\n", async_accesses);
			printf("###############################################################\n");
		}
	}
	else {
		//parent process
		printf("Parent process created Child process with PID: %d\n", pid);

		//wait for child process to execute read commmand
		int status;
		wait(&status);
		if (WIFEXITED(status)) {
			printf("Child process exited with status: %d\n", WEXITSTATUS(status));
		}

	}

	sleep(1);

cleanup:
	count_mmap_bpf__destroy(skel);
	return -err;
}
