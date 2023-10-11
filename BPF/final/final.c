#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "final.skel.h"

#define BUFFER_SIZE 4096


typedef __u64 u64;
typedef __u32 u32;
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

	/* Attach tracepoint handler */
	err = final_bpf__attach(skel);
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
		//child process
		printf("Child process started\n");

		for(int file_size = 32; file_size <= 32; file_size *= 4)
		{
			sleep(1);

			int bring_page = 1;
			stringkey bring_page_key = "bring_page";
			err = bpf_map__update_elem(skel->maps.pid_map, &bring_page_key, sizeof(bring_page_key), &bring_page, sizeof(bring_page), BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Failed to set bring_page = 0 (error code=%d)", err);
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

			int bs = 4; //bs stands for block size
			int fs = file_size; //fs stands for file size
			int rs = fs / 2; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)

			//Empty Cache
			int result = system("echo 1 > /proc/sys/vm/drop_caches");

			if (result == -1) {
				printf("Failed to empty cache.\n");
				goto cleanup;
			}
			
			char *engine = "psync";
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
	final_bpf__destroy(skel);
	return -err;
}
