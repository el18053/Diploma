#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "override.skel.h"

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
	struct override_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = override_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = override_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = override_bpf__attach(skel);
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

			//Empty Cache
			int result = 0; //system("echo 1 > /proc/sys/vm/drop_caches");

			if (result == -1) {
				printf("Failed to empty cache.\n");
				goto cleanup;
			}

			int bs = 4; //bs stands for block size
			int fs = 24; //fs stands for file size
			int rs = fs; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)


			char fioCommand[100];
			sprintf(fioCommand, "FILESIZE=%dk BLOCK_SIZE=%dk READSIZE=%dK fio readfile.fio", fs, bs, rs);

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

cleanup:
	override_bpf__destroy(skel);
	return -err;
}
