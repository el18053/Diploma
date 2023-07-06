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
		sleep(1);

		//child process
		printf("Child process started\n");

		//Init Counters to Zero
		stringkey access_key = "mark_page_accessed";
		stringkey copy_page_key = "copy_page_to_iter";
		stringkey access_key_1 = "sync_accessed";
		stringkey access_key_2 = "async_accessed";
		u32 v;

		for (int bs=1; bs<=32; bs*=2) { //bs stands for block size
			for(int fs=32; fs<=1024*1024; fs*=2) // fs stands for file size
			{
				v = 0;
				err = bpf_map__update_elem(skel->maps.execve_counter, &access_key, sizeof(access_key), &v, sizeof(v),  BPF_ANY);
				if (err != 0) {
					fprintf(stderr, "Failed to init the process pid, %d\n", err);
					goto cleanup;
				}

				v = 0;
				err = bpf_map__update_elem(skel->maps.execve_counter, &copy_page_key, sizeof(copy_page_key), &v, sizeof(v),  BPF_ANY);
				if (err != 0) {
					fprintf(stderr, "Failed to init the process pid, %d\n", err);
					goto cleanup;
				}

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

				char fioCommand[100];
				sprintf(fioCommand, "SIZE=%dk BLOCK_SIZE=%dk fio test.fio", fs, bs);

				// Execute the FIO command
				int result = system(fioCommand);

				if (result == -1) {
					printf("Failed to execute FIO command.\n");
					goto cleanup;
				}

				u32 accesses, copy_page, sync_accesses, async_accesses;

				err = bpf_map__lookup_elem(skel->maps.execve_counter, &access_key, sizeof(access_key), &accesses, sizeof(accesses), BPF_ANY);
				if (err != 0) {
					fprintf(stderr, "Lookup key from map error: %d\n", err);
					goto cleanup;
				}

				err = bpf_map__lookup_elem(skel->maps.execve_counter, &copy_page_key, sizeof(copy_page_key), &copy_page, sizeof(copy_page), BPF_ANY);
				if (err != 0) {
					fprintf(stderr, "Lookup key from map error: %d\n", err);
					goto cleanup;
				}

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

				const char* filename = "result.txt";

				// Open the file in append mode
				FILE* file = fopen(filename, "a");
				if (file == NULL) {
					printf("Failed to open the file.\n");
					goto cleanup;
				}

				fprintf(file, "FILE SIZE = %d KB\n", fs);
				fprintf(file, "BLOCK SIZE = %d KB\n", bs);
				fprintf(file, "Number page accesses : %d\n", accesses);
				fprintf(file, "Number page copied to user : %d\n", copy_page);
				fprintf(file, "Number page cache misses : %d\n", sync_accesses);
				fprintf(file, "Number of prefetched pages : %d\n", async_accesses);
				double ratio = 0;
				ratio = ((double)copy_page - sync_accesses) / copy_page;
				fprintf(file, "Cache Hit Ratio(%%) : %f\n", ratio*100);
				ratio = 1 - ratio;
				fprintf(file, "Cache Miss Ratio(%%) : %f\n", ratio*100);
				ratio = (async_accesses + sync_accesses) > 0 ? (double)async_accesses / (double)(async_accesses + sync_accesses) : 0;
				fprintf(file, "Cache Prefetching Ratio(%%) : %f\n", ratio*100);
				if (copy_page != sync_accesses + async_accesses) {
					if (bs < 4) {
						if (copy_page != 4 / bs * (sync_accesses + async_accesses))
							fprintf(file, "WARNING : COPY_PAGE != SYNC_ACCESSES + ASYNC_ACCESES\n");
					}
					else
						fprintf(file, "WARNING : COPY_PAGE != SYNC_ACCESSES + ASYNC_ACCESES\n");
				}
				fprintf(file, "###############################################################\n");

				// Close the file
				fclose(file);

			}
		}
	}
	else {
		//parent process
		printf("Parent process created Child process with PID: %d\n", pid);

		//Pid of the process that will execute the read sys call
		/*stringkey pid_key = "pid";
		  u32 v = pid;
		  err = bpf_map__update_elem(skel->maps.execve_counter, &pid_key, sizeof(pid_key), &v, sizeof(v),  BPF_ANY);
		  if (err != 0) {
		  fprintf(stderr, "Failed to init the process pid, %d\n", err);
		  goto cleanup;
		  }*/

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
