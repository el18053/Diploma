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

	/*stringkey pid_key = "pid";
	  u64 v = getpid();
	  err = bpf_map__update_elem(skel->maps.execve_counter, &pid_key, sizeof(pid_key), &v, sizeof(v),  BPF_ANY);
	  if (err != 0) {
	  fprintf(stderr, "Failed to init the process pid, %d\n", err);
	  goto cleanup;
	  }*/

	stringkey access_key = "mark_page_accessed";
	u64 v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &access_key, sizeof(access_key), &v, sizeof(v),  BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the process pid, %d\n", err);
		goto cleanup;
	}

	stringkey copy_page_key = "copy_page_to_iter";
	v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &copy_page_key, sizeof(copy_page_key), &v, sizeof(v),  BPF_ANY);
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

	pid_t pid = fork();

	if (pid == -1) {
		perror("Failed to fork process");
		goto cleanup;
	}

	else if (pid == 0) {
		//child process
		printf("Child process\n");

		/* trigger our BPF program */
		
		/*const char *file_path = "output.txt";
		int fd;
		char buffer[BUFFER_SIZE];
		ssize_t bytes_read, offset = 0;

		// Open the file
		fd = open(file_path, O_RDONLY);

		if (fd == -1) {
			perror("Failed to open the file");
			exit(1);
		}

		//Read the file backwards
		// Get the size of the file
		struct stat st;
		fstat(fd, &st);
		off_t file_size = st.st_size;

		for (offset = file_size - BUFFER_SIZE; offset >= 0; offset -= BUFFER_SIZE) {
			bytes_read = pread(fd, buffer, BUFFER_SIZE, offset);
			if (bytes_read == -1) {
				perror("pread");
				exit(EXIT_FAILURE);
			}
		}

		// Read the file sequentially
		offset = 0;
		while ((bytes_read = pread(fd, buffer, BUFFER_SIZE, offset)) > 0) {
			offset += bytes_read;
		}

		// Close the file
		close(fd);
		*/
		
		// Define the FIO command as a string
		const char* fioCommand = "fio test.fio";

		// Execute the FIO command
		int result = system(fioCommand);

		if (result == -1) {
		printf("Failed to execute FIO command.\n");
		goto cleanup;
		}
	}
	else {
		//parent process
		printf("Parent process\n");
        	printf("Child PID: %d\n", pid);
		
		/*stringkey pid_key = "pid";
		u64 v = pid;
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

		u64 accesses, copy_page, sync_accesses, async_accesses;

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

		printf("Number page accesses : %lld\n", accesses);
		printf("Number page copied to user : %lld\n", copy_page);
		printf("Number page cache misses : %lld\n", sync_accesses);
		printf("Number of prefetched pages : %lld\n", async_accesses);
		/*double ratio = 0;
		ratio = (copy_page - sync_accesses) / copy_page;
		printf("Cache Hit Ratio(%) : %f\n", ratio);
		ratio = 100 - ratio;
		printf("Cache Miss Ratio(%) : %f\n", ratio);*/
	}

	sleep(1);

cleanup:
	helloworld_bpf__destroy(skel);
	return -err;
}
