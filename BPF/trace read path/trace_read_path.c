#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "trace_read_path.skel.h"


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
	struct trace_read_path_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace_read_path_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}   

	/* Load & verify BPF programs */
	err = trace_read_path_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = trace_read_path_bpf__attach(skel);
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

		/*
		// Create file to read
		char command[100];
		sprintf(command, "python3 create_file.py %d", fs);

		int result = system(command);

		if (result == -1) {
		printf("Failed to create file.\n");
		goto cleanup;
		}

		//Empty Cache
		result = system("echo 1 > /proc/sys/vm/drop_caches");

		if (result == -1) {
		printf("Failed to empty cache.\n");
		goto cleanup;
		}

		// trigger our BPF program 

		const char *file_path = "output.txt";
		int fd;
		char buffer[BUFFER_SIZE];
		ssize_t bytes_read, offset = 0;

		// Open the file
		fd = open(file_path, O_RDONLY);

		if (fd == -1) {
		perror("Failed to open the file");
		exit(1);
		}

		// Read the file sequentially
		offset = 0;
		while ((bytes_read = pread(fd, buffer, BUFFER_SIZE, offset)) > 0) {
		offset += bytes_read;
		}

		// Close the file
		close(fd);
		*/
		// /*
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

		//After Read is completed delete the pid of the process. (You don't want to counter accesses anymore !)
		/*stringkey pid_key = "pid";
		  err = bpf_map__delete_elem(skel->maps.execve_counter, &pid_key, sizeof(pid_key),  BPF_ANY);
		  if (err != 0) {
		  fprintf(stderr, "Failed to delete the (key,pid) of the process with pid, %d\n", err);
		  goto cleanup;
		  }*/
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
	trace_read_path_bpf__destroy(skel);
	return -err;
}
