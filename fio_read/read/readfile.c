#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>

int main(int argc, char **argv)
{

	pid_t pid = fork();

	if (pid == -1) {
		perror("Failed to fork process");
		goto cleanup;
	}

	else if (pid == 0) {
		//child process
		printf("Child process started\n");

		//for(int file_size = 32; file_size <= 2*1024*1024; file_size *= 4)
		int file_size = 500*1024;
		{
			sleep(1);

			int bs = 4; //bs stands for block size
			int fs = file_size; //fs stands for file size
			int rs = fs; //rs stands for how many bytes of the file do we want to read (bs <= rs <= fs)

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
	return 0;
}
