#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "count.skel.h"

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
        struct count_bpf *skel;
        int err;

        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        /* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);

        /* Open BPF application */
        skel = count_bpf__open();
        if (!skel) {
                fprintf(stderr, "Failed to open BPF skeleton\n");
                return 1;
        }

        /* Load & verify BPF programs */
        err = count_bpf__load(skel);
        if (err) {
                fprintf(stderr, "Failed to load and verify BPF skeleton\n");
                goto cleanup;
        }

        /* Attach tracepoint handler */
        err = count_bpf__attach(skel);
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
                stringkey copy_page_key = "copy_page_to_iter";
                stringkey access_key_1 = "sync_accessed";
                stringkey access_key_2 = "async_accessed";
                u32 v;

                for(int i=1024; i<=1024; i*=2)
                {
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

                        // Create file to read
                        char command[100];
                        sprintf(command, "python3 create_file.py %d", i);

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

                        /* trigger our BPF program */

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

                        u32 copy_page, sync_accesses, async_accesses;

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

                        printf("FILE SIZE = %d Bytes\n", i*1024);
                        printf("Number page copied to user : %d\n", copy_page);
                        printf("Number page cache misses : %d\n", sync_accesses);
                        printf("Number of prefetched pages : %d\n", async_accesses);
                        double ratio = 0;
                        ratio = ((double)copy_page - sync_accesses) / copy_page;
                        printf("Cache Hit Ratio(%%) : %f\n", ratio*100);
                        ratio = 1 - ratio;
                        printf("Cache Miss Ratio(%%) : %f\n", ratio*100);
                        ratio = (async_accesses + sync_accesses) > 0 ? (double)async_accesses / (double)(async_accesses + sync_accesses) : 0;
                        printf("Cache Prefetching Ratio(%%) : %f\n", ratio*100);
                        printf("###############################################################\n");
                }
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
        count_bpf__destroy(skel);
        return -err;
}
