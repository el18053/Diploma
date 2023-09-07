#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdbool.h>

typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];
typedef char stringinput[128];

typedef unsigned long pgoff_t;
typedef __kernel_loff_t	loff_t;

struct file_ra_state {
	pgoff_t start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	/* private: use the readahead_* accessors instead */
	pgoff_t _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	//__type(key, stringkey);
	stringkey* key;
	__type(value, u32);
} execve_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024*1024);
	__type(key, int);
	__type(value, stringinput);
} log_file SEC(".maps");

int get_access(u32 process_pid)
{
	stringkey pid_key = "pid";
	u32 *saved_pid;
	saved_pid = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (saved_pid != NULL)
	{
		if (*saved_pid == process_pid)
			return 1;
		return 0;
	}

	return 0;
}

int get_key() {
	stringkey key = "key";
	int *key_val = bpf_map_lookup_elem(&execve_counter, &key);
	if(key_val != NULL) {
		int res = *key_val;
		*key_val += 1;
		return res;
	}
	return -1;
}

SEC("ksyscall/pread64")

int trace_pread64(struct pt_regs *ctx) {
	stringkey pid_key = "pid";
	u32 uid;
	uid = bpf_get_current_pid_tgid();

	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v == NULL) {
		bpf_printk("ksys_pread64 started from process with pid:%d", uid);

		
		int key = get_key();
		/*
		stringinput message;
		char str[] = "ksys_pread64 started from process with pid:    ";
		char uid_str[] = "    ";
		intToString(uid, uid_str);
		
		bpf_probe_read_str(message, sizeof(str), str);
		
		bpf_probe_read_str(message + sizeof(str), sizeof(message), uid_str);
		*/
		
		v = &uid;
		bpf_map_update_elem(&execve_counter, &pid_key, v, BPF_ANY);
	}

	return 0;

}

SEC("kretsyscall/pread64")

int trace_ret_pread64(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("ksys_pread64 exited\n");

		int key = get_key();

		stringkey pid_key = "pid";
		bpf_map_delete_elem(&execve_counter, &pid_key);


	}

	return 0;
}

SEC("kprobe/ondemand_readahead")

int my_ondemand(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("hello from my ondemand readahead!");

		int key = get_key();

		struct readahead_control ractl;

		// Use bpf_probe_read() to read the necessary data structures from kernel memory
		bpf_probe_read(&ractl, sizeof(struct readahead_control), (void *)PT_REGS_PARM1(ctx));
		
		bpf_simos(&ractl, 6);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
