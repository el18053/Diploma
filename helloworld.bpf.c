#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <stddef.h>

typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];


//SEC("tracepoint/syscalls/sys_enter_execve")
//SEC("tracepoint/exceptions/page_fault_kernel")
//SEC("kprobe/add_to_page_cache_lru")
//SEC("ksyscall/pread64")

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, stringkey);
	__type(value, u64);
} pid SEC(".maps");


SEC("ksyscall/pread64")
int trace_pread64(void *ctx) {
	bpf_printk("Hello from ksys_pread64\n");

	/* init the counter */
	stringkey key = "pid";

	u64 uid;
	uid = bpf_get_current_pid_tgid();

	int err = bpf_map_update_elem(&pid, &key, &uid, BPF_ANY);
	if (err != 0) {
		bpf_printk("Failed to init the counter, %d\n", err);
		return 1;
	}

	return 0;
}

SEC("kprobe/vfs_read")
int trace_vfs_read(void *ctx) {
	stringkey key = "pid";
	u64 *v = NULL; 
	v = bpf_map_lookup_elem(&pid, &key);
	if(v != NULL) {
		if(*v == bpf_get_current_pid_tgid())
			bpf_printk("Hello from vfs_read\n");
	}
	return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
root@debian:/home/simos/libbpf-bootstrap/examples/c# 

