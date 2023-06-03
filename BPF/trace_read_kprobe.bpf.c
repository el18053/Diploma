#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <stddef.h>

typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	//__type(key, stringkey);
	stringkey* key;
	__type(value, u64);
} read_map SEC(".maps");


SEC("kprobe/ksys_read")

int tracepoint_read_enter(struct pt_regs *ctx) {
	stringkey pid_key = "pid";
	u64 *v = NULL;
	v = bpf_map_lookup_elem(&read_map, &pid_key); 
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			char msg[] = "Hello, World!";

			//u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
			bpf_printk("%s from process with pid: %d\n", msg, uid);


			int fd = PT_REGS_PARM1(ctx);
			bpf_printk("fd of the read sys call is: %d\n", fd);
		}
	}
	return 0;
}

SEC("kretprobe/filemap_read") // or SEC("kretsyscall/pread64")

int trace_read_exit(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u64 *v;
	v = bpf_map_lookup_elem(&read_map, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {

			int ret = PT_REGS_RC(ctx);

			if (ret <= 0) {
				bpf_printk("ret is <= 0\n");
				return 0;
			}

			bpf_printk("Bytes of the read sys call are: %d\n", ret);

			stringkey key = "bytes_read";
			v = NULL;
			v = bpf_map_lookup_elem(&read_map, &key);
			if (v != NULL) {
				*v += ret;
				//bpf_map_update_elem(&read_map, &key, v, BPF_ANY);
				//bpf_printk("map value: %d\n", *v);
			}
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
