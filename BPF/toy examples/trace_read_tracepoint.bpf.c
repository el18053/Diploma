#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <stddef.h>

typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];

struct read_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	unsigned int padding;
	unsigned long fd;
	char* buf;
	size_t count;
};

struct read_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	//__type(key, stringkey);
	stringkey* key;
	__type(value, u64);
} execve_counter SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_pread64")

int tracepoint_sys_enter(struct read_enter_ctx *ctx) {
	stringkey pid_key = "pid";
	u64 *v = NULL;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key); 
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			char msg[] = "Hello, World!";

			//uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
			bpf_printk("%s from process with pid: %d", msg, uid);


			//const u64 fd = PT_REGS_PARM1(ctx);
			bpf_printk("fd of the read sys call is: %d", ctx->fd);


			//int byte = PT_REGS_PARM3(ctx);
			//bpf_printk("Bytes of the read sys call is: %d", ctx->count);
		}
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")

int trace_read_exit(struct read_exit_ctx *ctx)
{
	stringkey pid_key = "pid";
	u64 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			if (ctx->ret <= 0) {
				bpf_printk("ctx->ret is <= 0");
				return 0;
			}

			unsigned int bytes = ctx->ret;
			bpf_printk("Bytes of the read sys call is: %d", bytes);

			stringkey key = "execve_counter";
			v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &key);
			if (v != NULL) {
				// *v += 1;
				*v += bytes;
				//bpf_map_update_elem(&execve_counter, &key, v, BPF_ANY);
				bpf_printk("map value: %d", *v);
			}
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
