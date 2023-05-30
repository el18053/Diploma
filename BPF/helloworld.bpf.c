#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <stddef.h>

SEC("ksyscall/pread64")
int trace_pread64(void *ctx) {
	
	bpf_printk("Hello from ksys_pread64\n");

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
