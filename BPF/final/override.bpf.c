#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/kernel.h>


typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];
int something = 0;

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
	stringkey* key;
	__type(value, u32);
} execve_counter SEC(".maps");

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

SEC("ksyscall/pread64")

int trace_pread64(struct pt_regs *ctx) {
	stringkey pid_key = "pid";
	u32 uid;
	uid = bpf_get_current_pid_tgid();

	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v == NULL) {
		bpf_printk("ksys_pread64 started from process with pid:%d", uid);
		v = &uid;
		bpf_map_update_elem(&execve_counter, &pid_key, v, BPF_ANY);

	}
	return 0;

}

SEC("kretsyscall/pread64")

int trace_ret_pread64(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{

		int ret = PT_REGS_RC(ctx);
		bpf_printk("ksys_pread64 exited with ret=%d\n", ret);
		stringkey pid_key = "pid";
		bpf_map_delete_elem(&execve_counter, &pid_key);
	}
	return 0;
}

/*SEC("kprobe/ondemand_readahead")

int trace_ondemand_readahead_enter(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bool *ex_marker;
		ex_marker = &PT_REGS_PARM2(ctx);
		bpf_printk("marker is : %d", *ex_marker);
		//bool new = true;
		// ex_marker = new;
		bool ex_marker;
		bpf_probe_read(&ex_marker, sizeof(ex_marker), &PT_REGS_PARM2(ctx));
		bpf_printk("ex_marker is : %d", ex_marker);
		bpf_printk("** ondemand_readahead ** OVERWRITING");

		bool replace = 0;

		// overwrite the user space buffer
		long success = bpf_probe_write_user(&ex_marker, &replace, sizeof(bool));
	}

	return 0;
}*/

SEC("kprobe/__add_to_page_cache_locked")

int trace_add_to_page_cache_lru(struct pt_regs *ctx) {
	if( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("__add_to_page_cache_lru");
		if( something == 0)
		{
			bpf_override_return(ctx, -1);
			something += 1;
		}
	}
	return 0;

}

SEC("kretprobe/add_to_page_cache_lru")

int trace_ret_add_to_page_cache_lru(struct pt_regs *ctx) {
	if( get_access(bpf_get_current_pid_tgid()) )
	{
		int ret = PT_REGS_RC(ctx);
		bpf_printk("add_to_page_cache_lru exited with ret=%d", ret);
	}
	return 0;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
