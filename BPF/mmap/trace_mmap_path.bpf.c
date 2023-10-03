#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

typedef char stringkey[64];
typedef char stringinput[128];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, stringkey);
	__type(value, u32);
} execve_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024*1024);
	__type(key, int);
	__type(value, stringinput);
} log_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024*1024);
	__type(key, int);
	__type(value, int);
} index_map SEC(".maps");

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

SEC("kprobe/filemap_fault")

int trace_filemap_fault(struct pt_regs *ctx) {
	//stringkey comm;
	//bpf_get_current_comm(&comm, sizeof(comm));
	
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("filemap_fault started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "filemap_fault started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
		
		struct vm_fault *vmf = (struct vm_fault *)PT_REGS_PARM1(ctx);

		stringkey bring_page_key = "bring_page";
		int *bring_pages = bpf_map_lookup_elem(&execve_counter, &bring_page_key);
		if (bring_pages != NULL)
		{
			if (*bring_pages == 0)
			{
				*bring_pages = 1;
				bpf_simos(vmf, &index_map);
			}
		}	
	}	

	return 0;
}

SEC("kprobe/pagecache_get_page")

int trace_pagecache_get_page(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("pagecache_get_page started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "pagecache_get_page started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/pagecache_get_page")

int trace_ret_pagecache_get_page(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("pagecache_get_page exited");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "pagecache_get_page exited");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_enter(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		//page_cache_sync_ra started!
		int req_count = 0;
		req_count = PT_REGS_PARM2(ctx);
		bpf_printk("page_cache_sync_ra started with req_count=%d", req_count);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "page_cache_sync_ra started with req_count=%d", req_count);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_exit(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		//page_cache_sync_ra exits!
		bpf_printk("page_cache_sync_ra finished");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "page_cache_sync_ra exited");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/page_cache_async_ra")

int trace_page_cache_async_ra_enter(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		//page_cache_async_ra started!
		int req_count = 0;
		req_count = PT_REGS_PARM3(ctx);
		bpf_printk("page_cache_async_ra started with req_count=%d", req_count);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "page_cache_async_ra started with req_count=%d", req_count);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/page_cache_async_ra")

int trace_page_cache_async_ra_exit(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		//page_cache_async_ra exits!
		bpf_printk("page_cache_async_ra finished");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "page_cache_async_ra exited");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/do_page_cache_ra")

int trace_do_page_cache_ra(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int req_size = PT_REGS_PARM2(ctx);
		int async_size = PT_REGS_PARM3(ctx);
		bpf_printk("do_page_cache_ra started with req_size=%d, async_size=%d", req_size, async_size);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "do_page_cache_ra started with req_size=%d, async_size=%d", req_size, async_size);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/page_cache_ra_unbounded")

int trace_page_cache_ra_unbounded(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int nr_to_read = PT_REGS_PARM2(ctx);
		int lookahead_size = PT_REGS_PARM3(ctx);

		bpf_printk("page_cache_ra_unbounded started with nr_to_read=%d and lookahead_size=%d", nr_to_read, lookahead_size);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "page_cache_ra_unbounded started nr_to_read=%d and lookahead_size=%d", nr_to_read, lookahead_size);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/page_cache_ra_unbounded")

int trace_page_cache_ra_unbounded_exit(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("page_cache_ra_unbounded exited");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "page_cache_ra_unbounded exited");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/add_to_page_cache_lru")

int trace_page_cache_lru(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int offset = PT_REGS_PARM3(ctx);

		//bpf_printk("add_to_page_cache_lru started with offset : %d", offset);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "add_to_page_cache_lru started with offset : %d", offset);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
