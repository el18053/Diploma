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
		stringinput message = "";
		BPF_SNPRINTF(message, sizeof(message), "ksys_pread64 started from process with pid:%d", uid);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

		v = &uid;
		bpf_map_update_elem(&execve_counter, &pid_key, v, BPF_ANY);
	}

	return 0;

}

SEC("kretsyscall/pread64")

int trace_ret_pread64(struct pt_regs *ctx) {
	u32 uid = bpf_get_current_pid_tgid();

	if ( get_access(uid) )
	{
		bpf_printk("ksys_pread64 exited\n");

		int key = get_key();
		stringinput message = "";
		BPF_SNPRINTF(message, sizeof(message), "ksys_pread64 exited from process with pid:%d\n", uid);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

		stringkey pid_key = "pid";
		bpf_map_delete_elem(&execve_counter, &pid_key);

	}

	return 0;
}

/*SEC("kprobe/vfs_read")

int trace_pread64(struct pt_regs *ctx) {
	stringkey pid_key = "pid";
	u32 uid;
	uid = bpf_get_current_pid_tgid();

	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v == NULL) {
		
		struct file *f = (struct file *)PT_REGS_PARM1(ctx);
		struct file **filp = &f;
		char *filename = "test";

		int ret = bpf_get_filename(filename, sizeof(filename), filp);

		if(ret == 1)
		{
			bpf_printk("vfs_read started from process with pid:%d", uid);
		
			int key = get_key();
			stringinput message = "";
			BPF_SNPRINTF(message, sizeof(message), "vfs_read started from process with pid:%d", uid);
			bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

			v = &uid;
			bpf_map_update_elem(&execve_counter, &pid_key, v, BPF_ANY);
		}
	}

	return 0;

}

SEC("kretprobe/vfs_read")

int trace_ret_pread64(struct pt_regs *ctx) {
	u32 uid = bpf_get_current_pid_tgid();

	if ( get_access(uid) )
	{
		bpf_printk("vfs_read exited\n");

		int key = get_key();
		stringinput message = "";
		BPF_SNPRINTF(message, sizeof(message), "vfs_read exited from process with pid:%d\n", uid);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

		stringkey pid_key = "pid";
		bpf_map_delete_elem(&execve_counter, &pid_key);

	}

	return 0;
}*/

SEC("kprobe/generic_file_read_iter")

int trace_generic_file_read_iter(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("generic_file_read_iter started");

		stringinput message;	
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "generic_file_read_iter started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/filemap_read")

int trace_filemap_read(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("filemap_read started");

		stringinput message;	
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "filemap_read started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/filemap_get_pages")

int trace_filemap_get_pages(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("filemap_get_pages started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "filemap_get_pages started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
		
		struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
		struct file **filp = &iocb->ki_filp;
		
		//struct kiocb iocb;
		//bpf_probe_read(&iocb, sizeof(struct kiocb), (void*)PT_REGS_PARM1(ctx));
		
		stringkey bring_page_key = "bring_page";
		int *bring_page = bpf_map_lookup_elem(&execve_counter, &bring_page_key);
		if (bring_page != NULL)
		{
			if (*bring_page == 1)
			{
				char *filename = "test";
				
				int ret = bpf_get_filename(filename, sizeof(filename), filp);
				if(ret == 1)
				{
					*bring_page = 0;
					bpf_force_page2cache(filp, &index_map);
				}
			}

		}	
	}	

	return 0;
}

/*SEC("kprobe/filemap_read_page")

int trace_filemap_read_page(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("filemap_read_page started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "filemap_read_page started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}*/

SEC("kprobe/my_custom_function_2")

int trace_filemap_read_page(struct pt_regs *ctx) {

	//if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("my_custom_func started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "my_custom_func started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/filemap_get_read_batch")

int trace_filemap_get_read_batch(struct pt_regs *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int index = PT_REGS_PARM2(ctx);
		int last_index = PT_REGS_PARM3(ctx);
		bpf_printk("filemap_get_read_batch started with index=%d, last_index=%d", index, last_index);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "filemap_get_read_batch started with index=%d, last_index=%d", index, last_index);
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

		//time to bring some pages of our own
		struct readahead_control ractl;
		bpf_probe_read(&ractl, sizeof(struct readahead_control), (void *)PT_REGS_PARM1(ctx));
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

SEC("kprobe/force_page_cache_ra")

int trace_force_page_cache_ra(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int req_count = 0;
		req_count = PT_REGS_PARM2(ctx);
		bpf_printk("force_page_cache_ra started with req_count=%d", req_count);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "force_page_cache_ra started with req_count=%d", req_count);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/ondemand_readahead")

int trace_ondemand_readahead_enter(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bool hit_readahead_marker = PT_REGS_PARM2(ctx);
		int req_size = PT_REGS_PARM3(ctx);
		bpf_printk("ondemand_readahead started with req_size=%d, hit_readahead_marker=%d", req_size, (int)hit_readahead_marker);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "ondemand_readahead started with req_size=%d, hit_readahead_marker=%d", req_size, (int)hit_readahead_marker);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

		/*struct readahead_control ractl;

		// Use bpf_probe_read() to read the necessary data structures from kernel memory
		bpf_probe_read(&ractl, sizeof(struct readahead_control), (void *)PT_REGS_PARM1(ctx));

		struct file_ra_state ra;

		bpf_probe_read(&ra, sizeof(struct file_ra_state), (void *)ractl.ra);

		bpf_printk("");
		bpf_printk("rac->_index The index of the first page in this readahead reqeuest : %d", ractl._index);
		bpf_printk("file_ra_state ra :");
		bpf_printk("ra->start Where the most recent readahead started : %d", ra.start); 
		bpf_printk("ra->size Number of pages read in the most recent readahead : %d", ra.size);
		bpf_printk("ra->async_size Start next readahead when this many pages are left : %d", ra.async_size);
		bpf_printk("ra->ra_pages Maximum size of a readahead request : %d", ra.ra_pages);
		bpf_printk("ra->mmap_misses How many mmap accesses missed in the page cache : %d", ra.mmap_miss);
		bpf_printk("ra->prev_pos The last byte in the most recent read request : %d\n", ra.prev_pos);
		*/
	}

	return 0;
}

SEC("kprobe/page_cache_next_miss")

int trace_page_cache_next_miss(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		int index = PT_REGS_PARM2(ctx);
		bpf_printk("page_cache_next_miss started with index=%d", index);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "page_cache_next_miss started with index=%d", index);
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

SEC("kprobe/read_pages")

int trace_read_pages(struct pt_regs *ctx) {
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bool skip_page = PT_REGS_PARM3(ctx);
		bpf_printk("read_pages started with skip_page=%d", (int)skip_page);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "read_pages started with skip_page=%d", (int)skip_page);
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

		bpf_printk("add_to_page_cache_lru started with offset : %d", offset);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "add_to_page_cache_lru started with offset : %d", offset);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/copy_page_to_iter")

int trace_copy_page_to_iter(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{

		size_t offset = PT_REGS_PARM2(ctx); 
		size_t bytes = PT_REGS_PARM3(ctx);

		bpf_printk("copy_page_to_iter started with offset=%d, bytes=%d", offset, bytes);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "copy_page_to_iter started with offset=%d, bytes=%d", offset, bytes);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/copy_page_to_iter")

int trace_copy_page_to_iter_exit(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		size_t return_bytes = PT_REGS_RC(ctx);

		bpf_printk("copy_page_to_iter exited and returned : %d bytes", return_bytes);

		stringinput message = "";
		int key = get_key();
		BPF_SNPRINTF(message, sizeof(message), "copy_page_to_iter exited and returned : %d bytes", return_bytes);
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/mark_page_accessed")

int trace_mark_page_accessed(struct pt_regs *ctx)
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		bpf_printk("mark_page_accessed started");

		stringinput message;
		int key = get_key();
		bpf_probe_read_str(message, sizeof(message), "mark_page_accessed started");
		bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
