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


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 128);
        //__type(key, stringkey);
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
                bpf_printk("ksys_pread64 exited\n");
                stringkey pid_key = "pid";
                bpf_map_delete_elem(&execve_counter, &pid_key);
        }

        return 0;
}

SEC("kprobe/filemap_read")

int trace_filemap_read(void *ctx) {

        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("filemap_read started");
        }

        return 0;
}

SEC("kprobe/filemap_get_pages")

int trace_filemap_get_pages(struct pt_regs *ctx) {

        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("filemap_get_pages started");
        }

        return 0;
}

SEC("kprobe/filemap_read_page")

int trace_filemap_read_page(struct pt_regs *ctx) {

        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("filemap_read_page started");
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
        }

        return 0;
}

SEC("kprobe/page_cache_next_miss")

int trace_page_cache_next_miss(struct pt_regs *ctx) {
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("page_cache_next_miss started");
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
        }

        return 0;
}

SEC("kprobe/read_pages")

int trace_read_pages(struct pt_regs *ctx) {
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bool skip_page = PT_REGS_PARM3(ctx);
                bpf_printk("read_pages started with skip_page=%d", (int)skip_page);
        }

        return 0;
}

SEC("kprobe/__page_cache_alloc")

int trace_page_cache_alloc(void *ctx) {

	if ( get_access(bpf_get_current_pid_tgid()) )
  	{
  		bpf_printk("page_cache_alloc started");
  	}

  	return 0;
 }

SEC("kprobe/add_to_page_cache_lru")

int trace_page_cache_lru(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("add_to_page_cache_lru started");
        }

        return 0;
}

SEC("kretprobe/copy_page_to_iter")

int trace_copy_page_to_iter(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {

		size_t offset = PT_REGS_PARM2(ctx); 
		size_t bytes = PT_REGS_PARM3(ctx);

		bpf_printk("copy_page_to_iter started with offset=%d, bytes=%d", offset, bytes);
        }

        return 0;
}

SEC("kprobe/mark_page_accessed")

int trace_mark_page_accessed(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                bpf_printk("mark_page_accessed started");
        }

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";