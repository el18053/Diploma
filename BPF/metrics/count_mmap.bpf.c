#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;
typedef char stringkey[64];


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

SEC("kprobe/filemap_fault")

int trace_filemap_fault(struct pt_regs *ctx) 
{
	stringkey pid_key = "pid";
	u32 *saved_pid = bpf_map_lookup_elem(&execve_counter, &pid_key);

	if (saved_pid == NULL)
	{
		struct vm_fault vmf;// = (struct vm_fault *)PT_REGS_PARM1(ctx);
		bpf_probe_read(&vmf, sizeof(struct vm_fault), (struct vm_fault *)PT_REGS_PARM1(ctx));
		struct vm_area_struct *vma = vmf.vma;
		struct file **filp = &vma->vm_file;

		char *filename = "test";
		int ret = bpf_get_filename(filename, sizeof(filename), filp);

		if(ret == 1)
		{
			u32 uid = bpf_get_current_pid_tgid();
			saved_pid = &uid;
			bpf_map_update_elem(&execve_counter, &pid_key, saved_pid, BPF_ANY);
		}

	}	

	return 0;
}

SEC("kretprobe/filemap_fault")

int trace_filemap_fault_exit(struct pt_regs *ctx) 
{
	if ( get_access(bpf_get_current_pid_tgid()) )
	{
		stringkey pid_key = "pid";	
		bpf_map_delete_elem(&execve_counter, &pid_key);
	}

	return 0;
}

SEC("kprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_enter(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                //page_cache_sync_ra started!
                
		//int req_count = 0;
                //req_count = PT_REGS_PARM2(ctx);
                //bpf_printk("page_cache_sync_ra started with req_count=%d", req_count);
                
		stringkey sync_ra_key = "sync_ra";
                u32 flag = 1;
                u32 *v = &flag;
                bpf_map_update_elem(&execve_counter, &sync_ra_key, v, BPF_ANY);
        }

        return 0;
}

SEC("kretprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_exit(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                //page_cache_sync_ra exits!
                
		//bpf_printk("page_cache_sync_ra finished");
                
		stringkey sync_ra_key = "sync_ra";
                u32 *v = NULL;
                v = bpf_map_lookup_elem(&execve_counter, &sync_ra_key);
                if (v != NULL) {
                        *v = 0;
                }
        }

        return 0;
}

SEC("kprobe/page_cache_async_ra")

int trace_page_cache_async_ra_enter(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                //page_cache_async_ra started!
                
		//int req_count = 0;
                //req_count = PT_REGS_PARM3(ctx);
                //bpf_printk("page_cache_async_ra started with req_count=%d", req_count);
                
		stringkey async_ra_key = "async_ra";
                u32 flag = 1;
                u32 *v = &flag;
                bpf_map_update_elem(&execve_counter, &async_ra_key, v, BPF_ANY);
        }

        return 0;
}

SEC("kretprobe/page_cache_async_ra")

int trace_page_cache_async_ra_exit(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                //page_cache_async_ra exits!
                
		//bpf_printk("page_cache_async_ra finished");
                
		stringkey async_ra_key = "async_ra";
                u32 *v = NULL;
                v = bpf_map_lookup_elem(&execve_counter, &async_ra_key);
                if (v != NULL) {
                        *v = 0;
                }
        }

        return 0;
}

SEC("kprobe/add_to_page_cache_lru")

int trace_page_cache_lru(struct pt_regs *ctx)
{
        if ( get_access(bpf_get_current_pid_tgid()) )
        {
                //bpf_printk("add_to_page_cache_lru started");

                stringkey sync_ra_key = "sync_ra";
                u32 *v = NULL;
                v = bpf_map_lookup_elem(&execve_counter, &sync_ra_key);
                if (v != NULL && *v == 1) {
                        stringkey new_key = "sync_accessed";
                        u32 *sync_accesses = NULL;
                        sync_accesses = bpf_map_lookup_elem(&execve_counter, &new_key);
                        if (sync_accesses != NULL) {
                                *sync_accesses += 1;
                        }

                }


                stringkey async_ra_key = "async_ra";
                v = NULL;
                v = bpf_map_lookup_elem(&execve_counter, &async_ra_key);
                if (v != NULL && *v == 1) {
                        stringkey new_key = "async_accessed";
                        v = NULL;
                        v = bpf_map_lookup_elem(&execve_counter, &new_key);
                        if (v != NULL) {
                                *v += 1;
                        }
                }

        }

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
