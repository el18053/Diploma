#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>


typedef char stringkey[64];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	//__type(key, stringkey);
	stringkey* key;
	__type(value, u32);
} pid_map SEC(".maps");

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
	saved_pid = bpf_map_lookup_elem(&pid_map, &pid_key);
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
	stringkey bring_pages_key = "bring_page";
	int *bring_page = bpf_map_lookup_elem(&pid_map, &bring_pages_key);

	if (bring_page != NULL)
	{
		if (*bring_page == 1)
		{
			struct vm_fault vmf;
			bpf_probe_read(&vmf, sizeof(struct vm_fault), (struct vmf *)PT_REGS_PARM1(ctx));
			struct vm_area_struct *vma = vmf.vma;
			struct file **filp = &vma->vm_file;
			char *filename = "test";

			int ret = bpf_get_filename(filename, sizeof(filename), filp);
			if(ret == 1)
			{
				*bring_page = 0;
				bpf_simos(filp, &index_map);
			}
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
