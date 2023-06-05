#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
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
} execve_counter SEC(".maps");


/*SEC("ksyscall/pread64")

int trace_pread64(void *ctx) {
	stringkey pid_key = "pid";
	u64 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("ksys_pread64 started\n");
		}
	}
	return 0;

}*/

SEC("ksyscall/pread64")

int trace_pread64(void *ctx) {
	stringkey pid_key = "pid";
	u32 uid;
	uid = bpf_get_current_pid_tgid();

	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	//if (v == NULL) {
		bpf_printk("ksys_pread64 started from process with pid:%d\n", uid);
		v = &uid;
		bpf_map_update_elem(&execve_counter, &pid_key, v, BPF_ANY);
	//}
	
	return 0;

}

SEC("kretsyscall/pread64")

int trace_ret_pread64(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("ksys_pread64 exited\n");
		}
	}
	return 0;

}

SEC("kprobe/filemap_read")

int trace_filemap_read(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("filemap_read started\n");
		}
	}
	return 0;

}

SEC("kprobe/filemap_get_pages")

int trace_filemap_get_pages(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("filemap_get_pages started\n");
		}
	}
	return 0;

}

SEC("kprobe/filemap_get_read_batch")

int trace_filemap_get_read_batch(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("filemap_get_read_batch started\n");
		}
	}
	return 0;

}


SEC("kprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_enter(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//page_cache_sync_ra started!
			//bpf_printk("page_cache_sync_ra started\n");
			stringkey sync_ra_key = "sync_ra";
			u64 myValue = 1;
			u64* v = &myValue;
			bpf_map_update_elem(&execve_counter, &sync_ra_key, v, BPF_ANY);
		}
	}
	return 0;

}

SEC("kretprobe/page_cache_sync_ra")

int trace_page_cache_sync_ra_exit(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//page_cache_sync_ra exits!
			//bpf_printk("page_cache_sync_ra finished\n");
			stringkey sync_ra_key = "sync_ra";
			u64 *v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &sync_ra_key);
			if (v != NULL) {
				*v = 0;
			}
		}
	}
	return 0;
}

SEC("kprobe/page_cache_async_ra")

int trace_page_cache_async_ra_enter(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//page_cache_async_ra started!
			//bpf_printk("page_cache_async_ra started\n");
			stringkey sync_ra_key = "async_ra";
			u64 myValue = 1;
			u64* v = &myValue;
			bpf_map_update_elem(&execve_counter, &sync_ra_key, v, BPF_ANY);
		}
	}
	return 0;

}

SEC("kretprobe/page_cache_async_ra")

int trace_page_cache_async_ra_exit(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//page_cache_async_ra exits!
			//bpf_printk("page_cache_async_ra finished\n");
			stringkey sync_ra_key = "async_ra";
			u64 *v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &sync_ra_key);
			if (v != NULL) {
				*v = 0;
			}
		}
	}
	return 0;
}

SEC("kprobe/ondemand_readahead")

int trace_ondemand_readahead(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("ondemand_readahead started\n");
		}
	}
	return 0;

}

SEC("kprobe/do_page_cache_ra")

int trace_do_page_cache_ra(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("do_page_cache_ra started\n");
		}
	}
	return 0;

}

SEC("kprobe/page_cache_ra_unbounded")

int trace_page_cache_ra_unbounded(void *ctx) {
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			bpf_printk("page_cache_ra_unbounded started\n");
		}
	}
	return 0;

}



SEC("kprobe/add_to_page_cache_lru")

int trace_page_cache_lru(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			stringkey sync_ra_key = "sync_ra";
			u64 *v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &sync_ra_key);
			if (v != NULL && *v == 1) {
				stringkey new_key = "sync_accessed";
				v = NULL;
				v = bpf_map_lookup_elem(&execve_counter, &new_key);
				if (v != NULL) {
					*v += 1;
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
	}

	return 0;

}

SEC("kretprobe/copy_page_to_iter")

int trace_copy_page_to_iter(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//bpf_printk("copy_page_to_iter started\n");
			stringkey new_key = "copy_page_to_iter";
			u64 *v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &new_key);
			if (v != NULL) {
				//if ( PT_REGS_RC(ctx) )
					*v += 1;
			}
		}
	}

	return 0;

}

SEC("kprobe/mark_page_accessed")

int trace_mark_page_accessed(struct pt_regs *ctx)
{
	stringkey pid_key = "pid";
	u32 *v;
	v = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (v != NULL) {
		u32 uid;
		uid = bpf_get_current_pid_tgid();
		if (*v == uid) {
			//bpf_printk("mark_page_accessed started\n");
			stringkey new_key = "mark_page_accessed";
			u64 *v = NULL;
			v = bpf_map_lookup_elem(&execve_counter, &new_key);
			if (v != NULL) {
				*v += 1;
			}
		}
	}

	return 0;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
