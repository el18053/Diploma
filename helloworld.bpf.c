SEC("tracepoint/syscalls/sys_enter_pread64")


int bpf_prog(struct pt_regs *ctx) {
  char msg[] = "Hello, World!";

  u32 uid;
  //uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  uid = bpf_get_current_pid_tgid();
  bpf_printk("%s from process with pid: %d\n", msg, uid);


  const u64 fd = PT_REGS_PARM1(ctx);
  //bpf_printk("fd of the read sys call is: %d\n", fd);


  //int byte = PT_REGS_PARM3(ctx);
  //bpf_printk("Bytes of the read sys call is: %d\n", byte);



  stringkey key = "execve_counter";
  u64 *v = NULL;
  v = bpf_map_lookup_elem(&execve_counter, &key);
  if (v != NULL) {
    //*v += 1;
    *v = fd;
    //bpf_map_update_elem(&execve_counter, &key, v, BPF_ANY);
    //bpf_printk("map value: %d\n", *v);
  }


  return 0;
}
