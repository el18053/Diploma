#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp;

int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "kprobe handler_pre called\n");
    return 0;
}

int handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    printk(KERN_INFO "kprobe handler_post called\n");
    return 0;
}

void handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    printk(KERN_INFO "kprobe handler_fault called: trap #%dn", trapnr);
}

static int __init kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;
    kp.addr = (kprobe_opcode_t *)0x12345678; // address of the function to probe
    kp.symbol_name = "my_function"; // name of the function to probe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "Failed to register kprobe\n");
        return ret;
    }
    printk(KERN_INFO "Kprobe registered\n");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
