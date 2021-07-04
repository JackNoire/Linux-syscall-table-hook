#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

unsigned long *sys_call_table;
long (*real_openat)(const struct pt_regs *);
long (*real_unlinkat)(const struct pt_regs *);

void disable_write_protection(void)
{
    asm("mov %%cr0,%%rax\n\t"
        "and $0xfffffffffffeffff,%%rax\n\t"
        "mov %%rax,%%cr0"
        :
        :
        :"%rax");
}

void enable_write_protection(void)
{
    asm("mov %%cr0,%%rax\n\t"
        "or  $0x10000,%%rax\n\t"
        "mov %%rax,%%cr0"
        :
        :
        :"%rax");
}

asmlinkage long fake_openat(const struct pt_regs *regs)
{
    char str[256] = {0};
    copy_from_user(str, (char *)regs->si, 255);
    if ((regs->dx & O_CREAT) && strcmp(str, "/dev/null") != 0) {
        printk(KERN_INFO "openat: rdi:%016lx rsi:%016lx rdx:%016lx r10:%016lx\n", regs->di, regs->si, regs->dx, regs->r10);
        printk(KERN_ALERT "create filename: %s\n", str);
    }
    return real_openat(regs);
}

asmlinkage long fake_unlinkat(const struct pt_regs *regs)
{
    char str[256] = {0};
    copy_from_user(str, (char *)regs->si, 255);
    printk(KERN_INFO "unlinkat: rdi:%016lx rsi:%016lx rdx:%016lx r10:%016lx\n", regs->di, regs->si, regs->dx, regs->r10);
    printk(KERN_ALERT "delete filename: %s\n", str);
    return real_unlinkat(regs);
}

static int hook_init(void) {
    printk(KERN_INFO "Module Init...!!!\n");
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    printk(KERN_ALERT "syscall table address:%lx\n", (unsigned long)sys_call_table);

    disable_write_protection();
    real_openat = (void *)sys_call_table[__NR_openat];
    real_unlinkat = (void *)sys_call_table[__NR_unlinkat];

    sys_call_table[__NR_openat] = (unsigned long)fake_openat;
    sys_call_table[__NR_unlinkat] = (unsigned long)fake_unlinkat;

    enable_write_protection();

    return 0;
}

static void hook_exit(void) {
    disable_write_protection();
    sys_call_table[__NR_openat] = (unsigned long)real_openat;
    sys_call_table[__NR_unlinkat] = (unsigned long)real_unlinkat;
    enable_write_protection();

    printk(KERN_INFO "Module Exit...!!!\n");
}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YuanHuanyu");
MODULE_DESCRIPTION("Hook Module");