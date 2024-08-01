#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/fdtable.h>  // For files_fdtable

static int pre_handler(struct kprobe *p, struct pt_regs *regs) {
    int fd = (int)regs->di;  // file descriptor
    struct file *file = NULL;

    // 获取当前进程的文件描述符表
    struct fdtable *fdt = files_fdtable(current->files);

    if (!fdt) {
        printk(KERN_INFO "KProbes: Failed to get fdtable\n");
        return 0;
    }

    // 打印调试信息
    printk(KERN_INFO "KProbes: File descriptor = %d\n", fd);
    printk(KERN_INFO "KProbes: Max file descriptors = %d\n", fdt->max_fds);

    if (fd >= 0 && fd < fdt->max_fds) {
        file = fdt->fd[fd];
        if (file) {
            const char __user *buf = (const char __user *)regs->si;  // buffer pointer
            size_t count = (size_t)regs->dx;  // count
            loff_t *pos = (loff_t *)regs->cx;  // position

            // 打印文件信息
            printk(KERN_INFO "KProbes: vfs_write called\n");
            printk(KERN_INFO "KProbes: File: %s\n", file->f_path.dentry->d_name.name);
            printk(KERN_INFO "KProbes: Count: %zu\n", count);
            printk(KERN_INFO "KProbes: Position: %lld\n", *pos);
        } else {
            printk(KERN_INFO "KProbes: Failed to get file from fd\n");
        }
    } else {
        printk(KERN_INFO "KProbes: Invalid file descriptor\n");
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "vfs_write",
    .pre_handler = pre_handler,
};

static int __init kprobe_init(void) {
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "Register kprobe failed, returned %d\n", ret);
        return -1;
    }
    printk(KERN_INFO "KProbes registered\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "KProbes unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");