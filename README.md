sudo bpftrace trace_vfs_write.bt


sudo bpftrace -e 'kprobe:vfs_write { printf("vfs_write called\n"); }'


sudo bpftrace -e '
tracepoint:syscalls:sys_enter_write
{
    if (pid == 6618) {
        printf("pid: %d, fd: %d\n", pid, args->fd);
    }
}'




测试
tracepoint:syscalls:sys_enter_writev



sudo apt install linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)

sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_pwrite64/format


uname -r
sudo apt-get install linux-hwe-6.5-tools-common
or 6.2
sudo apt-get install linux-hwe-6.2-tools-common


sudo nano /usr/src/linux/.config


sudo bpftrace -e '
tracepoint:syscalls:sys_enter_pwrite64
{
    if (pid == $TARGET_PID) {
        printf("write pid: %d, fd: %d, buf: %p, size: %lu, offset: %lu\n", 
               pid, 
               args->fd, 
               args->buf, 
               args->count, 
               args->pos);
    }
}'