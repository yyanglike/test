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




