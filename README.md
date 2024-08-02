
## 跟踪指定函数
sudo bpftrace -e 'kprobe:vfs_write { printf("vfs_write called\n"); }'


## 指定进程id进行函数调用跟踪
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_write
{
    if (pid == 6618) {
        printf("pid: %d, fd: %d\n", pid, args->fd);
    }
}'



## 查询可以追踪的函数的命令：
 sudo ls /sys/kernel/debug/tracing/events/syscalls/
[sudo] password for yangyi: 
enable                             sys_enter_listxattr               sys_enter_set_mempolicy_home_node  sys_exit_fspick                   sys_exit_prlimit64
filter                             sys_enter_llistxattr              sys_enter_setns                    sys_exit_fstatfs                  sys_exit_process_madvise
sys_enter_accept                   sys_enter_lremovexattr            sys_enter_setpgid                  sys_exit_fsync                    sys_exit_process_mrelease
sys_enter_accept4                  sys_enter_lseek                   sys_enter_setpriority              sys_exit_ftruncate                sys_exit_process_vm_readv
sys_enter_access                   sys_enter_lsetxattr               sys_enter_setregid                 sys_exit_futex                    sys_exit_process_vm_writev
sys_enter_acct                     sys_enter_madvise                 sys_enter_setresgid                sys_exit_futex_waitv              sys_exit_pselect6
sys_enter_add_key                  sys_enter_mbind                   sys_enter_setresuid                sys_exit_futimesat                sys_exit_ptrace
sys_enter_adjtimex                 sys_enter_membarrier              sys_enter_setreuid                 sys_exit_getcpu                   sys_exit_pwrite64
sys_enter_alarm                    sys_enter_memfd_create            sys_enter_setrlimit                sys_exit_getcwd                   sys_exit_pwritev
sys_enter_arch_prctl               sys_enter_memfd_secret            sys_enter_set_robust_list          sys_exit_getdents                 sys_exit_pwritev2
sys_enter_bind                     sys_enter_migrate_pages           sys_enter_setsid                   sys_exit_getdents64               sys_exit_quotactl
sys_enter_bpf                      sys_enter_mincore                 sys_enter_setsockopt               sys_exit_getegid                  sys_exit_quotactl_fd

## 查询需要跟踪的函数的调用参数：
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_pwritev2/format


## 跟踪工具相关安装：
sudo apt install linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)


uname -r
sudo apt-get install linux-hwe-6.5-tools-common
or 6.2
sudo apt-get install linux-hwe-6.2-tools-common

## 安装指导开发库。
sudo apt-get update
sudo apt-get install -y libbpfcc-dev

## 查询需要看的例子参考check.sh


