#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <limits.h>
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>

// 执行 shell 命令并返回输出
void execute_command(const std::string& cmd) {
    // 创建管道
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        std::cerr << "Failed to create pipe" << std::endl;
        exit(1);
    }

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "Failed to fork process" << std::endl;
        exit(1);
    }

    if (pid == 0) {
        // 子进程：执行命令
        close(pipefd[0]); // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO); // 将标准输出重定向到管道
        execlp("/bin/sh", "sh", "-c", cmd.c_str(), (char *)nullptr);
        std::cerr << "Failed to execute command" << std::endl;
        exit(1);
    } else {
        // 父进程：读取输出
        close(pipefd[1]); // 关闭写端
        char buffer[128];
        ssize_t bytes_read;
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            std::cout << buffer; // 输出到控制台
        }
        close(pipefd[0]); // 关闭读端
        waitpid(pid, nullptr, 0); // 等待子进程结束
    }
}

std::string get_fd_path(int pid, int fd) {
    std::stringstream ss;
    ss << "/proc/" << pid << "/fd/" << fd;
    char path[PATH_MAX];
    ssize_t len = readlink(ss.str().c_str(), path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        return std::string(path);
    }
    return "Not found or inaccessible";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>" << std::endl;
        return 1;
    }

    int target_pid = std::stoi(argv[1]);

    // BPF 程序，使用 C++ 插值
    std::string bpf_program = R"(
#include <linux/rwsem.h>
#define rwf_t unsigned int

tracepoint:syscalls:sys_enter_write
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("write pid: %d, fd: %d, size: %d\n", pid, args->fd, args->count);
    }
}
tracepoint:syscalls:sys_enter_pwrite64
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("pwrite64 pid: %d, fd: %d, buf: %p, size: %lu, offset: %lu\n", 
               pid, 
               args->fd, 
               args->buf, 
               args->count, 
               args->pos);
    }
}
tracepoint:syscalls:sys_enter_writev
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("writev pid: %d, fd: %d, vec: %p, vlen: %lu\n", 
               pid, 
               args->fd, 
               args->vec, 
               args->vlen);
    }
}
tracepoint:syscalls:sys_enter_pwritev
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("pwritev pid: %d, fd: %d, vec: %p, vlen: %lu\n", 
               pid, 
               args->fd, 
               args->vec, 
               args->vlen);
    }
}
tracepoint:syscalls:sys_enter_pwritev2
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("pwritev2 pid: %d, fd: %lu, vec: %p, vlen: %lu, pos_l: %lu, pos_h: %lu, flags: %u\n", 
               pid, 
               args->fd, 
               args->vec, 
               args->vlen, 
               args->pos_l, 
               args->pos_h, 
               args->flags);
    }
})";

    // 写入 BPF 程序到文件
    std::ofstream bpf_file("/tmp/bpf_program.bt");
    if (!bpf_file) {
        std::cerr << "Failed to open /tmp/bpf_program.bt for writing" << std::endl;
        return 1;
    }
    bpf_file << bpf_program;
    bpf_file.close();

    // 运行 bpftrace
    std::string bpftrace_cmd = "sudo bpftrace /tmp/bpf_program.bt";
    execute_command(bpftrace_cmd);

    return 0;
}