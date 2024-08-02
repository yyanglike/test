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
#include <ctime>

// 执行 shell 命令并返回输出
std::string execute_command(const std::string& cmd) {
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

    std::string output;

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
            output += buffer; // 追加到输出字符串
        }
        close(pipefd[0]); // 关闭读端
        waitpid(pid, nullptr, 0); // 等待子进程结束
    }

    return output;
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
        printf("write pid: %d, fd: %d, size: %d\\n", pid, args->fd, args->count);
    }
}
tracepoint:syscalls:sys_enter_pwrite64
{
    if (pid == )" + std::to_string(target_pid) + ")" + R"(
    {
        printf("pwrite64 pid: %d, fd: %d, buf: %p, size: %lu, offset: %lu\\n", 
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
        printf("writev pid: %d, fd: %d, vec: %p, vlen: %lu\\n", 
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
        printf("pwritev pid: %d, fd: %d, vec: %p, vlen: %lu\\n", 
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
        printf("pwritev2 pid: %d, fd: %d, vec: %p, vlen: %lu, pos_l: %lu, pos_h: %lu, flags: %u\\n", 
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

    // 运行 bpftrace 并获取输出
    std::string bpftrace_cmd = "sudo bpftrace /tmp/bpf_program.bt";
    std::string bpftrace_output = execute_command(bpftrace_cmd);

    // 处理 bpftrace 输出
    std::string log_file_path = "/tmp/bpftrace.log"; // 更改为用户目录下的文件
    std::ofstream log_file(log_file_path, std::ios_base::app);
    if (!log_file) {
        std::cerr << "Failed to open log file for writing: " << log_file_path << std::endl;
        return 1;
    }

    std::istringstream output_stream(bpftrace_output);
    std::string line;
    while (std::getline(output_stream, line)) {
        // 过滤掉启动消息
        if (line.find("Attaching") != std::string::npos) {
            continue;
        }

        // 解析输出的不同格式数据
        int pid = -1, fd = -1;
        std::string vec, buf, size, offset, vlen, pos_l, pos_h, flags;

        if (line.find("write pid") != std::string::npos) {
            sscanf(line.c_str(), "write pid: %d, fd: %d, size: %s", &pid, &fd, &size[0]);
        } else if (line.find("writev pid") != std::string::npos) {
            sscanf(line.c_str(), "writev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, &vec[0], &vlen[0]);
        } else if (line.find("pwrite64 pid") != std::string::npos) {
            sscanf(line.c_str(), "pwrite64 pid: %d, fd: %d, buf: %s, size: %s, offset: %s", &pid, &fd, &buf[0], &size[0], &offset[0]);
        } else if (line.find("pwritev pid") != std::string::npos) {
            sscanf(line.c_str(), "pwritev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, &vec[0], &vlen[0]);
        } else if (line.find("pwritev2 pid") != std::string::npos) {
            sscanf(line.c_str(), "pwritev2 pid: %d, fd: %d, vec: %s, vlen: %s, pos_l: %s, pos_h: %s, flags: %s", &pid, &fd,&vec[0], &vlen[0], &pos_l[0], &pos_h[0], &flags[0]);
        }
        // 检查是否成功提取到 PID 和文件描述符
        if (pid == -1 || fd == -1) {
            log_file << "Failed to parse line: " << line << std::endl;
            continue;
        }

        // 输出调试信息
        log_file << "Debug: Parsing file path for PID " << pid << ", FD " << fd << std::endl;

        // 获取文件描述符对应的文件路径
        std::string file_path = get_fd_path(pid, fd);

        // 检查文件路径是否存在
        if (!file_path.empty() && file_path != "Not found or inaccessible") {
            log_file << "File path for FD " << fd << " in process " << pid << ": " << file_path << std::endl;
        } else {
            log_file << "File path for FD " << fd << " in process " << pid << ": Not found or inaccessible" << std::endl;
        }

    }
    log_file.close();
    return 0;
}        