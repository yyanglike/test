#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <limits.h>
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>
#include <ctime>

// 获取文件描述符对应的文件路径
std::string get_fd_path(int pid, int fd) {
    std::stringstream ss;
    ss << "/proc/" << pid << "/fd/" << fd;
    char path[PATH_MAX];
    ssize_t len = readlink(ss.str().c_str(), path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        return std::string(path);
    } else {
        return "Not found or inaccessible";
    }
}

// 执行 shell 命令并解析输出
void execute_and_parse_command(const std::string& cmd, const std::string& log_file_path) {
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
        // 父进程：读取输出并解析
        close(pipefd[1]); // 关闭写端

        std::ofstream log_file(log_file_path, std::ios_base::app);
        if (!log_file) {
            std::cerr << "Failed to open log file for writing: " << log_file_path << std::endl;
            return;
        }

        char buffer[128];
        std::string partial_line;
        ssize_t bytes_read;

        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            partial_line += buffer;

            size_t pos;
            while ((pos = partial_line.find('\n')) != std::string::npos) {
                std::string line = partial_line.substr(0, pos);
                partial_line.erase(0, pos + 1);

                // 过滤掉启动消息
                if (line.find("Attaching") != std::string::npos) {
                    continue;
                }

                std::cout << "Processing line: " << line << std::endl;
                log_file << "Processing line: " << line << std::endl;

                // 解析输出的不同格式数据
                int pid = -1, fd = -1;
                char vec[128] = {0}, buf[128] = {0}, size[128] = {0}, offset[128] = {0}, vlen[128] = {0}, pos_l[128] = {0}, pos_h[128] = {0}, flags[128] = {0};

                if (line.find("write pid") != std::string::npos) {
                    sscanf(line.c_str(), "write pid: %d, fd: %d, size: %s", &pid, &fd, size);
                } else if (line.find("writev pid") != std::string::npos) {
                    sscanf(line.c_str(), "writev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, vec, vlen);
                } else if (line.find("pwrite64 pid") != std::string::npos) {
                    sscanf(line.c_str(), "pwrite64 pid: %d, fd: %d, buf: %s, size: %s, offset: %s", &pid, &fd, buf, size, offset);
                } else if (line.find("pwritev pid") != std::string::npos) {
                    sscanf(line.c_str(), "pwritev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, vec, vlen);
                } else if (line.find("pwritev2 pid") != std::string::npos) {
                    sscanf(line.c_str(), "pwritev2 pid: %d, fd: %d, vec: %s, vlen: %s, pos_l: %s, pos_h: %s, flags: %s", &pid, &fd, vec, vlen, pos_l, pos_h, flags);
                }

                // 检查是否成功提取到 PID 和文件描述符
                if (pid == -1 || fd == -1) {
                    log_file << "Failed to parse line: " << line << std::endl;
                } else {
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
            }
        }

        // 处理剩余的行
        if (!partial_line.empty()) {
            std::cout << "Processing remaining line: " << partial_line << std::endl;
            log_file << "Processing remaining line: " << partial_line << std::endl;

            // 解析输出的不同格式数据
            int pid = -1, fd = -1;
            char vec[128] = {0}, buf[128] = {0}, size[128] = {0}, offset[128] = {0}, vlen[128] = {0}, pos_l[128] = {0}, pos_h[128] = {0}, flags[128] = {0};

            if (partial_line.find("write pid") != std::string::npos) {
                sscanf(partial_line.c_str(), "write pid: %d, fd: %d, size: %s", &pid, &fd, size);
            } else if (partial_line.find("writev pid") != std::string::npos) {
                sscanf(partial_line.c_str(), "writev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, vec, vlen);
            } else if (partial_line.find("pwrite64 pid") != std::string::npos) {
                sscanf(partial_line.c_str(), "pwrite64 pid: %d, fd: %d, buf: %s, size: %s, offset: %s", &pid, &fd, buf, size, offset);
            } else if (partial_line.find("pwritev pid") != std::string::npos) {
                sscanf(partial_line.c_str(), "pwritev pid: %d, fd: %d, vec: %s, vlen: %s", &pid, &fd, vec, vlen);
            } else if (partial_line.find("pwritev2 pid") != std::string::npos) {
                sscanf(partial_line.c_str(), "pwritev2 pid: %d, fd: %d, vec: %s, vlen: %s, pos_l: %s, pos_h: %s, flags: %s", &pid, &fd, vec, vlen, pos_l, pos_h, flags);
            }

            // 检查是否成功提取到 PID 和文件描述符
            if (pid == -1 || fd == -1) {
                log_file << "Failed to parse line: " << partial_line << std::endl;
            } else {
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
        }

        close(pipefd[0]); // 关闭读端
        waitpid(pid, nullptr, 0); // 等待子
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " " << std::endl;
        return 1;
    }
    std::string pid = argv[1];
    std::string cmd = "sudo bpftrace -e '"
                    "#include <linux/rwsem.h>\n"
                    "#define rwf_t unsigned int\n"
                    "tracepoint:syscalls:sys_enter_write\n"
                    "{\n"
                    "    if (pid == " + pid + ") {\n"
                    "        printf(\"write pid: %d, fd: %d, size: %d\\n\", pid, args->fd, args->count);\n"
                    "    }\n"
                    "}\n"
                    "tracepoint:syscalls:sys_enter_pwrite64\n"
                    "{\n"
                    "    if (pid == " + pid + ") {\n"
                    "        printf(\"pwrite64 pid: %d, fd: %d, buf: %p, size: %lu, offset: %lu\\n\", pid, args->fd, args->buf, args->count, args->pos);\n"
                    "    }\n"
                    "}\n"
                    "tracepoint:syscalls:sys_enter_writev\n"
                    "{\n"
                    "    if (pid == " + pid + ") {\n"
                    "        printf(\"writev pid: %d, fd: %d, vec: %p, vlen: %lu\\n\", pid, args->fd, args->vec, args->vlen);\n"
                    "    }\n"
                    "}\n"
                    "tracepoint:syscalls:sys_enter_pwritev\n"
                    "{\n"
                    "    if (pid == " + pid + ") {\n"
                    "        printf(\"pwritev pid: %d, fd: %d, vec: %p, vlen: %lu\\n\", pid, args->fd, args->vec, args->vlen);\n"
                    "    }\n"
                    "}\n"
                    "tracepoint:syscalls:sys_enter_pwritev2\n"
                    "{\n"
                    "    if (pid == " + pid + ") {\n"
                    "        printf(\"pwritev2 pid: %d, fd: %lu, vec: %p, vlen: %lu, pos_l: %lu, pos_h: %lu, flags: %u\\n\", pid, args->fd, args->vec, args->vlen, args->pos_l, args->pos_h, args->flags);\n"
                    "    }\n"
                    "}'";
    std::string log_file_path = "trace_log.txt";

    execute_and_parse_command(cmd, log_file_path);

    return 0;
}