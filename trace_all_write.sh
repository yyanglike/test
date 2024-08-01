#!/bin/bash

# 使用 bpftrace 捕获 sys_enter_write 和 sys_exit_write 事件
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_write
{
    @fd[tid] = args->fd;
    @count[tid] = args->count;
}

tracepoint:syscalls:sys_exit_write
{
    printf("exit: pid: %d, tid: %d, fd: %d, size: %d\n", pid, tid, @fd[tid], @count[tid]);
    delete(@fd[tid]);
    delete(@count[tid]);
}' | while read -r line; do
    echo "Processing line: $line"
    
    # 检查行是否包含 'exit' 关键字
    if [[ $line == exit* ]]; then
        # 解析 BPFtrace 输出，获取 PID、TID、文件描述符和写入大小
        pid=$(echo $line | awk -F, '{print $1}' | awk '{print $3}')
        tid=$(echo $line | awk -F, '{print $2}' | awk '{print $3}')
        fd=$(echo $line | awk -F, '{print $3}' | awk '{print $3}')
        size=$(echo $line | awk -F, '{print $4}' | awk '{print $3}')
        
        # 调试信息
        echo "Debug (initial parse): pid=$pid, tid=$tid, fd=$fd, size=$size"
        
        # 确保所有变量都已正确提取
        if [[ -z "$pid" || -z "$tid" || -z "$fd" || -z "$size" ]]; then
            echo "Failed to parse one of the variables. pid=$pid, tid=$tid, fd=$fd, size=$size"
            continue
        fi
        
        # 构造调试命令
        file_path_cmd="ls -l /proc/$pid/fd/$fd 2>/dev/null"
        offset_cmd="cat /proc/$pid/fdinfo/$fd 2>/dev/null | grep 'pos:' | awk '{print \$2}'"

        # 获取文件路径
        file_path=$(eval "$file_path_cmd" | awk '{print $NF}')
        # 获取偏移量
        offset=$(eval "$offset_cmd")

        # 调试信息
        echo "Debug (commands): file_path_cmd='$file_path_cmd', offset_cmd='$offset_cmd'"
        echo "Debug (results): file_path='$file_path', offset='$offset'"

        # 检查是否成功获取文件路径和偏移量，并过滤掉包含 "pipe", "socket", "log" 的路径
        if [[ -n "$file_path" && -n "$offset" && ! "$file_path" =~ (pipe|socket|log) ]]; then
            # 输出日志信息
            echo "pid: $pid, tid: $tid, fd: $fd, size: $size, offset: $offset, file path: $file_path"
        else
            echo "Filtered out or failed to get valid path/offset: file_path='$file_path', offset='$offset'"
        fi
    fi
done