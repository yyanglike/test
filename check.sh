#!/bin/bash

# 检查是否传递了 PID 参数
if [ -z "$1" ]; then
    echo "Usage: $0 <pid>"
    exit 1
fi

TARGET_PID=$1

# 使用 bpftrace 捕获 sys_enter_write 事件
sudo bpftrace -e "
tracepoint:syscalls:sys_enter_write
{
    if (pid == $TARGET_PID) {
        printf(\"pid: %d, fd: %d, size: %d\n\", pid, args->fd, args->count);
    }
}" | while read -r line; do
    # 过滤掉启动消息
    if [[ "$line" == *"Attaching"* ]]; then
        continue
    fi

    # 解析 BPFtrace 输出，获取 PID 和文件描述符
    pid=$(echo "$line" | awk '{print $2}')
    fd=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $6}')

    # 检查是否成功提取到 PID 和文件描述符
    if [[ -z "$pid" || -z "$fd" || -z "$size" ]]; then
        echo "Failed to parse line: $line"
        continue
    fi

    # 获取文件描述符对应的文件路径
    file_path=$(sudo ls -l /proc/$pid/fd/$fd 2>/dev/null | awk '{print $NF}')

    # 输出文件路径
    if [[ -n "$file_path" ]]; then
        echo "File path for FD $fd in process $pid: $file_path"
    else
        echo "File path for FD $fd in process $pid: Not found or inaccessible"
    fi
done