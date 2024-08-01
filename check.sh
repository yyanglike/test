#!/bin/bash

# 检查是否传递了 PID 参数
if [ -z "$1" ]; then
    echo "Usage: $0 <pid>"
    exit 1
fi

TARGET_PID=$1

# 使用 bpftrace 捕获 sys_enter_write、sys_enter_writev 和 sys_enter_pwrite64 事件
sudo bpftrace -e "
tracepoint:syscalls:sys_enter_write
{
    if (pid == $TARGET_PID) {
        printf(\"write pid: %d, fd: %d, size: %d\n\", pid, args->fd, args->count);
    }
}
tracepoint:syscalls:sys_enter_pwrite64
{
    if (pid == $TARGET_PID) {
        printf(\"write pid: %d, fd: %d, buf: %p, size: %lu, offset: %lu\n\", 
               pid, 
               args->fd, 
               args->buf, 
               args->count, 
               args->pos);
    }
}
tracepoint:syscalls:sys_enter_writev
{
    if (pid == $TARGET_PID) {
        printf(\"writev pid: %d, fd: %d, vec: %p, vlen: %lu\n\", 
               pid, 
               args->fd, 
               args->vec, 
               args->vlen);
    }
}" | while IFS= read -r line; do
    # 过滤掉启动消息
    if [[ "$line" == *"Attaching"* ]]; then
        continue
    fi

    # 解析输出的不同格式数据
    case "$line" in
        *"write"*)
            pid=$(echo "$line" | awk '{print $3}' | tr -d ',')
            fd=$(echo "$line" | awk '{print $5}' | tr -d ',')
            size=$(echo "$line" | awk '{print $7}')
            ;;
        *"writev"*)
            pid=$(echo "$line" | awk '{print $3}' | tr -d ',')
            fd=$(echo "$line" | awk '{print $5}' | tr -d ',')
            vec=$(echo "$line" | awk '{print $7}' | tr -d ',')
            vlen=$(echo "$line" | awk '{print $9}')
            ;;
        *"pwrite64"*)
            pid=$(echo "$line" | awk '{print $3}' | tr -d ',')
            fd=$(echo "$line" | awk '{print $5}' | tr -d ',')
            buf=$(echo "$line" | awk '{print $7}' | tr -d ',')
            count=$(echo "$line" | awk '{print $9}')
            offset=$(echo "$line" | awk '{print $11}')
            ;;
    esac

    # 检查是否成功提取到 PID 和文件描述符
    if [[ -z "$pid" || -z "$fd" ]]; then
        echo "Failed to parse line: $line"
        continue
    fi

    # 输出调试信息
    echo "Debug: Parsing file path for PID $pid, FD $fd"

    # 获取文件描述符对应的文件路径
    file_path=$(sudo ls -l /proc/$pid/fd/$fd 2>/dev/null)

    # 检查文件路径是否存在
    if [[ -n "$file_path" ]]; then
        # 从 ls 输出中提取实际路径
        file_path=$(echo "$file_path" | awk '{print $NF}')
        echo "File path for FD $fd in process $pid: $file_path"
    else
        echo "File path for FD $fd in process $pid: Not found or inaccessible"
    fi
done