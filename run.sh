#!/bin/bash

# 检查是否传递了参数
if [ -z "$1" ]; then
  echo "Usage: $0 <b>"
  exit 1
fi

# 读取参数b
b=$1

# 计算n
n=$((2 * b - 1))

# 定义其他参数
c=2
d=30
e=10

# 创建并运行sgxserver会话
for id in $(seq 0 $n); do
  session_name="sgxserver_${id}"
  tmux new-session -d -s $session_name "./sgxserver $id $b $c $d $e"
done

# 创建并运行sgxclient会话
# tmux new-session -d -s sgxclient "./sgxclient 0 $b $c 1 0 0"

echo "All tmux sessions created and commands executed."

