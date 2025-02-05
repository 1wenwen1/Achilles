#!/bin/bash

# 读取IP地址列表
IP_LIST=$(cat raw_ip_list)

# 使用计数器，从1开始命名tmux会话
count=1

# 循环遍历IP地址列表
for ip in $IP_LIST
do
    # 创建一个新的tmux会话，并命名为数字
    tmux new-session -d -s "setup$count"
    
    # 在新的tmux会话中连接到指定的IP地址
    tmux send-keys -t "setup$count" "ssh -i TShard -o StrictHostKeyChecking=no root@$ip 'bash init.sh'" C-m

    # 增加计数器
    ((count++))
done

