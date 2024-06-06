#!/bin/bash

# 获取当前所有的tmux会话列表
sessions=$(tmux list-sessions -F "#S")

# 循环遍历每个会话，并关闭它们
for session in $sessions
do
    tmux kill-session -t "$session"
done
