#!/bin/bash

# Read the list of IP addresses
IP_LIST=$(cat  /root/damysus_updated/deployment/priv_ip.txt)

# Use the counter to name the tmux session from 1
count=1


echo "Config SGX environment..."
# Loop the list of IP addresses
for ip in $IP_LIST
do
    # Create a new tmux session and name it a number
    tmux new-session -d -s "setup$count"
    
    # Connect to the specified IP address in the new tmux session
    tmux send-keys -t "setup$count" "ssh -i  /root/damysus_updated/TShard -o StrictHostKeyChecking=no root@$ip 'bash init.sh'" C-m

    # Add a counter
    ((count++))
done
