#!/bin/bash




# Execute commands and display output in real-time
echo "Running create_run_instances.py..."
python3 /root/damysus_updated/deployment/create_run_instances.py

# Wait for 60 seconds
sleep 60

echo "Running get_priv_ip.py..."
python3 /root/damysus_updated/deployment/get_priv_ip.py

# Wait for 30 seconds
sleep 30

echo "Running gen_ip.py..."
python3 /root/damysus_updated/deployment/gen_ip.py 31 5

echo "instance creat successfully!"

# Wait for 30 seconds
sleep 30

# Read the list of IP addresses
IP_LIST=$(cat /root/damysus_updated/deployment/priv_ip.txt)

# Remove the old SSH host key entry for this IP to avoid SSH key conflicts
echo "Removing old SSH host key entries..."
for ip in $IP_LIST
do
    ssh-keygen -f "/root/.ssh/known_hosts" -R "$ip"
    sleep 3
done
sleep 30
echo "Running transfer.py..."
python /root/damysus_updated/deployment/transfer.py


