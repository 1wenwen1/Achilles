#!/bin/bash

# Write "------LAN--------" to stats.txt
echo "------ALN--------" > /root/Achilles/stats.txt

# Read the list of IP addresses from the file
IP_LIST=$(cat /root/Achilles/ip_list)

for ip in $IP_LIST
do
    # Use SSH to execute commands on the remote server
    ssh -i /root/Achilles/TShard -o StrictHostKeyChecking=no root@$ip <<EOF
        # Try to remove the existing network queue configuration, but continue even if it fails
        sudo tc qdisc del dev eth0 root || true
        
        # Add a 1ms network delay using the netem tool
        sudo tc qdisc add dev eth0 root netem delay 1ms
EOF
done

cd /root/Achilles/deployment
# Generate the IP addresses for the clients and servers
python gen_ip.py 31 5


# execute experiments
payload=(128 256 512)
cd /root/Achilles
# Loop through each fault value and run the command
for p in "${payload[@]}"
do
    # Execute the Python script with the current fault value
    python run.py --p1 --batchsize 400 --payload $p --faults 10
    python close.py
    sleep 5
    python run.py --p2 --batchsize 400 --payload $p --faults 10
    python close.py
    sleep 5
    python run.py --p3 --batchsize 400 --payload $p --faults 10
    python close.py
    sleep 5
done