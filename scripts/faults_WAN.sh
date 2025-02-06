#!/bin/bash

# Read the list of IP addresses from the file
IP_LIST=$(cat /root/damysus_updated/ip_list)

for ip in $IP_LIST
do
    # Use SSH to execute commands on the remote server
    ssh -i /root/damysus_updated/TShard -o StrictHostKeyChecking=no root@$ip <<EOF
        # Try to remove the existing network queue configuration, but continue even if it fails
        sudo tc qdisc del dev eth0 root || true
        
        # Add a 1ms network delay using the netem tool
        sudo tc qdisc add dev eth0 root netem delay 20ms
EOF
done

cd /root/damysus_updated/deployment
# Generate the IP addresses for the clients and servers
python gen_ip.py 6 2


# execute experiments
faults=(1 2 4 10 20 30)
cd /root/damysus_updated
# Loop through each fault value and run the command
for f in "${faults[@]}"
do
    # Execute the Python script with the current fault value
    python run.py --p1 --batchsize 400 --payload 256 --faults $f
    python run.py --p2 --batchsize 400 --payload 256 --faults $f
    python run.py --p3 --batchsize 400 --payload 256 --faults $f
done