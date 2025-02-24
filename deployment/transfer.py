import subprocess
from concurrent.futures import ThreadPoolExecutor

# Read the IP list
with open('/root/Achilles/deployment/priv_ip.txt', 'r') as file:
    ips = file.readlines()

# Remove the line breaks at the end of each line
ips = [ip.strip() for ip in ips]

# Define the SCP command
def scp_command(ip):
    source_file = '/root/Achilles/deployment/archive.tar.gz'
    source_file1 = '/root/Achilles/deployment/init.sh'
    destination = f'root@{ip}:/root/'
    command = f'scp -i /root/Achilles/TShard  -o StrictHostKeyChecking=no {source_file} {destination}'
    command1 = f'scp -i /root/Achilles/TShard {source_file1} {destination}'
    try:
        subprocess.run(command, shell=True, check=True)
        subprocess.run(command1, shell=True, check=True)
        print(f"Successfully transferred file to {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to transfer file to {ip}: {e}")

with ThreadPoolExecutor() as executor:
    executor.map(scp_command, ips)

