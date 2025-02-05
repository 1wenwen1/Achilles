import subprocess
from concurrent.futures import ThreadPoolExecutor

# 读取IP列表
with open('raw_ip_list', 'r') as file:
    ips = file.readlines()

# 去除每行末尾的换行符
ips = [ip.strip() for ip in ips]

# 定义SCP命令
def scp_command(ip):
    source_file = '/root/archive.tar.gz'
    source_file1 = '/root/init.sh'
    source_file2 = '/root/init2.sh'
    destination = f'root@{ip}:/root/'
    command = f'scp -i TShard  -o StrictHostKeyChecking=no {source_file} {destination}'
    command1 = f'scp -i TShard {source_file1} {destination}'
    command2 = f'scp -i TShard {source_file2} {destination}'
    try:
        subprocess.run(command, shell=True, check=True)
        subprocess.run(command1, shell=True, check=True)
        subprocess.run(command2, shell=True, check=True)
        print(f"Successfully transferred file to {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to transfer file to {ip}: {e}")

# 多线程执行SCP命令
with ThreadPoolExecutor() as executor:
    executor.map(scp_command, ips)

