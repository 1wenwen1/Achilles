import paramiko
import glob
import shutil
from pathlib import Path
from subprocess import Popen, PIPE
import os
from paramiko import SSHClient, AutoAddPolicy
from concurrent.futures import ThreadPoolExecutor, as_completed
from scp import SCPClient
import threading
import time
import math
from threading import Lock

views = 30
timeout = 10
factor = 2
faults = 1


# 读取 IP 列表
def read_ip_list(filename):
    with open(filename, 'r') as file:
        ip_list = [line.strip() for line in file.readlines()]
    return ip_list

# 读取 servers 文件
def read_servers(filename):
    servers = []
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split()
            id = int(parts[0].split(':')[1])
            host = parts[1].split(':')[1]
            port1 = int(parts[2].split(':')[1])
            port2 = int(parts[3].split(':')[1])
            servers.append((id, host, port1, port2))
    return servers

# SCP 文件到节点
def scp_to_node(ip, files):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        for file in files:
            remote_path = f'/root/damysus_updated'  # 假设你的远程用户是 root，修改为实际的远程路径前缀
            scp.put(file, remote_path=remote_path)
    ssh.close()

# SSH 执行 sgxserver
def ssh_exec_server_non_blocking(id, host, port1, port2, extra_params, completion_set, lock):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='root', key_filename='./TShard')
    cmd = f"export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/sdk_libs && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && cd /root/damysus_updated && rm -rf stats/* && ./sgxserver {id} {faults} {factor} {views} {timeout}"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    # 非阻塞地监控命令执行状态
    def monitor_ssh():
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        output = stdout.read().decode()
        error = stderr.read().decode()
        print(f"sgxserver on {host} with id {id} output:\n{output}")
        print(f"sgxserver on {host} with id {id} error:\n{error}")
        with lock:
            completion_set.add((id, host))
        ssh.close()

    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor_ssh)
    monitor_thread.start()

def ssh_exec_servers_non_blocking(servers, extra_params, max_workers=6):
    completion_set = set()
    lock = Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ssh_exec_server_non_blocking, server[0], server[1], server[2], server[3], extra_params, completion_set, lock): server for server in servers}
        for future in as_completed(futures):
            server = futures[future]
            try:
                future.result()
                print(f"sgxserver on {server[1]} with id {server[0]} started successfully.")
            except Exception as e:
                print(f"sgxserver on {server[1]} with id {server[0]} generated an exception: {e}")
    
    # 等待所有 sgxserver 完成
    while len(completion_set) < len(servers):
        time.sleep(1)

# SSH 执行 sgxclient
def ssh_exec_client(id, host, port1, port2, extra_params):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='your_username', key_filename='./TShard')
    cmd = f"sgxclient --id {id} --port1 {port1} --port2 {port2} {extra_params}"
    ssh.exec_command(cmd)
    ssh.close()

# SCP 文件从节点到本地
def scp_from_node(ip):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        scp.get('/remote/damysus/stats/*', local_path='damysus/stats/')  # 修改为实际的远程路径和本地路径
    ssh.close()

# 多线程 SCP 到节点
def scp_files_to_nodes(ip_list, files, max_workers=6):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scp_to_node, ip, files) for ip in ip_list]
        for future in futures:
            future.result()


# 多线程 SSH 执行 sgxserver

# 等待并在 id:0 的主机上执行 sgxclient
def ssh_exec_client_on_id0(servers, extra_params):
    id0_server = next((server for server in servers if server[0] == 0), None)
    if id0_server:
        time.sleep(5 + math.log(len(servers), 2))
        ssh_exec_client(id0_server[0], id0_server[1], id0_server[2], id0_server[3], extra_params)

# 多线程 SCP 从节点到本地
def scp_files_from_nodes(ip_list):
    threads = []
    for ip in ip_list:
        thread = threading.Thread(target=scp_from_node, args=(ip,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

def start_all_sgxservers(servers, extra_params, max_workers=6):
    completion_set = set()
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(ssh_exec_server_non_blocking, id, host, port1, port2, extra_params, completion_set, lock) for id, host, port1, port2 in servers]
        for future in as_completed(futures):
            future.result()
    return completion_set, lock

# 本地执行 sgxclient
def local_exec_client():
    cmd = f"./sgxclient 0 {faults} {factor} 1 0 0"
    process = Popen(cmd, shell=True, cwd='/root/damysus_updated', stdout=PIPE, stderr=PIPE)
    # 如果需要在后台运行而不等待输出，可以去掉 stdout=PIPE 和 stderr=PIPE

    # 如果想要立即返回并继续执行其他任务，可以直接返回
    return process

# 关闭本地 sgxclient
def stop_local_sgxclient():
    cmd = "pkill -f sgxclient"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop sgxclient output:\n{output}")
    print(f"Stop sgxclient error:\n{error}")


# 阻塞等待所有 sgxserver 实例结束
def wait_for_all_sgxservers_to_finish(completion_set, lock, total_servers):
    while len(completion_set) < total_servers:
        time.sleep(1)
    print("All sgxserver instances have finished.")

def clear_local_stats():
    stats_path = Path('/root/damysus_updated/stats/')
    if stats_path.exists() and stats_path.is_dir():
        shutil.rmtree(stats_path)
    stats_path.mkdir(parents=True, exist_ok=True)

# 将远程 /root/damysus_updated/stats/ 目录中的内容 SCP 到本地相同目录
def scp_stats_from_node(ip, local_path, remote_path):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path=local_path, recursive=True)
    ssh.close()

# 多线程 SCP stats 内容到本地
def scp_stats_from_nodes(ip_list, local_path, remote_path, max_workers=6):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scp_stats_from_node, ip, local_path, remote_path) for ip in ip_list]
        for future in as_completed(futures):
            future.result()

def calculate_mean_of_values(directory):
    vals_files = glob.glob(os.path.join(directory, 'vals*'))
    total_count = 0
    sum_first = 0.0
    sum_second = 0.0

    for file_path in vals_files:
        with open(file_path, 'r') as file:
            line = file.readline().strip()
            if line:
                values = list(map(float, line.split()))
                if len(values) >= 2:
                    sum_first += values[0]
                    sum_second += values[1]
                    total_count += 1

    if total_count > 0:
        mean_first = sum_first / total_count
        mean_second = sum_second / total_count
        return (mean_first, mean_second)
        print(f"Mean of the first number across all vals files: {mean_first}")
        print(f"Mean of the second number across all vals files: {mean_second}")
    else:
        print("No vals files found or no valid data.")
        return 0

def make_instance(protocol, batchsize, payload, faults, pro_dir):
    p = 0
    if(protocol == 'achillies'):
        cmd = "git stash && git checkout achillies"
        p = 0
    elif(protocol == 'flex'):
        cmd = "git stash && git checkout flexi"
        p = 1

    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop checkout output:\n{output}")
    print(f"Stop checkout error:\n{error}")


    folder_path = pro_dir
    if not os.path.exists(folder_path):
    # 如果文件夹不存在，则创建
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")
    else:
        print(f"Folder '{folder_path}' already exists.")
    

    file_name = "sgxserver"

# 构建完整的文件路径
    file_path = os.path.join(folder_path, file_name)

    cmd_sgxserver = f"make sgxserver -j8 && cp sgxserver {pro_dir}/"

# 检查文件是否存在
    if os.path.isfile(file_path):
    # 执行命令x
        command = 'echo "File exists"'
        cmd_sgxserver = f"cp {file_path} ./"
        print(command)
    else:
    # 执行命令y
        command = 'echo "File does not exist"'
        print(command)

    print(f'exec {cmd_sgxserver}')

    cmd = f"python expmkp.py --faults {faults} --payload {payload} --p {p} --mkpp && make clean && make enclave.so enclave.signed.so sgxclient sgxkeys -j8 && {cmd_sgxserver}"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop expmkp output:\n{output}")
    print(f"Stop expmkp error:\n{error}")

def start_one_exp(protocol, batchsize, payload, faults):

    pro_dir = f'{protocol}_{faults}_{payload}_{batchsize}_0'

    ip_list = read_ip_list('ip_list')
    servers = read_servers('servers')

    make_instance(protocol, batchsize, payload, faults, pro_dir)

    files_to_copy2 = [
        os.path.expanduser('~/damysus_updated/sgxserver'), 
        os.path.expanduser('~/damysus_updated/servers'),
        os.path.expanduser('~/damysus_updated/sgxclient'),
        os.path.expanduser('~/damysus_updated/enclave.so'),
        os.path.expanduser('~/damysus_updated/enclave.signed.so'),
        os.path.expanduser('~/damysus_updated/sgxkeys')
    ]  # 修改为实际的文件列表

 

   # files_to_copy = [
   #     os.path.expanduser('~/damysus_updated/servers'), 
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxserver'),
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxclient'),
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxkeys')
   #  ]  # 修改为实际的文件列表

    extra_params = '--other_param value'  # 补充实际的其它参数

    # 多线程 SCP 文件到节点
    scp_files_to_nodes(ip_list, files_to_copy2)

    # 多线程 SSH 执行 sgxserver

    completion_set, lock = start_all_sgxservers(servers, "--additional_params")
    print("start")

    time.sleep(5 + math.log(len(servers), 2))

    # 启动本地 sgxclient
    local_exec_client()

    # 阻塞等待所有 sgxserver 实例结束
    wait_for_all_sgxservers_to_finish(completion_set, lock, len(servers))

    stop_local_sgxclient()

    clear_local_stats()

    # 多线程将远程 /root/damysus_updated/stats/ 目录中的内容 SCP 到本地
    scp_stats_from_nodes(ip_list, '/root/damysus_updated/', '/root/damysus_updated/stats/')

    stats_directory = '/root/damysus_updated/stats/'

    # 计算所有 vals 文件的第一个数和第二个数的均值
    r1, r2 = calculate_mean_of_values(stats_directory)

    print(pro_dir, r1, r2)

    with open('stats.txt', 'a') as f:
        f.write(f'{pro_dir}, {r1}, {r2}\n')


    # 等待并在 id:0 的主机上执行 sgxclient
    # ssh_exec_client_on_id0(servers, extra_params)

    # 多线程 SCP 从节点到本地
    # scp_files_from_nodes(ip_list)

if __name__ == "__main__":

    #ip_list = read_ip_list('ip_list')

    #files_to_copy2 = [
    #    os.path.expanduser('~/damysus_updated/servers'),
    #    os.path.expanduser('~/damysus_updated/enclave.so'),
    #    os.path.expanduser('~/damysus_updated/enclave.signed.so'),
    #]  # 修改为实际的文件列表

    #scp_files_to_nodes(ip_list, files_to_copy2)

    start_one_exp("achillies", 400, 0, 1)
    start_one_exp("flex", 400, 0, 1)
