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

views = 100
timeout = 10
factor = 2
faults = 1
numctran = 5
sleeptime = 0
exen = 'exen1'

no_cache = False
no_stash = True
payloadsize_list = [0, 256, 512]
numtrans_list = [200,400, 600]


# 读取 IP 列表
def read_ip_list(filename):
    with open(filename, 'r') as file:
        ip_list = [line.strip() for line in file.readlines()]
    return ip_list

# 读取 servers 文件
def read_servers(total, filename):
    servers = []
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split()
            id = int(parts[0].split(':')[1])
            host = parts[1].split(':')[1]
            port1 = int(parts[2].split(':')[1])
            port2 = int(parts[3].split(':')[1])
            servers.append((id, host, port1, port2))
            if(len(servers) == total):
                break
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
def ssh_exec_server_non_blocking(id, host, port1, port2, factor, faults, completion_set, lock):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='root', key_filename='./TShard')
    cmd = f"export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/sdk_libs && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && cd /root/damysus_updated && rm -rf stats/* && ./server {id} {faults} {factor} {views} {timeout} > out{id}"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    # 非阻塞地监控命令执行状态
    def monitor_ssh():
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        output = stdout.read().decode()
        error = stderr.read().decode()
        # print(f"sgxserver on {host} with id {id} output:\n{output}")
        # print(f"sgxserver on {host} with id {id} error:\n{error}")
        with lock:
            completion_set.add((id, host))
        ssh.close()

    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor_ssh)
    monitor_thread.start()

def ssh_exec_servers_non_blocking(servers, factor, faults, max_workers=6):
    completion_set = set()
    lock = Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ssh_exec_server_non_blocking, server[0], server[1], server[2], server[3], factor, faults, completion_set, lock): server for server in servers}
        for future in as_completed(futures):
            server = futures[future]
            try:
                future.result()
                print(f"sgxserver on {server[1]} with id {server[0]} started successfully.")
            except Exception as e:
                print(f"sgxserver on {server[1]} with id {server[0]} generated an exception: {e}")
    
    # 等待所有 sgxserver 完成

    total = factor * faults + 1

    l = 0


    while len(completion_set) < total:
        if(len(completion_set) > l):
            l = len(completion_set)
            print(f'finishied {l}')
        print(f'completion_set {len(completion_set)}')
        time.sleep(5)

# SSH 执行 sgxclient
def ssh_exec_client(id, host, port1, port2, extra_params):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='your_username', key_filename='./TShard')
    cmd = f"client --id {id} --port1 {port1} --port2 {port2} {extra_params}"
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

def start_all_sgxservers(servers, factor, faults, max_workers=6):
    completion_set = set()
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(ssh_exec_server_non_blocking, id, host, port1, port2, factor, faults, completion_set, lock) for id, host, port1, port2 in servers]
        for future in as_completed(futures):
            future.result()
    return completion_set, lock

# 本地执行 sgxclient
def local_exec_client(factor, faults):
    cmd = f"./client 0 {faults} {factor} {numctran} {sleeptime} 0 > clientoutput"
    process = Popen(cmd, shell=True, cwd='/root/damysus_updated', stdout=PIPE, stderr=PIPE)
    # 如果需要在后台运行而不等待输出，可以去掉 stdout=PIPE 和 stderr=PIPE

    # 如果想要立即返回并继续执行其他任务，可以直接返回
    return process

def cp_client_stats():
    with open('client_stats', 'a') as f:
        f.write(f'views: {views}, numctrans: {numctran}, sleepttime: {sleeptime}\n')
    cmd = 'cat stats/client* >> client_stats && echo "" >> client_stats'
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop sgxclient output:\n{output}")
    print(f"Stop sgxclient error:\n{error}")


# 关闭本地 sgxclient
def stop_local_sgxclient():
    cp_client_stats()

    cmd = "pkill -f client"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop sgxclient output:\n{output}")
    print(f"Stop sgxclient error:\n{error}")

def rm_local_stats():
    cmd = "rm -rf stats/*"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()

def stop_remote_server():
    cmd = "python close_noTEE.py"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()


# 阻塞等待所有 sgxserver 实例结束
def wait_for_all_sgxservers_to_finish(completion_set, lock, total_servers):
    l = 0
    t = 0 
    while len(completion_set) < total_servers:
        if(len(completion_set) > l):
            l = len(completion_set)
            t = time.time()
            print(f'finishied {l}')
        time.sleep(3)
        if(t != 0 and time.time() - t > 10):
            stop_remote_server()
            break
            
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

def find_first_number(directory):
    rtt_files = glob.glob(os.path.join(directory, 'rtt-*'))

    for file_path in rtt_files:
        with open(file_path, 'r') as file:
            line = file.readline().strip()
            if line:
                try:
                    first_value = float(line.split()[0])
                    if not math.isnan(first_value):
                        return first_value
                except ValueError:
                    continue

    print("No valid data found.")
    return None

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
                    print(f'{total_count}, {values[0]}, {values[1]}')
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

def make_instance(protocol, batchsize, payload, faults, pct):

    pro_dir = f'{exen}/{protocol}_{faults}_{payload}_{batchsize}_{pct}'

    p = 0
    cmd_stash = 'git stash &&'
    if no_stash:
        cmd_stash = ' '

    if(protocol == 'achillies'):
        cmd = f"{cmd_stash} git checkout achillies"
        p = 0
    elif(protocol == 'achillies-N'):
        cmd = f"{cmd_stash} git checkout achillies"
        p = 5
    elif(protocol == 'flex'):
        cmd = f"{cmd_stash} git checkout flexi"
        p = 1
    elif(protocol == 'damysus'):
        cmd = f"{cmd_stash} git checkout main"
        p = 4

    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    # print(f"Stop checkout output:\n{output}")
    # print(f"Stop checkout error:\n{error}")


    folder_path = pro_dir
    if not os.path.exists(folder_path):
    # 如果文件夹不存在，则创建
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")
    else:
        print(f"Folder '{folder_path}' already exists.")
    

    file_name = "server"

# 构建完整的文件路径
    file_path = os.path.join(folder_path, file_name)

    cmd_sgxserver = f"make server -j8 && cp server {pro_dir}/ && cp App/params.h {pro_dir}/"

# 检查文件是否存在
    if os.path.isfile(file_path):
    # 执行命令x
        command = 'echo "File exists", copy to here'
        cmd_sgxserver = f"cp {file_path} ./"
        print(command)
    else:
    # 执行命令y
        command = 'echo "File does not exist"'
        print(command)

    if no_cache:
        cmd_sgxserver = 'make server -j8'

    print(f'exec {cmd_sgxserver}')

    cmd = f"python expmkp.py --faults {faults} --payload {payload} --p {p} --numtrans {batchsize} --pct {pct} --mkpp"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print("make finished")
    print(f"Stop expmkp output:\n{output}")
    print(f"Stop expmkp error:\n{error}")

def start_one_exp(protocol, batchsize, payload, faults, pct):

    pro_dir = f'{protocol}_{faults}_{payload}_{batchsize}_{pct}'

    factor = 2
    if protocol == 'flex':
        factor = 3

    total = factor * faults + 1


    ip_list = read_ip_list('ip_list')
    servers = read_servers(total, 'servers')

   # print(ip_list)
    ip_list_set = set()
    for server in servers:
        ip_list_set.add(server[1])
    ip_list = list(ip_list_set)
   # print(ip_list)

    make_instance(protocol, batchsize, payload, faults, pct)

    files_to_copy2 = [
        os.path.expanduser('~/damysus_updated/server'), 
        os.path.expanduser('~/damysus_updated/servers'),
        os.path.expanduser('~/damysus_updated/client'),
        # os.path.expanduser('~/damysus_updated/config'),
        # os.path.expanduser('~/damysus_updated/enclave.so'),
        # os.path.expanduser('~/damysus_updated/enclave.signed.so'),
        # os.path.expanduser('~/damysus_updated/sgxkeys')
    ]  # 修改为实际的文件列表

 
   # files_to_copy = [
   #     os.path.expanduser('~/damysus_updated/servers'), 
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxserver'),
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxclient'),
   #     os.path.expanduser(f'~/damysus_updated/exe/{pro_dir}/sgxkeys')
   #  ]  # 修改为实际的文件列表

    extra_params = '--other_param value'  # 补充实际的其它参数

    rm_local_stats()
    # 多线程 SCP 文件到节点
    scp_files_to_nodes(ip_list, files_to_copy2)


    # 多线程 SSH 执行 sgxserver

    # rm_local_stats()

    completion_set, lock = start_all_sgxservers(servers, factor, faults)
    print("start")

    time.sleep(10 + math.log(len(servers), 2))

    # 启动本地 sgxclient
    local_exec_client(factor, faults)

    # 阻塞等待所有 sgxserver 实例结束
    wait_for_all_sgxservers_to_finish(completion_set, lock, total)

    #stop_local_sgxclient()

    #clear_local_stats()

    # 多线程将远程 /root/damysus_updated/stats/ 目录中的内容 SCP 到本地

    scp_stats_from_nodes(ip_list, '/root/damysus_updated/', '/root/damysus_updated/stats/')

    stats_directory = '/root/damysus_updated/stats/'

    # 计算所有 vals 文件的第一个数和第二个数的均值
    r1, r2 = calculate_mean_of_values(stats_directory)
    rtt = find_first_number(stats_directory)

    cp_client_stats()

    print(pro_dir, r1, r2)

    with open('stats.txt', 'a') as f:
        f.write(f'{pro_dir}, {r1}, {r2}, {rtt}\n')


    # 等待并在 id:0 的主机上执行 sgxclient
    # ssh_exec_client_on_id0(servers, extra_params)

    # 多线程 SCP 从节点到本地
    # scp_files_from_nodes(ip_list)o



def run_achillies():

    pr = "achillies"
    start_one_exp(pr, 400, 500, 10, 0)


    return

    ps = [0, 256, 500]
    bs = [200, 400, 600]


    for p in ps:
        start_one_exp(pr, 400, p, 10, 0)

dc = {}

def test_payload():
    prs = ["flex", "achillies", "damysus"]
    #fs = [1,2,3,4]
    for f in fs:
        for pr in prs:
            start_one_exp(pr, 400, 256, f, 0)

def make_instancess():
    ps = [256, 500, 0]
    ts = [0, 20]
    bs = [200, 400, 600]
    fs = [1, 2, 4, 10, 20, 30]
    b = 400
    p = 256
    t = 0
    f = 10

    tasks = []


    # test payload
    for p in ps:
        tasks.append(("flex", b, p, f, 20))
        tasks.append(("achillies", b, p, f, 0))
        tasks.append(("damysus", b, p, f, 20))
        t = 0
        #tasks.append(("flex", b, p, f, 0))
        #tasks.append(("damysus", b, p, f, 0))



    p = 256

    # test batch 
    for b in bs:
        t = 0
        tasks.append(("achillies", b, p, f, t))
        tasks.append(("flex", b, p, f, 20))
        tasks.append(("damysus", b, p, f, 20))

    b = 400

    #for f in fs:
    #    for t in ts:
    #        tasks.append(("flex", b, p, f, t))
    #        tasks.append(("damysus", b, p, f, t))
    #    t = 0
    #    tasks.append(("achillies", b, p, f, t))
    #f = 10

    star = 0

    for i in range(len(tasks)):
        task = tasks[i]
        if(task in dc):
            continue
        dc[task] = 1
 
        if(i<star):
            continue
        print(f"start task {task}")
        with open('stats.txt', 'a') as f:
            f.write(f'task: {i}\n')
        start_one_exp(task[0], task[1], task[2], task[3], task[4])
        

def make_instances():
    global views
    ps = [256, 500, 0]
    ts = [0, 20]
    bs = [200, 400, 600]
    fs = [1, 2, 4]
    b = 400
    p = 256
    t = 0
    f = 10

    tasks = []

    # test payload
    for f in fs:
        tasks.append(("flex", b, p, f, 20))
        tasks.append(("achillies", b, p, f, 0))
        tasks.append(("damysus", b, p, f, 20))

    b = 400

    #for f in fs:
    #    for t in ts:
    #        tasks.append(("flex", b, p, f, t))
    #        tasks.append(("damysus", b, p, f, t))
    #    t = 0
    #    tasks.append(("achillies", b, p, f, t))
    #f = 10

    star = 0

    for i in range(len(tasks)):
        task = tasks[i]
        if(task in dc):
            continue
        dc[task] = 1
 
        if(i<star):
            continue
        print(f"start task {task}")
        with open('stats.txt', 'a') as f:
            f.write(f'task: {i}\n')
        start_one_exp(task[0], task[1], task[2], task[3], task[4])
 

def test_batch():
    #bs = [200,400,800,1600,3200]
    bs = [400]
    #bs.reverse()
    print(bs)
    for b in bs:
        start_one_exp("achillies", b, 256, 3, 0)



def test_pct():
    ps = [256, 500, 0]
    ts = [0, 10, 20, 40, 80]
    bs = [200, 400, 600]
    fs = [1, 2, 4]
    b = 400
    p = 256
    t = 0
    f = 10

    tasks = []

    # test payload
    for t in ts:
        tasks.append(("flex", b, p, f, t))
        #tasks.append(("achillies", b, p, f, 0))
        tasks.append(("damysus", b, p, f, t))

    b = 400

    #for f in fs:
    #    for t in ts:
    #        tasks.append(("flex", b, p, f, t))
    #        tasks.append(("damysus", b, p, f, t))
    #    t = 0
    #    tasks.append(("achillies", b, p, f, t))
    #f = 10

    star = 0

    for i in range(len(tasks)):
        task = tasks[i]
        if(task in dc):
            continue
        dc[task] = 1
 
        if(i<star):
            continue
        print(f"start task {task}")
        with open('stats.txt', 'a') as f:
            f.write(f'task: {i}\n')
        start_one_exp(task[0], task[1], task[2], task[3], task[4])
 
def test_f30():
    ps = [256, 500, 0]
    ts = [0, 20]
    bs = [200, 400, 600]
    fs = [20]
    b = 400
    p = 256
    t = 0
    f = 10

    tasks = []
    for f in fs:
        tasks.append(("achillies", b, p, f, 0))
        tasks.append(("flex", b, p, f, 20))
        tasks.append(("damysus", b, p, f, 20))

    b = 400
    star = 0

    for i in range(len(tasks)):
        task = tasks[i]
        if(task in dc):
            continue
        dc[task] = 1
 
        if(i<star):
            continue
        print(f"start task {task}")
        with open('stats.txt', 'a') as f:
            f.write(f'task: {i}\n')
        start_one_exp(task[0], task[1], task[2], task[3], task[4])
 

if __name__ == "__main__":
    
    with open('stats.txt', 'a') as f:
        f.write(f"Start, views: {views}\n")

    #ip_list = read_ip_list('ip_list')

    # local_exec_client(3, 1)

    #files_to_copy2 = [
    #    os.path.expanduser('~/damysus_updated/servers'),
    #    os.path.expanduser('~/damysus_updated/enclave.so'),
    #    os.path.expanduser('~/damysus_updated/enclave.signed.so'),
    #]  # 修改为实际的文件列表

    #make_instances()
    #scp_files_to_nodes(ip_list, files_to_copy2)
    #test_f30()
    #run_achillies()
    #views = 1000

    #start_one_exp("achillies", 400, 0, 10, 0)
    #start_one_exp("achillies", 400, 0, 10, 0)
    #views = 100
    # start_one_exp("flex", 400, 256, 10, 20)
    #start_one_exp("damysus", 400, 512, 10, 20)
    #test_payload()
    #start_one_exp("flex", 400, 256, 1, 0)
    #start_one_exp("damysus", 400, 256, 1, 0)
    #start_one_exp("damysus", 400, 256, 2, 0)
    #start_one_exp("damysus", 400, 256, 3, 0)
    #start_one_exp("flex", 400, 256, 2, 0)
    #start_one_exp("flex", 400, 256, 3, 0)

    #test_batch()

    start_one_exp("achillies-N", 400, 256, 20, 0)

    # local_exec_client(2, 1)
    
    # start_one_exp("flex", 400, 256, 2 ,20)
    # time.sleep(10)
    # start_one_exp("flex", 400, 256, 2 ,20)
    # time.sleep(10)
    # start_one_exp("flex", 400, 256, 2 ,20)
    # start_one_exp("damysus", 400, 256, 2, 20)


    # start_one_exp("achillies", 400, 256, 10, 0)
    # time.sleep(10)
    # start_one_exp("damysus", 400, 256, 10, 20)
    # time.sleep(10)
    # start_one_exp("flex", 400, 256, 10, 20)
    # time.sleep(10)


    # for numtran in numtrans_list:
    #     start_one_exp("achillies", numtran, 256, 10, 0)
    #     time.sleep(10)
    #     start_one_exp("damysus", numtran, 256, 10, 20)
    #     time.sleep(10)
    #     start_one_exp("flex", numtran, 256, 10, 20)
    #     time.sleep(10)
    # for payload in payloadsize_list:
    #     start_one_exp("achillies", 400, payload, 10, 0)
    #     start_one_exp("damysus", 400, payload, 10, 20)
    #     start_one_exp("flex", 400, payload, 10, 20)
    #     time.sleep(10)
