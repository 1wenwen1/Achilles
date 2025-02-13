import subprocess
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
import argparse

views = 20
timeout = 10
timeoutTime = 120
Factor = 2
numctran = 1
sleeptime = 0
exen = '/root/damysus_updated/exe'
no_cache = False
no_stash = True

params       = "/root/damysus_updated/App/params.h" # (don't change, hard coded in C++)

# read IP list
def read_ip_list(filename):
    with open(filename, 'r') as file:
        ip_list = [line.strip() for line in file.readlines()]
    return ip_list

# read servers
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

# send files to node
def scp_to_node(ip, files):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        for file in files:
            remote_path = f'/root/damysus_updated'  # 假设你的远程用户是 root，修改为实际的远程路径前缀
            scp.put(file, remote_path=remote_path)
    ssh.close()

# execute sgxserver
def ssh_exec_server_non_blocking(id, host, port1, port2, factor, faults, completion_set, lock):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='root', key_filename='./TShard')
    cmd = f"export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/sdk_libs && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && cd /root/damysus_updated && rm -rf stats/* && ./sgxserver {id} {faults} {factor} {views} {timeout} > out{id}"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    # Non-blocking monitoring of command execution status
    def monitor_ssh():
        stdout.channel.recv_exit_status() 
        output = stdout.read().decode()
        error = stderr.read().decode()
        # print(f"sgxserver on {host} with id {id} output:\n{output}")
        # print(f"sgxserver on {host} with id {id} error:\n{error}")
        with lock:
            completion_set.add((id, host))
        ssh.close()

    # start monitoring thread
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
    
    # waiting sgxserver instances to finish

    total = factor * faults + 1

    l = 0


    while len(completion_set) < total:
        if(len(completion_set) > l):
            l = len(completion_set)
            print(f'finishied {l}')
        print(f'completion_set {len(completion_set)}')
        time.sleep(5)

# SSH execute sgxclient
def ssh_exec_client(id, host, port1, port2, extra_params):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, username='your_username', key_filename='./TShard')
    cmd = f"sgxclient --id {id} --port1 {port1} --port2 {port2} {extra_params}"
    ssh.exec_command(cmd)
    ssh.close()

# acquire stats from node
def scp_from_node(ip):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        scp.get('/remote/damysus/stats/*', local_path='damysus/stats/')  # 修改为实际的远程路径和本地路径
    ssh.close()

# send files to nodes
def scp_files_to_nodes(ip_list, files, max_workers=6):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scp_to_node, ip, files) for ip in ip_list]
        for future in futures:
            future.result()




#execute clients
def ssh_exec_client_on_id0(servers, extra_params):
    id0_server = next((server for server in servers if server[0] == 0), None)
    if id0_server:
        time.sleep(5 + math.log(len(servers), 2))
        ssh_exec_client(id0_server[0], id0_server[1], id0_server[2], id0_server[3], extra_params)

# acquire stats from nodes
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

# execute sgxclient locally
def local_exec_client(factor, faults):
    cmd = f"./sgxclient 0 {faults} {factor} {numctran} {sleeptime} 0 > clientoutput"
    process = Popen(cmd, shell=True, cwd='/root/damysus_updated', stdout=PIPE, stderr=PIPE)
    # If need to run in the background without waiting for the output, can remove stdout=PIPE and stderr=PIPE.

    # If want to return immediately and continue to perform other tasks, can return directly.
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


# stop local sgxclient
def stop_local_sgxclient():
    cp_client_stats()

    cmd = "pkill -f sgxclient"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop sgxclient output:\n{output}")
    print(f"Stop sgxclient error:\n{error}")

def rm_local_stats():
    cmd = "rm -rf /root/damysus_updated/stats/*"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()

def stop_remote_server():
    cmd = "python3 /root/damysus_updated/close.py"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    subprocess.run(cmd, shell=True, check=True)


# Block and wait for all sgxserver instances to end
def wait_for_all_sgxservers_to_finish(completion_set, lock, total_servers):
    l = 0
    start_time = time.time()  # Start the timer
    while len(completion_set) < total_servers:
        if(len(completion_set) > l):
            l = len(completion_set)
            t = time.time()
            print(f'finishied {l}')
        # Check if the timeout has been reached
        if time.time() - start_time > timeoutTime:
            print(f"Timeout reached. Stopping remote server.")
            stop_remote_server()  # Stop the server if timeout
            break
    
    # If all servers finish, print a message
    if len(completion_set) == total_servers:
        print("All sgxserver instances have finished.")
            


def clear_local_stats():
    stats_path = Path('/root/damysus_updated/stats/')
    if stats_path.exists() and stats_path.is_dir():
        shutil.rmtree(stats_path)
    stats_path.mkdir(parents=True, exist_ok=True)

# SCP the stats in the remote /root/damysus_updated/stats/ directory to the same local directory
def scp_stats_from_node(ip, local_path, remote_path):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path=local_path, recursive=True)
    ssh.close()

# Multi-threaded SCP stats content to local
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

    if(protocol == 'Achilles'):
        cmd = f"{cmd_stash} git checkout Achilles"
        p = 0
        factor = 2
    elif(protocol == 'Achilles-Recovery'):
        cmd = f"{cmd_stash} git checkout Achilles"
        p = 5
        factor = 2
    elif(protocol == 'FlexiBFT'):
        cmd = f"{cmd_stash} git checkout FlexiBFT"
        p = 1
        factor = 3
    elif(protocol == 'Damysus'):
        cmd = f"{cmd_stash} git checkout Damysus"
        p = 4
        factor = 2

    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop checkout output:\n{output}")
    print(f"Stop checkout error:\n{error}")

    print(f"mkprotocol: {protocol}, factor:{factor}, batchsize: {batchsize}, payload: {payload}, faults: {faults}, pct: {pct}")
    mkParams(protocol,factor,faults,batchsize,payload,pct)

    folder_path = pro_dir
    if not os.path.exists(folder_path):
    # If the folder does not exist, create
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")
    else:
        print(f"Folder '{folder_path}' already exists.")
    

    file_name = "sgxserver"

# Build a complete file path
    file_path = os.path.join(folder_path, file_name)

    cmd_sgxserver = f"make sgxserver -j8 && cp sgxserver {pro_dir}/ && cp App/params.h {pro_dir}/"

# Check whether the file exists
    if os.path.isfile(file_path):
        command = 'echo "File exists", copy to here'
        cmd_sgxserver = f"cp {file_path} ./"
        print(command)
    else:
        command = 'echo "File does not exist"'
        print(command)

    if no_cache:
        cmd_sgxserver = 'make sgxserver -j8'

    print(f'exec {cmd_sgxserver}')

    cmd = f"python expmkp.py --faults {faults} --payload {payload} --p {p} --numtrans {batchsize} --pct {pct} --mkpp && make clean && make enclave.so enclave.signed.so sgxclient sgxkeys -j8 && {cmd_sgxserver}"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print("make finished")
    # print(f"Stop expmkp output:\n{output}")
    # print(f"Stop expmkp error:\n{error}")


def start_experiment_local(protocol, batchsize, payload, faults, pct):
    factor = 2
    if protocol == 'FlexiBFT':
        factor = 3
    total = factor * faults + 1
    make_instance(protocol, batchsize, payload, faults, pct)

    cmd = f"python expmkp.py --p6 --faults {faults} --payload {payload} --numtrans {batchsize} --pct {pct}"
    subprocess.run(cmd, shell=True, check=True)





def start_experiment(protocol, batchsize, payload, faults, pct):

    pro_dir = f'{protocol}_{faults}_{payload}_{batchsize}_{pct}'

    factor = 2
    if protocol == 'FlexiBFT':
        factor = 3

    total = factor * faults + 1


    ip_list = read_ip_list('/root/damysus_updated/ip_list')
    servers = read_servers(total, '/root/damysus_updated/servers')

   # print(ip_list)
    ip_list_set = set()
    for server in servers:
        ip_list_set.add(server[1])
    ip_list = list(ip_list_set)
   # print(ip_list)

    make_instance(protocol, batchsize, payload, faults, pct)

    files_to_copy2 = [
        os.path.expanduser('~/damysus_updated/sgxserver'), 
        os.path.expanduser('~/damysus_updated/servers'),
        os.path.expanduser('~/damysus_updated/sgxclient'),
        os.path.expanduser('~/damysus_updated/enclave.so'),
        os.path.expanduser('~/damysus_updated/enclave.signed.so'),
        os.path.expanduser('~/damysus_updated/sgxkeys')
    ] 

 
    extra_params = '--other_param value'

    rm_local_stats()

    scp_files_to_nodes(ip_list, files_to_copy2)

    # Multi-threaded SSH execution sgxserver
    completion_set, lock = start_all_sgxservers(servers, factor, faults)
    print("start")

    time.sleep(10 + math.log(len(servers), 2))

    #start localsgxclient
    local_exec_client(factor, faults)

    # Block and wait for all sgxserver instances to end
    wait_for_all_sgxservers_to_finish(completion_set, lock, total)

    #stop_local_sgxclient()

    #clear_local_stats()

    # Multithreading will remotely /root/damysus_updated/stats/ content SCP in the directory to the local
    scp_stats_from_nodes(ip_list, '/root/damysus_updated/', '/root/damysus_updated/stats/')

    stats_directory = '/root/damysus_updated/stats/'

    # Calculate the average value of the first and second numbers of all vals files
    r1, r2 = calculate_mean_of_values(stats_directory)
    # rtt = find_first_number(stats_directory)

    cp_client_stats()

    print(pro_dir, r1, r2)

    with open('/root/damysus_updated/stats.txt', 'a') as f:
        # f.write(f'{pro_dir}, {r1}, {r2}, {rtt}\n')
        f.write(f'{pro_dir}, {r1}, {r2},\n')


    # Wait and execute sgxclient on the host with id:0
    # ssh_exec_client_on_id0(servers, extra_params)

    # Multi-threaded SCP from node to local
    # scp_files_from_nodes(ip_list)o

def only_make_instance(protocol, batchsize, payload, faults, pct):

    pro_dir = f'{exen}/{protocol}_{faults}_{payload}_{batchsize}_{pct}'

    folder_path = pro_dir
    if not os.path.exists(folder_path):
    # If the folder does not exist, create
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")
    else:
        print(f"Folder '{folder_path}' already exists.")

    file_name = "sgxserver"
    file_path = os.path.join(folder_path, file_name)

    if os.path.isfile(file_path):
        command = 'echo "File exists"'
        print(command)
        return 
    else:
        command = 'echo "File does not exist"'
        print(command)

    p = 0
    if(protocol == 'Achilles'):
        cmd = "git stash && git checkout Achilles"
        p = 0
    elif(protocol == 'Achilles-Recovery'):
        cmd = f"git stash && git checkout Achilles"
        p = 5
    elif(protocol == 'FlexiBFT'):
        cmd = "git stash && git checkout FlexiBFT"
        p = 1
    elif(protocol == 'Damysus'):
        cmd = "git stash && git checkout Damysus"
        p = 4

    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop checkout output:\n{output}")
    print(f"Stop checkout error:\n{error}")

    cmd_sgxserver = f"make sgxserver -j8 && cp sgxserver {pro_dir}/ && cp App/params.h {pro_dir}/"

    print(f'exec {cmd_sgxserver}')

    cmd = f"python expmkp.py --faults {faults} --payload {payload} --p {p} --pct {pct} --numtran {batchsize} --mkpp && make clean && {cmd_sgxserver}"
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode()
    error = stderr.decode()
    print(f"Stop expmkp output:\n{output}")
    print(f"Stop expmkp error:\n{error}")

def mkParams(protocol,constFactor,numFaults,numTrans,payloadSize,pct):
    f = open(params, 'w')
    f.write("#ifndef PARAMS_H\n")
    f.write("#define PARAMS_H\n")
    f.write("\n")
    # f.write("#define " + protocol.value + "\n")
    if protocol == "Achilles":
        f.write("#define ACHILLES\n")
    elif protocol == "FlexiBFT":
        f.write("#define CHAINED_CHEAP_AND_QUICK\n")
    elif protocol == "Damysus":
        f.write("#define CHAINED_CHEAP_AND_QUICK\n")
    f.write("#define MAX_NUM_NODES " + str((constFactor*numFaults)+1) + "\n")
    f.write("#define MAX_NUM_SIGNATURES " + str((constFactor*numFaults)+1-numFaults) + "\n")
    f.write("#define MAX_NUM_TRANSACTIONS " + str(numTrans) + "\n")
    f.write("#define PAYLOAD_SIZE " +str(payloadSize) + "\n")
    f.write("#define PERSISTENT_COUNTER_TIME " +str(pct) + "\n")
    f.write("\n")
    f.write("#endif\n")
    f.close()
# End of mkParams


def main():
    with open('/root/damysus_updated/stats.txt', 'a') as f:
        f.write(f"Start, views: {views}\n")

    parser = argparse.ArgumentParser(description='Start one experiment with given parameters.')
    parser.add_argument("--p1",        action="store_true",    help="run Achilles")
    parser.add_argument("--p2",        action="store_true",    help="run FlexiBFT")
    parser.add_argument("--p3",        action="store_true",    help="run Damysus")
    parser.add_argument("--local",     action="store_true",    help="run locally")
    parser.add_argument('--batchsize', type=int,  default=400, help='Batch size')
    parser.add_argument('--payload',   type=int,  default=256, help='Payload size')
    parser.add_argument('--faults',    type=int,  default=1,   help='Number of faults')
    args = parser.parse_args()

    if args.p1:
        Protocol = "Achilles"
        pct = 0
    elif args.p2:
        Protocol = "FlexiBFT"
        pct = 20
    elif args.p3:
        Protocol = "Damysus"
        pct = 20
    else:
        Protocol = "Achilles"


    if args.local:
        start_experiment_local(Protocol, args.batchsize, args.payload, args.faults, pct)
    else:
        start_experiment(Protocol, args.batchsize, args.payload, args.faults, pct)


    # start_experiment(Protocol, args.batchsize, args.payload, args.faults, args.pct)
    # start_experiment_local(Protocol, args.batchsize, args.payload, args.faults, pct)


if __name__ == "__main__":
    
    main()

