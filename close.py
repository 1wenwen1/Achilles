import paramiko
from paramiko import SSHClient, AutoAddPolicy
from concurrent.futures import ThreadPoolExecutor, as_completed

# Read the IP list
def read_ip_list(filename):
    with open(filename, 'r') as file:
        ip_list = [line.strip() for line in file.readlines()]
    return ip_list

# Connect through SSH and close the sgxserver process
def close_sgxserver(ip):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(ip, username='root', key_filename='./TShard')
    cmd = "pkill sgxserver"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()  # 等待命令执行完成
    output = stdout.read().decode()
    error = stderr.read().decode()
    #print(f"Close sgxserver on {ip} output:\n{output}")
    #print(f"Close sgxserver on {ip} error:\n{error}")
    ssh.close()

# Multi-threading closes the remote sgxserver, limiting the number of concurrent threads to 6
def close_sgxserver_on_nodes(ip_list, max_workers=6):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(close_sgxserver, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
                #print(f"Closed sgxserver on {ip} successfully.")
            except Exception as e:
                pass

                #print(f"Closing sgxserver on {ip} generated an exception: {e}")

if __name__ == "__main__":
    ip_list = read_ip_list('ip_list')
    close_sgxserver_on_nodes(ip_list)
    print("closed")

