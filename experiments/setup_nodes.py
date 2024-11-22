import os
import time
from config import *

#
#Usage:
# 1. Go to OurWork/AAzurite
# 2. npm install -g azurite
# 3. start Azurite in the background: azurite --silent --location ./azurite_data --debug ./azurite_debug.log --tableHost 127.0.0.1 --tablePort 10002 &
# 4. Verify it is running: ps aux | grep azurite
#

# Default Azurite Configuration
AZURITE_ACCOUNT_NAME = "devstoreaccount1"
AZURITE_ACCOUNT_KEY = "Eby8vdM02xWkA3az9W5ZPcuwwd2E9aMJW6DhDeUpgw=fGzv3nwKONNlGRd29aZJof7PRwIgORJFjBRzq=C41vHcP9mlX1Ag=="
AZURITE_ENDPOINT = "http://127.0.0.1:10002/devstoreaccount1"

# Update Azurite connection settings
os.environ['STORAGE_ACCOUNT_NAME'] = AZURITE_ACCOUNT_NAME
os.environ['STORAGE_MASTER_KEY'] = AZURITE_ACCOUNT_KEY

# Modify this command for local Azurite usage
CMD = f"screen -d -m {NIMBLE_BIN_PATH}"

# Determine if there are distinct endpoints for load balancer
HAS_LB = LISTEN_IP_ENDPOINT_1 != LISTEN_IP_LOAD_BALANCER

# Helper function for executing commands locally or remotely
def ssh_cmd(ip, cmd):
    if LOCAL_RUN:
        return cmd.replace('\'', '')
    else:
        return f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} {SSH_USER}@{ip} {cmd}"

# Helper function to create output folder on remote or local
def setup_output_folder(ip, out_folder):
    folder_cmd = ssh_cmd(ip, f"\'mkdir -p {out_folder}\'")
    print(folder_cmd)
    os.system(folder_cmd)

# Helper function to collect results from a remote machine
def collect_results(ip):
    if LOCAL_RUN:
        return ""
    else:
        cmd = f"scp -r -i {SSH_KEY_PATH} {SSH_USER}@{ip}:{OUTPUT_FOLDER} ./"
        print(cmd)
        os.system(cmd)

# Setting up endorsers (main, backup, SGX)
def setup_main_endorsers():
    endorsers = [
        (SSH_IP_ENDORSER_1, LISTEN_IP_ENDORSER_1, PORT_ENDORSER_1),
        (SSH_IP_ENDORSER_2, LISTEN_IP_ENDORSER_2, PORT_ENDORSER_2),
        (SSH_IP_ENDORSER_3, LISTEN_IP_ENDORSER_3, PORT_ENDORSER_3),
    ]
    for ip, listen_ip, port in endorsers:
        cmd = ssh_cmd(ip, f"{CMD}/endorser -t {listen_ip} -p {port}")
        print(cmd)
        os.system(cmd)

    time.sleep(5)

# Setting up the coordinator
def setup_coordinator(store):
    coordinator = f"{CMD}/coordinator -t {LISTEN_IP_COORDINATOR} -p {PORT_COORDINATOR} -r {PORT_COORDINATOR_CTRL} "
    coordinator += f"-e \"http://{LISTEN_IP_ENDORSER_1}:{PORT_ENDORSER_1},http://{LISTEN_IP_ENDORSER_2}:{PORT_ENDORSER_2},"
    coordinator += f"http://{LISTEN_IP_ENDORSER_3}:{PORT_ENDORSER_3}\" -l 60 {store}"

    cmd = ssh_cmd(SSH_IP_COORDINATOR, coordinator)
    print(cmd)
    os.system(cmd)
    time.sleep(5)

# Setting up endpoints
def setup_endpoints():
    endpoint1 = f"{CMD}/endpoint_rest -t {LISTEN_IP_ENDPOINT_1} -p {PORT_ENDPOINT_1} "
    endpoint1 += f"-c \"http://{LISTEN_IP_COORDINATOR}:{PORT_COORDINATOR}\" -l 60"
    cmd = ssh_cmd(SSH_IP_ENDPOINT_1, endpoint1)
    print(cmd)
    os.system(cmd)

    if HAS_LB:
        endpoint2 = f"{CMD}/endpoint_rest -t {LISTEN_IP_ENDPOINT_2} -p {PORT_ENDPOINT_2} "
        endpoint2 += f"-c \"http://{LISTEN_IP_COORDINATOR}:{PORT_COORDINATOR}\" -l 60"
        cmd = ssh_cmd(SSH_IP_ENDPOINT_2, endpoint2)
        print(cmd)
        os.system(cmd)

    time.sleep(5)

# Setting up the system
def setup(store, sgx=False):
    if not sgx:
        setup_main_endorsers()
        setup_coordinator(store)
    else:
        raise NotImplementedError("SGX setup not adapted for Azurite.")
    setup_endpoints()

# Teardown function
def teardown(sgx=False):
    kill_endpoints()
    kill_coordinator()
    kill_endorsers()

# Killing endorsers
def kill_endorsers():
    endorsers = [SSH_IP_ENDORSER_1, SSH_IP_ENDORSER_2, SSH_IP_ENDORSER_3]
    for ip in endorsers:
        cmd = ssh_cmd(ip, "pkill endorser")
        print(cmd)
        os.system(cmd)

# Killing endpoints
def kill_endpoints():
    endpoint1 = ssh_cmd(SSH_IP_ENDPOINT_1, "pkill endpoint_rest")
    print(endpoint1)
    os.system(endpoint1)

    if HAS_LB:
        endpoint2 = ssh_cmd(SSH_IP_ENDPOINT_2, "pkill endpoint_rest")
        print(endpoint2)
        os.system(endpoint2)

# Killing coordinator
def kill_coordinator():
    cmd = ssh_cmd(SSH_IP_COORDINATOR, "pkill coordinator")
    print(cmd)
    os.system(cmd)
