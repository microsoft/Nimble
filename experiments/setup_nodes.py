import os
import time
from config import *

# make sure to set the configuration in config.py

CMD = "screen -d -m " + NIMBLE_BIN_PATH
HAS_LB = LISTEN_IP_ENDPOINT_1 != LISTEN_IP_LOAD_BALANCER # if not the same, we assume 2 endpoints and a load balancer

def setup_main_endorsers():
    endorser1 = ssh_cmd(SSH_IP_ENDORSER_1, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_1 + " -p " + PORT_ENDORSER_1)
    endorser2 = ssh_cmd(SSH_IP_ENDORSER_2, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_2 + " -p " + PORT_ENDORSER_2)
    endorser3 = ssh_cmd(SSH_IP_ENDORSER_3, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_3 + " -p " + PORT_ENDORSER_3)

    print(endorser1)
    os.system(endorser1)
    print(endorser2)
    os.system(endorser2)
    print(endorser3)
    os.system(endorser3)

    time.sleep(5)

def setup_backup_endorsers():
    endorser4 = ssh_cmd(SSH_IP_ENDORSER_4, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_4 + " -p " + PORT_ENDORSER_4)
    endorser5 = ssh_cmd(SSH_IP_ENDORSER_5, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_5 + " -p " + PORT_ENDORSER_5)
    endorser6 = ssh_cmd(SSH_IP_ENDORSER_6, CMD + "/endorser -t " + LISTEN_IP_ENDORSER_6 + " -p " + PORT_ENDORSER_6)

    print(endorser4)
    os.system(endorser4)
    print(endorser5)
    os.system(endorser5)
    print(endorser6)
    os.system(endorser6)

    time.sleep(5)

def setup_sgx_endorsers():
    endorser1 = "screen -d -m " + NIMBLE_PATH + "/endorser-openenclave/host/endorser_host "
    endorser1 += NIMBLE_PATH + "/endorser-openenclave/enclave/enclave-sgx2.signed "
    endorser1 += "-p " + PORT_SGX_ENDORSER_1
    endorser1 = ssh_cmd(SSH_IP_SGX_ENDORSER_1, endorser1)

    endorser2 = "screen -d -m " + NIMBLE_PATH + "/endorser-openenclave/host/endorser_host "
    endorser2 += NIMBLE_PATH + "/endorser-openenclave/enclave/enclave-sgx2.signed "
    endorser2 += "-p " + PORT_SGX_ENDORSER_2
    endorser2 = ssh_cmd(SSH_IP_SGX_ENDORSER_2, endorser2)

    endorser3 = "screen -d -m " + NIMBLE_PATH + "/endorser-openenclave/host/endorser_host "
    endorser3 += NIMBLE_PATH + "/endorser-openenclave/enclave/enclave-sgx2.signed "
    endorser3 += "-p " + PORT_SGX_ENDORSER_3
    endorser3 = ssh_cmd(SSH_IP_SGX_ENDORSER_3, endorser3)

    print(endorser1)
    os.system(endorser1)
    print(endorser2)
    os.system(endorser2)
    print(endorser3)
    os.system(endorser3)

    time.sleep(30) # they take much longer to boot


def setup_coordinator(store):
    coordinator = CMD + "/coordinator -t " + LISTEN_IP_COORDINATOR + " -p " + PORT_COORDINATOR + " -r " + PORT_COORDINATOR_CTRL
    coordinator += " -e \"http://" + LISTEN_IP_ENDORSER_1 + ":" + PORT_ENDORSER_1
    coordinator += ",http://" + LISTEN_IP_ENDORSER_2 + ":" + PORT_ENDORSER_2
    coordinator += ",http://" + LISTEN_IP_ENDORSER_3 + ":" + PORT_ENDORSER_3
    coordinator += "\" -l 60"
    coordinator += store

    coordinator = ssh_cmd(SSH_IP_COORDINATOR, coordinator)

    print(coordinator)
    os.system(coordinator)
    time.sleep(5)

def setup_coordinator_sgx(store):
    coordinator = CMD + "/coordinator -t " + LISTEN_IP_COORDINATOR + " -p " + PORT_COORDINATOR + " -r " + PORT_COORDINATOR_CTRL
    coordinator += " -e \"http://" + LISTEN_IP_SGX_ENDORSER_1 + ":" + PORT_SGX_ENDORSER_1
    coordinator += ",http://" + LISTEN_IP_SGX_ENDORSER_2 + ":" + PORT_SGX_ENDORSER_2
    coordinator += ",http://" + LISTEN_IP_SGX_ENDORSER_3 + ":" + PORT_SGX_ENDORSER_3
    coordinator += "\" -l 60"
    coordinator += store

    coordinator = ssh_cmd(SSH_IP_COORDINATOR, coordinator)

    print(coordinator)
    os.system(coordinator)
    time.sleep(5)



def setup_endpoints():
    endpoint1 = CMD + "/endpoint_rest -t " + LISTEN_IP_ENDPOINT_1 + " -p " + PORT_ENDPOINT_1
    endpoint1 += " -c \"http://" + LISTEN_IP_COORDINATOR + ":" + PORT_COORDINATOR + "\" -l 60"
    endpoint1 = ssh_cmd(SSH_IP_ENDPOINT_1, endpoint1)

    print(endpoint1)
    os.system(endpoint1)

    if HAS_LB:
        endpoint2 = CMD + "/endpoint_rest -t " + LISTEN_IP_ENDPOINT_2 + " -p " + PORT_ENDPOINT_2
        endpoint2 += " -c \"http://" + LISTEN_IP_COORDINATOR + ":" + PORT_COORDINATOR + "\" -l 60"
        endpoint2 = ssh_cmd(SSH_IP_ENDPOINT_2, endpoint2)

        print(endpoint2)
        os.system(endpoint2)

    time.sleep(5)

def kill_endorsers():
    endorser1 = ssh_cmd(SSH_IP_ENDORSER_1, "pkill endorser")
    endorser2 = ssh_cmd(SSH_IP_ENDORSER_2, "pkill endorser")
    endorser3 = ssh_cmd(SSH_IP_ENDORSER_3, "pkill endorser")

    print(endorser1)
    os.system(endorser1)
    print(endorser2)
    os.system(endorser2)
    print(endorser3)
    os.system(endorser3)

def kill_sgx_endorsers():
    endorser1 = ssh_cmd(SSH_IP_SGX_ENDORSER_1, "pkill endorser_host")
    endorser2 = ssh_cmd(SSH_IP_SGX_ENDORSER_2, "pkill endorser_host")
    endorser3 = ssh_cmd(SSH_IP_SGX_ENDORSER_3, "pkill endorser_host")

    print(endorser1)
    os.system(endorser1)
    print(endorser2)
    os.system(endorser2)
    print(endorser3)
    os.system(endorser3)

def kill_backup_endorsers():
    endorser4 = ssh_cmd(SSH_IP_ENDORSER_4, "pkill endorser")
    endorser5 = ssh_cmd(SSH_IP_ENDORSER_5, "pkill endorser")
    endorser6 = ssh_cmd(SSH_IP_ENDORSER_6, "pkill endorser")

    print(endorser4)
    os.system(endorser4)
    print(endorser5)
    os.system(endorser5)
    print(endorser6)
    os.system(endorser6)

def kill_coordinator():
    coordinator = ssh_cmd(SSH_IP_COORDINATOR, "pkill coordinator")

    print(coordinator)
    os.system(coordinator)


def kill_endpoints():
    endpoint1 = ssh_cmd(SSH_IP_ENDPOINT_1, "pkill endpoint_rest")
    print(endpoint1)
    os.system(endpoint1)

    if HAS_LB:
        endpoint2 = ssh_cmd(SSH_IP_ENDPOINT_2, "pkill endpoint_rest")

        print(endpoint2)
        os.system(endpoint2)

def setup(store, sgx):
    if sgx:
        setup_sgx_endorsers()
        setup_coordinator_sgx(store)
    else:
        setup_main_endorsers()
        setup_coordinator(store)

    setup_endpoints()

def teardown(sgx):
    kill_endpoints()
    kill_coordinator()
    if sgx:
        kill_sgx_endorsers()
    else:
        kill_endorsers()

def ssh_cmd(ip, cmd):
    if LOCAL_RUN:
        return cmd.replace('\'', '')
    else:
        return "ssh -o StrictHostKeyChecking=no -i " + SSH_KEY_PATH + " " + SSH_USER + "@" + ip + " " + cmd

def setup_output_folder(ip, out_folder):
    # Create output folder in case it doesn't exist
    folder_cmd = ssh_cmd(ip, "\'mkdir -p " + out_folder + "\'")

    print(folder_cmd)
    os.system(folder_cmd)

def collect_results(ip):
    if LOCAL_RUN:
        return ""
    else:
        cmd = "scp -r -i " + SSH_KEY_PATH + " " + SSH_USER + "@" + ip + ":" + OUTPUT_FOLDER + " ./"
        print(cmd)
        os.system(cmd)
