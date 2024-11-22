import os
import time
import random
from config import *
from setup_nodes import *
from datetime import datetime

timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "fig-4-" + dt_string
NUM_ITERATIONS = 1
NUM_LEDGERS = [2000000] #, 200000, 500000, 1000000]

def reconfigure(out_folder, tcpdump_folder, num):

    tcp_file_name = start_tcp_dump(num, tcpdump_folder)

    # perform reconfiguration
    cmd = "\'" + NIMBLE_BIN_PATH + "/coordinator_ctrl"
    cmd += " -c \"http://" + LISTEN_IP_COORDINATOR + ":" + PORT_COORDINATOR_CTRL + "\""
    cmd += " -a \"http://" + LISTEN_IP_ENDORSER_4 + ":" + PORT_ENDORSER_4
    cmd += ";http://" + LISTEN_IP_ENDORSER_5 + ":" + PORT_ENDORSER_5
    cmd += ";http://" + LISTEN_IP_ENDORSER_6 + ":" + PORT_ENDORSER_6
    cmd += "\" >> " + out_folder + "/reconf-time-" + str(num)  + "ledgers.log\'"
    cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

    print(cmd)
    os.system(cmd)

    complete_tcp_dump(out_folder, num, tcp_file_name)


def start_tcp_dump(num, tcpdump_folder):
    # Stop tcpdump in case it is still running
    # cmd = "\"sudo pkill tcpdump\""
    cmd = "sudo pkill tcpdump"
    cmd = ssh_cmd(SSH_IP_COORDINATOR, cmd)

    print(cmd)
    os.system(cmd)

    endorser_ports = [PORT_ENDORSER_1, PORT_ENDORSER_2, PORT_ENDORSER_3, PORT_ENDORSER_4, PORT_ENDORSER_5, PORT_ENDORSER_6]
    endorser_ports = list(set(endorser_ports)) # get unique ports

    # Start tcpdump to collect network traffic to and from all endorsers
    tcp_file_name = tcpdump_folder + "/" + str(num) + ".pcap"
    # cmd = "screen -d -m \"sudo tcpdump"
    cmd = "screen -d -m sudo tcpdump"
    for port in endorser_ports:
        cmd += " tcp dst port " + port + " or tcp src port " + port + " or "
    cmd = cmd.rsplit(" or ", 1)[0]
    # cmd += " -w " + tcp_file_name + "\""
    cmd += " -w " + tcp_file_name + ""
    cmd = ssh_cmd(SSH_IP_COORDINATOR, cmd)

    print(cmd)
    os.system(cmd)
    return tcp_file_name


def complete_tcp_dump(out_folder, num, file_name):
    # cmd = "\"sudo pkill tcpdump\""
    cmd = "sudo pkill tcpdump"
    cmd = ssh_cmd(SSH_IP_COORDINATOR, cmd)

    print(cmd)
    os.system(cmd)

    print("Waiting 30 seconds for pcap file to be written")
    time.sleep(30) # enough time 

    # Parse pcap file and output statistics to log
    # cmd = "\"bash " + NIMBLE_PATH + "/experiments/tcpdump-stats.sh " + file_name + " > "
    cmd = "bash "+ NIMBLE_PATH + "/experiments/tcpdump-stats.sh " + file_name + " > "
    # cmd += out_folder + "/reconf-bw-" + str(num) + "ledgers.log\""
    cmd += out_folder + "/reconf-bw-" + str(num) + "ledgers.log"
    cmd = ssh_cmd(SSH_IP_COORDINATOR, cmd)

    print(cmd)
    os.system(cmd)


def create_ledgers(num):
    # wkr2 doesn't have a way to specify exact number of requests. Instead, we create a load
    # and run it for as long as needed.
    rps = 5000 # create 5000 ledgers per second
    duration = str(int(num/rps)) + "s"

    # Run client (wrk2) to set up the ledgers
    cmd = "\'" + WRK2_PATH + "/wrk2 -t60 -c60 -d" + duration + " -R" + str(rps)
    cmd += " --latency http://" + LISTEN_IP_LOAD_BALANCER + ":" + PORT_LOAD_BALANCER
    cmd += " -s " + NIMBLE_PATH + "/experiments/create.lua"
    cmd += " -- " + str(rps) + "req > /dev/null\'"

    cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

    print(cmd)
    os.system(cmd)



out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
tcpdump_folder = NIMBLE_PATH + "/experiments/tcpdump_traces/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)
setup_output_folder(SSH_IP_COORDINATOR, out_folder)
setup_output_folder(SSH_IP_COORDINATOR, tcpdump_folder)

for num in NUM_LEDGERS:
    print("Starting experiment for " + str(num) + " ledgers")
    teardown(False)
    kill_backup_endorsers()

    setup("", False)
    setup_backup_endorsers()

    create_ledgers(num)
    reconfigure(out_folder, tcpdump_folder, num)

teardown(False)
kill_backup_endorsers()
collect_results(SSH_IP_CLIENT)
collect_results(SSH_IP_COORDINATOR)
