import os
import time
import random
from config import *
from setup_nodes import *
from datetime import datetime

timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "fig_3a-" + dt_string
NUM_ITERATIONS = 1
LOAD = [50000]  #[5000, 10000, 15000, 20000, 25000, 50000, 55000] # requests/sec

def run_3a(time, op, out_folder):
    # Run client (wrk2)
    for i in LOAD:
        cmd = "\'" + WRK2_PATH + "/wrk -t120 -c120 -d" + time + " -R" + str(i)
        cmd += " --latency http://" + LISTEN_IP_LOAD_BALANCER + ":" + PORT_LOAD_BALANCER
        cmd += " -s " + NIMBLE_PATH + "/experiments/" + op + ".lua"
        cmd += " -- " + str(i) + "req"
        cmd += " > " + out_folder + op + "-" + str(i) + ".log\'"

        cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

        print(cmd)
        os.system(cmd)



out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)

for i in range(NUM_ITERATIONS):
    teardown()
    setup("", False)

    # Creates the ledgers so that we can append to them
    operation = "create"
    duration = "90s"
    run_3a(duration, operation, out_folder)

    # Append to the ledgers
    operation = "append"
    duration = "30s"
    run_3a(duration, operation, out_folder)

    # Read from the ledgers
    operation = "read"
    duration = "30s"
    run_3a(duration, operation, out_folder)

teardown()
collect_results(SSH_IP_CLIENT)
