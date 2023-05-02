import os
import time
import random
from config import *
from setup_nodes import *
from datetime import datetime

timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "fig-3b-" + dt_string
NUM_ITERATIONS = 1

# Our table implementation can support much higher throughput for reads than create or append
CREATE_APPEND_LOAD = [2000] #[500, 1000, 1500, 2000, 2500]  # requests/second
READ_LOAD = [50000] # CREATE_APPEND_LOAD + [10000, 15000, 25000, 50000, 55000]

def run_3b(time, op, out_folder):
    load = CREATE_APPEND_LOAD

    if op == "read":
        load = READ_LOAD

    # Run client (wrk2)
    for i in load:
        cmd = "\'" + WRK2_PATH + "/wrk -t120 -c120 -d" + time + " -R" + str(i)
        cmd += " --latency http://" + LISTEN_IP_LOAD_BALANCER + ":" + PORT_LOAD_BALANCER
        cmd += " -s " + NIMBLE_PATH + "/experiments/" + op + ".lua"
        cmd += " -- " + str(i) + "req"
        cmd += " > " + out_folder + op + "-" + str(i) + ".log\'"

        cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

        print(cmd)
        os.system(cmd)

if os.environ.get('STORAGE_MASTER_KEY', '') == "" or os.environ.get('STORAGE_ACCOUNT_NAME', '') == "":
    print("Make sure to set the STORAGE_MASTER_KEY and STORAGE_ACCOUNT_NAME environment variables")
    exit(-1)

out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)

store = " -s table -n nimble" + str(random.randint(1,100000000)) + " -a \"" + os.environ['STORAGE_ACCOUNT_NAME'] + "\""
store += " -k \"" + os.environ['STORAGE_MASTER_KEY'] + "\""

for i in range(NUM_ITERATIONS):
    teardown(False)
    setup(store, False)

    # Creates the ledgers so that we can append to them
    operation = "create"
    duration = "90s"
    run_3b(duration, operation, out_folder)

    # Append to the ledgers
    operation = "append"
    duration = "30s"
    run_3b(duration, operation, out_folder)

    # Read from the ledgers
    operation = "read"
    duration = "30s"
    run_3b(duration, operation, out_folder)

teardown(False)
collect_results(SSH_IP_CLIENT)
