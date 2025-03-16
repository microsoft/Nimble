import os
import subprocess
import time
import random

import logging

from config import *
from setup_nodes import *
from datetime import datetime

RED = "\033[31;1m"  # Red and Bold for failure
GREEN = "\033[32;1m"  # Green and Bold for success
RESET = "\033[0m"  # Reset to default

timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "fig-3b-" + dt_string
NUM_ITERATIONS = 1

# Our table implementation can support much higher throughput for reads than create or append
CREATE_APPEND_LOAD = [50000]  # [500, 1000, 1500, 2000, 2500] requests/second
READ_LOAD = [50000]  # CREATE_APPEND_LOAD + [10000, 15000, 25000, 50000, 55000]


# Setup logging
def setup_logging(log_folder):
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    log_file = os.path.join(log_folder, "experiment.log")

    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )


def run_3b(time, op, out_folder):
    load = CREATE_APPEND_LOAD

    setup_logging(out_folder)
    log_dir = os.path.dirname("./logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    if op == "read":
        load = READ_LOAD

    # Run client (wrk2)
    for i in load:
        cmd = "\'" + WRK2_PATH + "/wrk2 -t120 -c120 -d" + time + " -R" + str(i)
        cmd += " --latency http://" + LISTEN_IP_LOAD_BALANCER + ":" + PORT_LOAD_BALANCER
        cmd += " -s " + NIMBLE_PATH + "/experiments/" + op + ".lua"
        cmd += " -- " + str(i) + "req"
        cmd += " > " + out_folder + op + "-" + str(i) + ".log\'"

        logging.info(f"Executing command: {cmd}")

        cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

        print(cmd)
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode != 0:
            logging.error(f"{RED}Command failed with return code: {result.returncode}{RESET}")
            logging.error(f"{RED}Standard Output: {result.stdout.decode()}{RESET}")
            logging.error(f"{RED}Standard Error: {result.stderr.decode()}{RESET}")
            print(f"{RED}An error happened with: {cmd} \nError output: {result.stderr.decode()}\n\n{RESET}")
        else:
            logging.info(f"{GREEN}Command executed successfully. Output captured in: {out_folder}{op}-{i}.log{RESET}")
            print(f"{GREEN}Command executed successfully. Output captured in: {out_folder}{op}-{i}.log{RESET}")


if os.environ.get('STORAGE_MASTER_KEY', '') == "" or os.environ.get('STORAGE_ACCOUNT_NAME', '') == "":
    print("Make sure to set the STORAGE_MASTER_KEY and STORAGE_ACCOUNT_NAME environment variables")
    exit(-1)

out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)

store = f" -s table -n nimble{random.randint(1, 100000000)} -a \"{os.environ['STORAGE_ACCOUNT_NAME']}\""
store += f" -k \"{os.environ['STORAGE_MASTER_KEY']}\""

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
