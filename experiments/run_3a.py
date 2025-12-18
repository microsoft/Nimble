import os
import subprocess
import logging
from datetime import datetime
from setup_nodes import *
from config import *  # Assuming your configuration is correctly set up


timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "fig-3a-" + dt_string
NUM_ITERATIONS = 1
LOAD = [50000]  #[5000, 10000, 15000, 20000, 25000, 50000, 55000] # requests/sec


# Setup logging
def setup_logging(log_folder):
    # Create log folder if it doesn't exist
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)
    
    log_file = os.path.join(log_folder, "experiment.log")
    
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

def run_3a(time, op, out_folder):
    # Setup logging for the experiment
    setup_logging(out_folder)
    log_dir = os.path.dirname("./logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Run client (wrk2)
    for i in LOAD:
        cmd = "\'" + WRK2_PATH + "/wrk2 -t120 -c120 -d" + time + " -R" + str(i)
        cmd += " --latency http://" + LISTEN_IP_LOAD_BALANCER + ":" + PORT_LOAD_BALANCER
        cmd += " -s " + NIMBLE_PATH + "/experiments/" + op + ".lua"
        cmd += " -- " + str(i) + "req"
        cmd += " > " + out_folder + op + "-" + str(i) + ".log\'"
        
        logging.info(f"Executing command: {cmd}")

        cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

        print(cmd)
        
        # Use subprocess to execute the command and capture output
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode != 0:
            logging.error(f"Command failed with return code: {result.returncode}")
            logging.error(f"Standard Output: {result.stdout.decode()}")
            logging.error(f"Standard Error: {result.stderr.decode()}")
        else:
            logging.info(f"Command executed successfully. Output captured in: {out_folder}{op}-{i}.log")



# Main experiment loop
out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)


for i in range(NUM_ITERATIONS):
    teardown(False)
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

teardown(False)
print(f"{SSH_IP_CLIENT=}")
collect_results(SSH_IP_CLIENT)

