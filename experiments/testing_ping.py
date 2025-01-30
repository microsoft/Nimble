import os
import subprocess
import logging
from datetime import datetime
from setup_nodes import *
from config import *

# /home/kilian/Nimble/target/release/endorser

# Setup logging
def setup_logging(log_folder):
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)
    
    log_file = os.path.join(log_folder, "testing_ping.log")
    
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

def run_ping_test(time, out_folder):
    setup_logging(out_folder)
    log_dir = os.path.dirname("./logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    LOAD = [50]
    for i in LOAD:
        cmd = f"'{WRK2_PATH}/wrk2 -t120 -c120 -d{time} -R{i} --latency http://{LISTEN_IP_LOAD_BALANCER}:{PORT_LOAD_BALANCER}"
        cmd += f" -s {NIMBLE_PATH}/experiments/ping.lua -- {i}req > {out_folder}ping-{i}.log'"

        logging.info(f"Executing command: {cmd}")

        cmd = ssh_cmd(SSH_IP_CLIENT, cmd)

        print(cmd)
        
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode != 0:
            logging.error(f"Command failed with return code: {result.returncode}")
            logging.error(f"Standard Output: {result.stdout.decode()}")
            logging.error(f"Standard Error: {result.stderr.decode()}")
        else:
            logging.info(f"Command executed successfully. Output captured in: {out_folder}ping-{i}.log")

# Main test loop
timestamp = time.time()
dt_object = datetime.fromtimestamp(timestamp)
dt_string = dt_object.strftime("date-%Y-%m-%d-time-%H-%M-%S")

EXP_NAME = "ping-test-" + dt_string
out_folder = OUTPUT_FOLDER + "/" + EXP_NAME + "/"
setup_output_folder(SSH_IP_CLIENT, out_folder)

teardown(False)
setup("", False)

operation = "ping"
duration = "30s"
run_ping_test(duration, out_folder)

teardown(False)
print(f"{SSH_IP_CLIENT=}")
collect_results(SSH_IP_CLIENT)