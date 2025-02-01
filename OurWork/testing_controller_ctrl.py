import subprocess
import time
import logging
import os

# Set up logging
current_directory = os.getcwd()
log_directory = os.path.join(current_directory, "/testing_results")
os.makedirs(log_directory, exist_ok=True)
log_file = os.path.join(log_directory, f"controller_ctrl_{time.strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Define the commands to be executed

# Define the commands to be executed
commands = [
    "/Users/matheis/VSCProjects/Nimble/target/release/endorser -p9090",
    "/Users/matheis/VSCProjects/Nimble/target/release/endorser -p9091",
    "/Users/matheis/VSCProjects/Nimble/target/release/coordinator -ehttp://localhost:9090 -i1",
    '/Users/matheis/VSCProjects/Nimble/target/release/coordinator_ctrl -a "http://localhost:9091"',
    '/Users/matheis/VSCProjects/Nimble/target/release/coordinator_ctrl --gettimeoutmap',
    '/Users/matheis/VSCProjects/Nimble/target/release/coordinator_ctrl --pingallendorsers'
]

# Execute the commands and capture their outputs
outputs = []
processes = []
for command in commands:
    print(f"Executing command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    processes.append(process)
    time.sleep(4)

for process in processes:
    process.kill()
    stdout, stderr = process.communicate()
    outputs.append(stdout.decode())
    outputs.append(stderr.decode())
# Log the outputs sequentially
for i, command in enumerate(commands):
    logging.info(f"Output of command {command}:")
    logging.info("stdout:")
    logging.info(outputs[2*i])
    logging.info("stderr:")
    logging.info(outputs[2*i + 1])