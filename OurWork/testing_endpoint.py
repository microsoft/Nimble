import requests
import subprocess
import time
import logging
import os
import base64

# Set up logging
log_directory = "/Users/matheis/VSCProjects/Nimble/OurWork/testing_results"
os.makedirs(log_directory, exist_ok=True)
log_file = os.path.join(log_directory, f"endpoint_{time.strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Define the commands to be executed
commands = [
    "/Users/matheis/VSCProjects/Nimble/target/release/endorser -p9090",
    "/Users/matheis/VSCProjects/Nimble/target/release/endorser -p9091",
    "/Users/matheis/VSCProjects/Nimble/target/release/coordinator -ehttp://localhost:9090 -i1",
    '/Users/matheis/VSCProjects/Nimble/target/release/endpoint_rest'
]

# Execute the commands and capture their outputs
outputs = []
processes = []
for command in commands:
    print(f"Executing command: {command}")
    logging.info(f"Executing command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    processes.append(process)
    time.sleep(2)

time.sleep(4)

# Define the URIs for the requests
get_uris = [
    "http://localhost:8082/pingallendorsers",
    "http://localhost:8082/timeoutmap"
]
 # Define the data for the GET requests
put_uri = "http://localhost:8082/addendorsers"
put_data = {"endorsers": base64.b64encode("http://localhost:9091".encode())} # Define the data for the PUT request



# Send GET requests
for uri in get_uris:
    try:
        response = requests.get(uri)
        logging.info(f"GET {uri} - Status Code: {response.status_code}")
        logging.info(f"Response: {response.text}")
    except requests.RequestException as e:
        logging.error(f"GET {uri} - Request failed: {e}")
    time.sleep(1)

# Send PUT request
try:
    response = requests.put(put_uri, params=put_data)
    logging.info(f"PUT {put_uri} - Code: {response.status_code}")
    logging.info(f"Response: {response.text}")
except requests.RequestException as e:
    logging.error(f"PUT {put_uri} - Request failed: {e}")

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