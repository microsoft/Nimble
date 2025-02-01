import subprocess
import time
import logging
import os

# Set up logging
current_directory = os.getcwd()
print(current_directory)
log_directory = os.path.join(current_directory, "OurWork", "testing_results")
os.makedirs(log_directory, exist_ok=True)
log_file = os.path.join(log_directory, f"testing_autoscheduler_{time.strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Start two terminal processes in the background with arguments
endorser1_args = [os.path.join(current_directory, 'target/release/endorser'), '-p', '9090']
endorser2_args = [os.path.join(current_directory, 'target/release/endorser'), '-p', '9091']
coordinator_args = [os.path.join(current_directory, 'target/release/coordinator'), '-e', 'http://localhost:9090,http://localhost:9091', '-i1']

logging.info("Starting first endorser")
endorser1 = subprocess.Popen(endorser1_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
logging.info("Starting second endorser")
endorser2 = subprocess.Popen(endorser2_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)



# Give some time for the processes to start
time.sleep(2)

# Start another process in the background and forward its output
logging.info("Starting coordinator")
coordinator = subprocess.Popen(coordinator_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Give some time for the process to run
time.sleep(10)

# Kill one of the first two processes
logging.info("Killing first endorser")
endorser1.kill()

# Give some time for the process to run
time.sleep(10)

# Capture the output of coordinator


# Kill all processes
endorser2.kill()
coordinator.kill()

# Capture the output of all processes
outputs = []
stdout, stderr = endorser1.communicate()
outputs.append(stdout.decode())
outputs.append(stderr.decode())
stdout, stderr = endorser2.communicate()
outputs.append(stdout.decode())
outputs.append(stderr.decode())
stdout, stderr = coordinator.communicate()
outputs.append(stdout.decode())
outputs.append(stderr.decode())

# Log the outputs
logging.info("STDOUT of first endorser:")
logging.info(outputs[0])
logging.info("STDERR of first endorser:")
logging.info(outputs[1])
logging.info("STDOUT of second endorser:")
logging.info(outputs[2])
logging.info("STDERR of second endorser:")
logging.info(outputs[3])
logging.info("STDOUT of coordinator:")
logging.info(outputs[4])
logging.info("STDERR of coordinator:")
logging.info(outputs[5])