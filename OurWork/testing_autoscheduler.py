import subprocess
import time
import os
import signal

# Start two terminal processes in the background with arguments
endorser1_args = ['/home/jan/uni/ws24/comp-sys/Nimble/target/release/endorser', '-p', '9090']
endorser2_args = ['/home/jan/uni/ws24/comp-sys/Nimble/target/release/endorser', '-p', '9091']
coordinator_args = ['/home/jan/uni/ws24/comp-sys/Nimble/target/release/coordinator', '-e', 'http://localhost:9090,http://localhost:9091']

print("Starting first endorser")
endorser1 = subprocess.Popen(endorser1_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print("Starting second endorser")
endorser2 = subprocess.Popen(endorser2_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Give some time for the processes to start
time.sleep(2)

# Start another process in the background and forward its output
print("Starting coordinator")
coordinator = subprocess.Popen(coordinator_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# Give some time for the process to run
time.sleep(30)

# Kill one of the first two processes
print("Killing first endorser")
os.kill(endorser1.pid, signal.SIGTERM)

# Give some time for the process to run
time.sleep(30)

# Forward the output of coordinator
for line in coordinator.stdout:
    print(line.decode(), end='')
