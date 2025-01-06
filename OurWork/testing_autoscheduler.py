import subprocess

# Define the commands to run in parallel
commands = [
    "/home/kilian/target/release/endorser -p 9090",
    "/home/kilian/target/release/endorser -p 9091",
    '/home/kilian/target/release/coordinator -e "http://localhost:9090,http://localhost:9091"'
]

# Start the processes
processes = [subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for command in commands]

# Print the output of each process
for process in processes:
    stdout, stderr = process.communicate()
    print(stdout.decode())
    if stderr:
        print(stderr.decode())