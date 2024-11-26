LOCAL_RUN = True  # set to True if you want to run all nodes and experiments locally. Else set to False.
                  # If set to True, you can ignore all the IP addresses and SSH stuff below. They won't be used.
                  # You cannot run any of the Azure table experiments locally.

# Azure Storage Emulator Settings for Azurite
# Azurite default settings for local Azure emulator.
AZURITE_STORAGE_ACCOUNT_NAME = "user"   # Default Azurite storage account name
AZURITE_STORAGE_MASTER_KEY = "1234"  # Default Azurite master key

# Azurite Emulator Endpoints (by default Azurite runs locally on port 10000, 10001, and 10002 for blob, queue, and table)
AZURITE_BLOB_HOST = "127.0.0.1"  # Localhost for blob service
AZURITE_BLOB_PORT = "10000"  # Azurite default port for blob storage

AZURITE_QUEUE_HOST = "127.0.0.1"  # Localhost for queue service
AZURITE_QUEUE_PORT = "10001"  # Azurite default port for queue storage

AZURITE_TABLE_HOST = "127.0.0.1"  # Localhost for table service
AZURITE_TABLE_PORT = "10002"  # Azurite default port for table storage

# Azurite Emulator does not require an actual storage account or secret, so you can use these defaults
# These variables will be used if you're running tests or simulations that interact with Azure storage locally

SSH_IP_ENDORSER_1 = "127.0.0.1"
LISTEN_IP_ENDORSER_1 = "127.0.0.1"
PORT_ENDORSER_1 = "9091"

SSH_IP_ENDORSER_2 = "127.0.0.1"
LISTEN_IP_ENDORSER_2 = "127.0.0.1"
PORT_ENDORSER_2 = "9092"

SSH_IP_ENDORSER_3 = "127.0.0.1"
LISTEN_IP_ENDORSER_3 = "127.0.0.1"
PORT_ENDORSER_3 = "9093"

SSH_IP_COORDINATOR = "127.0.0.1"
LISTEN_IP_COORDINATOR = "127.0.0.1"
PORT_COORDINATOR = "8080"
PORT_COORDINATOR_CTRL = "8090" # control pane

SSH_IP_ENDPOINT_1 = "127.0.0.1"
LISTEN_IP_ENDPOINT_1 = "127.0.0.1"
PORT_ENDPOINT_1 = "8082"

SSH_IP_ENDPOINT_2 = "127.0.0.1"
LISTEN_IP_ENDPOINT_2 = "127.0.0.1"
PORT_ENDPOINT_2 = "8082"

LISTEN_IP_LOAD_BALANCER = "127.0.0.1"  # if no load balancer is available just use one endpoint (ENDPOINT_1)
                                        # and set the LISTEN IP of that endpoint here

PORT_LOAD_BALANCER = "8082"  # if no load balancer is available just use one endpoint (ENDPOINT_1)
                             # and set the PORT of that endpoint here

SSH_IP_CLIENT = "127.0.0.1"  # IP of the machine that will be running our workload generator.

# Backup Endorsers for reconfiguration experiment
SSH_IP_ENDORSER_4 = "127.0.0.1"
LISTEN_IP_ENDORSER_4 = "127.0.0.1"
PORT_ENDORSER_4 = "9094"

SSH_IP_ENDORSER_5 = "127.0.0.1"
LISTEN_IP_ENDORSER_5 = "127.0.0.1"
PORT_ENDORSER_5 = "9095"

SSH_IP_ENDORSER_6 = "127.0.0.1"
LISTEN_IP_ENDORSER_6 = "127.0.0.1"
PORT_ENDORSER_6 = "9096"

# SGX experiment on SGX machines
SSH_IP_SGX_ENDORSER_1 = "127.0.0.1"
LISTEN_IP_SGX_ENDORSER_1 = "127.0.0.1"
PORT_SGX_ENDORSER_1 = "9091"

SSH_IP_SGX_ENDORSER_2 = "127.0.0.1"
LISTEN_IP_SGX_ENDORSER_2 = "127.0.0.1"
PORT_SGX_ENDORSER_2 = "9092"

SSH_IP_SGX_ENDORSER_3 = "127.0.0.1"
LISTEN_IP_SGX_ENDORSER_3 = "127.0.0.1"
PORT_SGX_ENDORSER_3 = "9093"


# Paths to Nimble executables and wrk2 for workload generation
NIMBLE_PATH = "/root/Nimble"
NIMBLE_BIN_PATH = NIMBLE_PATH + "/target/release"
WRK2_PATH = "/nix/store/kfh6s74hilmpr0kjwy163n7lri1fk7i4-wrk2-4.0.0-e0109df/bin"
OUTPUT_FOLDER = NIMBLE_PATH + "/experiments/results"

# SSH User and Key Path for connecting to remote machines
SSH_USER = "hviva"
SSH_KEY_PATH = "/home/hviva/.ssh/id_ed25500"

# Azurite doesn't need actual Azure credentials, so you can use the following default:
STORAGE_ACCOUNT_NAME = AZURITE_STORAGE_ACCOUNT_NAME  # Use Azurite storage account name
STORAGE_MASTER_KEY = AZURITE_STORAGE_MASTER_KEY  # Use Azurite storage master key
