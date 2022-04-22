# NimbleEndorser

## Prerequisites

### Add Intel package server to the apt server list

1. `curl -sSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -`
2. `sudo apt-add-repository "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main"`

### Install packages

`sudo apt-get install build-essential cmake nasm libssl-dev lib-sgxdcap-ql lib-sgxdcap-ql-dev`

### Clone the crypto submodule in the NimbleLedger folder

`git submodule update --init --recursive`

## Build NimbleEndorser

1. `mkdir build`
2. `cd build`
3. `cmake ..`
4. `make`
5. If grpc build fails, do `cd build/_deps/grpc-build; make`
6. `cd ../enclave`
7. `make`

## Test NimbleEndorser

1. In NimbleEndorser, run `build/host/endorser_host enclave/endorser.so private.pem` to start the endorser.
2. In NimbleLedger, run `cargo run --bin coordinator -- 8080 -e "http://localhost:9096"` to start the coordinator.
3. In NimbleLedger, run `cargo run --bin client` to start the client.
