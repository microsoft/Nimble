# Nimble: Rollback Protection for Confidential Cloud Services 

Nimble is a service that helps applications running in trusted execution environments (TEEs) detect 
rollback attacks (i.e., detect whether a data item retrieved from persistent storage is the latest version).

Nimble can also be used as a generic tamper-proof fault-tolerant append-only ledger.

Nimble will appear at [OSDI 2023](https://www.usenix.org/conference/osdi23).


To reproduce the results in our paper, please follow the instructions below
to build Nimble and then see [experiments/](experiments/).

# Dependencies

Install make, gcc, protobuf-copiler, perl, libssl-dev, pkg-config. In Ubuntu, you can type:

```text
sudo apt install make gcc libssl-dev pkg-config perl protobuf-compiler
```

## Building and running tests

Install [`rustup`](https://rustup.rs/)

Clone the repository:

```text
git clone https://github.com/MSRSSP/Nimble
```

To run tests:

```text
cargo test
```

To build:

```text
cargo build --release
```

Optional: to build the Nimble endorser that runs in Intel SGX with open enclave, please folow the instructions [here](endorser-openenclave/).


Running a toy local setup with 2 endorsers, coordinator, REST endpoint, and sample REST client.
Run each on a different terminal.


  ```bash
    ./target/release/endorser -p 9090
    ./target/release/endorser -p 9091 
    ./target/release/coordinator -e "http://localhost:9090,http://localhost:9091" 
    ./target/release/endpoint_rest
    ./target/release/light_client_rest
  ```


## Details of Nimble's Rust binaries

Below are the different Nimble binaries, and some of the basic
options. Each binary has many other options. You can see them by
running the binary and with the `--help` flag.


# Endorser

```
  ./target/release/endorser
    -t HOSTNAME
    -p PORT 
```

# Coordinator

```
  ./target/release/coordinator
    -h HOSTNAME
    -p PORT
    -e "http://HOST_ENDORSER_1:PORT,http://HOST_ENDORSER_2:PORT,http://HOST_ENDORSER_3:PORT" 
    -s "memory" # use "table" to use Azure table instead and provide the following
    -a AZURE_STORAGE_ACCOUNT_NAME
    -k AZURE_STORAGE_MASTER_KEY
```

Below is a helper tool to interact with the coordinator. After you
kill some endorsers, you can add new ones (reconfiguration) by running.

```
  ./target/release/coordinator_ctrl 
    -c "http://HOST_COORDINATOR:PORT" 
    -a "http://HOST_NEW_ENDORSER_1:PORT;http://HOST_NEW_ENDORSER_2:PORT"
```

# REST Endpoint

```
  ./target/release/endpoint_rest
    -t HOST
    -p PORT
    -c "http://HOST_COORDINATOR:PORT"
```


# REST Client 

```
  ./target/release/endpoint_rest
    -e "http://HOST_ENDPOINT:PORT"
```
