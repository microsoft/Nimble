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

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
