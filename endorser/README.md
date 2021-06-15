# Nimble: Rollback-protection for cloud storage

## Setup instructions
* Install the [OpenEnclave SDK](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs)

* Run the following commands, after cloning this repository:
    ```
    cd endorser
    mkdir build
    cmake ..
    make run
    ```

* There are no tests in the code, but a successful run should print:
    ```
    Host: enter main
    Host: create enclave for image:/home/srinath/endorser/endorser/build/enclave/enclave.signed
    Host: Identity of the endorser is: 0x....
    Host: Asking the endorser to endorse a block
    Host: terminate the enclave
    Host: Endorser completed successfully.
    [100%] Built target run
    ```