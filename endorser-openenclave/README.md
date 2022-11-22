# Nimble: Rollback-protection for cloud storage

## Setup instructions
* Install the [OpenEnclave SDK](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs)

* Install cmake and g++
     ```
    sudo apt install cmake g++
     ```

* Run the following commands, after cloning this repository:
    ```
    cd endorser-openenclave
    mkdir build
    cmake .
    make run
    ```

* Troubleshoot:
You may encounter issues with some dependencies in deps not existing. For some reason the compiler is not compiling them. You might need to go to each of
the problematic depdency folders (inside the deps folder) and manually type make.

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
