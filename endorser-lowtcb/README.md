# NimbleEndorser

## Prerequisites

### SGX Driver

1. Disable the inbox driver by adding `GRUB_CMDLINE_LINUX_DEFAULT="nosgx"` to `/etc/default/grub` (and run `update-grub`).
2. Follow the instructions [here](https://github.com/0xabu/linux-sgx-driver) to build the SGX driver from Andrew Baumann.
3. Load the driver by running `sudo insmod isgx.ko` and unload it by running `sudo rmmod isgx`.
4. `/dev` may be mounted with noexec. To enable exec, run `sudo mount -o remount,exec /dev`.
5. On Azure ACC VM running Ubuntu 20.04 LTS Gen2, run `sudo rmmod intel_sgx` to unload the existing driver.

### NimbleLedger

Clone and build [NimbleLedger](https://github.com/MSRSSP/NimbleLedger).

## Build NimbleEndorser

1. `mkdir build`
2. `cd build`
3. `cmake ..`
4. `make`
5. `cd ../enclave`
6. `make`

## Test NimbleEndorser

1. In NimbleEndorser, run `build/host/endorser_host enclave/endorser.so private.pem` to start the endorser.
2. In NimbleLedger, run `cargo run --bin coordinator -- 8080 -e "http://localhost:9096"` to start the coordinator.
3. In NimbleLedger, run `cargo run --bin client` to start the client.
