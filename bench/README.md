# Bench

`bench` is an E2E Benchmarking utility for the `NimbleLedger` APIs.

## Build

```shell
$ cargo build --bin bench --release
```

## Current support:

1. `--num_clients`: Number of concurrent clients to be used in the benchmark.
2. `-r, --requests`: Number of requests to `methods` by each client.
3. `-m, --methods`: A number/set of numbers between 1-4 corresponding to the APIs to benchmark.
   1. `1 = NewLedger`: Benchmark Creates `-r * -c` ledgers and uses `-a = 16` byte default app byte sizes.
   2. `2 = Append`: Benchmark Creates 1 ledger entry and appends `-r * -c` messages.
   3. `3 = ReadByLatest`: :no_entry_sign: Unimplemented
   4. `4 = ReadByIndex` : :no_entry_sign: Unimplemented
4. `-a, --app-or-block-byte-size`: Number of bytes to generate to use in benchmarks, defaults to 16 bytes.
5. `-w, --write-file-out`: Writes Benchmark CSV log file out with the following schema:

```log
clients,total_requests,reqs_per_client,request_type,avg_service_latency,service_throughput,verification_throughput
```

## Examples:

Running `NewLedger` and `Append` benchmarks:

The command below uses defaults `-a = 16` with a coordinator `--coordinator http://[::1]:8080`.
Please bring up the `docker` environment or run atleast 1 coordinator and 1 endorser to perform the benchmark tests. 

```shell
$ target/release/bench -m 1 2

  *  [START] Initializing 10 Clients
  *  [ END ] Initializing 10 Clients 82.116µs
Starting the NewLedger benchmark with 10 clients each sending 1000 requests...
  *  [START] Firing 10000 NewLedger Requests
    * Completed Firing all NewLedger Requests 49.409391ms
    * Received: 1000 responses 524.17117ms
    * Received: 2000 responses 636.34044ms
    * Received: 3000 responses 1.023313773s
    * Received: 4000 responses 1.023758799s
    * Received: 5000 responses 1.024270792s
    * Received: 6000 responses 1.02465221s
    * Received: 7000 responses 1.025090454s
    * Received: 8000 responses 1.025523282s
    * Received: 9000 responses 1.025962949s
    * Received: 10000 responses 1.026372535s
  *  [ END ] Firing 10000 NewLedger Requests 1.02638473s
  *  [START] Verify NewLedger Responses
    * Sequential 700.98831ms
    * Parallel 165.55578ms
  *  [ END ] Verify NewLedger Responses 165.578303ms
Starting the Append benchmark with 10 clients each sending 1000 requests...
  *  [START] Firing 10000 Append Requests
    * Completed Firing all Append Requests 112.731589ms
    * Received: 1000 responses 206.97802ms
    * Received: 2000 responses 669.03125ms
    * Received: 3000 responses 669.521289ms
    * Received: 4000 responses 804.094063ms
    * Received: 5000 responses 804.533167ms
    * Received: 6000 responses 804.937231ms
    * Received: 7000 responses 805.355983ms
    * Received: 8000 responses 805.768059ms
    * Received: 9000 responses 807.009079ms
    * Received: 10000 responses 807.40985ms
  *  [ END ] Firing 10000 Append Requests 807.417251ms
  *  [START] Verify Append Responses
    * Sequential 636.459662ms
    * Parallel 155.061809ms
  *  [ END ] Verify Append Responses 155.083637ms
```

### Help / Manual
```shell
$ target/release/bench -h

LedgerBench 0.1.0
E2E Benchmarking utility for NimbleLedger APIs

USAGE:
    bench [OPTIONS]

OPTIONS:
    -a, --app-or-block-byte-size <APP_OR_BLOCK_BYTE_SIZE>
            The number of random bytes to be generated as application bytes payload (NewLedger
            AppBytes/Append Block Size) [default: 16]

    -n, --num_clients <CLIENTS>
            The number of concurrent clients to use in the benchmark [default: 10]

    -h, --help
            Print help information

    -m, --methods <METHODS>...
            The API to benchmark, Integers in the range 1-4 corresponding to:
             1. NewLedger
             2. Append
             3. ReadLatest
             4. ReadByIndex
             [default: 1 2] [possible values: 1, 2, 3, 4]

    -r, --requests <REQUESTS>
            The number of requests per client to use in the benchmark [default: 1000]

    -V, --version
            Print version information

    -w, --write-file-out <WRITE_FILE_OUT>
            Write the result of the benchmark to a file [default: /dev/null]
```
