## Compiling Nimble

Follow the instructions in the root directory to build Nimble on all of the machines that you'll be using.

## Building the workload generator

In the machine that will be running the client, install [wrk2](https://github.com/giltene/wrk2), and
then install the following lua libraries:

```
  sudo apt install lua5.1 luarocks lua-bitop
  luarocks install lua-json
  luarocks install luasocket
  luarocks install uuid
```

## Configuring the scripts

We have scripts to generate the results of figure 3(a), figure 3(b), figure 3(c), and figure 4.
Each of these scripts (e.g., `run_3a.py`) allows you to specify the load you want. 
We have set them up to a single setting for your testing, but you can enable the other values if you want.


## Reproducing the results of Figure 3

Edit the contents of `config.py`. In particular, you'll need to set the IP address of all of the machines that we'll
use as well as the PATHs.

It is assumed that you have already compiled Nimble in each of those machines and they all have the same path to Nimble.

To reproduce the results of Figure 3(a), simply run 

```
  python3 run_3a.py
```

The script should SSH into each machine, set up the appropriate entity (endorser, coordinator, endpoint), then SSH into
the client machine and launch the workload. Once the script is done, the results will be in the `results` folder in
the machine which launched the `run_3a.py` script. The results folder will be copied to the current path.

In Figure 3 we plot the median and 95-th percentile latency. To get this value, look at the entry in the logs where the middle column says 0.5 and 0.95.
To get the throughput value, look at the value at the end of the log that says: Requests/sec.


To reproduce the results of Figure 3(b), you first need to set the environment variables `STORAGE_MASTER_KEY` and
`STORAGE_ACOUNT_NAME`. These are the values provided by Azure table when you look them up in the Azure portal.

Then run:
```
  python3 run_3b.py
```


To reproduce the results of Figure 3(c), you need to set up the SGX endorser machines. In addition to compiling Nimble
on those machines, you also need to compile the SGX endorser. Follow the instructions in [../endorser-openenclave/](../endorser-openenclave/).


Then run:
```
  python3 run_3c.py
```


## Reproducing the results of Figure 4

Edit the contents of `config.py` to include the IPs of the backup endorsers that will serve as the new endorsers.

To reproduce the results of Figure 4, simply run

```
  python3 run_4.py
```

The script should SSH into each machine, then SSH into the client machine to create the ledgers. Then it will trigger a reconfiguration.

Once the script is done, the results will be in the `results` folder in the machine which launched the 
`run_4.py` script. The results folder will be copied to the current path.

The results include: (1) reconfiguration time; (2) bandwidth. You should see both values.


## Reproducing the results of Figures 5 and 6

Figures 5 and 6 require running our modified version of the Hadoop Distributed File System (HDFS) on top of Nimble.
The steps are as follows. First, launch Nimble with in-memory store or tables. We provide two scripts to do this:

```
  python3 start_nimble_memory.py
```

or

```
  python3 start_nimble_table.py
```

Once Nimble is running, you can then follow the instructions on how to setup Nimble-HDFS in this repository: [https://github.com/mitthu/hadoop-nimble](https://github.com/mitthu/hadoop-nimble).


To restart Nimble, you can just run the above scripts again (they typically shut things down and then restart). 
To shutdown Nimble without restarting, you can run:

```
  python3 shutdown_nimble.py
```
