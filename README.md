# NimbleLedger: An append-only ledger with minimal TCB

# Dependencies

Install make, gcc, protobuf-copiler, perl, libssl-dev, pkg-config. In Ubuntu, you can type:

```text
sudo apt install make gcc libssl-dev pkg-config perl protobuf-compiler
```

## Building and running tests

Install [`rustup`](https://rustup.rs/)

Clone the repository:

```text
git clone https://github.com/MSRSSP/NimbleLedger
```

To run tests:

```text
cargo test
```

To build:

```text
cargo build --release
```

## Docker Deployment

> Note: The project requires a minimum docker-compose version v1.29.2. Please follow instructions [here](https://docs.docker.com/compose/install/#install-compose) to install/update `docker` and `docker-compose`.
> 
> :warning: The default installation of `docker` (`docker-ce`) needs `sudo` permissions to execute the commands. To avoid
> using elevated permissions, please follow the post-install steps to manage docker as a non-root user [here](https://docs.docker.com/engine/install/linux-postinstall/).
> This allows the `docker` commands listed in this file to be executed without `sudo`. Please use `sudo` otherwise with the commands.

The `Nimble` project contains three components:

1. Nimble `endorser`
2. Nimble `coordinator`
3. Nimble `client`

The image containing the three binaries above can be constructed by running the following command:

```shell
$ docker build . -t nimble:dev_latest
```

We use `docker-compose` to set up a network containing 5 endorsers, a client, and a coordinator.

Running the command below will use docker to create a network called `basic`
with `five` endorsers with hostnames `endorser-{1|2|3|4|5}` which run the endorser service and expose the
ports `9090-9094`. A `coordinator` service starts on `8080` and connects to the five endorsers, obtaining necessary
keys. The services from the containers are bound to the host machine on the same ports, essentially creating a
development environment with a 5 node endorser cluster.

It also starts the `client` which is an interactive docker shell provided to the user for running Nimble client. This can be done
by `cargo run --bin client` after starting a shell
into the `client` docker instance.

```shell
$ docker-compose up
```

The `docker-compose up` command will automatically `build` and create the necessary docker images and run the services.
The services will spin up in sequence with the `endorsers-{1-5}`. Once the endorsers are `ready`, the
`coordinator` service starts followed by the creation of the client.

The services can be selectively spun up by passing the service name to the
`docker-compose up/run` command. eg.

```shell
$ docker-compose run client
```

The above command enables an interactive shell with the client on the same network as the endorsers and coordinator.

To execute the client, and run the standard test suite execute the following in the container's interactive shell:

```shell
# ./client http://coordinator:8080
```

Note:
> The coordinator takes arguments for endorser services `-e` delimited by `,`.
> The default connection for the 5 node endorser network needed for the coordinator
> is passed as an argument in the service configuration of the docker-compose file.
