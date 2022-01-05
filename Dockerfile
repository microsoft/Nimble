# Docker Image for NimbleLedger

# Build container to compile Nimble
FROM rustlang/rust:nightly as build

# Create a new shell project with necessary manifests, cache build dependencies
RUN USER=root cargo new --bin NimbleLedger
WORKDIR /NimbleLedger
RUN USER=root cargo new --bin bench
RUN USER=root cargo new --bin client
RUN USER=root cargo new --bin coordinator
RUN USER=root cargo new --bin endorser
RUN USER=root cargo new --lib ledger
RUN USER=root cargo new --lib verifier
COPY ./Cargo.toml ./Cargo.toml
COPY ./bench/Cargo.toml ./bench/Cargo.toml
COPY ./client/Cargo.toml ./client/Cargo.toml
COPY ./coordinator/Cargo.toml ./coordinator/Cargo.toml
COPY ./endorser/Cargo.toml ./endorser/Cargo.toml
COPY ./ledger ./ledger
COPY ./verifier ./verifier
CMD echo "[Nimble] Building Nimble Dependencies"
RUN cargo build --release
RUN rm bench/src/*.rs
RUN rm client/src/*.rs
RUN rm coordinator/src/*.rs
RUN rm endorser/src/*.rs
RUN rm ledger/src/*.rs
RUN rm verifier/src/*.rs

# Now copy the actual source code
COPY ./bench ./bench
COPY ./client ./client
COPY ./coordinator ./coordinator
COPY ./endorser ./endorser
COPY ./ledger ./ledger
COPY ./proto ./proto
COPY ./verifier ./verifier
CMD echo "[Nimble] Building Nimble"
RUN cargo build --release
CMD echo "[Nimble] Build Complete"

FROM rustlang/rust:nightly
MAINTAINER ["Sudheesh Singanamalla", "Srinath Setty"]
COPY --from=build /NimbleLedger/target/release/bench .
COPY --from=build /NimbleLedger/target/release/client .
COPY --from=build /NimbleLedger/target/release/coordinator .
COPY --from=build /NimbleLedger/target/release/endorser .
CMD ls -al

