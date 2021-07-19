# Docker Image for Nimble

# Build container to compile Nimble
FROM rustlang/rust:nightly as build
MAINTAINER ["Sudheesh Singanamalla", "Srinath Setty"]
COPY Nimble /Nimble
WORKDIR /Nimble
CMD echo "[Nimble] Building Nimble Endorser"
RUN cargo build --release --bin endorser
CMD echo "[Nimble] Building Nimble Coordinator"
RUN cargo build --release --bin coordinator
CMD echo "[Nimble] Building Nimble Client"
RUN cargo build --release --bin client
CMD echo "[Nimble] Build Complete"

