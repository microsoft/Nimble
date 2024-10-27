#! /bin/bash

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -- -y 

nix-shell -p protobuf

nix-shell -p gnumake

nix-shell -p pkg-config openssl
