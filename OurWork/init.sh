#! /bin/bash
SSH_AUTH_SOCK= ssh -v -F /dev/null -i <path/to/privkey> -oProxyCommand="ssh tunnel@login.dos.cit.tum.de -i <path/to/privkey> -W %h:%p" <yourusername>@vislor.dos.cit.tum.de

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

nix-shell -p protobuf

nix-shell -p gnumake

nix-shell -p pkg-config openssl
