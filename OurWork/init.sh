#! /bin/bash
SSH_AUTH_SOCK= ssh -v -F /dev/null -i <path/to/privkey> -oProxyCommand="ssh tunnel@login.dos.cit.tum.de -i <path/to/privkey> -W %h:%p" <yourusername>@vislor.dos.cit.tum.de

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

#if .nix file does not work
#nix-shell -p protobuf gnumake pkg-config openssl

#if .nix file works. jackson needs sudo to run this command
nix-shell
