#! /bin/bash
SSH_AUTH_SOCK= ssh -v -F /dev/null -i /Users/matheis/.ssh/id_ed25519 -oProxyCommand="ssh tunnel@login.dos.cit.tum.de -i /Users/matheis/.ssh/id_ed25519 -W %h:%p" kilian@vislor.dos.cit.tum.de
SSH_AUTH_SOCK= ssh -v -F /dev/null -i ~/.ssh/Syslab/id_ed25500 -oProxyCommand="ssh tunnel@login.dos.cit.tum.de -i ~/.ssh/Syslab/id_ed25500 -W %h:%p" janhe@vislor.dos.cit.tum.de

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

#if .nix file does not work
#nix-shell -p protobuf gnumake pkg-config openssl

#if .nix file works. jackson needs sudo to run this command
nix-shell
