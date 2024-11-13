# shell.nix
with import <nixpkgs> {};

mkShell {
  buildInputs = [
    gcc
    protobuf
    gnumake
    pkg-config
    openssl
    screen
    cmake
  ];
}
