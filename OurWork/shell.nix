# shell.nix
with import <nixpkgs> {};

mkShell {
  buildInputs = [
    protobuf
    gnumake
    pkg-config
    openssl
    screen
  ];
}
