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
    lua51Packages.lua
    lua51Packages.luabitop
    lua51Packages.luarocks
    rustc
    cargo
    wrk2
#    llvm_13
#    llvmPackages_13.libcxxClang
#    clang13Stdenv
  ];
}
