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
    nodejs
    python3
#    azurite
    util-linux  #a working version of uuid   called: uuidgen
    pkgs.python311Packages.pip
    pkgs.python311Packages.setuptools
    pkgs.python311Packages.pydoop
  ];

  # shellHook ensures we install LuaSocket and set the correct paths
  shellHook = ''
    # Configure luarocks to install packages locally by default
    luarocks config local_by_default true

    # Install LuaSocket via luarocks in the local user directory
    luarocks install luasocket --local
    luarocks install uuid --local

    # Set LUA_PATH and LUA_CPATH to ensure Lua can find modules installed by luarocks
    export LUA_PATH="$HOME/.luarocks/share/lua/5.1/?.lua;$LUA_PATH"
    export LUA_CPATH="$HOME/.luarocks/lib/lua/5.1/?.so;$LUA_CPATH"
  '';
}
