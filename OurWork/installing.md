# Notes for Installation

TODO: Move all nix-env commands to shell.nix
Install:
Open nix-shell in OurWork/ (ignore env-var warning)
cargo: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
gcc-wrapper: ?
lua: nix-env -iA nixos.lua51Packages.lua
luarocks: nix-env -iA nixos.lua51Packages.luarocks
lua-bitop: nix-env -iA nixos.lua51Packages.lua-bitop
wrk2: nix-enc -iA nixos.wrk2

lua-json: luarocks install --local lua-json
luasocket: luarocks install --local luasocket
uuid: luarocks install --local uuid

to set lua path run: eval "$(luarocks path --bin)" (if you want also paste this command in your .bashrc)

Open experiments/config.py:
LOCAL_RUN = True
NIMBLE_PATH = Path to your Nimble install, for me /home/$user/Nimble
WRK2_PATH = /home/$user/.nix-profile/bin

run cargo test
run cargo build --release

Work, hopefully
