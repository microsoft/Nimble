clone https://github.com/TUM-DSE/CVM_eval
add pyhon3 to  https://github.com/TUM-DSE/CVM_eval/blob/main/nix/guest-config.nix
run sudo su
run the AMD SEV SNP commands from https://github.com/TUM-DSE/CVM_eval/blob/main/docs/development.md
run nix-shell
lua: nix-env -iA nixos.lua51Packages.lua
luarocks: nix-env -iA nixos.lua51Packages.luarocks
lua-bitop: nix-env -iA nixos.lua51Packages.luabitop
wrk2: nix-env -iA nixos.wrk2

to set lua path run: eval "$(luarocks path --bin)" 

lua-json: luarocks install lua-json
luasocket: luarocks install luasocket
uuid: luarocks install uuid

Open experiments/config.py:
NIMBLE_PATH = "/root/Nimble"
WRK2_PATH = "/nix/store/kfh6s74hilmpr0kjwy163n7lri1fk7i4-wrk2-4.0.0-e0109df/bin" #change to your wrk2 path



run cargo test
run cargo build --release
python3 run_<version>.py
