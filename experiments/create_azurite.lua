local current_folder = debug.getinfo(1, "S").source:sub(2):match("(.*[/\\])")
package.path = current_folder .. "/?.lua;" .. package.path

local base64url = require("base64url")
local socket = require("socket")
local json = require("json")
local uuid = require("uuid")
local sha = require("sha2")

time = math.floor(socket.gettime() * 1000)
math.randomseed(time)
uuid.randomseed(time)

local thread_count = 1

-- This function runs after all threads have been created
-- but before any of them runs
-- Its goal is to give each thread a unique thread id (tid)
function setup(thread)
  thread:set("tid", ""..thread_count)
  thread_count = thread_count + 1
end

-- This function initializes each thread. It expects the name of the
-- experiment (this ensures that the experiment for create counter with
-- a given load is in a different namespace as a create counter
-- with a different given load). As a result, we don't need to
-- delete all ledgers in the coordinator/endorsers since we would be creating
-- brand new ledgers on each experiment.
function init(args)
  if args[1] ~= nil then
    tid = args[1] .. tid
  end
end

-- Function to convert hex string to bytes
local function fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Variables for each thread context
ledger_id = 0
handles = {}

-- Local Azurite endpoint configurations (example local Azurite Blob Storage)
local azurite_account_name = "devstoreaccount1"
local azurite_account_key = "Eby8vdM02xNOz0n8sFAK9yF7JpvUwFtx+Yw/aF5AnkdeQn7k+2HfFd9qkhGVWZXdt4UtvO2qD7KM="
local local_host = "127.0.0.1"
local local_port = "10000"  -- Azurite default Blob storage port

-- Function to simulate a PUT request to Azurite or a local endpoint
request = function()
    -- Calculate the handle for the ledger
    local hash = sha.sha256(tid.."counter"..ledger_id)
    local handle = base64url.encode(fromhex(hash))

    ledger_id = ledger_id + 1
    local endpoint_addr = "http://" .. local_host .. ":" .. local_port .. "/" .. azurite_account_name .. "/counters/" .. handle
    local method = "PUT"
    local headers = {}

    -- Tag value for the counter
    local param = {
       Tag = base64url.encode(fromhex(sha.sha256(tid.."counter"..ledger_id..uuid()))),
    }

    -- Request body
    local body = json.encode(param)

    -- Headers
    headers["Content-Type"] = "application/json"

    -- Return the formatted HTTP request
    return wrk.format(method, endpoint_addr, headers, body)
end
