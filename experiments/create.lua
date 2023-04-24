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
-- experiment (this ensures that experiment for create counter with
-- a given load is in a different namespace as a create counter
-- with a different given load. As a result, we don't need to
-- delete all ledgers in the coordinator/endorsers since we would be creating
-- brand new ledgers on each experiment.
function init(args)
  if args[1] ~= nil then
    tid = args[1] .. tid
  end
end

local function fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Each thread gets its own context, so all threads have this variable initialized
-- at 0, and updated independently
ledger_id = 0

handles = {}

request = function()
    local hash = sha.sha256(tid.."counter"..ledger_id)
    local handle = base64url.encode(fromhex(hash))
    ledger_id = ledger_id + 1
    local endpoint_addr = "/counters/" .. handle
    local method = "PUT"
    local headers = {}

    local param = {
       Tag = base64url.encode(fromhex(sha.sha256(tid.."counter"..ledger_id..uuid()))),
    }

    local body = json.encode(param)
    headers["Content-Type"] = "application/json"
    return wrk.format(method, endpoint_addr, headers, body)
end
