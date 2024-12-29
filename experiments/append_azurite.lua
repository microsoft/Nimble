local current_folder = debug.getinfo(1, "S").source:sub(2):match("(.*[/\\])")
package.path = current_folder .. "/?.lua;" .. package.path

local base64url = require("base64url")
local socket = require("socket")
local json = require("json")
local uuid = require("uuidgen")
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
-- experiment (this ensures that experiment for append with
-- a given load is in a different namespace as an append 
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


-- Each thread gets its own context, so all threads have these variable initialized
-- and updated independently
ledger_id = 0
num_ledgers = 500
method = "POST"
endpoint_addr = "/counters/"
counters = {}
headers = {}
headers["Content-Type"] = "application/json"

local azurite_account_name = "devstoreaccount1"
local azurite_account_key = "Eby8vdM02xNOz0n8sFAK9yF7JpvUwFtx+Yw/aF5AnkdeQn7k+2HfFd9qkhGVWZXdt4UtvO2qD7KM="

-- Modified request function to use Azurite storage endpoints
request = function()
  local handle = base64url.encode(fromhex(sha.sha256(tid.."counter"..ledger_id)))
  local addr = "http://127.0.0.1:10000/" .. azurite_account_name .. "/counters/" .. handle  -- Azurite Blob endpoint

  if counters[ledger_id] == nil then
    counters[ledger_id] = 0
  end

  counters[ledger_id] = counters[ledger_id] + 1
  local counter = counters[ledger_id]
  ledger_id = (ledger_id + 1) % num_ledgers

  local content = {
    Tag = base64url.encode(fromhex(sha.sha256(tid.."counter"..counter))),
    ExpectedCounter = counter,
  }
  local body = json.encode(content)

  -- Add headers for Azurite authentication (this is simplified for Azurite)
  headers["x-ms-date"] = socket.gettime()  -- Example header, Azurite might require the current time
  headers["x-ms-version"] = "2020-04-08"   -- Example version, check Azurite docs for the exact version

  -- Send the request to Azurite
  return wrk.format(method, addr, headers, body)
end

