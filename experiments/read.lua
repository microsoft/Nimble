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

local function fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

handle = base64url.encode(fromhex(sha.sha256(uuid())))
endpoint_addr = "/counters/"
params = nil
counter = 0

content = {
  Tag = base64url.encode(fromhex(sha.sha256(uuid()))),
}

body = json.encode(content)

request = function()
  local addr = endpoint_addr .. handle
  local req = nil
  if params then
    -- This branch reads the counter by providing a nonce (that's just the first 16 bytes of the hash of a counter)
    local method = "GET"
    local nonce_encoded = base64url.encode(string.sub(sha.sha256("0"..counter), 1, 16))
    addr = addr .. params .. nonce_encoded
    counter = counter + 1
    req = wrk.format(method, addr)
  else
    -- This branch sets up the counter. The above branch performs the read counter operation
    local method = "PUT"
    local headers = {}
    headers["Content-Type"] = "application/json"
    req = wrk.format(method, addr, headers, body)
  end
  return req
end

response = function(status, headers, body)
  -- If this is the first time we are setting up the counter, then we should get a 201.
  -- It means that we just created the counter and we are ready to read it.
  -- We switch to read by just setting params to non-nil.
  if not params and (status == 200 or status == 201) then
    params = "?nonce="
  end
end
