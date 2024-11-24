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

-- Function to convert a hexadecimal string to a byte string
local function fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Variables for the counter and endpoint
handle = base64url.encode(fromhex(sha.sha256(uuid())))
endpoint_addr = "/counters/"
params = nil
counter = 0

-- Content to be sent in the PUT request
content = {
  Tag = base64url.encode(fromhex(sha.sha256(uuid()))),
}
body = json.encode(content)

-- Local Azurite or Local Server Configuration
local azurite_account_name = "devstoreaccount1"
local azurite_account_key = "Eby8vdM02xNOz0n8sFAK9yF7JpvUwFtx+Yw/aF5AnkdeQn7k+2HfFd9qkhGVWZXdt4UtvO2qD7KM="
local local_host = "127.0.0.1"
local local_port = "10000"  -- Azurite default Blob storage port (or your local server's port)

-- Main request function
request = function()
  local addr = "http://" .. local_host .. ":" .. local_port .. "/" .. azurite_account_name .. endpoint_addr .. handle
  local req = nil
  if params then
    -- This branch reads the counter by providing a nonce
    local method = "GET"
    local nonce_encoded = base64url.encode(string.sub(sha.sha256("0"..counter), 1, 16))
    addr = addr .. params .. nonce_encoded
    counter = counter + 1
    req = wrk.format(method, addr)
  else
    -- This branch sets up the counter (PUT request)
    local method = "PUT"
    local headers = {}
    headers["Content-Type"] = "application/json"
    req = wrk.format(method, addr, headers, body)
  end
  return req
end

-- Response handler
response = function(status, headers, body)
  -- If this is the first time we are setting up the counter, we should get a 201 response.
  -- It means the counter has been created successfully and we are now ready to read it.
  -- We switch to the read operation by setting params to non-nil.
  if not params and (status == 200 or status == 201) then
    params = "?nonce="  -- Modify based on your local server's read parameter.
  end
end
