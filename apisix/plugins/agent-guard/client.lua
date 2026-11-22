-- One helper for the gateway: every operation goes through the same address.
local http = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

-- Standalone YAML does not resolve references for custom plugin fields.
-- Resolve at call time for decisions, key fetches and outcome timers alike.
local function resolve_api_key(key)
  if type(key) ~= "string" or key == "" then return nil end
  if key:sub(1, 7):lower() == "$env://" then
    local name = key:sub(8)
    if not name:match("^[%a_][%w_]*$") then return nil end
    key = os.getenv(name)
  elseif key:sub(1, 10) == "$secret://" then
    local loaded, secret = pcall(require, "apisix.secret")
    if not loaded then return nil end
    local fetched, value = pcall(secret.fetch_by_uri, key)
    if not fetched then return nil end
    key = value
  end
  if type(key) ~= "string" or key == "" or key:sub(1, 1) == "$"
      or key:sub(1, 9) == "{vault://" or key:find("[%c]") then
    return nil
  end
  return key
end

function _M.acr_call(conf, operation, parameters, idem_key)
  local api_key = resolve_api_key(conf.api_key)
  if not api_key then return nil, "ACR API key unavailable" end
  local client = http.new()
  client:set_timeout(conf.timeout_ms or 3000)
  local res, err = client:request_uri(conf.gateway_url, {
    method = "POST",
    body = cjson.encode({ operation = operation, parameters = parameters }),
    headers = {
      ["content-type"] = "application/json",
      ["x-api-key"] = api_key,
      ["idempotency-key"] = idem_key,
    },
  })
  if not res then return nil, err end
  -- Never log response bodies: they may contain sensitive upstream diagnostics.
  if type(res.status) ~= "number" or res.status < 200 or res.status >= 300 then
    return nil, "HTTP " .. tostring(res.status or "unknown")
  end
  local answer = cjson.decode(res.body)
  if type(answer) ~= "table" then return nil, "Invalid JSON response" end
  if answer.error then return nil, "ACR application error" end
  return answer
end

return _M
