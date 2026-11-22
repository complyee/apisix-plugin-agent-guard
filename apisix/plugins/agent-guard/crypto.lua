-- One-way fingerprints and time helpers. The request body is hashed here, in
-- the gateway; only the hash is ever sent to Agent Control Room.
local core = require "apisix.core"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

local _M = {}

function _M.sha256_hex(text)
  local h = resty_sha256:new()
  h:update(text)
  return str.to_hex(h:final())
end

function _M.payload_hash(ctx)
  -- APISIX returns nil (no error) for an absent/empty body and reads bodies
  -- buffered to disk. Any error means the body cannot be bound: fail closed.
  -- Do not rely on client-controlled Content-Length to distinguish these.
  local body, err = core.request.get_body(nil, ctx)
  if err then return nil, "Unable to read request body for cryptographic binding." end
  if body ~= nil and type(body) ~= "string" then
    return nil, "Unable to read request body for cryptographic binding."
  end
  return _M.sha256_hex(body or "")  -- only this hash is sent, never the body
end

-- expiresAt is UTC ("2030-01-02T03:04:05Z"); returns epoch seconds or nil.
function _M.utc_epoch(iso)
  local y, mo, d, hh, mi, ss = tostring(iso or ""):match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
  if not y then return nil end
  return os.time({ year = y, month = mo, day = d, hour = hh, min = mi, sec = ss })
    - os.difftime(os.time(), os.time(os.date("!*t")))
end

return _M
