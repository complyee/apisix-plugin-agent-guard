-- Fetch the public grant-verification keys once per worker and cache them.
-- getGrantVerificationKey needs the policy.read scope.
local client = require "apisix.plugins.agent-guard.client"

local _M = {}
local cache = {}

local function load_keys(conf)
  local answer, err = client.acr_call(conf, "getGrantVerificationKey", {}, nil)
  if not answer or not answer.verificationKeys then return nil, err end
  local by_id = {}
  for _, k in ipairs(answer.verificationKeys.keys or {}) do
    by_id[k.keyId] = k.publicKey  -- base64url, raw 32-byte Ed25519 key
  end
  return { workspaceId = answer.verificationKeys.workspaceId, keys = by_id }
end

local function cached(conf, refresh)
  local key = "acr-keys:" .. conf.gateway_url
  local entry = cache[key]
  if refresh or not entry or ngx.now() >= entry.exp then
    local ks = load_keys(conf)
    if not ks then cache[key] = nil return nil end  -- never cache a failure
    entry = { value = ks, exp = ngx.now() + (conf.keys_ttl or 3600) }
    cache[key] = entry
  end
  return entry.value
end

function _M.get_keys(conf, key_id)
  local ks = cached(conf, false)
  if ks and key_id and not ks.keys[key_id] then
    ks = cached(conf, true)  -- unknown keyId: a rotation; refetch once
  end
  return ks
end

function _M._reset() cache = {} end  -- tests only

return _M
