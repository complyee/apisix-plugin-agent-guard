-- Runs AFTER a plugin that has verified the grant JWT (this plugin has a lower
-- priority than APISIX authentication plugins). That plugin checks signature,
-- kid, alg EdDSA, iss https://agent-cr.com, aud and exp against the JWK Set.
-- This step checks the token is for THIS request — that plugin cannot.
-- Never trust the decoded claims unless that plugin ran first and verified
-- the signature.
local core = require "apisix.core"
local cjson = require "cjson.safe"
local b64 = require "ngx.base64"
local crypto = require "apisix.plugins.agent-guard.crypto"
local request = require "apisix.plugins.agent-guard.request"

local _M = {}

function _M.bind_grant_jwt(conf, ctx)
  local auth = core.request.header(ctx, "Authorization") or ""
  local token = auth:match("^Bearer%s+(.+)$")
  if not token then return false end
  local seg = token:match("^[^.]+%.([^.]+)%.[^.]+$")
  local claims = seg and cjson.decode(b64.decode_base64url(seg) or "")
  if type(claims) ~= "table" or type(claims.acr) ~= "table" then return false end

  local agent = request.resolve_agent(conf, ctx) or ""
  local action = request.resolve_action(conf, ctx) or ""
  if agent == "" or action == "" then return false end  -- unknown agent or unmapped route: refuse
  local hash = crypto.payload_hash(ctx)
  if not hash then return false end

  return claims.sub == agent
    and claims.acr.action == action
    and claims.acr.payloadHash == hash  -- APISIX's own body hash
end

return _M
