-- Which governed action is this request, and which agent is asking?
local core = require "apisix.core"

local _M = {}

function _M.resolve_action(conf, ctx)
  local key = tostring(ctx.var.request_method) .. " " .. tostring(ctx.var.uri)
  local mapped = (conf.action_map or {})[key]
  if mapped and mapped ~= "" then return mapped end
  if conf.allow_action_header then
    local from_header = core.request.header(ctx, conf.action_header or "X-Acr-Action")
    if type(from_header) == "string" and from_header ~= "" then return from_header end
  end
  return nil
end

function _M.resolve_agent(conf, ctx)
  local source = conf.agent_source or "header"
  local agent
  if source == "consumer" then
    -- Set by an APISIX authentication plugin (key-auth, jwt-auth, basic-auth ...).
    local consumer = ctx.consumer
    agent = consumer and consumer.username
  elseif source == "jwt_claim" then
    -- Explicit server-side adapter contract, NOT a decoded bearer token.
    -- Only a preceding authentication plugin may populate this slot after
    -- verifying signature, allowed algorithm, issuer, audience and expiry.
    local identity = ctx.acr_verified_identity
    local claims = type(identity) == "table" and identity.claims
    agent = type(claims) == "table" and claims[conf.agent_claim or "sub"]
  elseif source == "header" then
    agent = core.request.header(ctx, conf.agent_header or "X-Agent-Id")
  end
  if type(agent) ~= "string" or agent == "" or agent:find("|", 1, true) then return nil end
  return agent
end

return _M
