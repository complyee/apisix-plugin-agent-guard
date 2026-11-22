-- Agent Control Room enforcement point for Apache APISIX.
-- Modes (conf.mode):
--   decide (default): ask Agent Control Room before APISIX forwards.
--   verify:           check a grant the request already carries, offline (Ed25519).
--   verify_jwt:       bind a grant JWT to this request, after a plugin
--                     verified its signature against the published key set.
local core = require "apisix.core"
local cjson = require "cjson.safe"
local client = require "apisix.plugins.agent-guard.client"
local crypto = require "apisix.plugins.agent-guard.crypto"
local request = require "apisix.plugins.agent-guard.request"

local plugin_name = "agent-guard"

local schema = {
  type = "object",
  properties = {
    -- https://<workspace>.agent-cr.com/api/public/v1/gateway
    gateway_url = { type = "string", minLength = 1 },
    -- A secret reference such as $env://ACR_API_KEY or $secret://vault/acr/api_key, never the key itself
    api_key = { type = "string", minLength = 1 },
    agent_header = { type = "string", default = "X-Agent-Id" },
    agent_source = { type = "string", default = "header", enum = { "header", "consumer", "jwt_claim" } },
    agent_claim = { type = "string", default = "sub" },
    action_header = { type = "string", default = "X-Acr-Action" },
    allow_action_header = { type = "boolean", default = false },
    -- "POST /payments/transfers": "payments.transfer.create"
    action_map = { type = "object", additionalProperties = { type = "string" }, default = {} },
    timeout_ms = { type = "integer", minimum = 1, default = 3000 },
    -- decide | verify | verify_jwt (see the header comment)
    mode = { type = "string", default = "decide", enum = { "decide", "verify", "verify_jwt" } },
    -- How long the published verification keys are cached, in seconds
    keys_ttl = { type = "integer", minimum = 1, default = 3600 },
  },
  required = { "gateway_url", "api_key" },
  encrypt_fields = { "api_key" },
}

local _M = {
  version = 0.1,
  -- Runs after APISIX authentication plugins (key-auth 2500, jwt-auth 2510,
  -- openid-connect 2599), so a Consumer or verified token is already known.
  priority = 2400,
  name = plugin_name,
  schema = schema,
}

function _M.check_schema(conf)
  return core.schema.check(schema, conf)
end

local function decide_access(conf, ctx)
  local action = request.resolve_action(conf, ctx)
  if not action then
    return 403, { message = "No governed action mapped for this route." }
  end
  local agent = request.resolve_agent(conf, ctx)
  if not agent then
    return 403, { message = "Missing or invalid agent identity." }
  end
  local hash, hash_err = crypto.payload_hash(ctx)
  if not hash then
    return 400, { message = hash_err }
  end
  local params = {
    agent = agent,
    action = action,
    resourceRef = ctx.var.request_uri,  -- path with query string
    payloadHash = hash,
  }
  local idem = "apisix-" .. ngx.md5(cjson.encode(params))
  local answer, err = client.acr_call(conf, "decideAction", params, idem)
  if not answer then
    core.log.error("ACR unreachable: ", err)
    return 503, { message = "Not forwarded: no decision." }  -- fail closed
  end
  local d = answer.decision or {}
  if d.effect == "grant" then
    ctx.acr_decision = { decisionId = d.decisionId, payloadHash = hash }  -- the hash APISIX computed
    core.request.set_header(ctx, "X-Acr-Decision-Id", d.decisionId)
    return  -- forward to the upstream service
  end
  if d.effect == "pending" then
    -- Held for a person. Return once; the caller polls getApprovalStatus. No loop here.
    return 202, { message = "Held for review.", approvalId = d.approvalId or answer.approvalId }
  end
  return 403, { message = "Refused.", rationale = d.rationale }
end

function _M.access(conf, ctx)
  if conf.mode == "verify" then
    -- Required lazily: decide mode never needs lua-resty-openssl.
    local verify = require "apisix.plugins.agent-guard.verify"
    if not verify.verify_grant(conf, ctx) then
      return 403, { message = "Grant check failed." }
    end
    return
  end
  if conf.mode == "verify_jwt" then
    local jwt_bind = require "apisix.plugins.agent-guard.jwt_bind"
    if not jwt_bind.bind_grant_jwt(conf, ctx) then
      return 403, { message = "Grant token is not bound to this request." }
    end
    return
  end
  return decide_access(conf, ctx)
end

local function report(premature, conf, decision, outcome, detail_code)
  if premature then
    core.log.warn("reportExecutionOutcome dropped on worker shutdown for decision ", decision.decisionId)
    return
  end
  local _, err = client.acr_call(conf, "reportExecutionOutcome", {
    decisionId = decision.decisionId,
    payloadHash = decision.payloadHash,
    outcome = outcome,
    detailCode = detail_code,
  }, "outcome-" .. decision.decisionId)
  if err then
    core.log.warn("reportExecutionOutcome failed for decision ", decision.decisionId, ": ", err)
  end  -- evidence only; no retries and no change to the response
end

function _M.log(conf, ctx)
  -- Offline verification never schedules outcome reports.
  if conf.mode == "verify" or conf.mode == "verify_jwt" then return end
  local decision = ctx.acr_decision
  if not decision then return end
  local status = tonumber(ngx.status) or 0
  local outcome = "aborted"
  if status >= 200 and status < 300 then
    outcome = "executed"
  elseif status >= 500 then
    outcome = "downstream_error"
  end
  local detail_code = status == 202 and "http_202_accepted" or "http_" .. tostring(status)
  local scheduled, err = ngx.timer.at(0, report, conf, decision, outcome, detail_code)
  if not scheduled then
    core.log.error("reportExecutionOutcome scheduling failed for decision ", decision.decisionId, ": ", err)
  end
end

return _M
