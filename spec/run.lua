-- Dependency-free test suite for apisix-plugin-agent-guard.
-- Mocks the APISIX and OpenResty APIs; runs on plain LuaJIT:  luajit spec/run.lua
package.path = "./?.lua;" .. package.path

----------------------------------------------------------------------
-- Pure-Lua SHA-256 (LuaJIT bit library) — stands in for resty.sha256
----------------------------------------------------------------------
local bit = require "bit"
local band, bxor, bnot = bit.band, bit.bxor, bit.bnot
local rshift, ror = bit.rshift, bit.ror

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256_bin(msg)
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
  local bits = len * 8
  msg = msg .. "\0\0\0\0"  -- high 32 bits of the 64-bit length (always 0 here)
  for i = 3, 0, -1 do
    msg = msg .. string.char(band(rshift(bits, i * 8), 0xff))
  end
  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local w = {}
  for chunk = 1, #msg, 64 do
    for i = 0, 15 do
      local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
      w[i] = a * 0x1000000 + b * 0x10000 + c * 0x100 + d
    end
    for i = 16, 63 do
      local s0 = bxor(ror(w[i - 15], 7), ror(w[i - 15], 18), rshift(w[i - 15], 3))
      local s1 = bxor(ror(w[i - 2], 17), ror(w[i - 2], 19), rshift(w[i - 2], 10))
      w[i] = band(w[i - 16] + s0 + w[i - 7] + s1, 0xffffffff)
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for i = 0, 63 do
      local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = band(hh + S1 + ch + K[i + 1] + w[i], 0xffffffff)
      local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = band(S0 + maj, 0xffffffff)
      hh, g, f, e, d, c, b, a = g, f, e, band(d + t1, 0xffffffff), c, b, a, band(t1 + t2, 0xffffffff)
    end
    h[1] = band(h[1] + a, 0xffffffff); h[2] = band(h[2] + b, 0xffffffff)
    h[3] = band(h[3] + c, 0xffffffff); h[4] = band(h[4] + d, 0xffffffff)
    h[5] = band(h[5] + e, 0xffffffff); h[6] = band(h[6] + f, 0xffffffff)
    h[7] = band(h[7] + g, 0xffffffff); h[8] = band(h[8] + hh, 0xffffffff)
  end
  local out = {}
  for i = 1, 8 do
    out[#out + 1] = string.char(
      band(rshift(h[i], 24), 0xff), band(rshift(h[i], 16), 0xff),
      band(rshift(h[i], 8), 0xff), band(h[i], 0xff))
  end
  return table.concat(out)
end

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function sha256_hex(s) return to_hex(sha256_bin(s)) end

----------------------------------------------------------------------
-- Minimal JSON encode/decode — stands in for cjson.safe
----------------------------------------------------------------------
local function json_encode(v)
  local t = type(v)
  if t == "string" then return '"' .. v:gsub('["\\]', "\\%0") .. '"'
  elseif t == "number" then return tostring(v)
  elseif t == "boolean" then return tostring(v)
  elseif t == "table" then
    if #v > 0 then  -- array-like
      local parts = {}
      for i = 1, #v do parts[i] = json_encode(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local parts = {}
    for k, val in pairs(v) do parts[#parts + 1] = json_encode(tostring(k)) .. ":" .. json_encode(val) end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

local function json_decode(s)
  local pos = 1
  local function skip_ws()
    local _, e = s:find("^[ \n\r\t]*", pos)
    pos = (e or 0) + 1
  end
  local parse_value
  local function parse_string()
    local i = pos + 1
    local buf = {}
    while true do
      local c = s:sub(i, i)
      if c == "" then error("json: unterminated string") end
      if c == '"' then pos = i + 1 return table.concat(buf) end
      if c == "\\" then
        local n = s:sub(i + 1, i + 1)
        local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
        if n == "u" then
          buf[#buf + 1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) % 256)
          i = i + 6
        else
          buf[#buf + 1] = map[n] or n
          i = i + 2
        end
      else
        buf[#buf + 1] = c
        i = i + 1
      end
    end
  end
  local function parse_object()
    pos = pos + 1
    local obj = {}
    skip_ws()
    if s:sub(pos, pos) == "}" then pos = pos + 1 return obj end
    while true do
      skip_ws()
      local k = parse_string()
      skip_ws()
      pos = pos + 1 -- ":"
      obj[k] = parse_value()
      skip_ws()
      local c = s:sub(pos, pos)
      pos = pos + 1
      if c == "}" then return obj end
    end
  end
  local function parse_array()
    pos = pos + 1
    local arr = {}
    skip_ws()
    if s:sub(pos, pos) == "]" then pos = pos + 1 return arr end
    while true do
      arr[#arr + 1] = parse_value()
      skip_ws()
      local c = s:sub(pos, pos)
      pos = pos + 1
      if c == "]" then return arr end
    end
  end
  function parse_value()
    skip_ws()
    local c = s:sub(pos, pos)
    if c == '"' then return parse_string()
    elseif c == "{" then return parse_object()
    elseif c == "[" then return parse_array()
    elseif c == "t" then pos = pos + 4 return true
    elseif c == "f" then pos = pos + 5 return false
    elseif c == "n" then pos = pos + 4 return nil
    else
      local num = s:match("^%-?%d+%.?%d*[eE]?[+-]?%d*", pos)
      pos = pos + #num
      return tonumber(num)
    end
  end
  return parse_value()
end

----------------------------------------------------------------------
-- base64url decode — stands in for ngx.base64
----------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local function b64url_decode(data)
  return (data:gsub(".", function(x)
    if x == "=" then return "" end
    local r, f = "", (B64:find(x, 1, true) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end

local function b64url_encode(data)
  return ((data:gsub(".", function(x)
    local r, b = "", x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return B64:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#data % 3 + 1]):gsub("%=", "")
end

----------------------------------------------------------------------
-- Mocks for resty.* / ngx / kong
----------------------------------------------------------------------
local state -- per-test mutable state, reset by setup()

package.preload["resty.sha256"] = function()
  return { new = function()
    return {
      update = function(self, s) self._buf = (self._buf or "") .. s end,
      final = function(self) return sha256_bin(self._buf or "") end,
    }
  end }
end
package.preload["resty.string"] = function() return { to_hex = to_hex } end
package.preload["cjson.safe"] = function()
  return { encode = json_encode, decode = function(body)
    local success, value = pcall(json_decode, body)
    if not success then return nil, "Invalid JSON" end
    return value
  end }
end
package.preload["resty.http"] = function()
  return { new = function()
    return {
      set_timeout = function() end,
      request_uri = function(_, _, options)
        state.http_calls = (state.http_calls or 0) + 1
        state.last_http_request = options
        if state.http_err then return nil, state.http_err end
        return { status = state.http_status or 200, body = state.http_raw_body or json_encode(state.http_body or {}) }
      end,
    }
  end }
end
package.preload["resty.openssl.pkey"] = function()
  return { new = function()
    return { verify = function(_, sig, message)
      state.verify_message = message
      state.verify_sig = sig
      return state.verify_result
    end }
  end }
end
package.preload["ngx.base64"] = function()
  return { decode_base64url = b64url_decode }
end

package.preload["apisix.core"] = function()
  return {
    request = {
      header = function(_, name) return state.headers[name] end,
      get_body = function()
        if state.body_err then return nil, state.body_err end
        if state.body == "" then return nil end  -- APISIX: empty body is nil, no error
        return state.body
      end,
      set_header = function(_, name, value) state.upstream_headers[name] = value end,
    },
    log = {
      error = function(...) state.logs.err[#state.logs.err + 1] = table.concat({ ... }) end,
      warn = function(...) state.logs.warn[#state.logs.warn + 1] = table.concat({ ... }) end,
    },
    schema = { check = function() return true end },
  }
end

local ctx
local function setup(opts)
  opts = opts or {}
  state = {
    headers = opts.headers or {},
    body = opts.body or "",
    body_err = opts.body_err,
    status = opts.status or 200,
    http_body = opts.http_body,
    http_err = opts.http_err,
    http_status = opts.http_status,
    http_raw_body = opts.http_raw_body,
    timer_err = opts.timer_err,
    logs = { err = {}, warn = {} },
    verify_result = opts.verify_result,
    upstream_headers = {},
    timers = {},
    now = opts.now or os.time(),
  }
  local path = opts.path or "/payments/transfers"
  ctx = {
    var = { request_method = opts.method or "POST", uri = path, request_uri = opts.request_uri or path },
    consumer = opts.consumer,
    acr_verified_identity = opts.identity,
  }
  _G.ngx = {
    md5 = sha256_hex,
    time = function() return state.now end,
    now = function() return state.now end,
    status = state.status,
    timer = { at = function(_, fn, ...)
      if state.timer_err then return nil, state.timer_err end
      state.timers[#state.timers + 1] = { fn = fn, args = { ... } }
      return true
    end },
  }
  package.loaded["apisix.plugins.agent-guard.keys"] = nil
  package.loaded["apisix.plugins.agent-guard.verify"] = nil
end

local passed, failed = 0, 0
local function ok(cond, name)
  if cond then passed = passed + 1 print("ok   - " .. name)
  else failed = failed + 1 print("FAIL - " .. name) end
end

local plugin = require "apisix.plugins.agent-guard"

local function base_conf(over)
  local conf = {
    gateway_url = "https://ws.agent-cr.com/api/public/v1/gateway",
    api_key = "resolved-secret",
    agent_header = "X-Agent-Id", agent_source = "header", agent_claim = "sub",
    allow_action_header = false, action_header = "X-Acr-Action",
    action_map = { ["POST /payments/transfers"] = "payments.transfer.create" },
    timeout_ms = 3000, mode = "decide", keys_ttl = 3600,
  }
  for k, v in pairs(over or {}) do conf[k] = v end
  return conf
end

local function access(conf) return plugin.access(conf, ctx) end
local function last_params()
  return json_decode(state.last_http_request.body).parameters
end
local function last_op()
  return json_decode(state.last_http_request.body).operation
end
local EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
local HELLO = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

-- 1. SHA-256 and crypto
ok(sha256_hex("") == EMPTY, "sha256 empty-string vector")
ok(sha256_hex("hello world") == HELLO, "sha256 hello-world vector")
local crypto = require "apisix.plugins.agent-guard.crypto"
setup({ body = "hello world" })
ok(crypto.payload_hash(ctx) == HELLO, "payload_hash fingerprints the body")
setup({ body = "" })
ok(crypto.payload_hash(ctx) == EMPTY, "payload_hash of an empty body (APISIX nil) is the empty hash")
setup({ body_err = "client aborted" })
ok(crypto.payload_hash(ctx) == nil, "payload_hash fails closed when the body cannot be read")
ok(crypto.utc_epoch("2030-01-02T03:04:05Z") ==
   os.time({ year = 2030, month = 1, day = 2, hour = 3, min = 4, sec = 5 })
     - os.difftime(os.time(), os.time(os.date("!*t"))), "utc_epoch parses UTC expiresAt")
ok(crypto.utc_epoch("not-a-date") == nil, "utc_epoch refuses a bad date")

-- 2. schema
local p = plugin.schema.properties
ok(plugin.name == "agent-guard", "plugin name is agent-guard")
ok(plugin.priority < 2500 and plugin.priority > 1008, "priority: after auth plugins, before proxy plugins")
ok(p.mode.default == "decide" and table.concat(p.mode.enum, ",") == "decide,verify,verify_jwt", "schema: three modes, decide default")
ok(p.timeout_ms.default == 3000, "schema: timeout defaults to 3000 ms")
ok(p.keys_ttl.default == 3600, "schema: keys cache defaults to 3600 s")
ok(p.allow_action_header.default == false, "schema: client action headers disabled by default")
ok(table.concat(p.agent_source.enum, ",") == "header,consumer,jwt_claim" and p.agent_source.default == "header", "schema: identity sources")
ok(p.agent_claim.default == "sub", "schema: verified identity claim defaults to sub")
ok(table.concat(plugin.schema.required, ",") == "gateway_url,api_key", "schema: gateway_url and api_key required")
ok(plugin.schema.encrypt_fields[1] == "api_key", "schema: api_key encrypted at rest")
ok(type(plugin.check_schema) == "function", "check_schema exported")

-- 3. request resolution
local request = require "apisix.plugins.agent-guard.request"
setup({ headers = { ["X-Acr-Action"] = "weaker.action" } })
ok(request.resolve_action(base_conf(), ctx) == "payments.transfer.create", "route map wins over client action header")
setup({ path = "/other", headers = { ["X-Acr-Action"] = "x.y" } })
ok(request.resolve_action(base_conf(), ctx) == nil, "unmapped route ignores client action header by default")
ok(request.resolve_action(base_conf({ allow_action_header = true }), ctx) == "x.y", "opt-in action header used for unmapped route")
setup({ method = "GET" })
ok(request.resolve_action(base_conf(), ctx) == nil, "method is part of the route key")
setup({ headers = { ["X-Agent-Id"] = "agent-a" } })
ok(request.resolve_agent(base_conf(), ctx) == "agent-a", "header identity")
setup({ headers = { ["X-Agent-Id"] = "a|b" } })
ok(request.resolve_agent(base_conf(), ctx) == nil, "agent containing | refused")
setup({ headers = { ["X-Agent-Id"] = "" } })
ok(request.resolve_agent(base_conf(), ctx) == nil, "empty agent refused")
setup({ consumer = { username = "agent_refund" }, headers = { ["X-Agent-Id"] = "spoof" } })
ok(request.resolve_agent(base_conf({ agent_source = "consumer" }), ctx) == "agent_refund", "consumer identity ignores spoofed header")
setup({ headers = { ["X-Agent-Id"] = "spoof" } })
ok(request.resolve_agent(base_conf({ agent_source = "consumer" }), ctx) == nil, "consumer source without consumer refused")
setup({ identity = { claims = { sub = "agent-jwt" } } })
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim" }), ctx) == "agent-jwt", "verified-identity claim")
setup({ headers = { Authorization = "Bearer x.y.z" } })
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim" }), ctx) == nil, "jwt_claim never decodes a raw bearer token")

-- 4. decide mode
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, body = "hello world", request_uri = "/payments/transfers?ref=1",
  http_body = { decision = { effect = "grant", decisionId = "dec-1" } } })
local code = access(base_conf())
ok(code == nil, "grant forwards")
ok(last_op() == "decideAction", "asks decideAction")
local prm = last_params()
ok(prm.agent == "agent-a" and prm.action == "payments.transfer.create", "sends agent and mapped action")
ok(prm.payloadHash == HELLO, "sends body hash, not body")
ok(not state.last_http_request.body:find("hello world", 1, true), "raw body never leaves the gateway")
ok(prm.resourceRef == "/payments/transfers?ref=1", "resourceRef includes the query string")
ok(state.last_http_request.headers["x-api-key"] == "resolved-secret", "API key header sent")
ok(state.last_http_request.headers["idempotency-key"]:match("^apisix%-") ~= nil, "idempotency key sent")
ok(state.upstream_headers["X-Acr-Decision-Id"] == "dec-1", "decision id forwarded upstream")
ok(ctx.acr_decision.payloadHash == HELLO, "decision kept for outcome report")

setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_body = { decision = { effect = "pending", approvalId = "apr-1" } } })
local c, b = access(base_conf())
ok(c == 202 and b.approvalId == "apr-1", "pending returns 202 once with approvalId")
ok(state.upstream_headers["X-Acr-Decision-Id"] == nil, "pending not forwarded")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_body = { decision = { effect = "refuse", rationale = "No rule." } } })
c, b = access(base_conf())
ok(c == 403 and b.rationale == "No rule.", "refusal returns 403 with rationale")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_body = { decision = { effect = "something" } } })
ok(access(base_conf()) == 403, "unknown effect refused")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_err = "timeout" })
ok(access(base_conf()) == 503, "no answer fails closed with 503")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_status = 500, http_raw_body = "secret diag" })
ok(access(base_conf()) == 503, "HTTP error fails closed")
local leaked = false
for _, l in ipairs(state.logs.err) do if l:find("secret diag", 1, true) then leaked = true end end
ok(not leaked, "response bodies never logged")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_raw_body = "not json" })
ok(access(base_conf()) == 503, "invalid JSON fails closed")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, http_body = { error = { code = "x" } } })
ok(access(base_conf()) == 503, "application error fails closed")
setup({})
ok(access(base_conf()) == 403 and state.http_calls == nil, "missing agent refused before asking ACR")
setup({ path = "/unmapped", headers = { ["X-Agent-Id"] = "agent-a" } })
ok(access(base_conf()) == 403 and state.http_calls == nil, "unmapped route refused before asking ACR")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, body_err = "read failed" })
ok(access(base_conf()) == 400 and state.http_calls == nil, "unreadable body refused with 400")

-- 5. outcome reporting
local function granted(status)
  setup({ headers = { ["X-Agent-Id"] = "agent-a" }, status = status,
    http_body = { decision = { effect = "grant", decisionId = "dec-9" } } })
  access(base_conf())
  plugin.log(base_conf(), ctx)
end
for _, case in ipairs({ { 200, "executed", "http_200" }, { 202, "executed", "http_202_accepted" },
  { 422, "aborted", "http_422" }, { 503, "downstream_error", "http_503" } }) do
  granted(case[1])
  local t = state.timers[1]
  ok(t and t.args[3] == case[2] and t.args[4] == case[3], "status " .. case[1] .. " reported as " .. case[2])
end
granted(200)
local t = state.timers[1]
t.fn(false, unpack(t.args))
prm = last_params()
ok(last_op() == "reportExecutionOutcome" and prm.decisionId == "dec-9" and prm.payloadHash == EMPTY, "report carries decision id and gateway hash")
ok(state.last_http_request.headers["idempotency-key"] == "outcome-dec-9", "report idempotency key is decision-correlated")
granted(200)
t = state.timers[1]
local calls_before = state.http_calls
t.fn(true, unpack(t.args))
ok(state.http_calls == calls_before and #state.logs.warn == 1, "premature timer drops report and logs it")
granted(200)
t = state.timers[1]
state.http_err = "down"
t.fn(false, unpack(t.args))
ok(#state.logs.warn == 1 and state.logs.warn[1]:find("dec-9", 1, true), "failed report logged with decision id, no retry")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, timer_err = "too many",
  http_body = { decision = { effect = "grant", decisionId = "dec-9" } } })
access(base_conf())
plugin.log(base_conf(), ctx)
ok(#state.logs.err == 1, "timer scheduling failure logged")
setup({})
plugin.log(base_conf(), ctx)
ok(#state.timers == 0, "no decision, no report")
setup({})
ctx.acr_decision = { decisionId = "x", payloadHash = "y" }
plugin.log(base_conf({ mode = "verify" }), ctx)
plugin.log(base_conf({ mode = "verify_jwt" }), ctx)
ok(#state.timers == 0, "offline modes never report")

-- 6. verify mode
local FUTURE = "2099-01-01T00:00:00Z"
local KEYS = { verificationKeys = { workspaceId = "ws-1", keys = { { keyId = "k1", publicKey = b64url_encode(string.rep("A", 32)) } } } }
local function grant_headers(over)
  local h = { ["X-Agent-Id"] = "agent-a", ["X-Acr-Key-Id"] = "k1", ["X-Acr-Decision-Id"] = "dec-5",
    ["X-Acr-Expires-At"] = FUTURE, ["X-Acr-Public-Signature"] = b64url_encode("sig") }
  for k, v in pairs(over or {}) do h[k] = v end
  return h
end
setup({ headers = grant_headers(), body = "hello world", http_body = KEYS, verify_result = true })
ok(access(base_conf({ mode = "verify" })) == nil, "valid grant forwards")
ok(state.verify_message == table.concat({ "acr-grant-v3", "ws-1", "k1", "dec-5", "agent-a",
  "payments.transfer.create", HELLO, FUTURE, "", "dec-5", "0" }, "|"), "acr-grant-v3 message in published field order")
ok(last_op() == "getGrantVerificationKey", "keys fetched, decideAction never called")
setup({ headers = grant_headers({ ["X-Acr-Parent-Decision-Id"] = "dec-p", ["X-Acr-Root-Decision-Id"] = "dec-r",
  ["X-Acr-Delegation-Depth"] = "2" }), http_body = KEYS, verify_result = true })
access(base_conf({ mode = "verify" }))
ok(state.verify_message:sub(-13) == "dec-p|dec-r|2", "lineage headers signed")
setup({ headers = grant_headers(), http_body = KEYS, verify_result = false })
ok(access(base_conf({ mode = "verify" })) == 403, "bad signature refused")
setup({ headers = grant_headers({ ["X-Acr-Expires-At"] = "2000-01-01T00:00:00Z" }), http_body = KEYS, verify_result = true })
ok(access(base_conf({ mode = "verify" })) == 403, "expired grant refused")
setup({ headers = grant_headers({ ["X-Acr-Key-Id"] = "k-unknown" }), http_body = KEYS, verify_result = true })
ok(access(base_conf({ mode = "verify" })) == 403 and state.http_calls == 2, "unknown key refetched once, then refused")
setup({ headers = grant_headers({ ["X-Acr-Public-Signature"] = false }), http_body = KEYS, verify_result = true })
ok(access(base_conf({ mode = "verify" })) == 403, "missing signature refused")
setup({ headers = grant_headers(), http_err = "down", verify_result = true })
ok(access(base_conf({ mode = "verify" })) == 403, "failed key fetch refused")
setup({ path = "/x", headers = grant_headers(), http_body = KEYS, verify_result = true })
ok(access(base_conf({ mode = "verify" })) == 403, "unmapped route refused in verify")
setup({ headers = grant_headers(), http_body = KEYS, verify_result = true })
local conf = base_conf({ mode = "verify" })
access(conf); access(conf)
ok(state.http_calls == 1, "keys cached between requests")

-- 7. verify_jwt mode
local function jwt(claims) return "Bearer h." .. b64url_encode(json_encode(claims)) .. ".s" end
local good = { sub = "agent-a", acr = { action = "payments.transfer.create", payloadHash = HELLO } }
setup({ headers = { ["X-Agent-Id"] = "agent-a", Authorization = jwt(good) }, body = "hello world" })
ok(access(base_conf({ mode = "verify_jwt" })) == nil, "bound JWT forwards")
setup({ headers = { ["X-Agent-Id"] = "agent-a", Authorization = jwt(good) }, body = "changed" })
ok(access(base_conf({ mode = "verify_jwt" })) == 403, "JWT for another body refused")
setup({ headers = { ["X-Agent-Id"] = "agent-b", Authorization = jwt(good) }, body = "hello world" })
ok(access(base_conf({ mode = "verify_jwt" })) == 403, "JWT for another agent refused")
setup({ headers = { ["X-Agent-Id"] = "agent-a" }, body = "hello world" })
ok(access(base_conf({ mode = "verify_jwt" })) == 403, "missing token refused")
setup({ headers = { ["X-Agent-Id"] = "agent-a", Authorization = jwt({ sub = "agent-a" }) } })
ok(access(base_conf({ mode = "verify_jwt" })) == 403, "token without acr claims refused")

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then os.exit(1) end
