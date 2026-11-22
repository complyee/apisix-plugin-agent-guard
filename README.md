# apisix-plugin-agent-guard

Agent Control Room enforcement point for [Apache APISIX](https://apisix.apache.org). The plugin asks Agent Control Room before APISIX forwards an agent's request — or, when the request already carries a grant, checks it offline against the published Ed25519 key set. APISIX routes, Agent Control Room decides, and your upstream service does the work.

It behaves exactly like its sibling [kong-plugin-agent-guard](https://github.com/complyee/kong-plugin-agent-guard); only the APISIX plugin shell differs.

- Full integration guide: https://agent-cr.com/plugins#apache-apisix
- API reference: https://agent-cr.com/api

## What it does

- **Asks before forwarding** (`mode: decide`, the default). Each request is mapped to a governed action, the request body is fingerprinted locally (SHA-256 — the body never leaves your network), and Agent Control Room answers grant, refuse or hold. A grant forwards the request with its decision id; a refusal returns 403; a hold returns 202 once with the approval id; no answer returns 503 — the request is not forwarded.
- **Checks a grant offline** (`mode: verify`). APISIX verifies the `acr-grant-v3` Ed25519 signature locally, rebuilt with this request's agent, action and body hash, so a grant for one agent, route or payload cannot be reused for another.
- **Binds a grant JWT** (`mode: verify_jwt`). A preceding plugin verifies the token against `https://agent-cr.com/.well-known/jwks.json`; this mode then binds it to this agent, route and body.
- **Attempts to report the outcome in `decide` mode** after the upstream answers, with a non-blocking `ngx.timer.at` callback. Best-effort evidence, not durable delivery or proof that a business transaction committed.
- **Fails closed.** No answer, an unknown key, a missing header or a failed check always means the request is not forwarded.

ACR is one control layer. An ACR grant never overrides a refusal by your identity provider, APISIX authentication or any other required control.

## Requirements

- Apache APISIX 3.x
- An Agent Control Room workspace address: `https://<workspace>.agent-cr.com/api/public/v1/gateway`
- An API key with the `policy.decide` scope (plus `policy.read` for `verify` mode), held as an APISIX secret reference (`$env://` or `$secret://`) — never as plain text in plugin config
- The calling agents registered in your workspace, and rules for each mapped action

## Install

```sh
luarocks install apisix-plugin-agent-guard
```

Or copy the `apisix/` folder of this repository somewhere on disk and point APISIX at it. Then enable the plugin in `conf/config.yaml` (listing `plugins` replaces the default list, so keep the plugins you use):

```yaml
apisix:
  extra_lua_path: "/opt/agent-guard/?.lua"   # only when copying the folder
nginx_config:
  envs:
    - ACR_API_KEY                            # lets $env://ACR_API_KEY resolve
plugins:
  - key-auth
  - agent-guard
  # ...the other plugins you use
```

and reload APISIX.

## Enable it on a route

Admin API:

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/transfers -X PUT \
  -H "X-API-KEY: $APISIX_ADMIN_KEY" -d '{
  "uri": "/payments/transfers",
  "methods": ["POST"],
  "upstream": { "type": "roundrobin", "nodes": { "payments.internal:8080": 1 } },
  "plugins": {
    "agent-guard": {
      "gateway_url": "https://<workspace>.agent-cr.com/api/public/v1/gateway",
      "api_key": "$env://ACR_API_KEY",
      "action_map": { "POST /payments/transfers": "payments.transfer.create" }
    }
  }
}'
```

Standalone (`apisix.yaml`) works the same way under `routes[].plugins`.

The plugin resolves `$env://ACR_API_KEY` itself at each ACR call, including in standalone YAML mode. Supply the variable to the APISIX process and list it under `nginx_config.envs` so workers can read it. `$secret://` references use the configured APISIX secret manager. A missing, empty or unresolved key fails closed before any HTTP request; the literal reference is never sent as a credential. Kong's `{vault://env/...}` syntax is not supported.

The integration suite uses the public dummy credential `test-api-key` for its mock server only. Never substitute a production key into that fixture.

## Configuration

| Parameter | Default | Description |
| --- | --- | --- |
| `gateway_url` | — (required) | Your workspace gateway address. |
| `api_key` | — (required) | A secret reference such as `$env://ACR_API_KEY` or `$secret://vault/acr/api_key`, never the key itself. Encrypted at rest when APISIX data encryption is on. |
| `agent_source` | `header` | `header`, `consumer` or `jwt_claim`; applies in every mode. Header mode is for development or a trusted proxy that overwrites caller headers, not public-client authentication. |
| `agent_header` | `X-Agent-Id` | Agent header used only in `header` mode. |
| `agent_claim` | `sub` | In `jwt_claim` mode, the claim read from the verified identity described below. |
| `action_header` | `X-Acr-Action` | Used only on unmapped routes with explicit header opt-in. |
| `allow_action_header` | `false` | Allow an action header on an unmapped generic proxy route. Never overrides a mapped route. |
| `action_map` | `{}` | `"METHOD /path"` → action name; always authoritative. Query parameters do not change the lookup. Unmapped requests refuse unless header opt-in is enabled. |
| `timeout_ms` | `3000` | Timeout for calls to Agent Control Room. |
| `mode` | `decide` | `decide`, `verify` or `verify_jwt`. |
| `keys_ttl` | `3600` | How long published verification keys are cached per worker, in seconds. |

## Request authority and payload binding

The plugin's priority is `2400`, so it runs after APISIX authentication plugins (`key-auth` 2500, `jwt-auth` 2510, `openid-connect` 2599). For production, use `agent_source: consumer` (the authenticated Consumer's `username` is the ACR agent name — register exactly that value) or `jwt_claim` with a verified identity. Missing identity returns 403 with no fallback to a caller header.

`jwt_claim` never decodes a bearer token itself. A trusted preceding plugin must verify signature, algorithm, issuer, audience and expiry, then set:

```lua
-- Only after successful authentication; never from request headers.
ctx.acr_verified_identity = { claims = verified_identity_claims }
```

The body is read with `core.request.get_body`, which also reads bodies APISIX buffered to disk. An empty body hashes as the empty string; a read error is refused (400 in `decide`, 403 in offline modes). Set a request-size limit (`client-control` plugin or `client_max_body_size`) suited to the route.

In `decide`, `resourceRef` is the path with its query string, so do not put secrets in query parameters. It is a policy input, not part of the `acr-grant-v3` signed message: offline modes bind agent, action and body only.

## Modes

### `decide` (default)

| Decision | APISIX answers | Forwarded? |
| --- | --- | --- |
| grant | upstream's response | yes, with `X-Acr-Decision-Id` |
| refuse | `403` with the rationale | no |
| pending (held for a person) | `202` once, with the approval id | no |
| no answer / unreachable | `503` | no |

A policy-hold `202` means the step is waiting for a person; it was not forwarded. The caller polls `getApprovalStatus` and resubmits. An ACR grant is not an upstream transaction lock or exactly-once guarantee: side-effecting services must enforce their own idempotency key, stable across retries and approval resumption. The idempotency header the plugin sends concerns its calls to ACR only.

### Outcome reporting limitations

In `decide` mode the `log` phase schedules one `ngx.timer.at(0, ...)` callback per forwarded grant. No retry queue or durable spool. Failures log a warning or error with the decision id; response bodies and API keys are never logged.

| Upstream status | Outcome | Detail code |
| --- | --- | --- |
| 2xx except 202 | `executed` | `http_<status>` |
| 202 | `executed` | `http_202_accepted` — accepted, not confirmed complete |
| 4xx and others | `aborted` | `http_<status>` |
| 5xx | `downstream_error` | `http_<status>` |

`verify` and `verify_jwt` never report outcomes. A missing report means execution is unknown, not refused.

### `verify`

The request carries `X-Acr-Key-Id`, `X-Acr-Decision-Id`, `X-Acr-Expires-At`, `X-Acr-Public-Signature`, plus `X-Acr-Parent-Decision-Id`, `X-Acr-Root-Decision-Id`, `X-Acr-Delegation-Depth` for delegated grants. Keys come from `getGrantVerificationKey`, cached for `keys_ttl`; an unknown key id triggers one refetch (key rotation). A local check cannot see a revocation — call `verifyDecision` where that matters.

### `verify_jwt`

Your application adds `grantFormat: "jwt"` to `decideAction` and sends `decision.grantJwt` as a bearer token. A preceding plugin must verify it against `https://agent-cr.com/.well-known/jwks.json` with alg `EdDSA`, issuer `https://agent-cr.com` and your workspace address as audience. APISIX's `jwt-auth` uses per-consumer keys and does not read a remote JWKS; check that the plugin you choose (for example `openid-connect` in bearer-only mode) accepts EdDSA, or use `verify` mode instead.

## Tests

```sh
luajit spec/run.lua                                                       # unit tests, mocked APISIX
docker compose -f spec/integration/docker-compose.yml up --abort-on-container-exit --exit-code-from tests   # live APISIX
```

## License

Apache-2.0
