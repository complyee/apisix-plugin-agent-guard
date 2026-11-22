# Changelog

## 0.1.0

First release, equivalent to kong-plugin-agent-guard 0.2.0:

- `decide` mode (default): authoritative route map, opt-in action header, header / Consumer / verified-claim agent identity, local SHA-256 body fingerprint, query string in `resourceRef`, idempotency key, fail-closed body reads and 503 on no answer, 202 once on a policy hold.
- `verify` mode: offline `acr-grant-v3` Ed25519 check against the published key set, cached per worker with one refetch on an unknown key id.
- `verify_jwt` mode: binds a grant JWT, already verified by a preceding plugin, to this agent, route and body.
- Best-effort outcome reports in `decide` mode only, with HTTP detail codes; response bodies are never logged.
- 78 LuaJIT unit tests and a Docker Compose live suite against real APISIX.
