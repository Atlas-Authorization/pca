# Changelog

## 0.5.0

- PCA in a box (`deploy/pca-in-a-box`): a Docker Compose stack that runs the whole flow locally (the proxy in observe mode, a sample API, a sample MCP server and agent, a live decisions page, an optional trust-directory log and witness) and walks observe, autopilot propose, a human's signature, enforce. A Helm chart (`deploy/helm/pca-proxy`) runs the proxy as a gateway or a sidecar, with an optional control-plane reporting agent.
- First release. A drop-in proxy that puts Proof-Carrying Authority in front of any MCP server (stdio or streamable HTTP) or HTTP API with no SDK and no code change in the agent or the upstream.
- MCP mode: `tools/list` shows only the tools the operator reviewed and whose definition is unchanged; every `tools/call` is mapped to an action, checked against its definition and decided by the full PCA pipeline; results are labelled untrusted; server-initiated sampling and elicitation are refused unless allowed; the upstream failing is a refusal.
- HTTP mode: routes mapped from an OpenAPI document or a rules list; path, query and JSON body checked against the action definition; the upstream request is rebuilt, not relayed; `sidecar` (the proxy mints the proof) and `verify` (the caller's `PCA-Action` is verified by the gateway) modes.
- One configuration file (JSON or YAML), strict, with `observe` and `enforce` modes and default deny; hash-chained audit receipts; step-up approvals over the CIBA broker with an optional signed webhook; optional OpenTelemetry.
- `pca-proxy init | mcp | http | review | approvals | audit`.
- Durable state: the grant's identity, the replay counters, the budget, the session taint and the per-action rate windows live in a crash-safe, hash-chained store (`state.dir`) and survive a restart; an unreadable or corrupt store refuses calls or stops the proxy from starting. `state: { backend: memory }` is the explicit development option.
- MCP over streamable HTTP (`mcp.listen`): named clients with bearer tokens, per-client sessions with their own upstream and lists, Origin and Host checks, session caps and idle sweep, taint isolated per client.
- `resources/read` and `prompts/get` are mapped to pinned read actions (default deny); lists show only what was reviewed.
- Count limits (`10/hour`) are a per-action sliding window kept by the proxy, not the grant's grant-wide rate caveat.
- Optional observed-parameters log (`audit.observedParams`, observe mode only, off by default) for `pca autopilot`: numeric, boolean and short-enum parameters, sensitivity-gated, hash-chained, bound to its receipt by the receipt's `obs1`/`obs2` facts; `pca-proxy audit verify FILE --params FILE`.
