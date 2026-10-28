# __PCA_APP_NAME__

An [MCP](https://modelcontextprotocol.io) server whose tools each require a
[Proof-Carrying Authority](https://www.npmjs.com/package/@atlasauth/pca) action, and an MCP agent that sends one with
every tool call.

```bash
npm install
npm run demo        # starts the server, runs the agent, stops; exits nonzero if an outcome is unexpected
```

Or in two terminals:

```bash
npm start           # MCP server on http://127.0.0.1:8788/mcp
npm run agent       # the agent's five tool calls
```

Expected output from the agent:

```
ok   refund $42        -> ALLOWED: refunded $42 on ch_123
ok   refund $100       -> ALLOWED: refunded $100 on ch_124
ok   delete_customer   -> DENIED: PCA denied: the grant does not permit stripe.delete_customer (it permits: stripe.refund)
ok   refund $5000      -> DENIED: PCA denied: stripe.refund on charge:ch_456 is outside the grant's limits (amount <= 500, amount >= 0)
ok   refund, no proof  -> DENIED: PCA denied: tool 'refund' requires a proof-carrying action: send it in the PCA-Action header
```

## What each file does

- `src/agent.ts`: the principal creates the agent with a grant (`stripe.refund` only, at most $500 each) and
  registers the grant with the server. The MCP client's `fetch` is `pcaFetch` from `@atlasauth/pca-mcp`: it adds a
  fresh `PCA-Action` header, signed by the agent's key, to every `tools/call`.
- `src/server.ts`: an MCP server over Streamable HTTP with two tools, `refund` and `delete_customer`. Each tool
  handler is wrapped by `requirePca`, which calls `authorizeToolCall` from `@atlasauth/pca-mcp-rs` and runs the tool
  only when it allows the call. That one call checks the proof against the grant from the server's own store, binds
  it to this exact tool call (verb, resource and arguments), and runs the full verifier: permissions, limits,
  revocation, replay and the trust budget (refunds are priced by the server from the amount). A refusal is an MCP
  tool error (`isError: true`) with the reason, so the model can see it.
- `src/tools.ts`: the mapping from MCP tool calls to PCA verbs and resources, shared by both sides.
- `src/store.ts`: the server's grant store, a folder of JSON files in `./.grants`.

## Rules worth keeping when you adapt this

- The server loads the grant from its own store, by the proof's signed `grant_ref`. Never accept a grant that
  arrives with the request.
- A signed proof is not a permission. The agent's key can sign any action; the grant's permissions and limits
  decide. Use `authorizeToolCall` (or `authorizeRequest`, which is the same check). Admission alone,
  `authorizeRequest(..., { admissionOnly: true })`, checks neither limits, nor the binding to the call, nor replay.
- Keep `toolAction` the same on both sides: it is what binds a proof to one tool call.
- The replay counter and trust budget live in `memoryPcaStore()`, which is one process only. Use a shared store
  (Redis, your database) when you run more than one server process.

PCA's cryptography has not been independently audited. Treat this starter as learning material, not production code.
