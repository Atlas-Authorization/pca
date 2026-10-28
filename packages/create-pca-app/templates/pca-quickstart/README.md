# __PCA_APP_NAME__

A working [Proof-Carrying Authority](https://atlasauth.net/docs/pca) app: an AI agent proves every
action it takes, and a resource server verifies the proof and allows or denies. No bearer token the
agent can spend freely — each action carries its own proof, bound to exact limits.

## Run it

```bash
npm install
npm start
```

Expected output:

```
refund $42 (within limit)    -> ALLOWED (HTTP 200)
refund $5000 (over limit)    -> DENIED (HTTP 403)
   reason: policy: ...
```

Both proofs are cryptographically valid. The second is denied by the server's **policy**: the grant
only permits refunds up to `$500`.

## What's where

- **`src/agent.ts`** — the agent side. One `agent({ permissions, limits })` call compiles plain intent
  into a signed grant + policy + trust budget; `.act()` emits a proof-carrying action per tool call.
- **`src/server.ts`** — the resource-server side. One Express route guarded by `requirePCA()` (via
  `@atlasauth/pca-express`): it verifies each inbound proof offline and is default-deny.
- **`src/run.ts`** — starts the server in-process, fires a legit and an over-budget refund, prints the
  verdicts.

Nothing in the agent authorizes anything — the server's verifier always decides.
