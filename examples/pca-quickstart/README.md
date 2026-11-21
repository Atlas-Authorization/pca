# PCA quickstart

The whole [Proof-Carrying Authority](https://atlasauth.net/docs/pca) loop in two small files and one
command. An AI agent proves every action it takes; a resource server verifies the proof and allows or
denies. No bearer token the agent can spend freely — each action carries its own proof, bound to exact
limits.

## Run it

> **Status:** the PCA packages now depend only on `@atlasauth/pca`; nothing from any other product. The `0.1.0`
> builds on npm predate that, so `npm install` from the registry fails until the next release of the `pca-*`
> packages. Installing tarballs packed from this repo runs it today. Meanwhile the self-contained
> [pca-demo](../pca-demo/README.md) covers the same loop and much more.


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

## The idea in three steps

1. **Install** `@atlasauth/pca` (agent) and `@atlasauth/pca-express` (server).
2. **Wrap the agent** with `agent({ permissions, limits })` and call `.act(verb, resource, params)`.
3. **Guard the server** route with `requirePCA({ audience, resolveGrant, budgetStore })`.

Nothing in the agent authorizes anything — the server's verifier always decides.

See the [5-minute quickstart](https://atlasauth.net/docs/pca/guides/five-minute-quickstart) for the
copy-paste version, or scaffold a fresh project with `npm create pca-app@latest`.
