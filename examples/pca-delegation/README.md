# pca-delegation

Delegate to a sub-agent that can only be **narrower** than its parent, and guard the server with `protect()`.

```bash
npm install
npm start
```

- `parent.subAgent({ addedCaveats })` adds one hop to the chain. A hop can add restrictions (a lower spend ceiling,
  an expiry, a call count) and never remove one, so the sub-agent cannot exceed its parent.
- `protect({ audience, grants, operation })` is the server side in one call: your grant list, a replay store, a
  revocation source, a single-step plan and catalog risk. Pass `.options` to `requireAuthorized` or to any framework
  adapter (`pcaExpress`, `pcaFastify`, `pcaHono`, `pcaNext`).
- `server.revoke(grantId)` stops the parent and every sub-agent under that grant.
- `explainRefusal(reason)` turns a refusal reason into what it means and how to fix it.

## Make it yours

- Replace the in-memory store: pass `budgetStore` (see the store conformance kit in the PCA docs).
- Replace `grants` with a function that reads your database.
- Agent-to-agent calls (A2A) use the same chain: see the A2A guide in the PCA docs.
