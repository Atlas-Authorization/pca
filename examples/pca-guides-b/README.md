# pca-guides-b

Runnable companions to five PCA how-to guides. Each script is deterministic (a fixed clock, fake networks, fresh keys), prints one line per outcome, ends with `All outcomes as expected.` and exits non-zero if any outcome differs.

```bash
npm install
npm run obligations-leases-break-glass   # obligations, leases, break glass
npm run token-vault-proxy                # the credential vault in proxy mode
npm run spend-rails                      # a virtual card with the mandate's limits
npm run sandbox                          # a tool that can only use handles
npm run mcp-pca-need                     # the pca_need hint on an insufficient_scope refusal
npm start                                # all five, in order
```

| Script | Guide | Offline stand-in |
|---|---|---|
| `obligations-leases-break-glass` | Obligations, leases and break glass | In-memory lease store |
| `token-vault-proxy` | Keep API credentials away from the agent | A function in place of the outbound HTTP call; the in-memory connection store |
| `spend-rails` | Spend rails, a virtual card with the same limits | Hand-made Issuing events signed with a local secret; no Stripe account |
| `sandbox` | Run an agent's tool in a sandbox | A hand-assembled WebAssembly tool |
| `mcp-pca-need` | Tell an MCP client exactly what it needs | Header strings only; no server |

The stand-ins are test doubles. The in-memory stores keep everything in process memory, so use durable, encrypting stores in production. Each guide lists what to change.

Requires Node.js 20 or later. Uses only the published `@atlasauth/*` packages.
