---
title: Tell an MCP client exactly what it needs
order: 18
---

# Tell an MCP client exactly what it needs

**Problem.** Your MCP server refuses a tool call with `403 insufficient_scope`. A plain client can only learn the scope name and ask for it again. It cannot learn that this particular refund was refused because it is over a limit, or that a person has to approve it.

**Fix.** Add one more field to the `WWW-Authenticate` challenge: `pca_need`. It carries the typed requirement (which verb on which resource, which scopes, which limit, which approval tier). A client that does not know it ignores it and steps up by scope exactly as before. A PCA-aware client reads it and can start an approve-or-amend flow.

```bash
npm install @atlasauth/pca @atlasauth/pca-mcp-rs @atlasauth/pca-mcp
```

The hint is **unsigned and advisory**. It grants nothing and widens nothing. The server decides again from the proof it is shown on the next request. A client must treat every field as untrusted display text: someone who can alter the header can only make the client ask for more than it needs, and the principal still reviews what is asked.

## Server: send the need with the refusal

```ts
import { wwwAuthenticateChallenge } from '@atlasauth/pca-mcp-rs';
import type { PcaNeed } from '@atlasauth/pca';

const need: PcaNeed = {
  v: 1,
  kind: 'scope',                     // 'scope' | 'grant' | 'discharge' | 'escalate'
  verb: 'stripe.refund',
  resource: 'charge/ch_1',
  scopes: ['refunds:write'],         // what the plain scope parameter names
  limits: { 'money.usd': 40 },       // advisory: the ceiling this request would need
};

const header = wwwAuthenticateChallenge({
  resourceMetadataUrl: 'https://rs.example/.well-known/oauth-protected-resource',
  error: 'insufficient_scope',
  scope: 'refunds:write',
  pcaNeed: need,
});

res.status(403).set('WWW-Authenticate', header).end();
```

If you use `admitRequest` from the same package, it adds a `pca_need` derived from the verified proof on a scope denial by itself; pass `pcaNeed: false` in its options to turn that off, or a function to build your own (to add limits or discharges). A malformed or oversized need never replaces the denial: the hint is dropped and the refusal stands.

Kinds and their extra fields:

| `kind` | Use it when | Extra fields |
|---|---|---|
| `scope` | The client needs a scope it did not ask for | `scopes` |
| `grant` | The client needs a different grant | `grant_ref` |
| `discharge` | Another party must attest a claim first | `discharges: [{ issuer, claim }]` |
| `escalate` | A person must approve | `tier` (2 guardian, 3 principal), required |

Unknown members are refused, a `tier` on anything but `escalate` is refused, and the encoded value is at most 2048 characters. That keeps the header small and the hint reviewable.

## Client: read it, or ignore it

```ts
import { planStepUp, pcaNeedProblem } from '@atlasauth/pca-mcp';

const plan = planStepUp(res.status, res.headers.get('www-authenticate'), {
  requested: ['tickets:read'], // scopes already asked for
  attempts: 0,
  pcaAware: true,              // opt in; a stock client leaves this off
});
```

| `plan` | What to do |
|---|---|
| `{ action: 'scope', scopes, attempts }` | Request those scopes again (the old ones plus the new) |
| `{ action: 'pca', need, fallbackScopes, attempts }` | Show `need` for approval, or amend the request; `fallbackScopes` is the plain step-up if you cannot |
| `{ action: 'give_up', reason }` | Stop. `not_insufficient_scope`, `retry_limit` (three attempts by default) or `no_new_scope` |

A missing, malformed or oversized `pca_need` is not an error. `planStepUp` falls back to the scope plan, and `pcaNeedProblem(header)` tells you why it was ignored (`bad_base64`, `too_long`, `unknown_member`, and so on) for your logs.

To cite a need in an approval record, use `pcaNeedDigest(need)`: a stable content address, different for any other resource or limit.

## Expected output

The companion script (`npm run mcp-pca-need` in the `pca-guides-b` examples):

```
ok   a stock client steps up by scope -> {"action":"scope","attempts":1,"scopes":["refunds:write","tickets:read"]}
ok   and does exactly what it does without the field -> {"action":"scope","attempts":1,"scopes":["refunds:write","tickets:read"]}
ok   a PCA-aware client gets the typed need -> {"action":"pca","attempts":1,"fallbackScopes":["refunds:write","tickets:read"],"need":{"kind":"scope","limits":{"money.usd":40},"resource":"charge/ch_1","scopes":["refunds:write"],"v":1,"verb":"stripe.refund"}}
ok   a malformed pca_need falls back to the scope step-up -> {"action":"scope","attempts":1,"scopes":["refunds:write"]}
ok   and the client can log why -> "bad_base64"
ok   the third retry -> {"action":"give_up","reason":"retry_limit"}

All outcomes as expected.
```

## When it goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Server throws while building the header | The need is malformed or over 2048 characters once encoded | Send fewer fields; move detail to your own approval page |
| A PCA-aware client still gets a `scope` plan | No `pca_need`, or one that failed to decode | Check `pcaNeedProblem(header)` |
| The client loops | It ignores `attempts` | Pass the running count to `planStepUp`; it gives up after three |
| A retry after approval is still refused | The hint is not a grant | Mint the grant or answer the escalation, then send a new proof |

## Next

- Build the server that sends this: [MCP quickstart](./mcp-quickstart.md).
- Put PCA in front of an existing MCP server: [MCP gateway profile](./mcp-gateway-profile.md).
- The approval itself: [Agent payments, risk-priced approvals and wallet permissions](./agent-payments-and-approvals.md).
