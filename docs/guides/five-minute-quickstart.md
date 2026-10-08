---
title: Add PCA in 5 minutes
order: 5
---

# Add PCA in 5 minutes

Proof-Carrying Authority (PCA) gives your AI agent a way to **prove**, on every tool call, that the
human behind it authorized that exact action — within exact limits. Instead of handing the agent a
bearer token it can spend however it likes, each action carries its own proof. Your server verifies
that proof and allows or denies.

You don't need to understand the cryptography to use it. Three steps.

## The fastest start: scaffold it

```bash
npm create pca-app@latest my-pca-app
cd my-pca-app
npm install
npm start
```

That prints a live `ALLOWED` for a legit action and a `DENIED` for an over-budget one. The rest of this
page is the same thing, by hand.

## Step 1 — Install

```bash
npm install @atlasauth/pca @atlasauth/pca-express express
```

- `@atlasauth/pca` — the agent side (build and prove actions).
- `@atlasauth/pca-express` — the server side (`requirePCA()` for Express).

## Step 2 — Wrap the agent with `agent()`

One call turns plain intent — *what the agent may do, and the limits* — into everything needed to prove
each action. Then `.act()` hands you a proof-carrying action to send with each tool call.

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';

const principal = generateKeyPair(); // the human's key (in production: their secure key / passkey-backed root)

const a = agent({
  principal,
  goal: 'reconcile October refunds',
  permissions: { stripe: ['refund'] }, // the agent may issue refunds...
  limits: { refund: '$500/day' },       // ...but never more than $500 per refund.
  aud: 'ins_quickstart',                // the resource server this action is for
});

// Build a proof-carrying action for ONE tool call. This does not authorize anything on its own.
const { encoded } = a.act('stripe.refund', 'charge:ch_123', { amount: 42, currency: 'usd' }, { counter: 1 });

// Send `encoded` (plus the plaintext params) to your server with the tool call:
await fetch('http://localhost:3000/refunds', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ pcactn: encoded, params: { amount: 42, currency: 'usd' } }),
});
```

## Step 3 — Guard the server with `requirePCA()`

Wrap the protected route. The guard verifies the inbound proof offline and is **default-deny**: if a
required check can't be enforced, the request is denied. Your handler runs only on success.

```ts
import express from 'express';
import { memoryPcaStore, pcaExpress } from '@atlasauth/pca-express';
import { merkleRoot, planNodeLeaf, readEnvelope } from '@atlasauth/pca';

const app = express();
app.use(express.json());

// The grant you trust (the agent's principal registers it with you out of band).
const grant = /* the Root Intent Grant for this agent */;
const bMax = readEnvelope(grant)?.risk_policy.bMax ?? 0;

const pcaGuard = pcaExpress({
  audience: 'ins_quickstart',                                   // must equal the action's `aud`
  resolveGrant: async (ref) => (ref === grant.id ? grant : null),
  budgetStore: memoryPcaStore(),                                // replay + budget (use Redis/DB in prod)
  hooks: { revocation: () => ({ enforced: true, ok: true }) },  // plug your revocation list here
  context: (req, p) => {
    const { params } = (req.body ?? {}) as { params?: Record<string, unknown> };
    // Rebuild the action's one-node plan so the verifier can confirm + authorize it.
    const plan = [{
      id: p.plan.node_id,
      verb: p.action.verb,
      resource: p.action.resource,
      params_digest: p.action.params_digest,
      reversibility_class: p.action.reversibility_class,
    }];
    return {
      params,
      plan,
      planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root,
      budget: { B: bMax, tau: Date.now(), asOf: Date.now() },
    };
  },
});

app.post(
  '/refunds',
  (req, res, next) => pcaGuard({ headers: req.headers, body: req.body }, res, next),
  (_req, res) => res.json({ ok: true, status: 'refunded' }), // runs only if the proof verified + policy allowed
);

app.listen(3000);
```

Send a `$42` refund and it is **allowed**. Send `$5000` and it is **denied** — the proof is still
valid, but the grant only permits refunds up to `$500`. You never had to write a policy check: the
limit you declared in Step 2 is enforced by the verifier.

## That's it

- The agent proves each action; the server decides. Nothing the agent holds is a free pass.
- Change the limits in `agent({ limits })` and the verifier enforces the new ones — no server change.

Next: [Agent quickstart](./agent-quickstart.md) for sub-agents, receipts and step-up, and the
[Resource-server quickstart](./resource-server-quickstart.md) for the full set of checks you can require.
