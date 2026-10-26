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

That plays nine scripted outcomes (allow, deny, step-up, replay, tamper, budget, sub-agent, offline receipt) and exits nonzero if any deviates; see [Run the end-to-end demo](./run-the-demo.md). For a smaller version (two refunds `ALLOWED`, one over the limit `DENIED`), scaffold `--template pca-quickstart`. The rest of this page builds that loop by hand.

## Step 1 — Install

```bash
mkdir pca-quickstart && cd pca-quickstart
npm init -y && npm pkg set type=module
npm install @atlasauth/pca @atlasauth/pca-express express tsx
```

- `@atlasauth/pca` — the agent side (build and prove actions).
- `@atlasauth/pca-express` — the server side (`requirePCA()` for Express).

## Step 2 — Wrap the agent with `agent()` (`agent.ts`)

One call turns plain intent — *what the agent may do, and the limits* — into everything needed to prove
each action. Then `.act()` hands you a proof-carrying action to send with each tool call. This agent tries
four refunds.

```ts
import { writeFileSync } from 'node:fs';
import { agent, generateKeyPair } from '@atlasauth/pca';

const principal = generateKeyPair(); // the human's key (in production: their secure key / passkey-backed root)

const a = agent({
  principal,
  goal: 'reconcile October refunds',
  permissions: { stripe: ['refund'] }, // the agent may issue refunds...
  limits: { refund: '$500/day' },       // ...at most $500 each, and $500 in total per day.
  aud: 'ins_quickstart',                // the resource server this action is for
});

// The principal registers the grant with the server out of band (here: a file the server reads).
writeFileSync('grant.json', JSON.stringify(a.grant));

// One proof-carrying action per tool call. `act` does not authorize anything; the server decides.
for (const [charge, amount] of [['ch_1', 42], ['ch_2', 100], ['ch_3', 400], ['ch_4', 5000]] as const) {
  const params = { amount, currency: 'usd' };
  const { encoded } = a.act('stripe.refund', `charge:${charge}`, params);
  const res = await fetch('http://localhost:3000/refunds', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pcactn: encoded, charge, params }), // the proof, plus the charge and params it is for
  });
  const body = (await res.json()) as { verdict?: { reasons?: string[] } };
  // The verdict lists every reason; skip the note about risk inputs the server priced at the worst case.
  const reason = body.verdict?.reasons?.find((r) => !r.includes('risk input'));
  console.log(`refund $${amount} -> ${res.ok ? 'ALLOWED' : `DENIED (${reason})`}`);
}
```

## Step 3 — Guard the server with `requirePCA()` (`server.ts`)

Wrap the protected route. The guard verifies the inbound proof offline and is **default-deny**: if a
required check can't be enforced, the request is denied. Your handler runs only on success.

Two things are the server's job. The route **names the operation it will run** (`operation`: the verb, the
resource and the params, taken from the route and the body, never from the proof), and the proof must be for exactly
that, so it cannot be reused for another charge or amount. And `context` **prices each refund** from the amount (which
the verifier checks against the signed digest), so a `$42` refund spends `42` of the agent's `$500` daily budget. The
trust budget starts at the grant's signed ceiling; after the first call, the guard keeps the spent budget in the store.

```ts
import { readFileSync } from 'node:fs';
import express from 'express';
import { memoryPcaStore, pcaExpress } from '@atlasauth/pca-express';
import { merkleRoot, planNodeLeaf, readEnvelope, type Capability } from '@atlasauth/pca';

const app = express();
app.use(express.json());

// The grant you trust: the one the principal registered with you out of band. Never take it from the request.
const loadGrant = (): Capability => JSON.parse(readFileSync('grant.json', 'utf8')) as Capability;

const store = memoryPcaStore(); // replay counters + trust budgets (production: a shared store with claim or withKeyLock)

const pcaGuard = pcaExpress({
  audience: 'ins_quickstart',                                   // must equal the action's `aud`
  resolveGrant: async (ref) => { const g = loadGrant(); return ref === g.id ? g : null; },
  budgetStore: store,
  // The operation THIS route executes, from the route and the body, never from the proof.
  operation: (req) => {
    const { charge, params } = (req.body ?? {}) as { charge?: string; params?: Record<string, unknown> };
    return { verb: 'stripe.refund', resource: `charge:${charge}`, params: params ?? {} };
  },
  hooks: { revocation: () => ({ enforced: true, ok: true }) },  // plug your revocation list here
  context: async (req, p) => {
    const { params } = (req.body ?? {}) as { params?: Record<string, unknown> };
    // Rebuild the action's one-node plan so the verifier can confirm + authorize it.
    const plan = [{
      id: p.plan.node_id,
      verb: p.action.verb,
      resource: p.action.resource,
      params_digest: p.action.params_digest,
      reversibility_class: p.action.reversibility_class,
    }];
    const policy = readEnvelope(loadGrant())?.risk_policy;
    // Price the refund from the amount the verifier checks against the signed digest: $42 under a $500 cap
    // spends 42 of the budget. (Risk inputs you do not supply are priced at the worst case: the whole cap.)
    const amount = params?.['amount'];
    const risk = typeof amount === 'number' && policy ? { blastRadius: Math.min(1, Math.max(0, amount / policy.kappa)) } : undefined;
    return {
      params,
      plan,
      planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root,
      ...(risk ? { risk } : {}),
    };
  },
});

app.post(
  '/refunds',
  (req, res, next) => pcaGuard({ headers: req.headers, body: req.body }, res, next),
  (_req, res) => res.json({ ok: true, status: 'refunded' }), // runs only if the proof verified + policy allowed
);

app.listen(3000, () => console.log('listening on http://localhost:3000'));
```

## Step 4 — Run it

In one terminal run `npx tsx server.ts`; in another, in the same directory, `npx tsx agent.ts`:

```
refund $42 -> ALLOWED
refund $100 -> ALLOWED
refund $400 -> DENIED (policy: trust budget depleted: human recharge required)
refund $5000 -> DENIED (policy: amount <= 500 not satisfied for stripe.refund on charge:ch_4)
```

The first two refunds are allowed and spend `$142` of the `$500` daily budget. The `$400` refund is within the
per-refund limit but more than the `$358` left, so it is **denied** until the principal approves more. The
`$5000` refund is **denied** outright — the proof is still valid, but the grant only permits refunds up to
`$500`. You never had to write a policy check: the limits you declared in Step 2 are enforced by the verifier.

## That's it

- The agent proves each action; the server decides. Nothing the agent holds is a free pass.
- Change the limits in `agent({ limits })` and the verifier enforces the new ones — no server change.

Next: [Agent quickstart](./agent-quickstart.md) for sub-agents, receipts and step-up, and the
[Resource-server quickstart](./resource-server-quickstart.md) for the full set of checks you can require.
