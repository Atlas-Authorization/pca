# Proof-Carrying Authority (`@atlasauth/pca`)

**Authorization for AI agents.** Instead of handing an agent a bearer token it waves at every
call, PCA has the agent present a *proof* with each action — a signed, self-describing **PCActn**
that a resource server verifies **offline**: is this action inside the authority the principal
granted, is the signing chain intact, is it a node of the plan the agent committed to, and is there
still trust budget left to do it without a human?

Think of it as the OAuth dance, re-cut for autonomy: the principal signs a **Root Intent Grant**
once; the agent then acts on its own, and every action carries its own evidence.

```
  principal ──grant──▶ agent ──PCActn(per action)──▶ resource server
   (signs the           (holds a          (verifies offline: chain · plan ·
    envelope +           capability,        signature · audience · budget,
    policy + budget)     emits proof)       then allows / steps-up / denies)
```

## Why it's different

- **No ambient authority.** A leaked PCActn authorizes *one* action on *one* resource server in a
  narrow time window — not "everything the token could do."
- **Attenuation by construction.** A sub-agent's capability can only ever be *narrower* than its
  parent's (caveats are append-only), so delegation can't widen power.
- **A budget with a theorem.** Every autonomous (no-human) action spends `κ·r` of a trust budget;
  the total an agent can do between two human co-signs is provably bounded by `bMax/κ` — even if the
  agent is fully compromised.
- **Offline, deterministic verification.** The resource server checks a PCActn with public keys and
  a canonical form; no callback to an authorization server on the hot path.

## Quickstart

**1 — the agent side.** Compile intent into a signed grant and emit a proof per tool call:

```ts
import { agent } from '@atlasauth/pca';

const a = agent({
  principal,                                   // the human's keypair (roots the grant)
  goal: 'reconcile October refunds',
  permissions: { stripe: ['refund'], gmail: ['send'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',                             // the resource server this is for
});

const { encoded } = a.act('stripe.refund', 'charge:ch_123', { amount: 42, currency: 'usd' }, { counter: 1 });
// POST to your resource server with the proof attached:
//   fetch(url, { method: 'POST', headers: pcaHeaders(encoded), body: ... })
```

**2 — the resource server.** Verify every inbound action (drop-in middleware per framework):

```ts
import { pcaExpress } from '@atlasauth/pca-express';

app.post('/refunds',
  pcaExpress({
    audience: 'ins_acme',
    resolveGrant: (grantRef) => grants.get(grantRef),   // your grant store
    budgetStore, context,                                // replay + the action params you enforce
  }),
  (req, res) => { const { verdict, pcactn } = req.pca!; /* ... */ });
```

That's the whole loop. Everything else below is depth, breadth and ergonomics on top of it.

## The ecosystem

| Package | What it is |
| --- | --- |
| `@atlasauth/pca` | Core: canonical hashing, Ed25519, capability chains, the PCActn + offline verifier, trust budget, plan Merkle commitments, the facade, connector catalog, framework-agnostic adapters, policy simulation/linting, approvals, the behavioral immune system, policy templates, the principal console, agent passport, DLP, reputation, compliance export, receipts, budget forecaster, sessions, NL→policy, Guardian HA, and the hybrid PQ KEM. |
| `@atlasauth/pca-agent` | Agent-side client: commit a plan, act, handle step-up, delegate, verify receipts. |
| **Agent frameworks** | `@atlasauth/pca-ai-sdk` · `@atlasauth/pca-langchain` · `@atlasauth/pca-openai` · `@atlasauth/pca-anthropic` · `@atlasauth/pca-mcp` — wrap a tool so each call emits a PCActn. |
| **Resource servers** | `@atlasauth/pca-express` · `@atlasauth/pca-fastify` · `@atlasauth/pca-hono` · `@atlasauth/pca-next` — `requirePCA`-style middleware that verifies the inbound PCActn. |
| **Payments** | `@atlasauth/pca-payments` — a spending mandate (caps, auto-approve threshold, bonded refunds) as a grant. |
| **Tooling** | `@atlasauth/pca-cli` (`pca decode`/`explain`/`keygen`/`simulate`) · `@atlasauth/pca-testing` (factories, fake verifier, assertions) · `@atlasauth/pca-events` (typed step-up events + signed webhooks) · `@atlasauth/pca-otel` (OpenTelemetry spans + metrics). |
| **Research** | `@atlasauth/pca-mpc` (malicious-secure MPC Policy VM) · `@atlasauth/pca-harness` (conformance). |

## Security model

A resource server accepts an action only if the PCActn passes, in order: **wire** (strict canonical
form) → **version** → **audience** (this server's id, so no cross-server replay) → **validity**
(time window) → **capability chain** (hash-linked, each hop signed, rooted at the grant) → **plan
inclusion** (the action is a committed plan node) → **leaf signature** → **counter** (anti-replay),
then the staged hooks: **attestation** (the agent is the model/weights/operator it claims),
**revocation / freshness** (a live beacon + unrevoked epoch), **taint gate** (DLP), **threshold**
(risk-adaptive human/guardian co-signs), **ZK compliance**. Verification is default-deny: a required
check that is merely *unenforced* denies.

### Post-quantum status

Every **signed surface** is crypto-agile (`ed25519 | ml-dsa-65 | hybrid-ed25519-ml-dsa-65`): the leaf
signature, the capability-chain hops, the guardian threshold cosign, the transparency tree heads +
witnesses, revocation epochs, beacons, settlements, attestation and the safety certificate — so the
whole authority chain can verify under a pure-PQ suite, with hybrid as the migration default. Key
exchange / secret-wrap uses the **hybrid X25519 + ML-KEM-768 KEM** (`kem.ts`): breaking it requires
defeating *both* the curve and the lattice. Hashes are SHA-2 (Grover-safe at these sizes); MPC MACs
are information-theoretic.

## Honest boundaries

"No flaw / perfect" is a direction, not a claim. Cryptographic assurance is earned by **independent
audit** and time; real security also needs **adoption**. The ZK proof system is migrating from
BN254 toward a 128-bit / transparent PQ backend, and the one classical root PCA doesn't own is AMD's
SEV-SNP attestation chain (their PQ roadmap). These are stated, never faked.

---

Part of **Proof-Carrying Authority** by Atlas.
