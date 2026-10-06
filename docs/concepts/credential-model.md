---
title: Credential model
order: 2
---

# Credential model

PCA has no bearer token. Authority is carried by three objects: the **Root Intent Grant**, an **attenuable capability chain** hanging off it, and, per action, a **PCActn** that presents the chain together with the proofs.

## Root Intent Grant

The principal authorizes *intent*, not a scope list. A grant is a root capability whose first caveat, of type `envelope`, carries the whole policy envelope. Because the envelope is a caveat of the root, it is covered by the root signature: tampering with it breaks `verifyChain`.

```ts
import { generateKeyPair, encodeKey, mintGrant, DEFAULT_RISK_POLICY } from '@atlasauth/pca';

const principal = generateKeyPair();
const agent = generateKeyPair();

const { grant, goalCommit, goalSalt } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(agent.publicKey),           // the key the grant is bound to
  goal: 'secure my account',                     // plaintext; only a salted hash is stored
  envelope: {
    predicates: [{ verb: 'list_sessions', resource: 'session:*' }],
    caveats: [{ type: 'expires', at: Date.now() + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
});
```

The `Envelope` interface:

| Field | Meaning |
|---|---|
| `goal_commit` | `goalCommitOf(goal, salt)`: a salted hash of the human-authored goal. `verifyGoalCommit(commit, goal, salt)` opens it. |
| `predicates` | Semantic action predicates the agent may perform. Default deny. See [Policy and risk](./policy-and-risk.md). |
| `caveats` | Bounds: expiry, rate, blast radius, reversibility ceiling, delegation depth. |
| `agent_binding` | `AgentBinding`: `model_allowlist`, `min_measurement`, `operator`, `weights_allowlist`. Enforced by [attestation](./attestation.md). |
| `risk_policy` | `RiskPolicy`: weights, thresholds θ₁/θ₂, κ, λ, ρ, bMax. |

`mintGrant` rejects an empty goal and an invalid risk policy (`validateRiskPolicy`). `readEnvelope(grant)` returns the envelope from the first `envelope` caveat, or `null` if it is absent or malformed; later attenuation can only add caveats, never replace that one. `readEnvelope` does not verify signatures, so run `verifyChain` first.

## Capability chains

A `Capability` is a signed, content-addressed hop:

```ts
interface Capability {
  id: string;          // = body_digest
  issuer: string;      // b64u key that signed this hop (root: the principal; child: the parent's holder)
  holder: string;      // b64u key this capability is bound to (cnf)
  caveats: Caveat[];   // append-only down the chain
  parent?: string;     // capHash() of the parent; absent on the root
  body_digest: string;
  sig: string;
}
```

Operations:

| Function | Effect |
|---|---|
| `mintRoot({ principalSecret, principalPublic, holder, caveats })` | Create the root capability. `mintGrant` is this plus envelope handling. |
| `attenuate(parent, addedCaveats, signerSecret)` | Child with the **same** holder; caveats = parent's ++ added. |
| `delegate(parent, toHolder, addedCaveats, signerSecret)` | Like `attenuate`, but rebinds `holder` to a new key (a sub-agent). |
| `verifyChain(chain, expectedRootIssuer?)` | Structural verification (below). |
| `capHash(cap)` | Hash of the full capability including signature; used as the child's `parent` link. |

### What `verifyChain` enforces

- The chain is non-empty; hop 0 has no `parent` and (if given) its issuer equals the expected principal.
- Every hop's `body_digest` equals the hash of its body and `id` equals `body_digest`.
- Every hop is signed by the key it must be signed by: the root by its issuer, each child by the **parent's holder** (holder-binding continuity: `child.issuer === parent.holder`).
- Each child's `parent` equals `capHash(parentCapability)` (hash-linked).
- **Attenuation only.** The parent's caveats must be an exact prefix of the child's. A child that drops, reorders or edits a parent caveat is rejected.

Because every caveat is a conjunctive constraint and caveats can only be appended, a child can never be wider than its parent: widening is impossible by construction. Delegation depth is itself a caveat.

Holder binding makes a leaked capability inert: acting requires a signature by the leaf holder's key. Caveat *semantics* (does this action satisfy the caveats?) are evaluated by the [Policy VM](./policy-and-risk.md); the chain check is structural.

## The PCActn

Each action is a `PCActn`: the action, the chain, the plan inclusion proof, attestation and provenance claims, a counter, a risk claim and the signature. Field-by-field layout and the signed bytes are in [Wire formats](../reference/wire-formats.md).

Properties that matter conceptually:

- **Bound to one action.** The action's verb, resource, `params_digest` and reversibility class are recomputed into the plan leaf; any change breaks inclusion.
- **Bound to the holder.** `sig` must verify under the leaf capability's `holder`. A threshold signature or FROST aggregate can stand in as that holder (see [Threshold and step-up](./threshold-and-step-up.md)).
- **Bound against replay.** `counter` is a non-negative integer that the resource server requires to strictly increase per holder.
- **Nothing here is a bearer secret.** Possessing a PCActn lets you replay exactly that one action at most once, and only if the counter has not moved.

Build and sign with `buildPCActn({ grant, chain, plan, nodeId, params, counter, signerSecret, ... })`, which refuses a node that does not exist or `params` that disagree with the node's committed `params_digest`.

Next: [Plan commitment](./plan-commitment.md).
