---
title: authN, authZ, authF
order: 1
---

# authN, authZ, authF

Authentication answers **who are you?** Authorization answers **what may you do?** For a human these two are enough, because the human is also the policy engine: they decide what to do, and their identity implies they are faithfully executing their own intent.

An autonomous agent breaks both assumptions. It is a stochastic process whose actions are unknown at grant time and steerable at run time by anything it reads. Knowing *which agent* is calling, and *which scopes* it holds, says nothing about whether *this action* is what the principal wanted.

PCA introduces a third question:

> **authF**: is this specific action a faithful, uncompromised execution of an authority the principal actually conferred?

## Six primitives that are the wrong shape for agents

| Primitive | Why it fails for an agent |
|---|---|
| Bearer tokens | "Whoever holds it is you." An agent is networked, long-lived and prompt-injectable. An exfiltrated token is full impersonation. |
| Scopes | Authority is scoped to API surface (`files:write`), not to what the user wanted. One checkbox cannot cover thousands of future autonomous actions. |
| One-time consent | A static grant at time 0 for behavior decided at time n by a model reading hostile input. |
| The confused deputy | The token does not bind an action to the intent that justified it, so injection redirects legitimate authority toward an attacker's goal. |
| Weak provenance | The resource sees "the user", not "agent X, for user Y, under grant Z, because goal G". Audit and non-repudiation are thin. |
| Coarse, slow revocation | You can kill a whole grant, but not "this agent's authority to do X, now that it is behaving oddly", and not instantly across a fleet. |

## What PCA changes

The resource server stops verifying *possession* and starts verifying a *proof*. A PCActn asserts, with cryptographic evidence for each clause:

> Action A is a valid opening of pre-authorized plan commitment Π, authorized by a capability chain that roots in principal P's signed grant, with enough signers for its risk, inside the policy envelope, not revoked, and not a replay.

Each clause maps to a layer of the stack:

| Layer | Question | Page |
|---|---|---|
| L0 | Is the executing agent the attested workload the grant names? | [Attestation](./attestation.md) |
| L1 | Is this action a node of a plan the principal authorized? | [Plan commitment](./plan-commitment.md) |
| L2 | Did the policy participate cryptographically in signing? | [Threshold and step-up](./threshold-and-step-up.md) |
| L3 | Is friction proportionate to risk, and is trust budget left? | [Policy and risk](./policy-and-risk.md) |
| L4 | Is the action's lineage clean of untrusted influence? | [Policy and risk](./policy-and-risk.md) |
| L5 | Is it unrevoked, fresh, and anchored in an audit log? | [Ledger and revocation](./ledger-and-revocation.md) |

## Principles

- **Authority is a statement about a verified computation, not a possessed secret.**
- **Least authority, cryptographically enforced.** Not "the resource server checks a policy", but "the action cannot be formed without the policy's signature".
- **Behavior is bound to pre-committed intent.** Runtime actions must open a tamper-evident plan.
- **Everything is attributable.** Every action is signed and ledger-anchored.
- **Graceful degradation.** The bottom rung is ordinary OAuth with proof of possession; PCA layers upward.
- **Friction scales with risk**, continuously and automatically.

## Non-goals

- Not a replacement for human-to-service login. OIDC and passkeys stay for humans ([PCA vs OAuth vs WebAuthn](../migration.md)).
- No blockchain dependency. The ledger is a Merkle log; the bond economics of [the optimistic path](./optimistic-and-zk.md) are optional and settled outside this library.
- Zero-knowledge and weights-level attestation are optional, staged capabilities, not requirements.

Next: [Credential model](./credential-model.md).
