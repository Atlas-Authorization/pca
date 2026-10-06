---
title: Threat model
order: 30
---

# Threat model

## Assumption: the agent is fully compromised

PCA is designed against the strongest adversary: one that **fully owns the agent process**. It can issue arbitrary tool calls (through prompt injection) up to remote code execution inside the agent, and may try to extract keys. The agent is not assumed honest.

The goal is to bound what a fully owned agent can do to **exactly the set the principal already sanctioned**.

## The reachable-action theorem (informal)

The set of actions a compromised agent can get a resource server to accept is:

```
Reachable  =  Π            committed plan: an L1 inclusion proof exists
            ∩ Envelope     the grant's predicates and caveats: the Policy VM will release the guardian share
            ∩ TaintClean   L4: causal lineage within the taint policy
            ∩ { A : threshold t(r(A)) is satisfiable by the adversary }
```

The guardian share is released only by the deterministic Policy VM, and only for compliant actions. The principal-device share is required when `r(A) > θ₂`. So the adversary's reachable set collapses to **low-risk, in-plan, in-policy, taint-clean actions**: actions the principal already authorized. Everything else needs the adversary to break (a) the signature scheme, (b) the Policy VM's release condition, or (c) obtain the human share.

Add the trust-budget [safety bound](../concepts/policy-and-risk.md#safety-bound): even among reachable actions, the total risk-weighted autonomous activity between two human recharges is at most `bMax / κ`.

Preconditions the theorem relies on: the verifier computes (or vouches for) risk inputs itself rather than trusting the agent's `risk_claim`; the verifier enforces the revocation, counter and threshold checks; the guardian key and the principal key are not compromised. See [Trust model](./trust-model.md).

## Key-theft lemma

Extracting the agent's key does not help:

- Outside a TEE, the agent's attestation quote will not match the grant's `agent_binding`, so the verifier rejects ([attestation](../concepts/attestation.md)). Inside a TEE the epoch key is derived from the enclave secret and never leaves it.
- Even **with** the agent's key, the agent share alone is `t - 1` short of a valid threshold signature for any `r > θ₁`. Forging one needs the guardian's policy-gated share or the human's share.

## The injection kill chain: independent cuts

An injected instruction such as "exfiltrate the org's billing data and wire funds" is cut at several layers independently. Any one suffices.

| Cut | Layer | Mechanism |
|---|---|---|
| 1 | L1 plan inclusion | The action is not a node of the committed plan, so there is no inclusion proof. It is rejected before credentials are read. |
| 2 | L4 taint | If the instruction entered through untrusted content, the action's lineage is tainted, `r` rises, and the action requires step-up or is refused. |
| 3 | L2/L3 threshold | A high-blast-radius, irreversible action has `r > θ₂` and requires the human share, which the compromised agent cannot produce. |
| 4 | L0 attestation | If the adversary swapped or fine-tuned the model to be more compliant, the weights digest changes and the identity is void. |

## Attack table

| Attack | Why it fails |
|---|---|
| Exfiltrated agent credential | No bearer token. The capability is bound to the holder key; a leaked chain is inert without a valid signature and threshold shares. |
| Prompt injection to a rogue action | Not in the plan commitment; taint raises risk; the Policy VM will not cosign. |
| Swapped or fine-tuned model | Attestation measurement changes; identity void (when attestation is enforced). |
| Confused deputy | The action is bound to a committed plan node and the lineage is taint-gated. |
| Compromised agent attempts a high-risk act | Short of the threshold without the human share. |
| Rogue or over-privileged sub-agent | Chain attenuation: `sub ⊂ parent`, depth-capped by caveat. |
| Replay or reorder of a captured PCActn | Strictly increasing per-holder counter; signed canonical body. |
| Repudiation | Every allowed action is signed and anchored in the ledger. |
| Mass or fleet compromise | Freeze or stop beacons. |
| Stale authority after revocation | Non-membership proof required for every capability in the chain. |
| Resource server learns private intent | Compliance proofs carry only commitments ([optimistic and ZK](../concepts/optimistic-and-zk.md)). |
| Griefing an honest optimistic claim | The challenge endpoint takes no challenger-supplied policy inputs; it re-adjudicates from the agent's recorded context. |
| Operator rewrites history | Append-only Merkle log with consistency proofs and witnessed heads. |
| Tampered grant | The envelope is a caveat of the root capability, covered by the root signature. |

## Defense-in-depth matrix

The layer that stops each compromise level:

| Compromise level | Stopped by |
|---|---|
| Benign bug, wrong tool | L1 plan inclusion |
| Prompt injection (in-band) | L4 taint gate and L1 |
| Prompt injection to a high-risk act | L2/L3 human-share threshold |
| Model swap or malicious fine-tune | L0 weights-level attestation |
| Agent RCE or key extraction | L0 TEE binding and L2 missing shares |
| Malicious operator (insider) | L5 transparency ledger and third-party witnesses |

## Out of scope

- A principal who authorizes a harmful plan and approves its step-ups. PCA bounds and records authority; it does not judge intent.
- Compromise of the principal's root key or the guardian key (see [Trust model](./trust-model.md)).
- Side channels in a given implementation.
- Semantic distance as a measure of "meaning": the deterministic plan-graph geodesic is a proxy, and embedding distance is advisory only.

Next: [Trust model](./trust-model.md).
