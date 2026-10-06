---
title: Glossary
order: 22
---

# Glossary

| Term | Meaning |
|---|---|
| **authN / authZ / authF** | Who are you / what may you do / is this action a faithful execution of conferred authority. See [authF](../concepts/authf.md). |
| **Principal (P)** | The human or owning organization that is the source of authority. Holds the root key. |
| **Agent (E)** | The autonomous process acting under a capability. May spawn sub-agents with strictly lesser authority. |
| **Guardian (G)** | The service that holds a threshold signing share and runs the Policy VM. In the hosted surface, Atlas. |
| **Resource server (RS)** | The service holding the protected resource; verifies PCActns offline. |
| **Root Intent Grant (G)** | The principal-signed root capability whose `envelope` caveat carries goal commitment, predicates, caveats, agent binding and risk policy. |
| **Envelope** | `{ goal_commit, predicates, caveats, agent_binding, risk_policy }`, the policy a grant carries. |
| **Capability** | A signed, hash-linked hop `{ id, issuer, holder, caveats, parent, body_digest, sig }`. |
| **Capability chain** | Root to leaf capabilities. Caveats can only be appended (attenuation). |
| **Attenuation** | Narrowing authority by adding caveats. Widening is impossible by construction. |
| **Holder (`cnf`)** | The key a capability is bound to; signatures for actions must verify under the leaf holder. |
| **Caveat** | A conjunctive constraint on a capability: `expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, plus the `envelope`. |
| **Predicate** | A data-only rule over verb, resource and conditions that permits an action. Default deny. |
| **Plan (Π)** | A DAG of intended `PlanNode`s committed by Merkle root (L1). |
| **Plan commitment** | The Merkle root of the plan's leaves. |
| **Inclusion proof** | A Merkle path proving a leaf is in a committed tree. |
| **PCActn** | Proof-carrying action: the wire object an agent presents per action. |
| **Policy VM** | `decide()`: the deterministic evaluator that releases or withholds the guardian share. |
| **Risk functional `r(A)`** | The clamped weighted sum of semantic distance, irreversibility, blast radius, taint, uncertainty and age. |
| **Semantic distance** | Normalized geodesic between an action's node and the goal node in the plan DAG. |
| **Threshold `t`** | Number of distinct role signatures required: 1, 2 or 3, monotone in `r`. |
| **Share** | One role's signature over `thresholdMessage(pcactn)`. |
| **Step-up** | Holding an action for the principal-device share when `t = 3`. |
| **Trust budget `B`** | A decaying allowance debited `κ·r` per auto-admitted action; recharged only by a human. |
| **κ, λ, ρ, bMax** | Cost scale, passive leak per second, recharge per human co-sign, budget cap. |
| **θ₁, θ₂** | Risk thresholds for `t = 1`, `t = 2` and `t = 3`. |
| **Safety bound** | `Σ r ≤ bMax / κ` between human recharges. |
| **FROST** | RFC 9591 Schnorr threshold signatures; aggregates `t` shares into one Ed25519 signature under a group key. |
| **DKG** | Distributed key generation: producing group-key shares with no trusted dealer (PedPoP). |
| **Attestation (L0)** | A document or hardware quote binding an agent to a model, weights digest, runtime measurement and operator. |
| **Agent binding** | The grant's attestation policy: `model_allowlist`, `min_measurement`, `operator`, `weights_allowlist`. |
| **Taint** | The fraction of an action's causal lineage derived from untrusted content (L4). |
| **Transparency ledger** | Per-principal append-only Merkle log of salted commitments to PCActns (L5). |
| **Crypto-shredding** | Destroying an entry's opening so its content is unrecoverable while proofs stay valid. |
| **Revocation set** | A sorted Merkle set of revoked capability ids supporting offline non-membership proofs. |
| **Beacon** | A short-lived guardian-signed freshness token; absence freezes authority (dead-man switch). |
| **Freeze** | The hosted instance-wide kill switch that denies every PCActn. |
| **Optimistic claim** | A bonded, signed claim of compliance for a reversible action, challengeable within a window (9A). |
| **Fraud proof** | A recomputable demonstration that a claim was false; slashes the bond. |
| **Compliance statement** | An attested-VM signed assertion that the Policy VM released an action, carrying only commitments (9B). |
| **Conformance suite** | Golden vectors for the core verification, used to certify independent verifiers. |
| **Reachable-action theorem** | The set of actions a compromised agent can get accepted is bounded by plan, envelope, taint policy and threshold. See [Threat model](../security/threat-model.md). |

Next: [Threat model](../security/threat-model.md).
