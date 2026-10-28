---
title: Optimistic authorization and ZK
order: 8
---

# Optimistic authorization and zero-knowledge compliance

Two optional accelerants. The first reduces latency; the second hides intent from the resource server. Both are additive: a deployment that uses neither still has the full core.

## 9A: Optimistic authorization with fraud proofs

Verifying every clause per action costs time. Borrowing the mechanics of optimistic rollups, a **reversible** action can proceed immediately on a cheap **signed claim of compliance**, backed by a **bond**. A **challenge window** then lets the guardian or principal prove the claim was false. If it was, the bond is slashed and the reversible effect is rolled back. The result is human-latency autonomy with economic accountability. **Irreversible actions never go optimistic**: they take the full threshold path.

### The claim

```ts
interface BondedClaim {
  pcactn_digest: string;        // the action this claim covers
  bond_ref: string;             // opaque handle to the posted bond
  claimed_r: number;            // the risk the agent claims
  reversibility_class: string;  // must not be 'irreversible'
  issued_at: number;            // ms
  challenge_window_ms: number;
  sig: string;                  // agent-leaf signature over the canonical body
}
```

| Function | Purpose |
|---|---|
| `openOptimistic(pcactn, { bondRef, claimedR, challengeWindowMs, issuedAt? }, signerSecret)` | Mint and sign a claim. **Throws** for an irreversible action. |
| `verifyClaim(claim, pcactn, signerPublic)` | Signature valid, claim covers this PCActn, not irreversible. It does **not** judge policy; that is a fraud proof's job. |
| `withinChallengeWindow(claim, now)` / `challengeWindowEnd(claim)` / `claimStatus(claim, now)` | Timing. Challenges are accepted while `now <= issued_at + challenge_window_ms`; afterward the claim is `finalized`. |

### Fraud proofs

A fraud proof is convincing only because it is **recomputable**, not because the challenger asserts it. `fileFraudProof({ claim, pcactn, grant, actualDecision, decideInput })` builds one from the Policy VM inputs; `verifyFraudProof(claim, proof, grant)` **re-runs `decide`** under the grant the *verifier* trusts, confirms the recomputed decision matches the one asserted, and confirms it genuinely refutes the claim. A claim is fraudulent when any of:

| `FraudKind` | Condition |
|---|---|
| `irreversible` | The action is irreversible (never eligible) |
| `policy-denied` | The Policy VM does not release the guardian share |
| `optimistic-not-allowed` | At the real risk the optimistic path is not permitted (for example `r` crossed θ₁) |
| `risk-understated` | Real `r` exceeds `claimed_r` by more than a margin |

`verifyFraudProof` returns `{ fraudulent, slashBondRef?, reason }`. It yields the verdict and the bond to slash. Settlement is a separate layer (internal accounting only; no money moves). For anything beyond a test, use `StoreBondLedger`, which commits each transition atomically to a durable `BondStore`, makes every retry safe and runs the challenge window on its own clock ([guide](../guides/optimistic-bonds.md)). The Map-backed `BondLedger` (test double, `@atlasauth/pca/ext/optimistic-testing`) is the reference for the decisions: it locks a bond in escrow when a claim opens, releases it when the window closes unchallenged, and slashes it only after re-verifying the fraud proof itself (a challenger's assertion is never enough). A slash is split between the challenger's reward account, a victim compensation pool and a treasury (`computeSlashSplit`), and every transition is a guardian-signed settlement record (`verifySettlement`). The library's accounts are in memory (`InMemoryBondAccount`); persist them in your own store. **Rolling back effects** is not part of PCA: undoing a reversible effect after a slash is the application's job.

### Hosted behavior

`POST /v1/pca/actions` accepts an optional `optimistic` claim. It is honored only for a non-irreversible action; the claim is verified up front (a bad claim is a `400` before the counter is consumed). The action still goes through the normal adjudication; the claim is recorded only when the action is allowed at `t <= 2`. The response then carries `optimistic: true`, a `claim_id` and the `challenge_window_ms`.

- `GET /v1/pca/claims/:id` returns the claim; a claim whose window closed unchallenged becomes `expired` (settled by silence).
- `POST /v1/pca/claims/:id/challenge` triggers a **re-adjudication**. The challenger supplies no policy inputs. The server re-runs the decision from the context the **agent itself recorded**, against the **current** grant, revocation set and time. It slashes only if that server-derived evaluation contradicts the claim, or if a capability in the chain has been revoked since the claim opened. An optional `reason` is audit metadata and never affects the outcome, and an optional `reward_account` only says where the challenger's share of a slash is paid. This makes the public endpoint grief-proof: an anonymous caller cannot inflate risk to slash an honest claim.

The hosted surface escrows bonds on its own internal ledger. A claim opens only when the depositor (the grant's principal) has funded a bond-account balance at least the bond the server sizes from the action's risk; otherwise the action is adjudicated normally without the fast path. A slash moves the bond out of escrow and splits it in the same transaction as the status change and the signed settlement record. These balances are internal accounting; no external payment rail is connected. See [API reference](../reference/api.md) and [Trust model](../security/trust-model.md).

## 9B: Zero-knowledge proof of compliance

The agent proves "action A is a valid derivation under policy P from committed plan Π" **without revealing P, Π, or its reasoning** to the resource server. The server learns only "authorized". The principal's intent stays private from the very service enforcing it.

`zk.ts` supports two realizations behind one hook, `createZkVerifier(opts)`:

| Mode | How it works | Trust |
|---|---|---|
| **SNARK / STARK** | `snarkBackend.verify({ proof, publicInputs, ctx })`. Two Groth16 backends ship: `createGroth16SnarkBackend` (BN254, the compliance circuit: commitment openings plus the release decision, i.e. plan membership and risk within budget) and `createPolicyVmSnarkBackend` / `createPolicyVmSnarkBackendBls12381` (BN254 or BLS12-381, a quantized Policy VM circuit: risk functional, threshold ladder, one predicate, the built-in numeric caveats and chain narrowing). Provers: `proveGroth16Compliance`, `provePolicyVmCompliance`. Transparent STARK provers (Winterfell, Plonky3) and a RISC Zero zkVM port of the release gate are available as Rust crates. | Soundness of the circuit (Groth16 also trusts its setup) |
| **Attested-VM** (implemented) | `createAttestedComplianceProver(secret).prove({ pcactn, decideInput, issued_at, expires_at })` runs the Policy VM inside a trusted attested VM and signs a `ComplianceStatement` that the VM released the guardian share. | The prover VM's key |

In both modes the verifier sees only **commitments**:

| Commitment | Definition |
|---|---|
| `action_commit` | `hashCanonical(pcactn.action)` (`actionCommitment`) |
| `policy_commit` | The grant's content address (`policyCommitment(grant)`), binding to the whole envelope without exposing it |
| `plan_commit` | The PCActn's `plan.root` |

The statement is `{ v: 1, mode: 'attested-vm', action_commit, policy_commit, plan_commit, released: true, r, issued_at, expires_at, prover, sig }`, carried in `pcactn.zk_compliance`. You cannot prove a false statement: `prove` throws when the action is not compliant.

The attested-VM verifier checks that the `prover` key is in `trustedProverKeys`, the signature, freshness, and that the three commitments bind to this action, plan and an expected policy. Supply `policyCommitments` (bare hashes) to enforce policy the resource server is not allowed to read (`pinnedPolicyCommitment(grant)` computes one); without them it derives the commitment from the grant it already holds, which is not private.

What the circuits do not cover: the compliance circuit proves the decision subset, not the whole policy; the Policy VM circuit proves a quantized, fixed-layout version of the policy (one numeric `where` bound, the built-in caveats), so arbitrary predicates and custom caveats stay outside it; and its commitments are SHA-256 over a fixed-layout struct, not the canonical-JSON commitments above, so bind it to the live action with its expected struct hashes. The STARK crates are not zero-knowledge (their traces are not blinded): they give soundness and succinctness, not witness privacy.

A PCActn that carries `zk_compliance` when the verifier has no ZK hook fails the `zk_compliance` check; it is never ignored.

The hosted `/v1/pca/actions` wires the ZK hook when the instance configures it: attested-VM mode with trusted prover keys, or SNARK mode with the Policy VM verifying key (optionally bound to the live action). Without that configuration, an action carrying a compliance proof is denied. Resource servers running `verifyPCActn` themselves pass `hooks.zk`.

## Attested-VM mode: a trusted signer, not a proof

Attested-VM mode is **not a zero-knowledge proof and not a proof of anything**. It is a statement signed by a prover key that your server trusts: "the Policy VM ran inside a machine I trust and released the guardian share for this action". If that key is stolen, or the machine lies, the statement is still valid. What the mode does give you is **privacy** (the verifier sees only three commitments, never the policy or plan) and **binding** (the statement is tied to this action, this plan and an expected policy, inside a validity window). Its verdict is labelled `attested_vm`, or `attested_vm_hw` when you also configure `proverAttestation` (hardware evidence that the prover key lives in a VM with an allowlisted measurement). It is never reported as `snark`, and a policy of `{ zk: 'snark' }` refuses it.

```ts
import { createAttestedComplianceProver, createZkVerifier, policyCommitment } from '@atlasauth/pca/ext/zk';

const prover = createAttestedComplianceProver(proverSecret);             // inside your trusted VM
pcactn.zk_compliance = prover.prove({ pcactn, decideInput, issued_at: now - 1_000, expires_at: now + 60_000 });

const zk = createZkVerifier({
  trustedProverKeys: [prover.publicKey],
  policyCommitments: [policyCommitment(grant)],                           // bare hashes: enforce a policy you may not read
  now: () => Date.now(),
});
```

**Rotation and revocation.** Add the new key to `trustedProverKeys`, put the old one in `revokedProverKeys` (a revoked key is denied even while still trusted), and drop it once its statements have expired.

**Failure modes.** Every row is a denial with this reason; none is a pass.

| If this is missing, stale or wrong | Result |
|---|---|
| No `zk_compliance` member | `no zk_compliance proof present` |
| A statement of another version or mode | `unrecognized compliance statement` |
| A statement that does not assert release | `statement does not assert release` |
| A prover key that is not trusted, or no trusted keys | `prover key is not trusted` |
| A revoked prover key | `prover key is revoked` |
| A body edited after signing, or no signature | `compliance statement signature does not verify` |
| A validity window that ends before it starts | `malformed statement validity window` |
| An expired statement, or one not yet valid (beyond the configured skew) | `compliance statement expired`, `compliance statement not yet valid` |
| A statement replayed on another action or another plan | `statement does not bind to this action`, `statement does not bind to this plan commitment` |
| A policy commitment that is not in your expected list (or an empty list) | `statement policy commitment is not an expected policy` |
| With `proverAttestation`: evidence invalid, not bound to the prover key, no measured identity, or a measurement not on your allowlist | `prover hardware evidence invalid: ...`, `... does not bind the prover key`, `... carries no measured identity`, `prover VM measurement is not allowlisted` |
| With `proverAttestation`: the hardware verifier throws or returns nothing | `zk verification error (fail closed): ...`, `prover hardware evidence invalid: no result` |
| A software or unlabelled hardware verifier, or an empty measurement allowlist | The verifier refuses to be built |

**Limits.** The prover key is a single point of trust. The hardware-bound variant is only as strong as the vendor verifier and the measurement you allowlisted. The prover cannot sign for an action the Policy VM would not release, but a compromised prover can sign anything. The Groth16 and Policy-VM SNARK modes in the same module are a separate construction: they carry a trusted setup and await an independent review and a ceremony, which is why the module stays below production.

Next: [Agent quickstart](../guides/agent-quickstart.md).
