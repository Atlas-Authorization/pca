# @atlasauth/pca-ratchet

> Maturity: **hardened** (hardened, awaiting independent audit). The engineering is done and evidenced by tests, a known-answer corpus, fuzz targets and a mutation gate; it awaits an independent cryptographic review (the GGM puncturable-key construction, the Pedersen range proof and the nullifier binding are this project's own composition of standard parts). It is never production until that review is done, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The PCA Capability Ratchet: two cryptographic primitives that replace bookkeeping in Proof-Carrying Authority with math.

1. **Puncturable forward-secure capability keys.** A GGM puncturable-PRF tree of one-time Ed25519 leaf keys under a Merkle-root commitment. Signing at a leaf punctures it, so once the state has been erased a spent action cannot be re-signed by an adversary who obtains only the new state. A copy of the state taken BEFORE the signing can sign the same leaf again (nothing in a stateless verifier marks the second signature invalid): use `verifyLeafSignatureOnce` with a spent-leaf store for one-time use at the verifier. Adapters round risk up, so a nonzero risk never costs zero units.
2. **Homomorphic risk accumulator.** Pedersen commitments on ristretto255 plus a zero-knowledge range proof that the committed total risk stays at or under a budget ceiling, without revealing individual risks.

Small adapters map a PCActn `counter` to a leaf index and core risk scores to accumulator units.

## Install

```sh
npm i @atlasauth/pca-ratchet @atlasauth/pca
```

## Usage

```ts
import {
  deriveRatchetRoot, signAtLeaf, verifyLeafSignature, isLeafAvailable,
  commitRisk, addCommitments, proveBudget, verifyBudget,
  counterToLeafIndex, riskToUnits,
} from '@atlasauth/pca-ratchet';

// 1. One-time-use keys: 2^4 = 16 leaves under one root commitment.
const seed = crypto.getRandomValues(new Uint8Array(32));
const { rootCommitment, state } = deriveRatchetRoot(seed, 4);

const msg = new TextEncoder().encode('transfer 10 USDC');
const leaf = counterToLeafIndex(3, 4);
const { signature, newState } = signAtLeaf(state, leaf, msg); // state is immutable; keep newState
verifyLeafSignature(rootCommitment, leaf, msg, signature);    // true (offline, root only)
isLeafAvailable(newState, leaf);                              // false
signAtLeaf(newState, leaf, msg);                              // throws RatchetError code 'leaf_punctured'

// 2. Budget proof: total risk <= 1000 units, individual risks hidden.
const risks = [riskToUnits(0.2), riskToUnits(0.35)];
const commits = risks.map((r) => commitRisk(r));
const sum = addCommitments(commits.map((c) => c.commitment));
const proof = proveBudget(risks, commits.map((c) => c.blinding), 1000);
verifyBudget(sum, 1000, proof); // true
verifyBudget(sum, 500, proof);  // false
```

## API

- Ratchet: `deriveRatchetRoot`, `signAtLeaf`, `verifyLeafSignature`, `availableLeaves`, `isLeafAvailable`, `RatchetError`, `MAX_RATCHET_DEPTH`.
- Accumulator: `commitRisk`, `addCommitments`, `openCommitment`, `proveBudget`, `verifyBudget`, `AccumulatorError`, `N_BITS`.
- Adapters: `counterToLeafIndex`, `leafIndexToCounter`, `leafIndexForAction`, `riskToUnits` (rounds UP: a nonzero risk is never 0 units), `RiskQuantizer` (carries the sub-unit remainder so the running total is `ceil(true sum)`), `budgetCeilingUnits` (floors), `RISK_SCALE`.
- Verifier-side bindings (red-team RT-11): `leafNullifier`, `verifyLeafSignatureOnce` with a `SpentLeafStore` (`memorySpentLeafStore`, or implement over a shared store) returns `ok` / `replay` / `equivocation` (same leaf, different message: evidence of a holder that kept an old state) / `invalid` / `store-error`. `issueRiskCommitment`, `verifyRiskAttestation`, `verifyAttestedBudget`: the party that computes the risk commits to it and signs `(actionDigest, commitment)`, so a prover cannot commit 0 for a 1.0-risk action or move a commitment to another action.

## Fail-closed table

Every row is pinned by a test that asserts the exact outcome.

| Missing or wrong | Result |
|---|---|
| Depth not an integer in range | `RatchetError` `invalid_depth` |
| Seed shorter than 32 bytes or not bytes | `RatchetError` `invalid_seed` |
| Leaf index negative, fractional, NaN or past the end | `RatchetError` `leaf_out_of_range`, state unchanged |
| Leaf already spent in this state | `RatchetError` `leaf_punctured` |
| State restored from an old backup, leaf signed again | the signature verifies alone; `verifyLeafSignatureOnce` returns `replay` (same message) or `equivocation` (different message) |
| Nullifier missing or taken from another root | `verifyLeafSignature` false; `verifyLeafSignatureOnce` `invalid`, and the leaf is not burned |
| Spent-leaf store throws or rejects | `store-error` (deny) |
| Risk or ceiling negative or fractional | `AccumulatorError` `invalid_value` |
| Risks and blindings of different length | `AccumulatorError` `length_mismatch` |
| Total over the ceiling, wrong ceiling, malformed commitment or truncated proof | `verifyBudget` false |

## Limits

No post-compromise security: whoever steals the current state can sign every unspent leaf. Forward security needs the caller to discard the old state, which JavaScript cannot enforce. The accumulator is not post-quantum (ristretto255), and the budget ceiling is capped at the proof width.

## Status

Hardened, awaiting audit. The cryptography here (GGM tree, Pedersen commitments, bit-decomposition range proof) is original and has been self-audited in tests (see the security audit in the PCA docs) but **not** independently audited; do not rely on it as the sole control for high-value actions. One-time-use is enforced by the key material only for an honest holder of the `RatchetState`; a verifier that wants it against a dishonest holder must use `verifyLeafSignatureOnce` with a spent-leaf store (Ed25519 here is deterministic, so a second signature does NOT reveal the key: reuse is detected by the verifier, not punished cryptographically, and the store must be shared and durable across the verifier fleet). Without a store, if a state is copied or restored from an old backup, spent leaves are available again, so persist the latest state atomically. `RatchetSignature` now carries a `nullifier` and `verifyLeafSignature` requires it (breaking: signatures made by earlier versions no longer verify). Commitments are only bound to the real action when issued through the attestation helpers; `verifyBoundedBudget` alone proves a property of whatever the prover committed. `verifyBudget` alone constrains only the SUM: use `proveRiskRange` per commitment and `verifyBoundedBudget` so a "negative" risk cannot cancel real risk.

## License

MIT - see LICENSE
