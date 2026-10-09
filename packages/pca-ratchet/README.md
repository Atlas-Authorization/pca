# @atlasauth/pca-ratchet

The PCA Capability Ratchet: two cryptographic primitives that replace bookkeeping in Proof-Carrying Authority with math.

1. **Puncturable forward-secure capability keys.** A GGM puncturable-PRF tree of one-time Ed25519 leaf keys under a Merkle-root commitment. Signing at a leaf permanently punctures it, so a spent action can never be re-signed (cryptographic one-time-use instead of a server-side counter check).
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
- Adapters: `counterToLeafIndex`, `leafIndexToCounter`, `leafIndexForAction`, `riskToUnits`, `budgetCeilingUnits`, `RISK_SCALE`.

## Status

Experimental. The cryptography here (GGM tree, Pedersen commitments, bit-decomposition range proof) is original and has **not** been independently audited; do not rely on it as the sole control for high-value actions. One-time-use holds only for the holder of the `RatchetState`: if a state is copied or restored from an old backup, spent leaves are available again, so persist the latest state atomically.

## License

MIT - see LICENSE
