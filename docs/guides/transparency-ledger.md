---
title: The transparency ledger and its witnesses
order: 10
---

# The transparency ledger and its witnesses

> **Status: experimental (hardened).** The engineering is finished and tested; there has been no independent audit, and no independent witness is operated by the project. The ledger lives under `@atlasauth/pca/ext/ledger` and is not part of PCA Core. See [maturity tiers](../maturity.md).

## What you get, and what it depends on

The ledger is an append-only Merkle log (the tree shape of RFC 6962, with the consistency proofs of RFC 9162). The guardian signs **checkpoints**: the size and root of the log at a moment. Anyone holding a checkpoint can later ask for a **consistency proof** and learn whether the log they see now still contains everything it contained then.

**The claim is tamper evidence, given at least one honest independent witness.** A witness is a separate party that cosigns a checkpoint only if it is consistent with the last one it cosigned. If you require your checkpoints to carry a cosignature from a witness you trust, an operator who rewrites history, truncates the log or shows two readers two different logs cannot produce a checkpoint you will accept.

Two things stay outside the claim:

- **Without an independent witness** the operator can still show non-communicating readers different logs. Witnesses are what turn a log into evidence. See [Operate a ledger witness](./operate-a-witness.md).
- **Censorship is not detectable.** An operator who never appends an entry leaves no trace in the log. A resource server that needs a record must demand an inclusion proof against a witnessed checkpoint before it acts.

## Quick start

```ts
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { KvLedgerStore, StoredLedger, cosignTreeHead, verifyCheckpointChain, verifyLedgerConsistency, verifyLedgerInclusion } from '@atlasauth/pca/ext/ledger';

const guardian = generateKeyPair(); // signs checkpoints
const witness = generateKeyPair(); // an independent party in real life
const guardianPublic = encodeKey(guardian.publicKey);

// Use openDurableState({ dir }) from '@atlasauth/pca/durable-state' in production: the log must survive the process.
const ledger = await StoredLedger.open({
  store: new KvLedgerStore(createMemoryDurableKv()),
  guardianSecret: guardian.secretKey,
  instanceId: 'prod-1',
  principal: 'grant-1',
});

// entries are opaque commitments: the PCActn or settlement record they stand for stays with its owner
for (let i = 0; i < 5; i++) await ledger.append(`entry-commitment-${i}`);
const first = await ledger.checkpoint(); // signed head: size 5
for (let i = 5; i < 12; i++) await ledger.append(`entry-commitment-${i}`);
const second = await ledger.checkpoint(); // size 12; refused if it is not consistent with the first

// an auditor with only the first checkpoint asks for a proof that the log still extends it
const proof = ledger.consistencyProofFrom(first.size);
console.log(verifyLedgerConsistency(first.root, second.root, proof)); // true

// a proof that entry 3 is in the log the second checkpoint describes
console.log(verifyLedgerInclusion(second.root, ledger.inclusionProof(3), 'entry-commitment-3')); // true

// a witness cosigns the heads; a client that insists on a witness refuses heads without one
const withWitness = (h: typeof first) => ({ ...h, witnesses: [cosignTreeHead(h, witness.secretKey)] });
const policy = { witnessKeys: [encodeKey(witness.publicKey)], threshold: 1 };
console.log(verifyCheckpointChain([{ sth: withWitness(first) }, { sth: withWitness(second), proof }], guardianPublic, policy).ok); // true
console.log(verifyCheckpointChain([{ sth: first }, { sth: second, proof }], guardianPublic, policy).ok); // false: no cosignature
```

## Checkpoints are verified at every boundary

`StoredLedger.open` rebuilds the Merkle tree from the stored entries and checks it against **every** stored checkpoint: the guardian's signature, the signed `prev_root` chain, the consistency proof between each pair, and that the entries reproduce each checkpoint's root. `checkpoint()` signs a new head only after the same check passes with the new head included, and only after proving the store still holds exactly the entries this handle is about to sign over.

| What the store did | `open` / `checkpoint` result |
|---|---|
| lost entries after a checkpoint | `rollback` |
| edited, inserted or reordered an entry | `tamper` |
| holds a checkpoint with a bad signature, another log's name, or signed by another key | `forged_checkpoint` |
| holds two checkpoints whose proof does not connect them | `inconsistent` |
| returns malformed data | `store_corrupt` |
| fails or is unreachable | `store_unavailable` |
| a post-quantum `suite` with no `pin` for the guardian, or an unknown suite name | `pin_missing` (at open) |

Checkpoints can be signed with a post-quantum or hybrid suite: pass `suite` (the key material) and `pin` (`{ pqPins: { <guardian identity>: <its ML-DSA public key> } }`); every stored checkpoint is then verified under the pin, and a pin that does not match the signing key is refused (`forged_checkpoint`) before anything is stored.

`verifyCheckpointChain` is the same check for a party that holds only checkpoints and proofs. It names the first boundary that fails (`at`) and why: `head` (a head does not verify), `proof_missing`, `inconsistent`, or `empty`.

## The store contract

`StoredLedger` needs a `LedgerStore`. Its two writes are compare-and-swap on the current length: `append(expectedSize, commits)` succeeds only when the log has exactly `expectedSize` entries, all of the batch or none of it, so two writers can never take one position and a log never has holes. The same batch at the same position is a replay. `appendCheckpoint` is the same on the checkpoint count, and also refuses a checkpoint beyond the end of the log or one that goes backwards. Acknowledged writes survive a restart or a crash; a write in flight at the crash is whole or absent.

`KvLedgerStore` is the reference, one document in a `DurableKv`. It is bounded (about twenty thousand entries per MiB of document); past that it refuses the write. A production log is a database table with a unique index on the position.

Check your own store:

```ts
import { describeLedgerStoreConformance, durableLedgerStoreAdapter } from '@atlasauth/pca-store-conformance';
describeLedgerStoreConformance(durableLedgerStoreAdapter()); // one test per claim: racing writers, batches, crashes
```

## Beacons: freezing everything

Liveness beacons let an issuer freeze every agent by stopping. A beacon is valid from 30 seconds before its issue time (clock skew) through its `not_after` inclusive, lives at most an hour, and is accepted only with a strictly higher sequence number than the last one accepted for the same instance, scope and issuer. `createBeaconAcceptor` keeps that number durably, so a restart cannot be used to replay an old beacon over a newer one. It refuses when it cannot tell.

## Wire vectors

Merkle inclusion, consistency proofs, signed tree heads, witness cosignatures, head-to-head consistency and checkpoint chains have shared vectors in the conformance corpus (layer **extension**). The TypeScript, Go, Python and Rust verifiers agree on all of them. The native verifiers handle Ed25519 heads; any other suite is refused as unsupported.

## Limits

- Tamper evidence needs at least one honest witness that is independent of the operator.
- Censorship by omission is not detected.
- The first checkpoint a witness sees is trusted on first use.
- The reference store is for correctness, not scale.
- Independent audit: not done.
