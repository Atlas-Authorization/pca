---
title: Ledger and revocation
order: 7
---

# Ledger and revocation

L5 is the accountability substrate: a principal-owned transparency log of every action, targeted revocation that a verifier checks offline, and a dead-man kill switch.

## Transparency ledger

`TransparencyLedger` is a per-principal, append-only Merkle log in the Certificate Transparency lineage (RFC 6962 tree shape, RFC 9162 consistency verification).

### Salted commitments

Each entry is a **salted commitment**, not plaintext:

```
commit = hashCanonical({ salt, pcactn_digest })      // pcactn_digest = hashCanonical(pcactn)
leaf   = SHA-256(0x00 || canonical(commit))           // the commit string alone
```

The Merkle leaf is the commit only, so the tree and every proof are independent of the *opening* (`{ salt, pcactn }`). The principal or operator holds the openings and can reveal specific entries to an auditor (`verifyOpening(commit, opening)`) without revealing the rest.

```ts
const ledger = new TransparencyLedger(principalPublic);
const { index, commit } = ledger.append(pcactn);          // optional { salt } for determinism
const head = ledger.head();                                // { size, root }; empty log root = SHA-256("")
const proof = ledger.inclusionProof(index);
verifyLedgerInclusion(head.root, proof, commit);           // true
```

### Proofs

| Need | API |
|---|---|
| An action is in the log | `inclusionProof(i)`, `verifyLedgerInclusion(root, proof, commit)` |
| The log only grew (nothing rewritten or dropped) | `consistencyProof(oldSize, newSize)`, `verifyLedgerConsistency(oldRoot, newRoot, proof)` (RFC 9162 section 2.1.4.2; never throws) |
| Historical root | `rootAt(size)` |
| Storage tamper detection | `auditOpenings()` lists indices whose opening no longer matches its commit |

### Witnessing and split-view detection

`witnessHead(guardianSecret)` signs the current head `{ principal, size, root }` (domain `atlas-pca/ledger-head/v1\0`). `verifyWitnessedHead(wh, witnessPublic)` checks it. `detectEquivocation(a, b, witnessPublic)` returns true when two validly witnessed heads from the same witness, for the same principal and size, have different roots: proof of a split view. Cross-size inconsistency is caught with consistency proofs. Third-party witnesses co-signing heads is how an operator is prevented from showing different principals different histories.

### Crypto-shredding

`shred(index)` destroys an entry's opening (salt and PCActn) while keeping its commit. The content is cryptographically unrecoverable (right to erasure), but the leaf, the root and every inclusion and consistency proof are unchanged, so tamper evidence survives. Two properties normally in tension are both preserved.

On the hosted surface the entries listing reports `shredded: true` for an entry without an opening. Shredding is a library operation; no public HTTP route shreds in this release.

## Revocation

Revocation must be checkable by the resource server **offline**, with no phone-home on the hot path. `revocation.ts` implements the revocation set as a **sorted Merkle set**, deterministic and free of RSA moduli or trusted setup.

- Leaves are the revoked ids in ascending order (UTF-16 code units) in an RFC 6962 shaped tree.
- The published root binds the set size: `root = SHA-256("pca-revset/v1\0" || canonical({ size, tree }))`. The empty tree is `SHA-256("")`.
- **Membership**: an ordinary inclusion proof (`verifyMembership`).
- **Non-membership** (`verifyNonMembership(root, proof, id)`): because leaves are sorted, `id` is absent iff two **adjacent** leaves `lo < id < hi` are both proven included at consecutive indices, or `id` is below the first leaf, above the last, or the set is empty. Leaf positions are verified from the proof path shape, with index and size bound by the root, so a prover cannot pass off non-adjacent leaves as neighbours. A revoked id has no bracketing pair and therefore no valid proof.

```ts
const set = new RevocationSet();
set.revoke(capId);                           // idempotent, returns true when newly revoked
set.root;                                    // current root
const proof = set.nonMembershipProof(other); // throws if `other` IS revoked

const hook = createRevocationChecker({
  root: () => trustedRevocationRoot,         // MUST come from a trusted, fresh source
  proofFor: (id) => proofs.get(id),
});
```

`createRevocationChecker` checks, by default, **every capability id in the PCActn's chain**, so revoking an ancestor kills all descendants. It fails closed: a missing root, a missing proof, or a revoked id each reject.

**Freshness caveat.** A proof is against a specific root. Verifiers must take the current root from a trusted, fresh source (for example a guardian-signed or witnessed epoch root); a stale root cannot show later revocations.

On the hosted surface, `POST /v1/pca/revocations` adds a capability id under a grant; revoking the grant's own id (the `grant_ref`) revokes the whole grant. The server builds the non-membership proofs itself on each action.

## Dead-man beacons and the kill switch

`beacons.ts`: the guardian signs short-lived beacons `{ v, scope, epoch, not_after, guardian, sig }` (domain `atlas-pca/beacon/v1\0`). Authority is live only while a valid beacon covers the current epoch. If the principal stops issuing beacons, every agent freezes by the next, short epoch.

| Function | Purpose |
|---|---|
| `issueBeacon({ guardianSecret, epoch, scope?, notAfter })` | Sign a beacon; scope `'*'` (`GLOBAL_SCOPE`) covers everything |
| `verifyBeacon(beacon, guardianPublic, nowEpoch, scope?)` | Signature against the pinned guardian key, freshness window, optional scope coverage |
| `isFrozen(beacons, nowEpoch, guardianPublic, scope?)` | Frozen when **no** valid beacon covers the epoch. Absence of beacons is a freeze. |

Epochs are integers supplied by the caller. Beacons are a library capability. The hosted surface exposes a simpler kill switch: `POST /v1/pca/freeze` denies every PCActn for the instance until `DELETE /v1/pca/freeze` clears it.

## Putting the controls together

| Want to stop | Use | Reach |
|---|---|---|
| One capability or sub-agent | Revoke its capability id | Targeted; descendants die with it |
| A whole grant | Revoke the `grant_ref` | Every chain under the grant |
| Everything on an instance now | `freeze` | Instance-wide, immediate |
| Everything, passively | Stop beacons | Effective by the next epoch |

Next: [Optimistic authorization and ZK](./optimistic-and-zk.md).
