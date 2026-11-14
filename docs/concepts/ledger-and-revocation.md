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

- Leaves are the revoked ids in ascending UTF-8 byte order (Unicode code point order, as for canonical JSON keys) in an RFC 6962 shaped tree.
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

### How stale may revocation state be?

The guardian signs each revocation epoch with `issued_at` and `not_after`. It re-signs at least every 60 seconds (`REVOCATION_EPOCH_REFRESH_MS`), and a signature is valid for 5 minutes (`REVOCATION_EPOCH_VALIDITY_MS`). Without further settings, the signer's `not_after` is the only limit: a verifier accepts a 4-minute-old epoch, so a revocation may take up to 5 minutes to reach it.

A verifier can set its own, stricter limit, based on how much harm a late revocation can do. Nothing changes unless you set one of these options:

| Option | Default when the policy is on | Effect |
|---|---|---|
| `maxRevocationAgeMs` | 5 min | The maximum age (`now - issued_at`) for any action. An older epoch is refused even before its `not_after`. |
| `staleness.costly` | `maxRevocationAgeMs` | The maximum age for `costly` and `rate_limited` actions. |
| `staleness.irreversible` | 2 min (`REVOCATION_IRREVERSIBLE_MAX_AGE_MS`, two refresh periods) | The maximum age for irreversible actions. |
| `allowUnsignedRootForIrreversible` | `false` | An irreversible action needs a guardian-signed epoch. A bare root, which cannot be dated, is refused. |

Per-class limits never exceed `maxRevocationAgeMs`. The class used is the stricter of your own class for the action (from your tool catalog or the authorized plan) and the class the agent signed. A missing or unknown class counts as irreversible.

On the checker:

```ts
const hook = createRevocationChecker({
  epoch: () => latestSignedEpoch,              // from GET /v1/pca/revocations/epoch
  guardianPublic,
  proofFor: (id) => proofs.get(id),
  maxRevocationAgeMs: 120_000,
  staleness: { irreversible: 60_000 },
  reversibilityClass: (ctx) => catalogClass(ctx.pcactn.action.verb),
});
```

With only a bare `root` (no signed epoch), set the policy and supply `rootIssuedAt`: the time your trusted source issued the root. If that time is unknown, the state cannot be verified and every action is denied. Irreversible actions are refused on this path unless `allowUnsignedRootForIrreversible` is set.

On `requirePCA`, pass the same policy as `revocationStaleness`. It caps the age of the epoch from the `revocationEpoch` option. When no signed epoch is available (no `revocationEpoch` option, or the source returned nothing), an irreversible action is denied with `freshness: no verifiable (guardian-signed) revocation state for an irreversible action`. This also applies when `freshness` is left out of `require`. A revocation source that throws makes the guard deny (fail closed).

With these settings, the time a revocation takes to reach a verifier is bounded by the verifier's own limit plus the guardian's refresh period, not only by the signer's `not_after`. A captured pre-revocation epoch replayed to a verifier that already accepted a newer epoch is refused as a rollback. A verifier that never saw the newer epoch, for example after a restart without persisted pins, refuses the old epoch once it is older than the limit.

**Rotating the guardian key.** A verifier checks each epoch against the one guardian key it pins (`guardianPublic`). Once you pin the new key, every epoch signed by the old key is refused, whatever its `not_after`. Until then, an old-key epoch is accepted only within its validity and your age limit. So after a rotation the old key stops working when you update the pin, or at the latest when its newest epoch reaches your age limit.

On the hosted surface, `POST /v1/pca/revocations` adds a capability id under a grant; revoking the grant's own id (the `grant_ref`) revokes the whole grant. The server builds the non-membership proofs itself on each action.

## Dead-man beacons and the kill switch

An issuer (the grant's principal, or the operator) signs short-lived **liveness beacons** `{ v: 2, instance, scope, epoch, seq, issued_at, not_after, issuer, sig }` (domain `atlas-pca/beacon/v2\0`). Authority is live only while a valid beacon covers the current moment. If the issuer stops issuing beacons, every agent freezes by the next, short epoch.

| Function | Purpose |
|---|---|
| `issueLivenessBeacon({ issuerSecret, instance, scope?, seq, issuedAt, validityMs? })` | Sign a beacon; scope `'*'` (`GLOBAL_SCOPE`) covers every grant of the instance. Validity is at most one hour (`BEACON_MAX_VALIDITY_MS`); the epoch is `floor(issued_at / 60 000)` |
| `verifyLivenessBeacon(beacon, { issuers, now, instance, scope? })` | Checks, in this order: instance, pinned issuer, signature, window shape, hard validity cap, epoch, not yet valid (more than 30 s in the future, `BEACON_CLOCK_SKEW_MS`), expired (`now > not_after`), scope coverage. The first failure names the reason |
| `isFrozenLiveness(beacons, check)` | Frozen when **no** beacon verifies. Absence of beacons is a freeze |
| `acceptBeacon(previous, next)` | A beacon replaces the stored one only with a strictly higher `seq`; an equal or lower one is a replay |
| `createBeaconAcceptor(kv)` | The same rule kept durably per (instance, scope, issuer), so a restart cannot be used to replay an old beacon over a newer one; it refuses when the store cannot decide |

A PCActn binds a beacon through its signed `freshness.beacon_ref` (`beaconRef(beacon)`), so no wire change is needed. The hosted surface also exposes a simpler kill switch: `POST /v1/pca/freeze` denies every PCActn for the instance until `DELETE /v1/pca/freeze` clears it.

## A durable log and its witnesses

`StoredLedger` (`@atlasauth/pca/ext/ledger`) keeps the log in a store with compare-and-swap appends, signs checkpoints, and on every open verifies the stored entries against each checkpoint (signature, `prev_root` chain, RFC 9162 proof at each boundary). A witness cosigns a checkpoint only if it is consistent with the last one it cosigned; a reader that requires a witness cosignature then refuses a rewritten or forked history. The claim is tamper evidence **given at least one honest witness independent of the operator**; censorship by omission is not detected. See [The transparency ledger and its witnesses](../guides/transparency-ledger.md) and [Operate a ledger witness](../guides/operate-a-witness.md).

## Putting the controls together

| Want to stop | Use | Reach |
|---|---|---|
| One capability or sub-agent | Revoke its capability id | Targeted; descendants die with it |
| A whole grant | Revoke the `grant_ref` | Every chain under the grant |
| Everything on an instance now | `freeze` | Instance-wide, immediate |
| Everything, passively | Stop beacons | Effective by the next epoch |

Next: [Optimistic authorization and ZK](./optimistic-and-zk.md).
