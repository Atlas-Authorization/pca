---
title: Guardian high availability
order: 12
---

# Guardian high availability

> **Status: production (pending CI).** The lease and fence are enforced against a store you supply; see [maturity tiers](../maturity.md). Import from `@atlasauth/pca/ext/research`.

The guardian that co-signs tier-2 and tier-3 actions is a single point of failure. Running more than one is easy. Making sure that **only one of them acts as leader at a time, and that a leader which lost its place cannot keep signing**, is the hard part. PCA gives you the two pieces: pure quorum decisions, and a durable, fenced leader lease.

## What you get

- **Quorum decisions** (`quorumStatus`, `degradeMode`, `selectSigners`, `failoverPlan`). Given health facts, they say whether a co-sign quorum is reachable, which guardians to ask, and how to degrade: `normal`, `read-only` (below quorum but some guardians live), or `halt`. A malformed set, a non-finite clock, a heartbeat dated in the future or a non-boolean `healthy` flag counts as down. Losing quorum only ever restricts authority.
- **A leader lease** (`acquireLease`, `renewLease`, `releaseLease`) over a `LeaseStore`. Every takeover increments a **fencing epoch** that never goes down. Expiry is decided by the **store's clock**, never the caller's. A holder stops acting `skewMs` before its lease ends, and a challenger waits `skewMs` after it, so bounded clock error cannot produce two leaders.
- **Fencing.** `fencedSigner` wraps a co-sign function: it runs only while the caller is the current leader and discards the signature if the lease was lost while signing. `createFenceGuard` is the resource-side half: it remembers the highest epoch it has seen and refuses a lower one, so a stale ex-leader's late write is rejected even if it got past its own check.
- **A reference store**, `KvLeaseStore`, over the durable state store. With file-backed durable state the lease and its epoch survive restarts.

## Use it

```ts
import { KvLeaseStore, acquireLease, renewLease, fencedSigner, createFenceGuard } from '@atlasauth/pca/ext/research';
import { openDurableState } from '@atlasauth/pca/durable-state';

const store = new KvLeaseStore(await openDurableState({ dir: '/var/lib/guardian/lease' }));
const opts = { ttlMs: 15_000, skewMs: 1_000 };

const got = await acquireLease(store, 'guardian-a', opts);
if (!got.ok) throw new Error(`not leader: ${got.reason}`); // 'held', 'lost-race', 'store-error', ...
let lease = got.lease;

setInterval(async () => {
  const r = await renewLease(store, lease, opts);
  if (r.ok) lease = r.lease;
  else process.exit(1); // lost the lease: stop signing
}, 5_000);

const cosign = fencedSigner(store, () => lease, (digest: Uint8Array) => mySigner.sign(digest));
const { result, epoch } = await cosign(digest);
// downstream: if (!fence.admit(epoch)) reject();  where fence = createFenceGuard()
```

Every failure is a refusal with a reason: `invalid`, `held`, `lost-race`, `stale`, `expired` or `store-error`. A store that errs, returns a corrupt record or a non-finite clock answers "no leader": nothing signs.

## Bring your own store

Implement `LeaseStore` (`read`, `cas`, `now`) over etcd, a SQL row with a version column, or any store with a linearizable compare-and-swap, then run the lease conformance suite from `@atlasauth/pca-store-conformance` (`runLeaseStoreConformance`, or `describeLeaseStoreConformance` in your test runner). It checks one winner among racing contenders, that a wrong expected record never writes, that the epoch never goes down, that a stale holder cannot renew or release, and that an acknowledged lease survives a restart or crash. It also ships four deliberately broken stores that it must flag.

## Failure behaviour

| Situation | Result |
|---|---|
| Store read, compare-and-swap or clock throws | `store-error`; no leader, no signature |
| Another holder has a live lease | `held`; nothing is written |
| Lease expired but inside the skew window | still `held` |
| Renewing after another process took over | `stale` |
| Renewing after the safe window (expiry minus skew) | `expired` |
| Malformed lease record or non-finite time | `invalid` |
| Signing with a lost or stale lease | the signature is discarded and a `FenceError` is thrown |
| Heartbeat in the future, NaN or not a boolean | the guardian counts as down |
| Non-finite `now` or a malformed guardian set | no live guardians, no quorum |

## What is and is not guaranteed

- Guaranteed, **if** the store's compare-and-swap is linearizable and clock error stays below `skewMs`: at most one holder per epoch, epochs strictly increase, a stale holder is refused.
- Not guaranteed: availability (a partitioned store means no leader, by design), and protection of a downstream that never checks the epoch. Checking before signing is inherently racy, so the fence guard on the receiving side is what closes the gap.
- The lease store's clock must be one clock. A store backed by several machines needs a single time source such as the database's own.
- Process deployment, health probing and the signing transport are yours.
