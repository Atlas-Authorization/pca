# Replay-store verification: TLA+ models and linearizability tests

The verified core (`docs/pca/security/verified-core.md`) treats **replay-store atomicity as trusted**: the machine-proved
decision (`formal/dafny/Replay.dfy`) fixes the order of checks and the verdict, but it assumes that `consumeOnce` and
`advance` are atomic across every verifier instance, durable until `retainUntilMs`, and fail closed. This page closes
that assumption two ways: the contract and each real implementation strategy are model-checked (TLA+), and the real
stores are run under heavy concurrency and crash injection and their recorded histories are checked for
linearizability.

Scope: what the models and runs establish, and what they do not (section 7). Nothing here is an independent audit.

> **Test your own store.** The linearizability harness below is packaged for users as `@atlasauth/pca-store-conformance`
> (implement a small adapter, run `pca-store-conformance --adapter ./my-adapter.mjs`); see
> [the store conformance kit guide](../guides/store-conformance-kit.md). `pca-doctor` runs a short version of it against
> a live deployment ([guide](../guides/pca-doctor.md)).

## 1. The contract

From `packages/pca/src/replay.ts`:

| Operation | Sequential specification |
|---|---|
| `consumeOnce(key, retainUntil, now)` | `TRUE` iff there is no live record for `key` (live = `until >= now`); records `retainUntil` |
| `prune(now)` | forgets only records with `retainUntil < now` |
| `advance(stream, c)` | `TRUE` iff `c` is strictly greater than the stored value, and then stores `c` (counters are never pruned) |
| failure | `reject` (never resolve `TRUE`) when the store cannot decide |

The guard stores `retainUntil = exp + skew`. A verifier accepts an action only while its **local** clock reads `now <= exp`.
The environment assumption is that any two verifier clocks (and the store's clock, for TTL stores) differ by at most `skew`
(`PCACTN_MAX_SKEW_MS`, 60 s).

## 2. TLA+ models (`formal/tla/`)

Run all: `formal/tla/run.sh` (TLC, `cases.txt` lists every configuration with its expected verdict), and
`formal/tla/run-apalache.sh` (Apalache, unbounded time). Both were run on the cloud box; `formal/tla/results/` holds the
TLC output of every case, which for each known-bad variant **is the counterexample trace**.

| Module | What it models |
|---|---|
| `ReplayContract.tla` | the abstract contract with real time, per-server clock offsets, retention, prune policy (`safe`, `early`, `evict`, `ttl`) and a volatile-store switch; also `advance` |
| `PgStore.tla` | Postgres at READ COMMITTED: `UPDATE .. WHERE counter < $n RETURNING`, `INSERT .. ON CONFLICT`, `SELECT .. FOR UPDATE` in a transaction (the reference server admission path), advisory locks, SELECT-then-INSERT on a unique index, a read-replica fast path; client crash, connection drop, commit-ack loss, server crash-restart with and without synchronous commit |
| `RedisStore.tla` | `SET NX`, Lua compare-and-advance, `WAIT 1`; primary failover with an asynchronous replica, restart under `appendfsync always` / `everysec` / no persistence, eviction |
| `MemStore.tla` | `InMemoryReplayStore`: one process, several processes, restart |
| `DurableLock.tla` | the OLD lock-file + journal protocol of `packages/pca/src/durable-state.ts` (O_EXCL create, age-based stale-lock break by rename, release by read-then-unlink); kept as the counterexample source |
| `DurableLockGen.tla` | the NEW protocol (immutable numbered lock generations created by `link(2)`, takeover only from a provably dead holder, highest-generation re-check, garbage collection of superseded generations) |
| `RequirePcaLock.tla` | `requirePCA`'s get, verify, put section under `withKeyLock`: exclusive lock, expiring lease, lease with a fencing check, no lock |
| `ApaContract.tla` | Apalache-typed twin of the contract for the unbounded-time proof |

Invariants (checked in every state): *write order* (acknowledged writes in commit order are strictly increasing),
*ack durable* (a `TRUE` answer is never undone), *at most one TRUE* per key, *false justified* (a `false` is backed by an
earlier committed value), and for the contract *ExactlyOnce* and *CounterMono*.

### 2.1 Results

54 configurations, 0 mismatches against the expected verdict (`formal/tla/results/SUMMARY.txt`): **26 hold** (exhaustive for
the stated bounds, including 4 to 5 concurrent clients with crashes, restarts and ack loss; the largest is 44 million
generated / 3.3 million distinct states) and **28 known-bad variants violate** the invariant, each with a counterexample trace in
`formal/tla/results/<case>.txt`. Good: the contract with skew within the bound (also for a TTL store), `UPDATE .. WHERE`,
`FOR UPDATE`, advisory lock, SELECT-then-INSERT on a unique index, the unlocked read fast path, Redis `SET NX` and Lua under
`appendfsync always`, `WAIT 1` with failover, a single in-memory process, `withKeyLock` as an exclusive lock or a fenced lease,
the old file lock with no stale breaking, and the new generation lock (with a dead pre-planted lock, 3 to 4 clients crashing anywhere, and garbage collection).

**Unbounded time (Apalache).** `ExactlyOnce` is proven for arbitrary time, three servers, any non-negative `Skew` and
`ExpT`, by an inductive invariant (`IndInv`): `Init => IndInv`, and `IndInv /\ Next => IndInv'` is discharged by the SMT
solver. The invariant says: a key is accepted at most once; a recorded key carries `exp + skew`; and a key that was accepted
but is no longer recorded implies every server clock is already past `exp`. With the offset bound exceeded or an early prune
horizon the same query returns a counterexample.

Apalache 0.62.3, 9 queries, 0 mismatches (`formal/tla/results/APALACHE.txt`): base and step for the concrete good
parameters and for the symbolic "all non-negative `Skew`, `ExpT`" case hold; the same step query with offset bound above `Skew`
fails, as do bounded runs with the early prune horizon.

### 2.2 What the bad variants show

| Variant (expected to fail) | Counterexample in one line |
|---|---|
| clock skew above the bound | server s3 runs 2 ahead: it prunes the record while s1 (offset 0) still accepts the same key; accepted twice |
| prune horizon from `exp` (no skew term) | same, with offsets inside the bound |
| capacity eviction of a live record | evict, then re-consume |
| volatile store + restart | restart empties the map; the nonce is accepted again |
| read-then-write, no transaction | two clients read "absent", both write, both told `TRUE` |
| `FOR UPDATE` in autocommit, or on an unseeded row | the lock is released at statement end / never taken; lost update |
| SELECT then `ON CONFLICT DO UPDATE` (overwrite) | second writer overwrites instead of conflicting |
| decision on a stale replica read | replica says absent; blind write on the primary |
| asynchronous commit + server crash | acked commit lost; later client accepted |
| Redis `GET` then `SET` | same as read-then-write |
| Redis async failover; `everysec` restart; no persistence; eviction | acked write lost, or key forgotten, then accepted again |
| `WAIT 1` with a primary restart | the replica has it but a restarted primary resyncs the replica from its own empty state |
| two in-memory instances | each has its own map |
| `withKeyLock` as an expiring lease with no fencing | lease expires under a paused holder; the paused holder's `put` accepts a counter the second node already accepted |
| no `withKeyLock` on a multi-node deployment | the in-process fallback lock only covers one process |
| old lock: owner stalled past `staleLockMs` | stolen lock; the stalled owner commits over the newer record (**fixed** by replacing the protocol, section 5.1) |
| old lock: two processes break the same dead owner's lock | one moves a *fresh* lock aside (rename), a third creates a new lock before it is put back, two writers in the critical section (**fixed**, section 5.1) |
| new lock with age-based takeover of an alive holder | two holders (`dl2_bad_age_break`): why takeover is restricted to provably dead holders |
| new lock without the highest-generation re-check, with garbage collection | a stale creator re-creates a removed generation and believes it holds the lock (`dl2_bad_gc_noverify`; found in the first implementation) |

## 3. Linearizability tests against the real stores (`tools/pca-linearizability/`)

Harness: a Go client (`pcalinz run`) with 50 to 210 connections across 3 processes per run, issuing `consume(key)` or
`advance(stream, c)` against a real store; every operation writes an **invocation** record (one `write(2)` to an append-only
file) before the request leaves the process and a **response** record after. A client killed with SIGKILL therefore leaves
its in-flight operations *pending* (they may or may not have taken effect). `pcalinz check` rebuilds the histories per key and
checks them with [porcupine](https://github.com/anishathalye/porcupine) against the nondeterministic sequential model of
section 1: an operation whose outcome is unknown (connection error, killed client, timeout) is treated as open-ended and
may linearize as applied or not applied. Keys are time-windowed so every worker contends on the same few keys at once.

Stores: Postgres 16 (own cluster with a streaming hot standby, own Redis 7.0; ports 5455, 5456, 6390; nothing else on the box
is touched) running the production SQL: `PcaCountersRepository` via the reference server admission sequence (seed, `BEGIN`, `SELECT
.. FOR UPDATE`, compare, `UPDATE .. WHERE counter < $n RETURNING`, `COMMIT`), the single-statement `advance`, the advisory-lock
variant, the Phase-A unlocked read fast path, the production attestation-nonce `UPDATE .. WHERE consumed_at IS NULL
RETURNING`, and the reference `INSERT .. ON CONFLICT .. DO UPDATE .. WHERE until < now RETURNING`; Redis `SET NX` and Lua.

Chaos (`scenario.sh`): `kill -9` of a random client process every few seconds (restarted under a new identity), random
`pg_terminate_backend` of 30% of the sessions (`CLIENT KILL` for Redis), and `kill -9` of the Postgres postmaster and children
(Redis server) every ~10 s with immediate restart.

Positive controls: each bad variant of section 2 that can be run for real is run, and the checker must flag it. A checker
that passes everything would be worthless.

### 3.1 Results

Totals: about 73 million operations in 40 recorded histories (all on the cloud box, 3 client processes and 60 to 210 connections
per run); more than 50 million of them under crash, connection-drop or server-restart injection (about 330 SIGKILLs of
clients, servers or sessions in the chaos runs, `kills=` below). Per-scenario lines:
`tools/pca-linearizability/results/CAMPAIGN-*.txt`.

| Scenario | Ops | Verdict |
|---|---|---|
| PG production admission (seed, `FOR UPDATE`, `UPDATE .. WHERE counter < $n`), 210 conns | 0.91 M | linearizable |
| PG single-statement `advance`, 210 conns | 1.52 M | linearizable |
| PG advisory-lock variant, 210 conns | 1.95 M | linearizable |
| PG Phase-A fast path + Phase B, 210 conns | 2.18 M | linearizable |
| PG production attestation-nonce consume, 210 conns | 4.76 M | linearizable |
| PG `INSERT .. ON CONFLICT .. WHERE until < now`, 210 conns | 2.58 M | linearizable |
| Redis `SET NX`, 210 conns | 5.48 M | linearizable |
| Redis Lua advance, 210 conns | 2.03 M | linearizable |
| PG admission, chaos (64 kills: clients, sessions, postmaster) | 0.12 M | linearizable |
| PG `UPDATE .. WHERE`, chaos (40 kills) | 2.39 M | linearizable |
| PG attestation nonce, chaos (37 kills) | 3.76 M | linearizable |
| PG `ON CONFLICT`, chaos (41 kills) | 2.45 M | linearizable |
| PG advisory, chaos (42 kills) | 2.68 M | linearizable |
| PG fast path, random connection drops | 2.96 M | linearizable (the one key that timed out was re-checked with a 50-minute budget: linearizable) |
| PG `UPDATE .. WHERE`, postmaster `kill -9` every ~10 s, `synchronous_commit=on` | 4.00 M | linearizable |
| Redis `SET NX`, AOF always, chaos (49 kills) | 5.56 M | linearizable (the two keys that timed out were re-checked with a 50-minute budget: both linearizable) |
| Redis Lua, AOF always, chaos (39 kills) | 2.91 M | linearizable |
| Redis `SET NX`, AOF everysec, chaos incl. `kill -9` of redis-server (50 kills) | 12.66 M | linearizable |
| Redis Lua, AOF everysec, chaos (35 kills) | 6.89 M | linearizable |
| **Control** PG SELECT then blind UPDATE, no transaction | 1.52 M | **flagged**: 23,510 of 26,885 keys non-linearizable |
| **Control** PG `FOR UPDATE` in autocommit | 0.72 M | **flagged**: 20,295 of 26,980 keys |
| **Control** PG decision on the hot-standby read | 1.31 M | **flagged**: 25,707 of 26,917 keys |
| **Control** PG SELECT then `ON CONFLICT DO UPDATE` | 4.95 M | **flagged**: 26,526 of 26,759 keys |
| **Control** Redis `GET` then `SET` | 1.36 M | **flagged**: 53,889 of 134,421 keys |
| **Control** Redis with no persistence, `kill -9` of the server | 6.66 M and 4.93 M | **flagged**: 20 and 51 keys (an acknowledged consume forgotten, then accepted again) |
| **Control** Redis `GET` then `SET` as consume-once | 3.40 M | **flagged**: 26,220 of 26,670 keys (two definite TRUEs for one key are now rejected directly, which removed the memory blow-up) |
| **Control** PG `synchronous_commit=off` + postmaster `kill -9`, time-windowed keys | 5.30 M | not reproduced: keys are never touched again after the restart, so a lost commit is invisible |
| **Control** PG `synchronous_commit=off` + postmaster `kill -9`, keys REVISITED after the restart (`-revisit`), consume-once | 2.71 M | **flagged**: 40 keys whose acknowledged consume was lost and then granted again |
| **Control** same, counter (`UPDATE .. WHERE counter < $n`) | 2.55 M | **flagged**: 32 keys |
| same workload, `synchronous_commit=on` | 1.87 M | linearizable (the control for the control) |

Checker scaling: porcupine's search is exponential in the number of mutually concurrent operations, so two verdict-preserving
steps were added (and validated by property tests, `main_test.go`, against porcupine on thousands of random histories, legal and
illegal): definite "false" answers that a completed "true" already explains are dropped (about half of all operations), and a
key that times out in porcupine and has no open-ended operation is decided by an exact O(n log n) procedure for the monotone
register. Keys that still time out are counted as unresolved, never as passes; the three that did (all with open-ended operations from the chaos runs) were re-checked with a 3,000 s budget each and are all linearizable, so no unresolved history remains.

The harness's own pitfalls found while building it (so a reader can trust the numbers): a first chaos run reported 63
violations because the checker read histories while relaunched clients were still writing (an operation missing from a
partial history can make a `false` look unexplained); the scenario now waits for every writer of the run. Early checks also
timed out on a key where all 120 workers overlapped; the windowing now spreads each window over 12 keys.

## 4. The PCA verifier's use of the stores under concurrency

| Path | Result |
|---|---|
| the reference server admission code: Phase A (no locks, may only deny) then Phase B in one transaction: freeze/revocation locks, budget and counter rows `FOR UPDATE` in a fixed order, the gate and the counter **re-read under the lock**, the whole verification **re-run** with the locked budget, attestation nonce consumed with an atomic conditional `UPDATE`, counter advanced with `UPDATE .. WHERE counter < $n`, ledger append and signed tree head in the same transaction | No TOCTOU between verify and consume: the decision that is committed is the one taken on the locked values, not Phase A's. Modelled (`pg_for_update_*`, `pg_replica_fastpath_*`), linearizability-tested with the production statements, and the existing `pca-anti-replay.test.ts` / `pca-reattest.test.ts` pass on the cloud box (33 tests in 2 files) |
| the unlocked Phase A read | Can only deny a counter `<=` the stored one; because the stored value is monotone a stale read can only under-deny. Model: `pg_replica_fastpath_*` holds, `pg_bad_replica_decide_consume` (deciding allow on the stale read) fails |
| `guardPCActnReplay` | Verify first, then guard (documented and enforced by ordering inside the guard: no store call before every pre-check passed). The nonce is consumed **before** the counter advances: if the counter store throws or denies after the nonce was consumed the nonce stays burned, so a retry of the same action is denied as a replay. That is an availability cost, never a double accept; `replay-tla-correspondence.test.ts` pins it |
| `requirePCA` (`server/require-pca.ts`) | `get`, verify, `put` run inside `withKeyLock(grant.id, ..)`, and `now` is read **after** the lock is acquired. Safe iff the lock cannot expire under its holder or `put` is fenced; the doc comment on `withKeyLock` now says so (`RequirePcaLock.tla`). Without `withKeyLock` the in-process fallback is per process, which `rp_bad_nolock_multinode` shows is not enough for several nodes (already documented as "MUST supply") |
| `Phase B` deny after the nonce consume | the `deny` returned if `counters.advance` reports `false` after the nonce was consumed would commit the nonce consumption. Unreachable (the counter was compared under the same row lock a few statements earlier, `rp_exclusive_lock`), so left as is |

## 5. Anomalies found

### 5.1 `durable-state.ts`: the age-based lock break was unsound (fixed by replacing the protocol)

The file store took a single lock file and let any process break it when it was older than `staleLockMs` (30 s by default),
by renaming whatever sat at that path to a graveyard. Two defects followed, both found by the models and reproduced on the real
code:

- **Stalled owner.** An owner stalled past `staleLockMs` inside the critical section (a blocked fsync, SIGSTOP, a long pause)
  had its lock given away, then resumed and replaced the journal from its stale snapshot: a **consume-once update could be told
  "first" twice**. TLA+: `dl_hung_steal` (and `dl_hung_steal_recheck`: a nonce re-check before the rename only shrinks the window).
- **Concurrent breakers.** A late breaker's rename could move a *fresh* lock; the code put it back only if the slot was still
  free, so a fourth process could take the slot and two writers entered the critical section. TLA+: `dl_dead_only`,
  `dl_dead_only_recheck`. Reproduced on the real code: 1 of 1,500 rounds with 10 processes told two of them "first".

Both are properties of the protocol, not of a missing check, so the protocol was replaced (commit `199991de`, refined in
`d4e59c7f`):

- The lock is a set of **immutable, numbered generation files** `state.lock.<g>`, each created atomically with its body by
  `link(2)` (so never torn, never renamed, never rewritten). The holder is the process named in the highest generation; the only
  way to take the lock is to create generation `g+1`, and `link(2)` lets exactly one creator win (a compare-and-swap on the
  generation). Release creates generation `g+1` marked free.
- A **live holder is never superseded**. A lock is taken over only from a *provably dead* holder (same host and `kill(pid, 0)`
  fails, or the pid's start time changed). Age no longer breaks anything: a stalled-but-alive holder keeps the lock, and waiters
  time out with `lock-timeout` (fail closed). The `staleLockMs` option was removed (breaking change, `docs/pca/CHANGELOG.md`). A legacy single-file `state.lock` is
  honoured as an extra holder and never touched.
- After creating a generation the creator re-checks that it is still the **highest**: TLC found that without it a stale creator
  can re-create a generation that garbage collection already removed (ABA) and believe it holds the lock (`dl2_bad_gc_noverify`;
  the first implementation had exactly this flaw and showed it as spurious `lock-lost` errors in about 0.6% of stress rounds).
  `assertLockHeld` (generation still highest and ours) stays as a last check before the journal rename; with the protocol it
  cannot fire.

Model results (`DurableLockGen.tla`, TLC): holds with a pre-planted dead lock and 3 or 4 clients crashing at any step (the
stalled owner is any process that simply takes no steps), including garbage collection of superseded generations with the
re-check; violated by the age-break rule (`dl2_bad_age_break`) and by dropping the re-check (`dl2_bad_gc_noverify`).

Real-code stress (`tools/pca-linearizability/durable/race-pool.mjs`): 10 persistent worker processes released at the same
wall-clock instant per round, fresh directory, a dead process's lock planted, one consume-once update each; exactly one TRUE
per round and a verifying journal chain are required. **New protocol: 61,250 rounds (7 concurrent pools: 35,000 with a planted legacy dead lock, 17,500 with a planted dead generation, 8,750 with no plant), 0 rounds without exactly one TRUE, 0 worker errors, 0 chain-verification failures. Old protocol, same harness: 3 rounds in 8,000 told two processes TRUE, 30 rounds had workers fail with corrupt/timeout errors.**

Regression tests (`packages/pca/src/durable-state-hung-owner.test.ts`, 3 tests) fail on both the original source and the
intermediate nonce-recheck version and pass on the new one: a stalled owner is waited for (exactly one "first"), a waiter times
out rather than stealing, and 12 concurrent breakers of a dead lock yield exactly one "first".

Costs and limits, stated plainly: the lock needs a local filesystem with working hard links (open fails closed with `link-unsupported` otherwise) and is for processes on one host; a holder that
stalls for ever blocks everyone until it dies (previously it was silently robbed); versions must not be mixed on one directory.

### 5.3 Real-store anomalies from the chaos runs

No violation was found in any production-shaped store configuration. What the runs did show:

- Every unsafe variant that can be run for real was flagged, so the checker discriminates (table above).
- Redis `appendfsync everysec` survived 85 `kill -9` events (clients and the server) with no acknowledged write lost, because the data is already in the
  page cache; its risk is machine/power loss, which these runs cannot inject (modelled: `redis_bad_everysec_restart`).
  Redis with persistence off loses acknowledged consumes on restart (flagged), so a Redis replay store needs AOF `always` (or
  `WAIT` with a primary that never restarts empty) and `noeviction`.
- Harness defects found and fixed along the way are listed at the end of section 3.1; one of them (cluster restart leaving an
  orphan shared-memory block after killing only the postmaster's direct children) invalidated the first chaos pass for Postgres,
  which was re-run from the corrected script.

## 6. How to reproduce

```
formal/tla/run.sh                                  # TLC, all cases (needs java + tla2tools.jar)
formal/tla/run-apalache.sh                         # unbounded-time proof
BOX=gcp tools/pca-linearizability/deploy.sh        # build the linux binary, push to the box
ssh box 'cd /work/replay-linz/tools && ./box-setup.sh pg-init && ./box-setup.sh redis-start always'
ssh box 'cd /work/replay-linz/tools && ./campaign.sh campaign-pg.txt  /work/replay-linz/CAMPAIGN-pg.txt'
ssh box 'cd /work/replay-linz/tools && ./campaign.sh campaign-redis.txt /work/replay-linz/CAMPAIGN-redis.txt'
ssh box 'cd /work/replay-linz/tools/durable && ./build.sh && ./stress.sh dl1 100 8 30000 kill'
```

## 7. What this does not establish

- The models are abstractions of the SQL / Redis / file protocols; they are not extracted from the code. The Go
  harness replicates the production SQL text, it does not drive the TypeScript repository classes. The two are linked by
  the existing the reference server anti-replay suite and by keeping the statements identical.
- Linearizability checking is sound for the histories it saw: a pass is evidence, not a proof. The TLA+ results are
  exhaustive only for the stated bounds (3 to 5 clients, 3 counter values, small time); the Apalache result is the one
  unbounded claim, and covers the contract with clocks, not the SQL.
- Operating-system or power-loss durability is not exercised: `kill -9` of a process does not lose data already `write(2)`n (Postgres `synchronous_commit=off` is the exception, because the WAL buffer is process memory, and it is reproduced above).
  Redis `appendfsync everysec` therefore passes the process-kill runs but loses up to a second on a machine crash (the TLA+
  model `redis_bad_everysec_restart` is the statement of that risk). Postgres `synchronous_commit = off` with `kill -9` is the runnable analogue and loses acknowledged commits when keys are revisited after the restart (reproduced; the TLA+ model `pg_bad_async_commit_restart` predicted it).
- All client processes of a run share one host clock. Timestamps from several boxes would make real-time ordering depend on
  NTP error, so cross-box runs are not used for checking.
- A store is only as good as its configuration: the contract needs synchronous, persistent commits (Postgres default,
  Redis `appendfsync always` or `WAIT` with no restart of the primary from an empty state), no eviction of live keys
  (`maxmemory-policy noeviction`), and clocks within `skew`.
