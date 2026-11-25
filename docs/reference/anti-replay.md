---
title: Anti-replay guarantees
order: 23
---

# Anti-replay guarantees

This page states what PCA guarantees about one-time use and freshness, which store each guarantee depends on, and what you must provide if you verify PCActns yourself instead of calling the hosted API.

## Summary

- **A PCActn is accepted at most once.** The hosted guardian enforces this with a strictly increasing `counter` per (instance, grant, leaf holder), held in Postgres and updated under a row lock inside the same transaction that debits the budget and anchors the ledger entry. If you submit the same action (or any action with the same or a lower counter) any number of times, from any number of servers, at the same instant, exactly one is admitted and the rest are denied with a `replay` reason.
- **Nothing is held in process memory for correctness.** Two or more API instances sharing one database behave as one. A restart, a new connection pool or a brand-new process cannot resurrect a consumed counter or nonce.
- **Failure is denial.** If the store fails mid-admission, the transaction rolls back: no ledger entry, no budget debit, and the counter is not burned (a retry is then admitted exactly once).

## What is enforced, and where

| Mechanism | Where | Atomicity primitive | Persistence | Multi-instance safe |
|---|---|---|---|---|
| PCActn single use (`counter`) | `pca_counters`, admission transaction | `SELECT ... FOR UPDATE` on the (grant, holder) row, then `UPDATE ... WHERE counter < $n` | Postgres, never pruned | Yes |
| Trust budget (spend) | `pca_budgets`, same transaction | Row lock, decide on the locked value, debit in the same transaction | Postgres | Yes: the sum spent never exceeds `bMax` under any interleaving |
| Per-node budget allocations | `pca_budget_nodes`, same transaction | Rows locked in stable `node_path` order | Postgres | Yes |
| Attestation nonce | `pca_attest_nonces` | `UPDATE ... SET consumed_at WHERE consumed_at IS NULL`, in the admission transaction | Postgres; purged only after the retention horizon | Yes |
| Step-up approval | `pca_stepups` | The approval re-runs full admission, so single use is the counter above; status moves by compare-and-swap | Postgres | Yes: any number of held copies and concurrent cosigns yield exactly one admission |
| Revocation epoch / kill switch | `pca_revocations`, `pca_freeze`, advisory locks | Admission takes a shared advisory lock, revoke and freeze take it exclusively | Postgres | Yes: a revoke either commits before the admission reads the gate or waits for its commit |
| Liveness beacons | `pca_beacons` | Advisory lock, then strictly increasing `seq` per (instance, scope, issuer) | Postgres | Yes |
| Ledger index | `pca_ledger_entries` | Unique `(instance, principal, idx)`; appends for one grant are already serialised by the budget lock | Postgres | Yes |
| Optimistic claims and bond settlements | created inside the admission transaction; settlement unique per (claim, action) | Unique index with `ON CONFLICT DO NOTHING` | Postgres | Yes |
| Payment mandates | `POST /v1/pca/payment-mandates/authorize` is a pure decision and consumes nothing; spending happens when the resulting PCActn is submitted to `/v1/pca/actions` | The counter and budget above | Postgres | Yes (the pure route is advisory by design) |
| Witness cosignature cache | in-process map | none | none | Not used for correctness. Every cosignature is re-verified on read; losing it loses nothing a witness cannot re-submit |
| Rate limits (`publicRateLimitPerMin`, quotas) | rate-limit store | Fixed window | Redis in production, memory in tests | Abuse control only. Replay safety does not depend on it |

The optional `nonce` field of a PCActn is **not** a server-side deduplication key. The spec makes it a token a resource server may track. The hosted API deduplicates on the counter, which is strictly stronger for a given holder: every accepted action has a counter greater than all earlier ones, so two accepted actions can never be the same action.

## Freshness rules

A PCActn carries `aud`, `iat` and `exp` (epoch milliseconds, all signed).

- `aud` must equal the verifier's own audience byte for byte. An action for another instance is denied before anything is consumed.
- `exp - iat` is at most 1 hour.
- `iat` may be at most 60 seconds ahead of the verifier clock (clock skew in the "fast sender" direction).
- The action is valid **through** `exp` inclusive and expired from `exp + 1 ms`. An expired action consumes nothing.
- The verifier's clock is read once per request. A request that waits on a row lock is still judged at the instant it started.

Server-issued attestation nonces live 2 minutes (`expires_at` in the challenge response), never longer than the 5 minute attestation ceiling. Freshness is taken from the server's own issue time, never from the attestation document's dates.

### Held attested step-ups: attestation is fresh at the moment of admission

An action that needs hardware or software attestation and also a human step-up can sit pending for up to 15 minutes, far longer than the 2 minute attestation nonce. The nonce TTL is not lengthened. Instead the attestation is renewed at approval:

- When the principal quorum is met and the nonce bound to the held action is no longer fresh (expired, consumed or unknown), the server does **not** admit and does **not** burn the step-up. `POST /v1/pca/stepups/:id/cosign` answers `202` with `result: "reattestation_required"` and a fresh server-issued nonce (`reattestation.nonce`, `expires_at`). The step-up stays `pending` with its cosignatures.
- The agent builds a new attestation bound to {holder, grant, epoch, new nonce} and completes with `POST /v1/pca/stepups/:id/reattest { attestation, action_digest }`. Admission then runs once through the normal admission transaction.
- The held PCActn is never altered, and the cosignatures are still judged against the original threshold message. Only the attestation check sees the new nonce.
- The new nonce is single use and is consumed in the same transaction as the counter, budget and ledger append. An expired or earlier nonce is never reusable; evidence for another held action, a document bound to another holder, or a wrong `action_digest` is rejected with a specific reason and the step-up stays pending.
- Concurrent completions (across servers too) admit exactly one: the nonce consume and the counter decide. Revocation, freeze, counter and budget checks apply at completion exactly as on any admission.
- An unexpired outstanding challenge is reused rather than replaced, so a third party who knows a step-up id cannot churn it. A step-up whose cosignatures are valid but whose attestation never arrives expires at its 15 minute deadline.
- If a policy change removes the attestation requirement while the step-up is held, the plain cosign completes it as before.

Covered by the re-attestation test suite: late cosign, stale or other-action or other-holder evidence, 30 concurrent completions over two servers, completion after the deadline, revocation at completion, and the unchanged non-attested path.

## Retention (pruning) never frees a valid record

- Counters are never pruned: a counter row is a high-water mark, and replay is detected by comparison, not by remembering every value.
- Attestation nonces are swept by the retention worker only when issued more than 1 hour ago. A nonce is valid for at most its 2 minute TTL plus the 60 second skew allowance, so the horizon is at least 20 times the longest validity. A nonce that has been swept is simply unknown and cannot bind an attestation, so an old nonce can never be accepted.
- Step-up rows are swept 24 hours after expiry.

The rule for any store you provide is: **retention must be at least the action's remaining validity plus the clock-skew allowance.** The library exports `REPLAY_MIN_RETENTION_MS` (max lifetime plus skew in both directions) as the floor.

## Cross-context isolation

- All server state is keyed by instance. A nonce or counter issued under one instance is invisible to every other instance.
- The grant in that key is never taken on trust from the PCActn alone: the verifier requires the signed `grant_ref` to equal the id of the chain root (`cap_chain[0].id`, check `grant_ref_bound`), and the hosted API additionally resolves it to a registered grant. A holder therefore cannot move to a fresh counter or nonce namespace by signing a different `grant_ref`. If you run the self-hosted guard (`guardPCActnReplay`), verify the PCActn FIRST and consult the replay store only for an action that verified; the guard itself does not check the chain.
- Counters are keyed by (instance, grant, holder). The same counter value under two grants, or the same agent key under two grants, is independent.
- An attestation nonce is bound to (grant, holder, epoch). A nonce issued for grant 1 cannot be consumed by an action of grant 2 even when the holder key is the same, and the failed attempt does not burn it.

## Strings are compared as exact bytes

PCA does not normalise Unicode. A nonce (or any other signed string) is compared as the exact UTF-8 bytes that were signed, so `U+00E9` and `U+0065 U+0301` are two different nonces even though they render identically. Lengths are bounded in UTF-8 bytes, not characters: a `nonce` is at most 128 bytes and an `aud` at most 256 bytes. A string containing a lone surrogate (not valid UTF-8) is malformed and refused. If your application needs normalisation-insensitive uniqueness, normalise before you sign.

## Self-hosted verifiers: what you must provide

`verifyPCActnCore` is a pure, stateless structural verifier. It checks the signatures, the validity window and that `counter` is a non-negative safe integer, but it cannot know whether an action was already accepted. If you verify PCActns in your own service, wrap it with the replay guard from `@atlasauth/pca`:

```ts
import { guardPCActnReplay, type ReplayStore, type CounterStore } from '@atlasauth/pca';

const verdict = await guardPCActnReplay(store, pcactn, {
  aud: 'my-instance-id',
  now: Date.now(),
  counters,            // optional CounterStore: also enforce the monotonic counter
  requireNonce: true,  // default; set false to rely on the counter alone
});
if (!verdict.ok) deny(verdict.code, verdict.reason);
```

Run it **after** the signature verified; consuming a nonce for an unauthenticated action would let anyone burn someone else's nonces. Your `ReplayStore` and `CounterStore` must satisfy this contract:

1. **Atomic across every verifier instance** that accepts actions for the same audience. For two concurrent calls with the same key, exactly one resolves `true`. A shared database with a unique key, `SET NX` in Redis, or a conditional write in DynamoDB all qualify. A per-process `Map` does not, unless exactly one process serves the audience.
2. **Durable until `retainUntilMs`.** The guard passes `exp` plus the skew allowance. Forgetting a key earlier lets a still-valid action replay.
3. **Fail closed.** If the store cannot decide, reject (throw). The guard turns that into a `store_unavailable` denial and never treats a failure as "unseen".
4. **Bounded.** If a store is full of live entries it must reject rather than evict a live one.

**File-backed state (`@atlasauth/pca/durable-state`) as a store.** If you back a replay or counter store with the durable-state module, its lock is correct only for processes on **one host** and only on a **local filesystem with working hard links** (ext4, xfs, btrfs, tmpfs, APFS). On NFS, SMB, FUSE or some overlay mounts exclusion is not guaranteed; opening such a directory fails closed with `link-unsupported` when hard links are unusable. A holder that stalls keeps the lock and **blocks the others until it dies** (they fail with `lock-timeout`, which the guard turns into a denial); nobody takes a live holder's lock. For several hosts use Postgres or Redis as above.

`InMemoryReplayStore` is the reference implementation. It is correct only for a single process whose lifetime covers the action lifetime. A restart empties it, which is a violation of rule 2, so use it for tests and single-process tools only.

## Replay-state invariant

Every replay mechanism above, hosted or self-hosted, enforces one rule:

> **In one authorization domain, an action id moves from unconsumed to consumed at most once, and an action is admitted only by the step that consumed it.**

- **Action id.** A (grant, leaf holder, counter) triple. Counters form one strictly increasing stream per (grant, leaf holder), so consuming counter `n` also consumes every counter at or below `n` for that stream. When a verifier also tracks the PCActn `nonce`, the nonce is a second action id under the same rule.
- **Authorization domain.** The set of verifiers that share one state store and one key space. The domain is exactly what the store key covers:

  | Verifier | Store key (the domain) |
  |---|---|
  | Hosted API | (instance, grant, leaf holder) |
  | `guardPCActnReplay` | (audience, grant, leaf holder) for counters; (audience, grant, leaf holder, nonce) for nonces |
  | `requirePCA`, `authorize` and `authorizeToolCall`, default (since 0.5) | (audience, grant, leaf holder) |
  | `requirePCA` with `replayScope: 'grant-holder'` (the 0.4 key) | (grant, leaf holder) |

  Two verifiers that do not share a store are two domains. That does not open a replay, because the PCActn's `aud` is signed and each verifier denies an action issued for another audience. Within one audience, every instance must share one store. With the 0.4 key (`replayScope: 'grant-holder'`), resource servers with different audiences that share a store also share counter streams. This can only cause extra denials, never a double acceptance. The default key carries the audience, so each audience has its own stream. A store written by 0.4 upgrades itself: while the audience-scoped key has no state, the guard starts from the old key's last counter and budget and never writes the old key again.
- **At most once, not exactly once.** The action id is consumed before your handler runs. If the process dies after the claim, or the claim lands but its answer is lost, the action is spent and a retry is denied as a replay. To make the side effect safe to retry, record it per operation (see [From authorization to execution](#from-authorization-to-execution-operation-records)).

### How `requirePCA` keeps the invariant across instances

`requirePCA` reads the holder's state (last counter, trust budget), verifies, then records the new state. That record step can be made safe in three ways. `guard.stateMode` reports which one a guard uses:

| `stateMode` | When | Safe for |
|---|---|---|
| `atomic-claim` | the `budgetStore` has `claim` and `raisePin` (`AtomicPcaStateStore`) | any number of processes and nodes sharing the store |
| `shared-lock` | the `budgetStore` has `withKeyLock` (a lock that every node shares and that cannot expire while it is held) | any number of processes and nodes sharing the store and the lock |
| `process-lock` | neither: an in-process lock serialises the read, verify and write steps | **one process only** |
| `none` | no `budgetStore` | nothing: the required `replay` check denies |

`claim(key, { counter, budgetBefore, budgetAfter })` is one compare-and-set. It succeeds only if the stored counter is lower than `counter` and the stored budget still equals the budget the decision was computed from. It answers `replay` when the counter is not fresh. It answers `conflict` when another action of the same holder changed the budget in between; the guard then re-reads, re-verifies and claims again, up to `claimRetries` times (default 3), and denies after that. A claim that cannot decide must throw, and the guard denies. With one atomic statement in your database, no lock is needed:

```sql
-- first action of a holder: the primary key lets exactly one insert win
INSERT INTO pca_state (key, last_counter, budget) VALUES ($key, $counter, $after)
  ON CONFLICT (key) DO NOTHING RETURNING 1;
-- later actions: the counter and the budget the decision read are both conditions of the write
UPDATE pca_state SET last_counter = $counter, budget = COALESCE($after, budget)
  WHERE key = $key AND (last_counter IS NULL OR last_counter < $counter)
    AND budget IS NOT DISTINCT FROM $before
  RETURNING 1;
```

The library ships two atomic stores. `atomicMemoryPcaStore()` is for one process only. `durablePcaStateStore(kv)` works over any key/value store with an atomic `update`, for example `openDurableState({ dir })` from `@atlasauth/pca/durable-state`, which is safe for several processes on one host. The store conformance kit includes a Postgres reference adapter.

**Multi-instance is the default.** Since 0.5 `requirePCA` assumes several instances unless the store says it is process-local: it refuses to construct with a store that only the in-process lock can serialise, that is, a store with neither `claim` nor `withKeyLock` that does not declare `scope: 'process'`. A store that declares `scope: 'process'` (`memoryPcaStore`, `atomicMemoryPcaStore`) is accepted, and `guard.stateMode === 'process-lock'` shows that the guard is correct for one process only. `multiInstance: true` also refuses a `scope: 'process'` store, and `multiInstance: false` runs a plain get/put store in one process on purpose.

**Testing your store.** The store conformance kit's `pca-state` profile runs your store through the real `requirePCA`: concurrent copies of one proof sent to one instance, to several instances, and to several processes (exactly one may be admitted); a process killed right after the claim (the same proof must then be denied, and the next counter admitted); a claim whose answer is lost, followed by a retry; and the claim operation itself through the linearizability checker. See [Testing your replay store](../guides/store-conformance-kit.md#7-the-store-behind-requirepca-the-pca-state-profile).

## From authorization to execution: operation records

The replay state ends at the decision. The side effect that follows can still be interrupted: the process can crash, the client can time out and retry, or two workers can pick up the same authorization. `executeAuthorized` from `@atlasauth/pca` keeps a record per operation. Its id is `operation.id` of the `authorize()` result, the digest of the presented PCActn. The record moves through these states:

| State | Meaning | Next |
|---|---|---|
| `pending` | claimed for execution; the side effect has not started | `executing`, or `aborted` (recheck failed, or found stale) |
| `executing` | the side effect has been started | `committed`, `failed`, or `uncertain` (found stale) |
| `committed` | the side effect completed; the record keeps its result | final |
| `failed` | the side effect threw; not re-run | final |
| `aborted` | the side effect never ran (recheck refused, or a crash before it started) | final |
| `uncertain` | a crash or a lost answer after the side effect started: it may or may not have happened | `committed` / `failed`, after reconciliation |

The rules:

- **One execution per operation id.** The `pending` record is created with an atomic create-if-absent before anything runs. Of any number of concurrent executions of one authorization, exactly one runs the side effect; the others get the record's answer.
- **Re-check before an irreversible side effect.** Between the decision and the side effect the grant can be revoked, the principal's approval can lapse, or the PCActn can expire. For an irreversible operation `executeAuthorized` requires a `recheck` and runs it, with the expiry check, immediately before the side effect. The class is the stricter of the signed class and your catalog's. A refusal records `aborted`. `createExecutor` builds the recheck from the `authorize` options: the revocation hook, the expiry, and, with a plan registry, the plan state.
- **Idempotency key.** The side effect receives the operation id as `idempotencyKey`. Pass it to the downstream call (for example as an `Idempotency-Key` header), so the downstream system can also refuse a second application and can answer "did this happen?" during reconciliation.
- **Nothing is silently re-run.** A second execution of the same id, or a retry of the same PCActn through `createExecutor`, is answered from the record. A record left open by a crash is settled once `pendingTimeoutMs` has passed (default 5 minutes). If it was still `pending`, it becomes `aborted`: the side effect never started, and the agent may sign a fresh PCActn. If it was `executing`, it becomes `uncertain`. Run `recoverOperations` at startup and periodically. Settle each `uncertain` record with `resolveOperation`, after asking the downstream system by the idempotency key.
- **A retry gets the record only while the authorization still stands.** `createExecutor` answers a retried PCActn from the record only when the replay is the only failing check: the proof, the binding to this operation, the policy and revocation all still pass now. The record must also be for the same verb, resource and params. A revoked grant gets a denial, not the stored result.

**Storage.** The store must make two operations atomic across every instance: create-if-absent, and a state transition that succeeds only from the expected state. `memoryOperationStore()` is for one process only. `durableOperationStore(kv)` works over any key/value store with an atomic `update`. In a database:

```sql
-- claim: exactly one insert wins
INSERT INTO pca_operation (id, state, verb, resource, params_digest, started_at)
  VALUES ($id, 'pending', $verb, $resource, $digest, $now)
  ON CONFLICT (id) DO NOTHING RETURNING 1;
-- transition: only from the state the executor expects
UPDATE pca_operation SET state = $next, result = $result, error = $error, finished_at = $now
  WHERE id = $id AND state = $from RETURNING 1;
```

## What is not guaranteed

- **Exactly-once execution of the side effect.** PCA guarantees that an authorization is consumed once. Operation records make the side effect run at most once per authorization, and they report a crash in the middle as `uncertain` instead of re-running it. Only the downstream system can make the side effect itself exactly-once: make it idempotent on the operation id (self-hosted) or on the receipt's ledger `index` or `commit` (hosted), and reconcile `uncertain` records against it.
- **Availability under store failure.** The system denies rather than allows; a database outage stops admissions.
- **Replay protection from the optimistic fast path alone.** The fast path still consumes the counter and budget at admission; only the fraud challenge window is deferred.

## How it is tested

The anti-replay suite runs against a real Postgres with two independent API graphs (separate pools and separate in-memory state) and separate OS processes:

- 60 parallel submissions of one PCActn across two servers: exactly one admitted, the rest denied with a replay reason, one ledger entry, one budget debit.
- 60 different PCActns racing for one counter; 80 distinct counters in random order (ledger order strictly increasing, counter ends at the last accepted).
- Budget races (40 sub-keys, and one holder with 60 counters): the number admitted equals what the budget affords and the budget never goes negative.
- A revoke racing 30 admissions; the exact `exp` instant with 40 parallel copies; clock skew in both directions.
- One attestation nonce presented by 40 actions on both servers: exactly one admitted. 40 concurrent attested actions on an 8-connection pool complete (no pool-exhaustion deadlock).
- One action held in 8 step-ups, each cosigned twice in parallel: exactly one admission and one approved step-up.
- Restart and reconnect: a new app and pool, and two separate processes firing at the same wall-clock instant, followed by a third process started later.
- Fail closed: an injected failure in the admission transaction leaves no ledger entry, counter or debit and a retry is admitted once; an unreachable database never admits.
- Cross-context, malformed counters, over-long and Unicode-equivalent nonces.
