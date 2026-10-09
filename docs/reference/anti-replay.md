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

`InMemoryReplayStore` is the reference implementation. It is correct only for a single process whose lifetime covers the action lifetime. A restart empties it, which is a violation of rule 2, so use it for tests and single-process tools only.

## What is not guaranteed

- **Exactly-once execution of the side effect.** PCA guarantees an authorisation is consumed once. If the resource server acts on a successful response and then crashes before recording it, the retry is denied as a replay. Make the downstream operation idempotent on the receipt's ledger `index` or `commit`.
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
