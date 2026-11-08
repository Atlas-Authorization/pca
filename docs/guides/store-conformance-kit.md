# Testing your replay store: the store conformance kit

A PCA verifier is only as safe as its replay and counter store. `verifyPCActn` decides whether an action is
authorized; whether it was **already used** is the store's job. The contract is short (see `ReplayStore` /
`CounterStore` in `@atlasauth/pca`):

| Operation | Must |
|---|---|
| `consumeOnce(key, retainUntilMs, nowMs)` | resolve `true` iff there is no live record for `key` (live = its horizon is `>= nowMs`), then record `retainUntilMs`; forget a record only after its horizon |
| `advance(stream, counter)` | resolve `true` iff `counter` is strictly greater than the stored value, then store it |
| both | be atomic across every verifier instance, durable across restarts, and reject (never resolve `true`) when they cannot decide |

`@atlasauth/pca-store-conformance` runs that contract against **your** store: it drives your adapter from many
concurrent clients (and, optionally, several processes that are killed mid-operation), records every call, and checks
the recorded history for **linearizability**: whether some one-at-a-time order of the calls, consistent with when each
call started and finished, explains every answer your store gave.

## 1. Write an adapter (about ten lines)

```js
// my-adapter.mjs
import { pool } from './db.js';

export function createAdapter(options) {
  return {
    name: 'my postgres store',
    capabilities: { durable: true },
    async open() {
      // one client = one connection / one verifier instance
      return {
        consumeOnce: (key, retainUntilMs, nowMs) => myStore.consumeOnce(key, retainUntilMs, nowMs),
        advance: (stream, counter) => myStore.advance(stream, counter),
        close: async () => {},
      };
    },
    // optional: restart() the backend, crash() it abruptly, teardown() pools
  };
}
```

The module may export the adapter object (default export or `adapter`) or a factory `createAdapter(options)`; the CLI
passes `--option k=v` pairs to the factory. Implement whichever operations you ship; the kit detects them (or declare
`capabilities.consumeOnce` / `capabilities.advance`).

| Adapter member | Meaning |
|---|---|
| `open()` | a new client against the shared backend. Called once per simulated verifier instance. |
| `restart()` | optional: restart the backend after every client is closed (e.g. restart the database server or reopen files). Without it the durability test only closes and reopens clients. |
| `crash()` | optional: crash the backend abruptly (followed by `restart()`), used once during the crash test |
| `teardown()` | optional: release pools and temp files. Never drop shared data here. |
| `capabilities.durable` | default `true`. Declare `false` only for a single-process in-memory store; the durability test is then skipped and reported as such. |

Use a key prefix or a dedicated database: the kit writes keys named `pcasc-<run>:...` and never deletes anything.

Two complete examples ship with the package: `examples/postgres-adapter.mjs` (`INSERT .. ON CONFLICT (key) DO UPDATE ..
WHERE until < $now RETURNING` and `UPDATE .. WHERE counter < $n RETURNING`) and `examples/redis-adapter.mjs`
(`SET key value NX PX ttl` and a Lua compare-and-set).

## 2. Run it

```sh
npx pca-store-conformance --adapter ./my-adapter.mjs --option url=postgres://...
```

| Flag | Default | |
|---|---|---|
| `--tests a,b` | all | `burst`, `concurrent`, `retention`, `durability`, `crash` |
| `--clients N` | 16 | concurrent clients |
| `--duration MS` | 2000 | length of the concurrent run |
| `--rounds N` | 20 | same-key bursts |
| `--revisit-keys N` | 500 | keys written and then revisited by the retention test |
| `--processes N` / `--kill-every MS` | 3 / 400 | crash test: client processes alive at once, and how often one is killed with SIGKILL |
| `--budget N` | 200000 | search states per key before the key is reported unresolved |
| `--json` | | machine-readable report |

Exit codes: `0` pass, `1` a violation was found, `3` unresolved (no violation, but not every key could be decided or no
call returned a definite answer), `2` usage or adapter error.

From a test suite:

```ts
import { describe, it } from 'vitest';
import { describeStoreConformance } from '@atlasauth/pca-store-conformance';
import { createAdapter } from './my-adapter.mjs';

describeStoreConformance(() => createAdapter({ url: process.env.DATABASE_URL }), {
  runner: { describe, it },
  crash: { module: new URL('./my-adapter.mjs', import.meta.url).pathname },
});
```

or programmatically: `const report = await runConformance(adapter, options); console.log(formatReport(report));`.

## 3. The tests

| Test | What it does | What it catches |
|---|---|---|
| `burst` | every client calls the operation on the SAME fresh key at the same moment, `rounds` times | read-then-write races: two winners for one nonce, one counter value accepted twice |
| `concurrent` | every client loops for `duration` over a few keys per short time window, so all clients contend on the same keys | the same, under sustained load and with reorderings; counters use small value ranges so duplicates and out-of-order values occur |
| `retention` | writes `revisit-keys` distinct keys, then revisits every key while it is still live | early pruning and capacity eviction of live records (a bounded cache that forgets) |
| `durability` | write, close every client, `restart()` the backend, read back | a consumed nonce that comes back, a counter that goes backwards |
| `crash` | several client processes, one killed with SIGKILL every `kill-every` ms (and the backend crashed once when the adapter has `crash()`) | lost or duplicated effects around client death; stores that are only correct within one process |

Every call is recorded twice: when it is invoked (before the request leaves the client) and when it returns. A call that
rejects, times out, or whose process is killed is recorded with an **unknown** outcome: it may or may not have taken
effect, at any time after it was invoked. A store that rejects when it cannot decide is behaving correctly, so unknown
outcomes are never counted against it; a run in which no call returned a definite answer is reported as unresolved.

## 4. Reading a failure

```
  [FAIL] burst/consumeOnce        320 ops, 20 keys, 0 errors/timeouts; 7 NON-LINEARIZABLE key(s)
      key pcasc-...:consume:burst:3 (16 ops, decided by overlap): minimal counterexample:
        c4: consumeOnce(now=1760000000123, retainUntil=1760000600123) [+0.000ms .. +2.105ms] -> TRUE
        c9: consumeOnce(now=1760000000124, retainUntil=1760000600124) [+0.412ms .. +2.388ms] -> TRUE
```

Each violating key comes with a **minimal counterexample**: recorded calls that no sequential order can explain. Here
two clients were both told they consumed the same nonce, so one action would be accepted twice. Times are relative to
the first call; `open` marks a call whose outcome is unknown.

The counterexample is shrunk only with deletions that cannot turn a legal history into an illegal one (removing a
`false` answer, or removing a write together with every `false` answer it could have explained). So the shrunk history
being illegal proves that the full recorded history is illegal: a FAIL is a real contract violation of the store as
wired by your adapter.

## 5. Positive controls: why a pass means something

The kit ships deliberately broken reference adapters, and its own test suite proves that each one is flagged:

| Built-in adapter | Mistake | Flagged by |
|---|---|---|
| `builtin:bad-read-then-write` | reads, awaits, then writes (no transaction / compare-and-set) | `burst`, `concurrent` |
| `builtin:bad-volatile` | claims durability but keeps state in process memory | `durability` |
| `builtin:bad-evicting` | a bounded cache that evicts live records (`--option capacity=N`) | `retention` |
| `builtin:bad-non-strict-counter` | accepts a counter equal to the last one | `burst`, `concurrent` |
| `builtin:in-memory` used by several processes | each process has its own map | `crash` |

and the good references pass: `builtin:in-memory` (the library's `InMemoryReplayStore`, single process) and
`builtin:durable-file` (the crash-safe multi-process file store from `@atlasauth/pca/durable-state`, `--option
dir=...`). Run one yourself to see what a failure looks like:

```sh
npx pca-store-conformance --adapter builtin:bad-read-then-write --tests burst
```

The checker is also validated against a brute-force reference on thousands of random small histories, legal and
illegal, including histories with unknown outcomes.

## 6. Limits: a pass is evidence, not proof

- The kit checks the histories it **observed**. A race that needs more clients, more load, a slower network or a
  failure the run did not inject can still exist. Run it with production-like concurrency, against a production-like
  deployment (same isolation level, same replication, same persistence settings), and repeat it.
- Linearizability search is exponential in the number of mutually concurrent calls on one key. Keys whose history has
  no unknown outcome are decided exactly and quickly; a key with unknown outcomes that exceeds the search budget is
  reported **unresolved**, never as a pass. Raise `--budget` or reduce `--clients` to decide it.
- Killing a client process does not lose data the server already acknowledged, and `restart()` is only as strong as
  what your adapter does in it. Power loss, disk-cache loss, a replica promoted with missing writes, and clock problems
  on a store that expires records by its own clock are not exercised unless your `crash()` / `restart()` hooks do it.
- All clients of a run share one machine's clock, so the real-time order between calls is exact. Do not merge histories
  recorded on different machines.
- The store also needs the right configuration: synchronous, persistent commits (Postgres `synchronous_commit=on`;
  Redis `appendfsync always` and `maxmemory-policy noeviction`), and clocks within 60 s of each other.

To check a whole deployment (clocks, proxy settings, verifier policy, and a quick version of the store probes), see
[pca-doctor](pca-doctor.md).

## 7. The store behind `requirePCA`: the `pca-state` profile

`requirePCA` and `authorizeToolCall` keep each agent's last counter and trust budget in a `PcaStateStore` (the
`budgetStore` / `state` option), not in a `ReplayStore`. The `pca-state` profile tests that store through the real guard,
with real signed PCActns, against the replay-state invariant: one action id is consumed at most once (see
[Anti-replay guarantees](../reference/anti-replay.md#replay-state-invariant)).

Write an adapter whose `open()` returns one handle per verifier instance:

```js
// my-pca-state.mjs
import postgres from 'postgres';
import { postgresPcaStateStore } from '@atlasauth/pca-store-conformance/examples/postgres-pca-state.mjs';

export function createPcaStateAdapter({ url }) {
  return {
    name: 'my postgres state store',
    capabilities: { durable: true, shared: true },
    async open() {
      const sql = postgres(url, { max: 1 });
      return { store: postgresPcaStateStore(sql), close: () => sql.end() };
    },
  };
}
```

```sh
npx pca-store-conformance --profile pca-state --adapter ./my-pca-state.mjs --option url=postgres://...
```

The kit ships this Postgres store as `examples/postgres-pca-state.mjs`: one `INSERT ... ON CONFLICT DO NOTHING` for a
holder's first action, then one `UPDATE ... WHERE last_counter < $counter AND budget IS NOT DISTINCT FROM $before`.
Copy its statements into your own store.

| Test | What it does | Must observe |
|---|---|---|
| `claim-burst`, `claim-concurrent`, `claim-durability` | the store's `claim` used as `advance(key, counter)`, through the linearizability checker of sections 3 and 4 (a store without `claim` is driven through `get` / `put`, under its `withKeyLock` if it has one) | no non-linearizable key |
| `one-instance` | `--clients` concurrent copies of one proof to one guard, `--rounds` times | exactly 1 admitted per round |
| `instances` | the copies spread over 4 guards, each on its own handle, built with `multiInstance: true` (the default for a store that is not process-local) | exactly 1 per round; a store that only the in-process lock can serialise is refused, which fails the test |
| `processes` | the same race from `--processes` child processes (2 guards each) | exactly 1 per round, across all processes |
| `crash-after-claim` | admitted, then the instance dies before its handler runs (the backend is crashed and restarted if the adapter can do that); then a child process is killed with SIGKILL right after its admission | the same proof is denied afterwards, the next counter is admitted |
| `retry-after-timeout` | the commit lands but its answer is lost; then a retry on another instance while the first commit is still in flight | the first call is denied (fail closed), the retry is denied as a replay; of the in-flight pair exactly 1 is admitted |

An adapter that declares `shared: false` (state in one process) skips `instances` and `processes`. One that declares
`durable: false` skips `crash-after-claim` and `claim-durability`. The report says which.

Positive controls, each flagged by the kit's own tests:

| Built-in adapter (`--profile pca-state`) | Mistake | Flagged by |
|---|---|---|
| `builtin:bad-get-put` | `get` / `put` with no `claim` and no `withKeyLock` | `instances`, `processes` (refused in multi-instance mode) |
| `builtin:bad-read-then-write-claim` | a `claim` that reads, awaits, then writes | `one-instance`, `instances`, `claim-burst` |
| `builtin:bad-local-lock` | a `withKeyLock` that locks only within one handle | `instances`, `processes` |
| `builtin:bad-volatile` | claims durability, forgets every claim on restart | `crash-after-claim`, `claim-durability` |
| `builtin:bad-unshared` | each handle has its own state but the adapter declares `shared` | `instances`, `retry-after-timeout` |

The good references are `builtin:in-memory` (`atomicMemoryPcaStore`, one process) and `builtin:durable-file`
(`durablePcaStateStore` over `@atlasauth/pca/durable-state`, several processes on one host, `--option dir=...`).
Programmatically: `formatPcaStateReport(await runPcaStateConformance(adapter, { module, moduleOptions }))`. Without
`module` (the adapter's module path) the child-process tests are skipped.


## Other stores: bond settlement and the transparency log

The same kit tests the two durable stores of the optimistic path and the ledger. They are not replay stores, so the check is a list of named claims, each driven against your store, rather than a linearizability search.

| Store | Run | What it checks |
|---|---|---|
| `BondStore` (internal bond accounting) | `runBondStoreConformance(adapter)` or `describeBondStoreConformance(adapter)` | an open or settle applies whole or not at all; a retry returns the stored record; racing settles have one winner; caps and overdrafts hold inside the store; time only moves forward; acknowledged commits survive a restart and a crash |
| `LedgerStore` (the log and its checkpoints) | `runLedgerStoreConformance(adapter)` or `describeLedgerStoreConformance(adapter)` | an append lands at exactly the length the caller saw, all of a batch or none; racing writers fill every position once with no holes; checkpoints stay inside the log and never go backwards; acknowledged writes survive a restart and a crash |

An adapter creates a fresh backend (`create()`), and hands back a client plus `reopen()` (another client on the same backend) and, optionally, `crash()` (kill it abruptly, return a client on what survived). Declare `durable: false` only for an in-process store; the durability checks are then reported as skipped. Each suite ships reference adapters that must pass and defective ones (a store that moves money before checking the phase, one that forgets on reopen, one that loses updates) that the suite must flag: a checker that passes everything is worthless.

```ts
import { describeBondStoreConformance, describeLedgerStoreConformance } from '@atlasauth/pca-store-conformance';
describeBondStoreConformance(myBondStoreAdapter);
describeLedgerStoreConformance(myLedgerStoreAdapter);
```
