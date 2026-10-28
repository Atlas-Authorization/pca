# @atlasauth/pca-store-conformance

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A conformance kit for Proof-Carrying Authority replay and counter stores. A PCA verifier refuses a replayed action by
consuming its nonce exactly once (`consumeOnce`) and by advancing per-stream counters (`advance`). This kit runs concurrent
clients against **your** store adapter, with restarts and process crashes, records the history, and checks it for
linearizability against that contract. A store that lets the same nonce through twice under load, or forgets consumed
nonces after a restart, fails here instead of in production.

> Status: **0.5.0.** A store that passes the suite is checked against the behaviours listed here, not audited.

## Install

```sh
npm i -D @atlasauth/pca-store-conformance
```

## Write an adapter

An adapter opens clients against one shared backend (your database, Redis, files, ...):

```ts
import type { StoreAdapter } from '@atlasauth/pca-store-conformance';

export const adapter: StoreAdapter = {
  name: 'my-redis-store',
  async open() {
    const client = await connect(); // your connection
    return {
      consumeOnce: (key, retainUntilMs, nowMs) => client.consumeOnce(key, retainUntilMs, nowMs), // true = first use
      advance: (streamKey, counter) => client.advance(streamKey, counter), // true = counter moved forward
      close: () => client.close(), // the backend's state must survive this
    };
  },
  restart: async () => { /* optional: restart the backend; enables the durability test */ },
  crash: async () => { /* optional: kill the backend abruptly; followed by restart() */ },
};
```

A client may implement `consumeOnce`, `advance` or both; the kit tests what is present.

## Run it

From the command line:

```sh
npx pca-store-conformance --adapter ./my-adapter.js
npx pca-store-conformance --adapter builtin:in-memory   # a reference adapter
```

Exit codes: `0` pass, `1` a violation was found, `3` unresolved (the search budget ran out), `2` a usage or adapter error.
Useful options: `--tests a,b` (a subset), `--clients N`, `--duration MS`, `--seed N` (reproduce a run), `--json`. Run
`npx pca-store-conformance --help` for the full list.

Or from your test suite:

```ts
import { describeStoreConformance, runConformance } from '@atlasauth/pca-store-conformance';
import { adapter } from './my-adapter';

describeStoreConformance(adapter); // registers the conformance tests in the current test runner

// or run it directly and inspect the report
const report = await runConformance(adapter);
```

## What a failure means

A violation report includes the concurrent history that cannot be explained by any sequential order of operations, so you
can reproduce it with `--seed`. Typical causes: a read-then-write instead of an atomic insert, a retention window that
drops keys too early, or a cache in front of the store that is not shared between verifier instances.

## Fail-closed behaviour

The kit reports "pass" only when it saw definite answers and found no violation.

| Missing or invalid | Result |
|---|---|
| A history that no sequential order explains (a double accept of one nonce, a counter that moves backward) | `fail`, exit code 1, with the minimal concurrent history |
| Every call failed or timed out, so nothing definite was observed | `unresolved`, exit code 3; never `pass` |
| The linearizability search ran out of budget | `unresolved`, exit code 3 |
| A client that implements neither `consumeOnce` nor `advance` | Throws (exit 2) |
| Adapter module that cannot be loaded, bad flag, unknown `--tests` name | Exit 2, nothing is reported as passing |
| Adapter declares `durable: false` | The durability test is reported as `skip` with the reason |
| Crash test without the adapter's module path | Reported as `skip` with the reason |
| A store that forgets consumed nonces after a restart, drops live keys early, or accepts an equal counter twice | `fail` in the durability, retention, burst or concurrent test |

## Limits

- It tests the histories it generates (concurrent clients, restarts, crashes, a bounded search); a pass is evidence for those, not a proof that your store is correct under every schedule.
- A `skip` counts as neither pass nor fail: an adapter that declares itself non-durable, or runs without a module path, passes without those tests, so read the per-test lines and not only the exit code.
- Restart and crash tests only run when the adapter provides `restart` and `crash`, and the crash test runs your adapter in child processes.
- It checks the replay and counter contract, not your store's performance, cost or security.
