# @atlasauth/pca-store-conformance

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A conformance kit for Proof-Carrying Authority replay and counter stores. A PCA verifier refuses a replayed action by
consuming its nonce exactly once (`consumeOnce`) and by advancing per-stream counters (`advance`). This kit runs concurrent
clients against **your** store adapter, with restarts and process crashes, records the history, and checks it for
linearizability against that contract. A store that lets the same nonce through twice under load, or forgets consumed
nonces after a restart, fails here instead of in production.

> Status: **0.4.2, unaudited.**

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
