# @atlasauth/pca-llamaindex

LlamaIndex.TS adapter for Proof-Carrying Authority — wrap a `FunctionTool` so every call emits a
PCActn (and hands you the proof) before the tool runs.

## Install

```sh
npm i @atlasauth/pca-llamaindex
# peer dependency, install alongside:
npm i llamaindex
```

## Usage

```ts
import { withPCA } from '@atlasauth/pca-llamaindex';

const guardedRefund = withPCA(
  agent,
  { verb: 'stripe.refund', resource: (args) => `charge:${args.charge}`, onProof: (pca) => attach(pca.headers) },
  refundTool, // your LlamaIndex FunctionTool
);
```

The wrapped tool has the same shape, so it drops into your agent's tool list. `agent` comes from
`@atlasauth/pca`'s facade. This attaches a proof-carrying action; it doesn't authorize — the resource
server's verifier decides. `llamaindex` is an optional peer dependency and is never imported.

Part of Proof-Carrying Authority — see [`@atlasauth/pca`](../pca).
