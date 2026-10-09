# @atlasauth/pca-llamaindex

LlamaIndex.TS adapter for Proof-Carrying Authority (PCA). `withPCA` wraps a `FunctionTool` so every call first builds a signed PCActn (failing fast if the agent's own grant does not permit it), hands you the proof to forward to the resource server, and then runs the original tool.

## Install

```sh
npm i @atlasauth/pca-llamaindex @atlasauth/pca
npm i llamaindex   # optional peer dependency (^0.8 || ^0.9 || ^0.10)
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCA } from '@atlasauth/pca-llamaindex';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',
});

const guardedRefund = withPCA(
  pcaAgent,
  {
    verb: 'stripe.refund',
    resource: (args) => `charge:${args.charge}`,
    onProof: (pca, args) => {
      // forward pca.headers (PCA-Action) to the resource server with your request
    },
  },
  refundTool, // your LlamaIndex FunctionTool
);
```

The wrapped tool has the same shape (`metadata` and other fields preserved; only `call` is wrapped), so it drops into your agent's `tools` array. If the agent's local dry-run denies the action, the call throws `PcaDenied` before the tool runs (disable with `failFast: false`).

## API

- `withPCA(agent, spec, tool)` - spec is `{ verb, resource, aud?, failFast?, onProof? }`.
- Re-exports `bridgeToolCall`, `pcaHeaders`, and the `PcaCall` type from `@atlasauth/pca`.

## Status

This package does not authorize anything. It attaches a proof-carrying action; the resource server's verifier (see `@atlasauth/pca`) decides. The `llamaindex` package is matched structurally and never imported. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
