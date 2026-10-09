# @atlasauth/pca-langchain

LangChain adapter for Proof-Carrying Authority (PCA). `withPCA` wraps a LangChain structured tool so every invocation first builds a signed PCActn for the call (failing fast if the agent's own grant does not permit it), hands you the proof to forward to the resource server, and then runs the original tool.

## Install

```sh
npm i @atlasauth/pca-langchain @atlasauth/pca
npm i @langchain/core   # optional peer dependency (^0.3)
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCA } from '@atlasauth/pca-langchain';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',
});

const guardedTool = withPCA(
  pcaAgent,
  {
    verb: 'stripe.refund',
    resource: (args) => `ch_${args.chargeId}`,
    onProof: (pca, args) => {
      // forward pca.headers (PCA-Action) to the resource server with your request
    },
  },
  refundTool, // your LangChain StructuredTool
);

// Use it like the original: tools: [guardedTool]
```

The wrapped tool is a copy that keeps every other field (`name`, `description`, `schema`, ...); whichever of `func` / `invoke` the tool exposes is wrapped. If the agent's local dry-run denies the action, the call throws `PcaDenied` before the tool runs (disable with `failFast: false`). Optional spec fields: `aud` (overrides the agent's default audience).

## API

- `withPCA(agent, spec, tool)` - spec is `{ verb, resource, aud?, failFast?, onProof? }`.
- Re-exports `bridgeToolCall`, `pcaHeaders`, and the `PcaCall` type (`{ pcactn, encoded, headers }`) from `@atlasauth/pca`.

## Status

This package does not authorize anything. It attaches a proof-carrying action to the call; the resource server's verifier (see `@atlasauth/pca`) decides. A tool call that bypasses the wrapper simply lacks a valid PCActn and fails server-side. The local dry-run is a convenience fast-fail, not a grant. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
