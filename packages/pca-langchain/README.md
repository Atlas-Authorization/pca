# @atlasauth/pca-langchain

LangChain adapter for Proof-Carrying Authority: wrap a StructuredTool so every invocation emits a PCActn (and attaches the proof) before the tool runs.

## Install

```sh
npm i @atlasauth/pca-langchain
# peer dependency, install alongside:
npm i @langchain/core
```

`@langchain/core` (^0.3) is an optional peer dependency.

## Usage

```ts
import { withPCA } from '@atlasauth/pca-langchain';

const guardedTool = withPCA(
  agent,                                       // core @atlasauth/pca Agent
  {
    verb: 'stripe.refund',
    resource: (args) => `ch_${args.chargeId}`,
    onProof: (pca) => { /* forward pca.encoded to the resource server */ },
  },
  refundTool,                                  // your LangChain StructuredTool
);

// Drop into an agent: tools: [guardedTool]
```

The wrapped tool keeps the same shape (whichever of `func` / `invoke` it exposes is wrapped). Each call builds + attaches a PCActn; it does not authorize on its own — the resource server's verifier decides.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
