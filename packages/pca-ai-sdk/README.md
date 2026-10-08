# @atlasauth/pca-ai-sdk

Vercel AI SDK adapter for Proof-Carrying Authority: wrap an AI SDK tool so every call emits a PCActn (and attaches the proof) before execute runs.

## Install

```sh
npm i @atlasauth/pca-ai-sdk
# peer dependency, install alongside:
npm i ai
```

`ai` (v4 or v5) is an optional peer dependency.

## Usage

```ts
import { withPCA } from '@atlasauth/pca-ai-sdk';
import { tool } from 'ai';

const tools = {
  refund: withPCA(
    agent,                                           // core @atlasauth/pca Agent
    {
      verb: 'stripe.refund',
      resource: (args) => `ch_${args.chargeId}`,
      onProof: (pca) => { /* forward pca.encoded to the resource server, e.g. headers */ },
    },
    tool({ description: 'Refund a charge', inputSchema, execute: async (args) => doRefund(args) }),
  ),
};
```

The wrapped tool keeps the same shape, so it drops straight into `tools`. Each call builds + attaches a PCActn (fast-failing on the agent's local dry-run); it does not authorize on its own — the resource server's verifier decides.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
