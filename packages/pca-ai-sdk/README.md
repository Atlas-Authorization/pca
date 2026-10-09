# @atlasauth/pca-ai-sdk

Vercel AI SDK adapter for Proof-Carrying Authority (PCA). `withPCA` wraps an AI SDK tool so every call first builds a PCActn (a signed proof-carrying action) with a PCA `Agent`, fails fast if the agent's local dry-run would be denied, hands the proof to your code so it can be forwarded to the resource server, and then runs the original `execute`. The wrapped tool keeps the same shape, so it drops straight into `tools`.

It does not authorize anything itself: it attaches a proof, and the resource server's verifier decides. If the wrapper is bypassed, the downstream action simply lacks a valid PCActn and fails server-side.

## Install

```sh
npm i @atlasauth/pca-ai-sdk @atlasauth/pca
npm i ai
```

`ai` (v4 or v5) is an optional peer dependency; the adapter only touches `description`, `parameters`, `inputSchema` and `execute`, so it does not import the SDK at runtime.

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCA } from '@atlasauth/pca-ai-sdk';
import { tool } from 'ai';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'issue refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',                       // the id your resource server verifies against
});

const tools = {
  refund: withPCA(
    pcaAgent,
    {
      verb: 'stripe.refund',
      resource: (args) => `charge:${args.chargeId}`,
      onProof: (pca) => { /* forward pca.headers (PCA-Action) or pca.encoded to your server */ },
    },
    tool({ description: 'Refund a charge', inputSchema, execute: async (args) => doRefund(args) }),
  ),
};
```

An over-limit or out-of-scope call throws before `execute` runs (set `failFast: false` to skip the local dry-run and let the server decide). Use `withPCATools(agent, tools, specs)` to wrap several tools at once; tools without a spec pass through unchanged.

## API

- `withPCA(agent, spec, tool)` and `withPCATools(agent, tools, specs)`.
- `GuardToolSpec`: `verb`, `resource` (string or function of the args), `aud`, `failFast`, `onProof`.
- Re-exports from `@atlasauth/pca`: `bridgeToolCall`, `pcaHeaders`, `PcaCall`.

## Status

Experimental. The underlying cryptography in `@atlasauth/pca` has not been independently audited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
