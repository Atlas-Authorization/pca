# @atlasauth/pca-llamaindex

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

Every row is a call on which the wrapped tool does not run.

| Missing or invalid | Result |
|---|---|
| The agent's local dry-run denies the action (over a limit, outside the grant) | Throws `PcaDenied` before `execute`; no proof is forwarded (default `failFast`) |
| `onProof`, the `resource` function or the agent itself throws (the proof cannot be built) | The error reaches the caller and the tool does not run |

## Limits

- It signs; it does not authorize. The resource server's verifier is the only authority, and a call that bypasses the wrapper simply carries no valid PCActn.
- The local dry-run is an offline convenience. It sees only the policy the agent object holds, so it cannot evaluate server-only state; with `failFast: false` it is skipped entirely and the server is the only gate.
- It does not verify, store, revoke or rate-limit anything, and it does not forward the proof for you: your `onProof` or handler must put it on the request.
- Only the tool's `execute` is wrapped; a tool called by some other path is not covered.
-

## Status

This package does not authorize anything. It attaches a proof-carrying action; the resource server's verifier (see `@atlasauth/pca`) decides. The `llamaindex` package is matched structurally and never imported. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
