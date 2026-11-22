# @atlasauth/pca-ai-sdk

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

Every row is a call on which the wrapped tool does not run.

| Missing or invalid | Result |
|---|---|
| The agent's local dry-run denies the action (over a limit, outside the grant) | Throws `PcaDenied` before `execute`; no proof is forwarded (default `failFast`) |
| `onProof`, the `resource` function or the agent itself throws (the proof cannot be built) | The error reaches the caller and the tool does not run |
| The wrapped tool has no `execute` | Throws `withPCA: the wrapped tool has no execute()` |
| A tool in `withPCATools` has no entry in `specs` | Passed through unwrapped and unguarded (by design: list every tool that acts) |

## Limits

- It signs; it does not authorize. The resource server's verifier is the only authority, and a call that bypasses the wrapper simply carries no valid PCActn.
- The local dry-run is an offline convenience. It sees only the policy the agent object holds, so it cannot evaluate server-only state; with `failFast: false` it is skipped entirely and the server is the only gate.
- It does not verify, store, revoke or rate-limit anything, and it does not forward the proof for you: your `onProof` or handler must put it on the request.
- Only the tool's `execute` is wrapped; a tool called by some other path is not covered.
-

## Status

Production tier: this package signs; it does not authorize. The resource server's verifier decides. The underlying cryptography in `@atlasauth/pca` has not been independently audited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
