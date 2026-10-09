# @atlasauth/pca-vercel-ai

Execution-time guard for the Vercel AI SDK, built on Proof-Carrying Authority. It wraps a tool so that its
`execute` first requires a proof-carrying action (PCActn) for this call, verifies it with the PCA core
(signature, capability chain, plan inclusion, audience, validity window, counter), and only then runs the
original `execute`. A missing, malformed or invalid proof throws a typed `PcaToolDenied`, which the AI SDK
surfaces as a tool error, so the side effect never happens. It also provides a `prepareStep` hook that
pauses the agent loop on risky tools until a step-up approval arrives.

It is the verify-at-execution counterpart of `@atlasauth/pca-ai-sdk`, which makes the agent attach a PCActn
when it calls a tool. The package is structurally typed against the AI SDK, so it works with any version
that uses `execute(args, options)` tools and does not itself import `ai`.

## Install

```sh
npm i @atlasauth/pca-vercel-ai @atlasauth/pca @atlasauth/pca-ai-sdk
npm i ai   # your AI SDK, if you are not already using it
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { pcaTools, PcaToolDenied } from '@atlasauth/pca-vercel-ai';

const AUD = 'ins_example';
const a = agent({
  principal: generateKeyPair(),
  goal: 'refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: AUD,
});

// Any AI SDK tool record: { description, inputSchema, execute }.
const refund = {
  description: 'Refund a charge',
  inputSchema: { type: 'object' },
  execute: async (args: { amount: number; charge: string }) => ({ refunded: args.amount }),
};

// Guard every tool. `verify.grant` is the signed grant the proof must chain to.
const tools = pcaTools(
  { refund },
  { verify: { grant: a.grant }, audience: AUD, per: { refund: { verb: 'stripe.refund' } } },
);

// The proof rides on the call via `experimental_context.pca`
// (generateText({ tools, experimental_context: { pca: encoded } })).
const args = { amount: 20, charge: 'ch_1' };
const { encoded } = a.act('stripe.refund', 'charge:ch_1', args, { aud: AUD });

await tools.refund.execute(args, { experimental_context: { pca: encoded } }); // runs

try {
  await tools.refund.execute(args, {}); // no proof
} catch (e) {
  if (e instanceof PcaToolDenied) console.log(e.kind); // 'missing' ('malformed' | 'verify' | 'binding' otherwise)
}
```

Always set `audience` (a string, or `null` to accept any audience): omitting it fails closed when the
PCActn carries an `aud`.

## Step-up on the agent loop

`pcaPrepareStep(agent, { intent, tools, approved?, onStepUp? })` returns a `prepareStep` function. It
reviews the tool calls made in the previous step; any that need a guardian or human co-sign (and are not
yet `approved`) are passed to `onStepUp` and removed from the next step's `activeTools`. `reviewToolCall`
and `pendingStepUps` expose the same review for use outside the loop.

## API

- `withPcaTool(tool, options)`, `pcaTools(record, { ...options, per?, only? })` - the execution guard.
- `proofFromContext` (default), `proofFromArgHeaders(field?, header?)` - where the proof is read from;
  override with the `require` option.
- `PcaToolDenied` (`kind`: `missing | malformed | verify | binding`, `verb`, `checks`).
- `pcaPrepareStep`, `reviewToolCall`, `pendingStepUps` - step-up support.
- Re-exports from `@atlasauth/pca-ai-sdk` (`withPCA`, `withPCATools`, `bridgeToolCall`, `pcaHeaders`) and
  from `@atlasauth/pca` (`verifyPCActnCore`, `decodePCActn`, `reviewAction`).

## Status

Verification is real, but it is only as strong as the grant you verify against and the enforcement gates
you enable. This guard protects the local execution boundary; when a tool makes a remote call, the remote
resource server should still verify the PCActn itself. The cryptography has not been independently audited.

## License

MIT - see LICENSE
