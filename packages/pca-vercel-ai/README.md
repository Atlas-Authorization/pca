# @atlasauth/pca-vercel-ai

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Execution-time guard for the Vercel AI SDK, built on Proof-Carrying Authority. It wraps a tool so that its
`execute` first requires a proof-carrying action (PCActn) for this call and authorizes it, and only then runs the
original `execute`. In full-policy mode (`authorize`, the default) the call is checked against the grant's limits
and caveats, bound to the args the agent signed, checked for revocation, and accepted only once. A missing, malformed or invalid proof throws a typed `PcaToolDenied`, which the AI SDK
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
import { agent, generateKeyPair, memoryPcaStore } from '@atlasauth/pca';
import { pcaTools, PcaToolDenied } from '@atlasauth/pca-vercel-ai';

const AUD = 'ins_example';
const a = agent({
  principal: generateKeyPair(),
  goal: 'refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$100/day' },
  aud: AUD,
});

// Any AI SDK tool record: { description, inputSchema, execute }.
const refund = {
  description: 'Refund a charge',
  inputSchema: { type: 'object' },
  execute: async (args: { amount: number; charge: string }) => ({ refunded: args.amount }),
};

const revoked = new Set<string>();
const tools = pcaTools(
  { refund },
  {
    audience: AUD,
    verb: 'stripe.refund',
    authorize: {
      grant: a.grant,            // or resolveGrant: (grantRef) => your stored grant
      state: memoryPcaStore(),   // replay counters and trust budgets; use a shared store (Redis, your DB) across processes
      isRevoked: (grant) => revoked.has(grant.id),
    },
  },
);

// The proof rides on the call via `experimental_context.pca`
// (generateText({ tools, experimental_context: { pca: encoded } })).
const args = { amount: 20, charge: 'ch_1' };
const { encoded } = a.act('stripe.refund', 'charge:ch_1', args);
await tools.refund.execute(args, { experimental_context: { pca: encoded } }); // runs

// Refused before the tool's execute runs, each with a PcaToolDenied:
const big = { amount: 400, charge: 'ch_1' };
const over = a.act('stripe.refund', 'charge:ch_1', big).encoded;
try {
  await tools.refund.execute(big, { experimental_context: { pca: over } }); // a validly signed $400 under a $100 grant
} catch (e) {
  if (e instanceof PcaToolDenied) console.log(e.kind); // 'policy'
}
try {
  await tools.refund.execute(args, { experimental_context: { pca: encoded } }); // the same proof again
} catch (e) {
  if (e instanceof PcaToolDenied) console.log(e.kind); // 'replay'
}
```

`authorize` requires `grant` (or `resolveGrant`), `state` and `isRevoked`, and `audience` must be a string. If
one is missing, building the guard throws; it never falls back to signature-only checking (since 0.5 that is the explicit `mode: 'signature-only'`). A revoked grant is
refused with kind `revoked`; args that differ from what the agent signed with kind `policy` (`params_digest`). By
default the operation is `{ verb, params: args }`; pass `authorize.operation: (args, options) => ({ verb,
resource, params })` to bind the resource as well. Optional: `isPlanAuthorized`, `risk` (server-side risk inputs;
by default `params.amount` is priced against the grant), `hooks`, `require`, `allowedSuites`, `pqPins`, `now`.

### Signature-only mode (explicit)

With `mode: 'signature-only'` and `verify: { grant }` instead of `authorize`, the guard checks only that the proof is genuine (signature,
capability chain, plan inclusion, audience, validity window, counter format). It does not read the grant's
limits, does not compare the args with the signed params, and does not stop a replay, so a validly signed $400
refund under a $100 grant runs. `verify` without the mode is refused when the guard is built. Use `authorize` for any tool that
acts.

```ts
const signatureOnly = pcaTools({ refund }, { mode: 'signature-only', verify: { grant: a.grant }, audience: AUD, verb: 'stripe.refund' });
```

Always set `audience` (a string, or `null` to accept any audience in signature-only mode): omitting it fails
closed when the PCActn carries an `aud`.

## Step-up on the agent loop

`pcaPrepareStep(agent, { intent, tools, approved?, onStepUp? })` returns a `prepareStep` function. It
reviews the tool calls made in the previous step; any that need a guardian or human co-sign (and are not
yet `approved`) are passed to `onStepUp` and removed from the next step's `activeTools`. `reviewToolCall`
and `pendingStepUps` expose the same review for use outside the loop.

## API

- `withPcaTool(tool, options)`, `pcaTools(record, { ...options, per?, only? })` - the execution guard. Give
  `authorize` (full policy, the default) or `mode: 'signature-only'` with `verify` (signature only).
- `proofFromContext` (default), `proofFromArgHeaders(field?, header?)` - where the proof is read from;
  override with the `require` option.
- `PcaToolDenied` (`kind`: `missing | malformed | verify | binding`, and in full-policy mode
  `policy | replay | revoked | config`; `verb`, `checks`).
- `pcaPrepareStep`, `reviewToolCall`, `pendingStepUps` - step-up support.
- Re-exports from `@atlasauth/pca-ai-sdk` (`withPCA`, `withPCATools`, `bridgeToolCall`, `pcaHeaders`) and
  from `@atlasauth/pca` (`verifyPCActnCore`, `decodePCActn`, `reviewAction`, `authorizeExecution`,
  `memoryPcaStore`).

## Status

In full-policy mode the guard enforces the grant's predicates, limits and caveats, binds the call to the signed
params, requires a revocation check and makes each PCActn single-use. In signature-only mode it checks only that
the proof is genuine. This guard protects the local execution boundary; when a tool makes a remote call, the remote
resource server should still verify the PCActn itself. The cryptography has not been independently audited.

## License

MIT - see LICENSE
