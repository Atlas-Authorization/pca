# @atlasauth/pca-mastra

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Mastra tool guard for Proof-Carrying Authority (PCA). `withPcaTool` wraps a Mastra tool so its `execute` first requires and verifies a PCActn for that call (failing closed with a typed `PcaToolDenied`) and only then runs the original `execute`. `guardStep` does the same kind of gating on a workflow step, pausing risky steps for a human or guardian co-sign.

## Install

```sh
npm i @atlasauth/pca-mastra @atlasauth/pca @atlasauth/pca-ai-sdk
```

`@mastra/core` is not a dependency: tools and steps are matched structurally.

## Usage

Full-policy mode (`authorize`) is the default. Each call is then checked against the grant's limits, bound to the tool input the agent signed, checked for revocation, and accepted only once:

```ts
import { agent, generateKeyPair, memoryPcaStore } from '@atlasauth/pca';
import { withPcaTool, pcaTools, PcaToolDenied } from '@atlasauth/pca-mastra';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$100/day' },
  aud: 'ins_acme',
});

const guarded = withPcaTool(refundTool /* from createTool(...) */, {
  audience: 'ins_acme',          // must equal the PCActn's signed `aud`
  verb: 'stripe.refund',         // the proof must be for this verb
  authorize: {
    grant: pcaAgent.grant,       // or resolveGrant: (grantRef) => your stored grant
    state: memoryPcaStore(),     // replay counters and trust budgets; use a shared store (Redis, your DB) across processes
    isRevoked: (grant) => revokedGrants.has(grant.id),
  },
});

// The proof rides on the run context. By default it is read from runtimeContext.get('pca').
const input = { amount: 20, currency: 'usd', charge: 'ch_1' };
const { encoded } = pcaAgent.act('stripe.refund', 'charge:ch_1', input);
runtimeContext.set('pca', encoded);
await guarded.execute({ context: input, runtimeContext }); // runs

// Each of these throws PcaToolDenied before the tool's execute runs:
//   a validly signed $400 refund under this $100 grant      (kind: 'policy')
//   the same proof presented a second time                  (kind: 'replay')
//   a call after the grant is revoked                       (kind: 'revoked')
//   a tool input that differs from what the agent signed    (kind: 'policy', params_digest)
```

`authorize` requires `grant` (or `resolveGrant`), `state` and `isRevoked`, and the guard's `audience` must be a string. If one is missing, `withPcaTool` throws when you build the guard; it never falls back to signature-only checking (since 0.5 that is the explicit `mode: 'signature-only'`). By default the operation is `{ verb, params: <the tool input> }`. Pass `authorize.operation: (ctx) => ({ verb, resource, params })` to bind the resource as well. Optional: `isPlanAuthorized`, `risk` (server-side risk inputs; by default `params.amount` is priced against the grant), `hooks`, `require`, `allowedSuites`, `pqPins`, `now`.

Guard a whole record of tools with `pcaTools({ refund: refundTool }, { audience, verb, authorize })` (override per tool with `per`, limit with `only`).

### Signature-only mode (explicit)

With `mode: 'signature-only'` and `verify: { grant }` instead of `authorize`, the guard checks only that the proof is genuine: signature, capability chain, plan inclusion, audience, validity window and counter format. It does not read the grant's limits, does not compare the tool input with the signed params, and does not stop a replay, so a validly signed $400 refund under a $100 grant runs. `verify` without the mode is refused when the guard is built. Use `authorize` for anything that acts.

```ts
const signatureOnly = withPcaTool(refundTool, { mode: 'signature-only', verify: { grant: pcaAgent.grant }, audience: 'ins_acme', verb: 'stripe.refund' });
// A missing, malformed, mismatched or unverifiable proof throws PcaToolDenied (kind: 'missing' | 'malformed' | 'binding' | 'verify').
```

Gate a workflow step on risk:

```ts
import { guardStep } from '@atlasauth/pca-mastra';

const step = guardStep(purgeStep /* from createStep(...) */, {
  agent: pcaAgent,
  intent: (stepId, input) => ({ verb: 'files.delete', resource: 'bucket/x', params: input }),
  onStepUp: ({ step, request }) => openApproval(request),
  approved: (request) => isCoSigned(request),
});
```

A step that needs a co-sign throws `PcaStepUpRequired` until `approved` returns true; one the grant forbids throws `PcaStepDenied`.

## API

- `withPcaTool(tool, options)`, `pcaTools(record, options)` - the execution guard. Give `authorize` (full policy, the default: `{ grant | resolveGrant, state, isRevoked, operation?, ... }`) or `mode: 'signature-only'` with `verify` (signature only: `{ grant, nowEpoch?, enforce?, hooks? }` or a custom `(pcactn) => VerifyResult`).
- `authorizeExecution`, `memoryPcaStore` - re-exported from `@atlasauth/pca` (the full-policy check the guard runs).
- `proofFromRunContext` (default), `proofFromContextHeaders(field?, header?)` - where the proof is read from; pass your own via `require`.
- `guardStep`, `reviewStep`, `pendingStepUps` - step-up on workflow steps.
- Errors: `PcaToolDenied` (`kind`: `missing`, `malformed`, `binding`, `verify`, and in full-policy mode `policy`, `replay`, `revoked`, `config`), `PcaStepUpRequired`, `PcaStepDenied`.
- Re-exports the attach side from `@atlasauth/pca-ai-sdk` (`withPCA`, `withPCATools`, `bridgeToolCall`, `pcaHeaders`).

## Status

In full-policy mode the guard enforces the grant's predicates, limits and caveats, binds the call to the signed params, requires a revocation check and makes each PCActn single-use. In signature-only mode it checks only that the proof is genuine (signature, capability chain, plan inclusion, audience, validity, counter format). It makes the local execution boundary refuse to act without a valid PCActn; it does not replace the resource server when a tool makes a remote call. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
