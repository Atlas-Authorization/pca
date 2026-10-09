# @atlasauth/pca-mastra

Mastra tool guard for Proof-Carrying Authority (PCA). `withPcaTool` wraps a Mastra tool so its `execute` first requires and verifies a PCActn for that call (failing closed with a typed `PcaToolDenied`) and only then runs the original `execute`. `guardStep` does the same kind of gating on a workflow step, pausing risky steps for a human or guardian co-sign.

## Install

```sh
npm i @atlasauth/pca-mastra @atlasauth/pca @atlasauth/pca-ai-sdk
```

`@mastra/core` is not a dependency: tools and steps are matched structurally.

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPcaTool, pcaTools, PcaToolDenied } from '@atlasauth/pca-mastra';

const pcaAgent = agent({
  principal: generateKeyPair(),
  goal: 'process refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'ins_acme',
});

// Guard one tool. The grant is what the proof's capability chain must resolve to.
const guarded = withPcaTool(refundTool /* from createTool(...) */, {
  verify: { grant: pcaAgent.grant },
  audience: 'ins_acme',          // matched against the PCActn's signed `aud` (null = accept any)
  verb: 'stripe.refund',         // optional: bind the proof to this tool
});

// Or guard a whole record of tools (override per tool with `per`, limit with `only`).
const tools = pcaTools({ refund: refundTool }, {
  verify: { grant: pcaAgent.grant },
  audience: 'ins_acme',
  per: { refund: { verb: 'stripe.refund' } },
});

// The proof rides on the run context. By default it is read from runtimeContext.get('pca').
const { encoded } = pcaAgent.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd', charge: 'ch_1' });
runtimeContext.set('pca', encoded);
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

- `withPcaTool(tool, options)`, `pcaTools(record, options)` - the execution guard. `verify` is `{ grant, nowEpoch?, enforce?, hooks? }` or a custom `(pcactn) => VerifyResult`.
- `proofFromRunContext` (default), `proofFromContextHeaders(field?, header?)` - where the proof is read from; pass your own via `require`.
- `guardStep`, `reviewStep`, `pendingStepUps` - step-up on workflow steps.
- Errors: `PcaToolDenied`, `PcaStepUpRequired`, `PcaStepDenied`.
- Re-exports the attach side from `@atlasauth/pca-ai-sdk` (`withPCA`, `withPCATools`, `bridgeToolCall`, `pcaHeaders`).

## Status

Verification here is real (signature, capability chain, plan inclusion, audience, validity, counter) but is only as strong as the grant and gates you configure. It makes the local execution boundary refuse to act without a valid PCActn; it does not replace the resource server when a tool makes a remote call. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
