# @atlasauth/pca-openai-agents

Guard for the OpenAI Agents SDK (`@openai/agents`) that makes every agent tool call proof-carrying. `withPcaTool` wraps a tool so its `execute` first requires a PCActn (read from the run context), verifies it with the PCA core, and only then runs the original tool; on any failure it throws `PcaToolDenied` and the tool does not run. Guardrails and `needsApproval` helpers cover the run-level gate and human or guardian step-up.

The package is duck-typed against the Agents SDK: it has no runtime dependency on `@openai/agents` and works with any compatible version.

## Install

```sh
npm i @atlasauth/pca-openai-agents
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-ai-sdk`.

## Usage

```ts
import { tool, Agent, run } from '@openai/agents';
import { withPcaTool, pcaInputGuardrail } from '@atlasauth/pca-openai-agents';

const refund = tool({ name: 'refund', description: '...', parameters, execute: doRefund });

const guarded = withPcaTool(refund, {
  verify: { grant },              // pcaAgent.grant: the signed Root Intent Grant the proof must chain to
  audience: 'ins_my_server',      // must equal the PCActn's signed aud (null = accept any)
  verb: 'stripe.refund',          // bind the proof to this tool
});

const agent = new Agent({
  name: 'support',
  tools: [guarded],
  inputGuardrails: [pcaInputGuardrail({ verify: { grant }, audience: 'ins_my_server' })],
});

// The agent holding the grant produces the proof (see @atlasauth/pca); it rides on the run context.
const { encoded } = pcaAgent.act('stripe.refund', 'charge:ch_1', toolInput, { aud: 'ins_my_server' });
await run(agent, input, { context: { pca: encoded } });
```

By default the proof is read from `context.pca` (or `context.pcaProof`); pass `require` to read it from the tool input or elsewhere. `verify` can also be a function `(pcactn) => VerifyResult`.

## API

- `withPcaTool(tool, options)` / `pcaTools(record, options)` - wrap one tool / a set
- `pcaInputGuardrail(options)`, `pcaToolGuard(options)` - Agents SDK guardrails that trip when no valid proof is present
- `pcaNeedsApproval(options)`, `withApproval(tool, options)` - map risky tools to the SDK's `needsApproval` using PCA step-up tiers
- `reviewToolCall(...)`, `pendingStepUps(reviews)` - feed an approval inbox
- `PcaToolDenied` (with `kind`: `missing | malformed | verify | binding`), `proofFromRunContext`, `proofFromInputHeaders`

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Verification is real (signature, capability chain, plan inclusion, audience, validity window, counter) but is only as strong as the grant and gates you configure. It guards the local agent-execution boundary; when a tool calls a remote service, that service's own verifier remains the authority. PCA's cryptography has not been independently audited.

## License

MIT - see LICENSE
