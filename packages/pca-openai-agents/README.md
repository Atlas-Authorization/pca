# @atlasauth/pca-openai-agents

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Guard for the OpenAI Agents SDK (`@openai/agents`) that makes every agent tool call proof-carrying. `withPcaTool` wraps a tool so its `execute` first requires a PCActn (read from the run context) and authorizes it, and only then runs the original tool. In full-policy mode (`authorize`, the default) the call is checked against the grant's limits and caveats, bound to the input the agent signed, checked for revocation, and accepted only once; on any failure it throws `PcaToolDenied` and the tool does not run. Guardrails and `needsApproval` helpers cover the run-level gate and human or guardian step-up.

The package is duck-typed against the Agents SDK: it has no runtime dependency on `@openai/agents` and works with any compatible version.

## Install

```sh
npm i @atlasauth/pca-openai-agents
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-ai-sdk`.

## Usage

```ts
import { tool, Agent, run } from '@openai/agents';
import { memoryPcaStore } from '@atlasauth/pca';
import { withPcaTool, pcaInputGuardrail } from '@atlasauth/pca-openai-agents';

const refund = tool({ name: 'refund', description: '...', parameters, execute: doRefund });

const guarded = withPcaTool(refund, {
  audience: 'ins_my_server',      // must equal the PCActn's signed aud
  verb: 'stripe.refund',          // the proof must be for this verb
  authorize: {
    grant,                        // pcaAgent.grant, or resolveGrant: (grantRef) => your stored grant
    state: memoryPcaStore(),      // replay counters and trust budgets; use a shared store (Redis, your DB) across processes
    isRevoked: (g) => revokedGrants.has(g.id),
  },
});

const agent = new Agent({
  name: 'support',
  tools: [guarded],
  // optional run-level pre-filter (signature only, see below)
  inputGuardrails: [pcaInputGuardrail({ verify: { grant }, audience: 'ins_my_server' })],
});

// The agent holding the grant produces the proof (see @atlasauth/pca); it rides on the run context.
const { encoded } = pcaAgent.act('stripe.refund', 'charge:ch_1', toolInput);
await run(agent, input, { context: { pca: encoded } });
```

In full-policy mode each of these throws `PcaToolDenied` before the tool runs: a validly signed $400 refund under a $100 grant (`kind: 'policy'`), the same proof presented again (`'replay'`), a call after the grant is revoked (`'revoked'`), and a tool input that differs from what the agent signed (`'policy'`, `params_digest`).

`authorize` requires `grant` (or `resolveGrant`), `state` and `isRevoked`, and `audience` must be a string. If one is missing, `withPcaTool` throws when you build the guard; it never falls back to signature-only checking (since 0.5 that is the explicit `mode: 'signature-only'`). By default the operation is `{ verb, params: <the tool input> }`; pass `authorize.operation: (input, runContext) => ({ verb, resource, params })` to bind the resource as well. Optional: `isPlanAuthorized`, `risk` (server-side risk inputs; by default `params.amount` is priced against the grant), `hooks`, `require`, `allowedSuites`, `pqPins`, `now`.

By default the proof is read from `context.pca` (or `context.pcaProof`); pass `require` to read it from the tool input or elsewhere.

### Signature-only mode (explicit) and the guardrails

With `mode: 'signature-only'` and `verify: { grant }` instead of `authorize`, `withPcaTool` checks only that the proof is genuine (signature, capability chain, plan inclusion, audience, validity window, counter format). It does not read the grant's limits, does not compare the tool input with the signed params, and does not stop a replay, so a validly signed $400 refund under a $100 grant runs. `verify` without the mode is refused when the guard is built. Use `authorize` on every tool that acts. `verify` can also be a function `(pcactn) => VerifyResult`.

`pcaInputGuardrail` and `pcaToolGuard` always run in signature-only mode: a guardrail runs before a specific tool call is known, so it cannot bind the proof to that call or spend it. Use them as an early pre-filter, and put the authority check on the tool with `authorize`.

## API

- `withPcaTool(tool, options)` / `pcaTools(record, options)` - wrap one tool / a set; give `authorize` (full policy, the default) or `mode: 'signature-only'` with `verify` (signature only)
- `pcaInputGuardrail(options)`, `pcaToolGuard(options)` - Agents SDK guardrails that trip when no valid proof is present
- `pcaNeedsApproval(options)`, `withApproval(tool, options)` - map risky tools to the SDK's `needsApproval` using PCA step-up tiers
- `reviewToolCall(...)`, `pendingStepUps(reviews)` - feed an approval inbox
- `PcaToolDenied` (with `kind`: `missing | malformed | verify | binding`, and in full-policy mode `policy | replay | revoked | config`), `proofFromRunContext`, `proofFromInputHeaders`
- `authorizeExecution`, `memoryPcaStore` - re-exported from `@atlasauth/pca`

## Fail-closed behaviour

Every row is a call on which the wrapped tool does not run; the guard throws `PcaToolDenied` with the `kind` shown (unless a different error is named).

| Missing or invalid | Result |
|---|---|
| No proof on the call (run `context` keys `pca` or `pcaProof`, or your `require` source) | `missing` |
| Proof that cannot be decoded | `malformed` |
| Proof signed for a different verb than the guard's `verb`, or (with `authorize.operation`) for a different resource than the call | `binding` |
| Bad signature or capability chain, wrong or absent audience, unknown grant, outside its validity window, or bad counter format | `verify` |
| Over a limit or caveat, or an input that differs from the signed params | `policy` (full-policy mode) |
| The same proof presented a second time | `replay` (full-policy mode) |
| The grant is revoked | `revoked` (full-policy mode) |
| A required component absent at call time | `config` (full-policy mode) |
| `resolveGrant`, `isRevoked`, the state store or the clock throws or rejects | `policy` with `authorization error (fail closed)` |
| A required component missing at construction (`grant` or `resolveGrant`, `state`, `isRevoked`, a string `audience`, an operation or `verb`) | `withPcaTool` throws `TypeError` when you build the guard |
| `authorize` together with `verify`, `verify` without `mode: 'signature-only'`, `mode: 'signature-only'` without `verify`, `authorize` with signature-only mode, or an unknown `mode` | `TypeError` at construction; it never downgrades to signature-only |
| A signature-only `verify` function that throws | The error reaches the caller and the tool does not run |
| No verifier configured in signature-only mode | Every call is refused (`verify`) |
| The wrapped tool has no `execute` | Throws after a valid proof (nothing runs) |

Guardrails and approvals:

| Missing or invalid | Result |
|---|---|
| `pcaInputGuardrail` or `pcaToolGuard` finds no valid proof (signature-only check) | The guardrail trips (`tripwireTriggered: true`) with the denial `kind` |
| A guardrail's verifier throws something other than a denial | The error reaches the caller |
| `pcaNeedsApproval`: the grant forbids the tool | Returns `true` (needs approval) by default; with `denyNeedsApproval: false` it returns `false` |
| `pcaNeedsApproval`: needs a co-sign and `approved` is absent or false | Returns `true` and calls `onStepUp` |

## Limits

- The guardrails are a signature-only pre-filter. They run before a specific tool call is known, so they cannot bind the proof to a call, check limits or spend it; put `authorize` on the tool.
- `needsApproval` is honoured by the Agents SDK, not by this package; with `denyNeedsApproval: false` a call the grant forbids is not flagged. A tool that does not use it is not gated by it.
- A tool whose `intent` mapping returns `null` is treated as safe (`needsApproval` is `false`).

- Local boundary only: when a tool calls a remote service, that service's own verifier remains the authority.
- Full policy is only as good as what you give it: a shared `state` store (a per-process memory store does not stop a replay across processes), a correct `isRevoked`, and a trusted `grant` or `resolveGrant`.
- Risk scores and thresholds are evaluated only from the `risk` inputs you supply (by default `params.amount` is priced against the grant).
- Tools you leave out of `pcaTools` (via `only`) or do not wrap are not guarded.
- Signature-only mode does not read limits, bind the tool input or stop a replay; use it only where another layer does.
-

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). In full-policy mode the tool guard enforces the grant's predicates, limits and caveats, binds the call to the signed params, requires a revocation check and makes each PCActn single-use. In signature-only mode (and in the guardrails) it checks only that the proof is genuine. It guards the local agent-execution boundary; when a tool calls a remote service, that service's own verifier remains the authority.

## License

MIT - see LICENSE
