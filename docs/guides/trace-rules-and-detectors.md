---
title: Trace rules and detectors
order: 44
---

# Trace rules and guardrail detectors

Two ways to add guardrails around what an agent does, both of which can only take authority away.

## Trace rules: "never B after A"

The classic prompt-injection exfiltration is a flow: the agent reads untrusted content (a web page, an inbound email), then sends something out. A trace rule forbids the order:

```
never trait:pca.external_communication after tool:web.fetch within 1h
```

Selectors: `tool:<verb>`, `trait:<trait id>`, `resource:<prefix>` (earlier side only) and `any`, separated by commas. The window is `<n>ms|s|m|h|d`, at most 30 days.

```ts
import { compileTraceRules, parseTraceRule } from '@atlasauth/pca-dataflow';

const rule = parseTraceRule('no_exfil', 'never trait:pca.external_communication after tool:web.fetch within 1h');
const { caveats, digest } = compileTraceRules([rule], verbTable); // verbTable: verb -> { traits, effects }
// put `caveats` on the grant (or a delegated hop); every verifier enforces them
```

The rule compiles into ordinary caveats that the verifier evaluates over its own record of the actions it admitted, so it works in every language the verifier ships in, with no rule engine. A send within the hour after a fetch is refused. If the verifier has no history to check, a send is refused too (unknown never allows); other actions are unaffected.

Compilation is strict: a tool that is not in your action set, a trait that matches nothing, or anything the caveats cannot express exactly is an error, not a silently skipped rule. An unreviewed action counts as having every trait, so trait selectors catch it.

### Importing Invariant rules

Rules written for Invariant Labs' guardrails import when they stay inside a small subset:

```ts
import { parseInvariantRule } from '@atlasauth/pca-dataflow';

const { rule, dropped } = parseInvariantRule('inv1', `
raise "Don't use send_email after get_website" if:
    (output: ToolOutput) -> (call2: ToolCall)
    output is tool:get_website
    prompt_injection(output.content, threshold=0.7)
    call2 is tool:send_email`, { horizon: '7d', dropUnsupported: true });
// dropped: ['prompt_injection(output.content, threshold=0.7)']
```

Invariant's `->` means "earlier in the trace", with no window, so you must state the horizon. Conditions outside the subset (detector calls, argument patterns, chains of three events) are errors unless you pass `dropUnsupported`, which removes them from the raise condition. A weaker raise condition fires more often, so the imported rule refuses more than the original, never less, and every removed line is reported.

### The lethal trifecta

An agent that can read private data, read untrusted content and send data out can be steered into leaking the first through the third. `pca actions lint` reports this (`LT-001`) for every send that both kinds of read can reach without a trace rule in between. Declare rules and any untrusted sources the lint cannot infer in `pca.config.json`:

```json
{ "trace": { "rules": ["no_exfil: never trait:pca.external_communication after tool:acme.page.fetch within 1d"],
             "untrusted": ["acme.inbox.read"] } }
```

A rule that does not compile is reported as `LT-000` (an error).

## Detectors: friction, never permission

Prompt-injection and data-leak detectors (Lakera Guard, Prompt Security, your own classifier) can add friction. PCA makes no detection claim, and authorization never depends on one: an attack that fools every detector still cannot exceed the grant, the plan or the trace rules.

The gateway that calls a detector signs a receipt of what it saw, bound to the exact content and optionally the session:

```ts
import { lakeraReceipt } from '@atlasauth/pca-dataflow';
import { detectorInputDigest, detectorSignal, tighten } from '@atlasauth/pca';

const receipt = lakeraReceipt(lakeraResponse, { detector: 'lakera', version: 'guard-v2', content: text, secretKey: gatewayKey, now: Date.now() });

const out = detectorSignal({ receipts: [receipt], policy, input_digests: [detectorInputDigest(text)], now: Date.now() });
const decision = tighten(baseDecision, out.signal); // never higher than baseDecision
```

- A suspicious verdict lowers the decision to `escalate` or `deny`, as your policy says for that detector.
- A clean verdict changes nothing. It is exactly the same as no receipt. There is no setting that requires a clean scan, because that would let a passed (or bypassed) detector buy back authority.
- A receipt that does not verify (unknown detector, unpinned key, other content, other session, too old) escalates.
- Adapters treat anything malformed or ambiguous from the vendor as suspicious (category `detector_error`), so a broken integration adds friction instead of looking clean.

`tighten[]` rules can read the outcome as `env.detect.<detector>` (true when flagged) and `env.detect.invalid`. A grant condition cannot: `env.detect` is model-derived, and a grant that reads it is refused.

The Prompt Security adapter accepts the response shapes read by two open-source integrations (LiteLLM and NVIDIA NeMo Guardrails), which differ; we could not check either against the vendor's own documentation.
