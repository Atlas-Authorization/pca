---
title: PCA vs OAuth vs WebAuthn
order: 40
---

# PCA vs OAuth vs WebAuthn: when to use which

These three do not compete. They answer different questions, and a complete agentic system uses all three.

- **WebAuthn** answers authN: *is this the person (or device) holding this key?*
- **OAuth 2.0** answers authZ-by-delegation: *what has this user allowed this application to do on their behalf?*
- **PCA** answers authF: *is this specific action a faithful execution of an authority the principal actually conferred?*

## Side by side

| | OAuth 2.0 | WebAuthn | PCA |
|---|---|---|---|
| Question answered | authZ: may this client act within a scope? | authN: is this the key holder, here, now? | authF: is this exact action a faithful, in-policy, uncompromised execution of the principal's intent? |
| The credential | Access token (bearer, or sender-constrained with DPoP/mTLS) plus a refresh token | A signed assertion over a server challenge, from a device-held key | A **proof-carrying action (PCActn)**: capability chain, plan-inclusion proof, counter, risk claim, signature(s) |
| What is conferred | A scope: a coarse, static set of permissions | Nothing. It proves presence, it grants no authority | A signed intent envelope: goal commitment, predicates, caveats and risk policy, narrowed by attenuation at each delegation |
| Flow | One-time consent, then reuse the token until expiry or revocation | Challenge-response per ceremony (login, step-up) | Commit a plan once, then a fresh proof per action, bound to a node of that plan |
| What the verifier checks | Token validity and scope (locally for JWTs, or by introspection) | Signature over the challenge, origin, RP ID, counter | Chain attenuation, plan inclusion, leaf signature, counter, caveats, policy, revocation, threshold at the risk-derived level |
| Stolen credential | Usable by anyone until expiry or revocation (bearer) | Useless without the device and user verification | One proof is bound to one action, plan node and counter. A stolen key is still confined by the plan, envelope and trust budget |
| Replay | Within token lifetime unless sender-constrained | Prevented by server challenge | Prevented by a strictly increasing per-holder counter |
| Least authority | Scope granularity, chosen at consent time | Not applicable | Predicates over verb, resource and params, plus attenuation: a sub-agent can only get less |
| Compromised or steered client | Not addressed. A valid token authorizes whatever the client does | Not addressed | The central threat. Out-of-plan actions have no inclusion proof; high-risk actions need co-signers; trust budget decays |
| Revocation | Revoke or expire tokens; introspection or short TTLs | Remove the credential | Revoke a capability id (descendants die with it), freeze the instance, expiry caveats |
| Auditability | Server logs the verifier chooses to keep | Server logs | A transparency ledger: per-action commits with inclusion proofs the principal can replay |
| Human in the loop | At consent time only | At the ceremony | At consent, and per action when the risk-derived threshold needs a principal-device co-signature |

## Why a token is the wrong shape for an agent

An OAuth token proves *possession*. For a human app that is adequate: the app's behavior is fixed by its code and the user's intent is implied by the UI. An agent's behavior is chosen at run time by a model that untrusted content can steer (prompt injection, the confused deputy). A scope like `files:write` cannot distinguish "save the report" from "overwrite everything", and the token is equally valid for both. PCA moves the question from "does the caller hold a secret?" to "is this action provably inside what was committed and signed?", and it makes that checkable offline by the resource server.

## What PCA does and does not do

- It does not replace identity. The principal's root key still has to come from somewhere trustworthy, which is exactly what WebAuthn is for.
- It does not replace delegated access to a third party's API. If the resource server only understands OAuth, PCA can sit in front as a policy and audit layer, but the downstream call still uses that API's tokens.
- It does not claim to detect a malicious plan by itself: it bounds what a plan can do (predicates, risk policy, thresholds, budget) and makes every action attributable and auditable. Hardware attestation and zero-knowledge compliance proofs are optional: they are checked only when you configure a verifier, except that a grant binding the agent's identity requires a valid attestation, and a PCActn carrying a compliance proof fails without a verifier.

## When to use which, and how they compose

| Situation | Use |
|---|---|
| Sign a person in; protect the root of authority | WebAuthn (passkeys) |
| Let a human grant a third-party app access to their data | OAuth 2.0 / OIDC |
| Let an autonomous agent act on a resource, with bounded and auditable authority | PCA |

They stack:

1. **WebAuthn establishes the human.** The principal authenticates with a passkey. The principal's PCA root key signs the Root Intent Grant, and the same principal later provides the device co-signature when a high-risk action steps up. Note that in this release the principal share is a raw Ed25519 signature over `thresholdMessage(pcactn)`; binding it to a passkey ceremony is an integration the console or device layer provides ([Trust model](./security/trust-model.md)).
2. **OAuth connects human to app.** The user signs in to the application hosting the agent, and OAuth/OIDC handles any third-party API access that the app uses on their behalf.
3. **PCA governs agent to resource.** The agent presents a PCActn per action, and the resource server verifies it (`verifyPCActn` / `requirePCA`) and anchors it in the ledger.

## Adopting PCA incrementally

PCA degrades gracefully, so each rung is independently adoptable and a resource server can start small.

| Rung | What you turn on | What you get |
|---|---|---|
| 0 | OAuth 2.1 with PKCE and proof of possession (already shipped). A PCActn with only a scope and a PoP signature *is* an OAuth PoP request. | Bearer-free baseline; OAuth-only clients keep working. |
| 1 | `verifyPCActn` core checks (chain, plan inclusion, leaf signature, counter), Policy VM, risk functional, ledger | Plan-bound actions, per-action attributability |
| 2 | Threshold verification, revocation proofs, kill switch | Human-in-the-loop by cryptography; targeted and global revocation |
| 3 | Attestation (software mode now), optimistic fast-path | Workload identity; low-latency reversible actions |
| 4 | Hardware attestation and SNARK compliance (seams) | Intent privacy, weights-level binding as they become available |

OIDC and OAuth clients that do not understand PCA still work against the Rung 0 surface; PCA-aware verifiers get authF. A resource server can start with only the core checks and add threshold, revocation, attestation and ZK hooks as they become available, checking `verdict.checks` to see exactly which clauses were `pass`, `fail`, `not-enforced` or `unsupported`.

See also: [overview](./README.md), [agent quickstart](./guides/agent-quickstart.md), [resource-server quickstart](./guides/resource-server-quickstart.md), [threat model](./security/threat-model.md), and the Internet-Draft `draft-atlas-pca-authf`.

## Upgrading to 0.5

### Natural-language approvals and goal binding (goal-to-decision)

- `approveDraft` now issues a v2 approval that covers the instruction, the model id and the prompt. Pass the instruction text as the grant's `goal` to `agentFromApprovedNL`: any other text throws `goal_mismatch`. Stored v1 approvals and drafts still load for one release; the result carries `legacy_unbound_instruction: true`, which you should treat as unreviewed instruction text. Re-approve them with 0.5.
- To bind a grant to what the principal approved, mint it with `goal` set to `ApprovedGoal.goal_string` and configure the verifier with `intent: { approved_goal }` (`ApprovedGoal.intent_policy`). Without `approved_goal` nothing changes.

0.5 changes the defaults of the verifier entry points so that the safe behaviour is the one you get without asking. Most changes make a call that used to allow a request deny it until you supply the missing piece, so run your tests against 0.5 before you deploy it. Each section below shows the 0.4 code, the 0.5 code and, where there is one, the explicit opt-out. The list of changes is in the [changelog](./CHANGELOG.md).

| You use | What changes | Section |
|---|---|---|
| `verifyPCActn` | A bare call denies unless revocation, replay, plan authorization, audience, validity and grant binding passed | [1](#1-verifypcactn-requires-the-default-checks) |
| `requirePCA` or an HTTP adapter (`pca-express`, `-fastify`, `-hono`, `-next`, `-fetch`) | An `operation` mapping is required; a shared store must be safe across instances; the replay key carries the audience | [2](#2-requirepca-binds-the-proof-to-an-operation) |
| `authorizeToolCall` / `authorizeRequest` (`pca-mcp-rs`) | `authorizeRequest` is the complete check; admission alone is opt-in | [3](#3-mcp-authorizerequest-is-the-complete-check) |
| `pca-gateway` | A full-policy `policy` is required; signature-only is explicit | [4](#4-the-gateway-is-full-policy-by-default) |
| `pca-mastra`, `pca-vercel-ai`, `pca-openai-agents` | `authorize` is the default mode; signature-only is explicit | [5](#5-agent-framework-guards-are-full-policy-by-default) |
| Code that reads `checks` | A fourth status, `unsupported` | [6](#6-checkstatus-gains-unsupported) |
| Imports from `@atlasauth/pca` | Experimental features moved to `@atlasauth/pca/ext/*`; Core loads none of them | [7](#7-experimental-features-moved-to-atlasauthpcaext) |

### 1. `verifyPCActn` requires the default checks

In 0.4 `verifyPCActn` reported and left the decision to you. With no `require` list, a proof whose revocation was never checked, or whose counter was never compared with stored state, still came back `allow: true`. In 0.5 the default `require` list is `DEFAULT_REQUIRED_CHECKS`: `counter`, `revocation`, `plan_root_authorized`, `audience`, `validity` and `grant_ref_bound` must all be `pass`.

Before:

```ts
const verdict = await verifyPCActn(pcactn, { grant, audience: 'ins_acme', context: { plan, planAuthorized: true } });
// 0.4: verdict.allow === true, although nothing checked revocation
```

After, supply what the default needs (a revocation check at least):

```ts
const verdict = await verifyPCActn(pcactn, {
  grant,
  audience: 'ins_acme',
  hooks: { revocation: ({ grant }) => ({ enforced: true, ok: !isRevoked(grant.id) }) },
  context: { plan, planAuthorized: true },
});
```

If you want the report alone, as in 0.4, say so:

```ts
const verdict = await verifyPCActn(pcactn, { grant, audience: 'ins_acme', require: [] }); // read verdict.checks yourself
```

`requirePCA` and `authorize` already applied these defaults; they are unaffected.

### Aggregate scopes need a durable `BudgetLedger`

If you declare an accumulator with `scope: 'principal'`, `'org'` or `'fleet'`, pass a durable `BudgetLedger` (for example `openDurableBudgetLedger({ dir })`, or your own checked with `runBudgetLedgerConformance`) to `admitAggregateAction`, and supply the principal, org and fleet ids of each action. A volatile ledger now throws `not_durable`, and a missing id denies with `scope_unbound`. Call `startAggregate` before the effect and `settleAggregate` after it. Session-scoped accumulators are unchanged.

### 2. `requirePCA` binds the proof to an operation

**`operation` is required.** In 0.4 a `requirePCA` guard verified that a proof was genuine and within the grant, but not that it was for the operation the route executes: a valid proof for `stripe.refund` was accepted by a route that deletes a customer if the grant also permitted that. In 0.5 a guard built without an `operation` mapping throws. The mapping names the verb, the resource and the exact params from your routing, never from the proof.

Before:

```ts
app.post('/refunds', pcaExpress({ audience: 'ins_acme', resolveGrant, budgetStore, hooks, context }), handler);
```

After:

```ts
app.post(
  '/refunds',
  pcaExpress({
    audience: 'ins_acme',
    resolveGrant,
    budgetStore,
    hooks,
    context,
    // the operation THIS route executes
    operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${req.body.charge}`, params: req.body.params }),
  }),
  handler,
);
```

With `operation`, the proof must be for exactly that verb, resource and params. The params you give are the ones the grant's predicates and caveats evaluate, and the adapters then run the strict `authorize` pipeline (a store and a revocation check are required, and the result carries the bound `operation`). The same applies to `pcaFastify`, `pcaHono`, `withPCA` of `pca-next` and `pca-fetch`, and to `siteGuard` of `pca-site`, which takes `operation: (req, verb) => ({ verb, resource, params })`.

To keep the unbound guard while you migrate, ask for it by name. Do not ship it:

```ts
pcaExpress({ /* ... */ insecureAllowUnboundOperation: true });
```

**A shared store must be safe across instances.** In 0.4 a store with only `get` and `put` was serialised by an in-process lock, which is correct for one process only, and nothing told you. In 0.5 `multiInstance` is on unless the store declares `scope: 'process'`, so such a store is refused when the guard is built. Give the store `claim` (an `AtomicPcaStateStore`: one compare-and-set per action) or `withKeyLock` (an exclusive per-key lock across every process), or use a store that declares `scope: 'process'`, such as `memoryPcaStore()`. To run a plain store in one process on purpose:

```ts
requirePCA({ /* ... */ budgetStore: myGetPutStore, multiInstance: false });
```

**The replay key carries the audience.** Counter and budget state used to be keyed by `grantId:holder`, so two resource servers sharing a store interfered with each other. In 0.5 the key also carries the audience (`replayScope: 'audience-grant-holder'`). You do not migrate the store: while the new key has no state, the guard starts from the `lastCounter` and budget under the old key, so a proof already spent stays spent, and it never writes the old key again. If your code reads the store by key, build the key with `pcaStateKey`:

```ts
// 0.4
const state = await store.get(`${grant.id}:${holder}`);
// 0.5
const state = await store.get(pcaStateKey(grant.id, holder, undefined, 'ins_acme'));
```

To keep the 0.4 key, pass `replayScope: 'grant-holder'`.

### 3. MCP: `authorizeRequest` is the complete check

`authorizeRequest` in `@atlasauth/pca-mcp-rs` used to check admission only: the proof is genuine, in scope and for this server. It did not check the grant's limits, bind the proof to the tool call or keep a replay counter, so a valid proof for an over-limit amount or another tool was admitted. In 0.5 `authorizeRequest` is `authorizeToolCall`, which does all of that.

Before:

```ts
const r = await authorizeRequest(req, { resource, authorizationServers, resolveGrant, prmUrl });
```

After, pass what the full check needs:

```ts
const r = await authorizeRequest(req, {
  resource,
  prmUrl,
  resolveGrant,
  tool: 'refund',
  args: { chargeId: 'ch_1', amount: 42 },
  toolAction: (tool, args) => ({ verb: 'stripe.refund', resource: `charge:${String(args.chargeId)}` }),
  state,      // replay counters and trust budgets
  isRevoked,  // is this grant revoked?
});
```

A call that omits these is refused with the names of the missing pieces; it is never downgraded to admission. If you really want admission alone, say so (the same function is also exported as `admitRequest`); the option type `AuthorizeRequestOptions` is now `AdmissionOptions`:

```ts
const r = await authorizeRequest(req, { resource, authorizationServers, resolveGrant, prmUrl, admissionOnly: true });
```

`authorizeToolCall` now runs on `authorize`, like the HTTP adapters with `operation`. It reads and writes state under the audience-scoped key described above.

### 4. The gateway is full-policy by default

In 0.4 `pca-gateway` verified the proof and the request binding and nothing more: the grant's limits were not evaluated, and replay and revocation were opt-in. In 0.5 `policy` is required. Full mode evaluates the grant's limits against the real params, requires a revocation check and a replay store, and the agent signs the real params with the request binding as a `binding` member (`bindParams`).

Before:

```ts
const gateway = createGateway({ audience, routes, resolveGrant });
```

After:

```ts
const gateway = createGateway({
  audience,
  routes,
  resolveGrant,
  policy: { mode: 'full', params: 'body', state, isRevoked },
});
// agent side: sign the real params plus the request binding
const { encoded } = agent.act(verb, resource, bindParams(params, requestBinding(req, { body: false })));
```

A gateway without a `policy` throws when it is built, and `authorize` denies every request. The 0.4 behaviour is the explicit signature-only mode. It now needs a `replayGuard`, and a `hooks.revocation` check unless you pass `requireChecks: []`:

```ts
createGateway({ audience, routes, resolveGrant, policy: { mode: 'signature-only' }, replayGuard: memoryReplayGuard(), hooks: { revocation } });
```

### 5. Agent-framework guards are full-policy by default

`withPcaTool` and `pcaTools` of `pca-mastra`, `pca-vercel-ai` and `pca-openai-agents` used to check the proof's signature when you passed `verify`. In 0.5 the default mode is full: pass `authorize` and every call checks the tool input against the signed params, evaluates the grant's limits, requires revocation and makes each proof single-use.

Before:

```ts
const tool = withPcaTool(refundTool, { verify: { grant }, audience: 'ins_acme', verb: 'stripe.refund' });
```

After:

```ts
const tool = withPcaTool(refundTool, {
  audience: 'ins_acme',
  verb: 'stripe.refund',
  authorize: { grant, state: memoryPcaStore(), isRevoked: (g) => revoked.has(g.id) },
});
```

`verify` alone is refused when the guard is built. Signature-only checking is the explicit mode:

```ts
withPcaTool(refundTool, { mode: 'signature-only', verify: { grant }, audience: 'ins_acme', verb: 'stripe.refund' });
```

The OpenAI Agents input and tool guardrails (`pcaInputGuardrail`, `pcaToolGuard`) remain signature-only pre-filters.

### 6. `CheckStatus` gains `unsupported`

A proof can carry a feature the verifier does not implement. Today that is a `bond_ref`. In 0.4 the `bond` check reported `not-enforced`, which reads as "nobody asked". In 0.5 it reports `unsupported`, which is never a pass: `verifyPCActn` denies the proof unless you list the check in `allowUnsupported`, and a required `unsupported` check fails with that word in the reason. The assurance report already used the same value.

```ts
const verdict = await verifyPCActn(pcactn, { /* ... */ allowUnsupported: ['bond'] });
verdict.checks.bond; // 'unsupported'
```

If you switch on the status, add the case:

```ts
switch (status) {
  case 'pass': /* ... */ break;
  case 'fail': /* ... */ break;
  case 'not-enforced': /* ... */ break;
  case 'unsupported': /* treat as not passed */ break;
}
```

### Goal compiler: facade limits are stricter

- A `$` limit on a verb whose catalog entry has no amount field now throws from `compilePolicy`. Give the verb an amount field in the catalog, or remove the limit.
- Two or more count limits now emit one `rate` caveat each. Code that read a single `rate` caveat from `caveats` should read all of them.
- A `$` limit alongside an irreversible action now keeps the default step-up thresholds instead of setting both to 1. Actions above the second threshold need the human co-signature again; pass `riskPolicy: { theta1: 1, theta2: 1 }` to restore auto-approval explicitly.
- `CompiledPolicy` gains `approximations`. `$N/day` is still a per-call ceiling plus a one-period grant lifetime in `compilePolicy`; use `liftLegacy` with the goal compiler for a real sliding-window cap. `liftLegacy` expresses money in minor units (cents), so amounts must be integers in minor units.

### 7. Experimental features moved to `@atlasauth/pca/ext/*`

The root entry used to export every feature, experimental ones included. In 0.5 it exports Core, the post-quantum suites, the server path, threshold multisig and durable state; the experimental features are subpaths of the same package, one per feature in the [maturity](./maturity.md) table:

| Subpath | Contains |
|---|---|
| `@atlasauth/pca/ext/intent` | the intent layer: intent binding, sessions, action schemas, accumulators, provenance, semantic thresholds |
| `@atlasauth/pca/ext/attestation` | hardware and software attestation, allowlists, the passport |
| `@atlasauth/pca/ext/frost` | FROST, the DKG, networked and post-quantum FROST |
| `@atlasauth/pca/ext/zk` | zero-knowledge compliance proofs |
| `@atlasauth/pca/ext/optimistic` | optimistic execution, challenge window, bond settlement |
| `@atlasauth/pca/ext/ledger` | the transparency ledger and liveness beacons |
| `@atlasauth/pca/ext/research` | mesh, sessions, immune system, reputation, DLP, console, policy simulation and the other research modules |

A name moves; it is not exported from both places. Change the import and nothing else:

```ts
// 0.4
import { verifyPCActn, mintSessionGrant, frostTrustedDealerKeygen } from '@atlasauth/pca';
// 0.5
import { verifyPCActn } from '@atlasauth/pca';
import { mintSessionGrant } from '@atlasauth/pca/ext/intent';
import { frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
```

If a build fails with "has no exported member", the name is in one of the subpaths above.

**Core loads none of them.** `@atlasauth/pca/core` used to load the intent layer, attestation, beacons and the ledger at run time, because the core verifier called into them. It no longer does. Its `verifyPCActnCore` does not evaluate the intent layer, and it refuses (never skips) anything that needs it: a PCActn carrying an `intent` or `intent_session` member is rejected at the wire check, and an `intent` or `intentV2` option denies. The root entry's `verifyPCActnCore`, and so `verifyPCActn`, `requirePCA` and `authorize`, have the intent layer loaded and behave as before. If you use Core and want the intent layer, pass it in:

<!-- pca-core-verify: allow Core with the intent extension passed in; the paragraph above says Core alone is not an authorization decision -->
```ts
import { verifyPCActnCore } from '@atlasauth/pca/core';
import { INTENT_EXTENSIONS } from '@atlasauth/pca/ext/intent';

const result = await verifyPCActnCore(pcactn, { grant, audience, extensions: INTENT_EXTENSIONS });
```


### 8. Research units: `agentFromNL`, safety certificates, reputation disputes

- `agentFromNL` is gone. Replace it with `draftPolicyFromNL` -> `approveDraft` (a pinned reviewer signs) -> `agentFromApprovedNL`.
- Safety certificates now include `scope: 'risk-budget-bound'` and optional signed `checks`. Reissue old certificates; `verifySafetyCertificate` refuses a certificate without `scope`.
- `DisputeRecord` requires a unique `id`. `reputation()` returns score 0 for invalid input instead of computing one.
- `quorumStatus` reports `available: false` for a quorum below 1, and heartbeats dated in the future count as down.
- Constant or skewed quantum entropy is rejected by the new health tests (pass `healthTest: false` only in tests).
### 9. Harness and control-evaluation inputs are validated

`new Harness(...)` now throws for an empty plan, duplicate plan node ids, an `agentSecret` that is not 32 bytes, a non-finite or negative budget and an empty audience, and `step()` returns `bad_candidate` when the oracle throws. Inputs whose provenance is anything other than exactly `trusted` count as untrusted (taint 1). `controlEval` throws for an empty red suite, `episodes` below 1 or a non-finite seed; pass real values. In `@atlasauth/pca-less-wasm`, a missing wasm file now fails its tests instead of skipping them.
### 10. Research-grade packages: `pca-mpc` default offline phase, `pca-abe` is FAME

`@atlasauth/pca-mpc`: the default offline phase no longer uses a dealer. If you relied on it, add the opt-in and accept that the dealer sees every share and key:

```ts
composeSecureMalicious(vectors, { insecureTrustedDealer: true });
launchLocal({ ..., offline: 'trusted-dealer', insecureTrustedDealer: true, mainJs });
```

Nodes started from a configuration file with `offline: 'trusted-dealer'` need `insecureTrustedDealer: true` in that file, and the dealer node is only started in that mode. Runs without the opt-in need no dealer node.

`@atlasauth/pca-abe`: regenerate master keys, issued keys and ciphertexts (the formats changed and old material is not readable). Remove calls to `rerandomizeKey` (issue a fresh key instead). A policy must not name the same attribute in two leaves; restructure it (for example, share the attribute above the gates) or issue distinct attribute tokens.

### 11. A decision is allow, deny or escalate; a model can only tighten

Three changes, all about making "ask a human" a real outcome and keeping model judgement out of the allow path.

**Results carry `decision`.** `authorize`, `createAuthorizer`, `requireAuthorized` and `requirePCA` now return `decision: 'allow' | 'deny' | 'escalate'`. `allow` (or `ok`) stays a boolean for one release and is exactly `decision === 'allow'`, so a host that only reads it still fails closed. A verdict whose every failing check is an unanswered question (`intent_required:`) or a `tighten` rule that asks for a person is `escalate`: status 403, with `escalation` (the request to put to the principal). If you treated every 403 as a plain deny, nothing breaks; if you want to ask the principal, read `decision`. To let a signed answer through, pass `escalation: { principals: [...] }` and the principal's `EscalationAnswer` (header `PCA-Escalation-Answer`, body `escalation_answer`, or `escalationAnswer` on `authorize`). The answer must be signed by a pinned principal key and bound to this grant, this exact PCActn and the holder's history; the replay counter spends it. An answer never upgrades a deny.

**Model-derived values are refused in a grant's `where` (rule 21, new `tighten` check).** `env.class.*`, `env.prov.*`, `env.judge.*` and `env.world.*` of a world decided by a single oracle came from a model or a classifier, and a wrong label could widen a grant (`not` and `ne` flip it). They may now appear only in the grant envelope's `tighten[]` list, `[{ id, when, signal: 'escalate' | 'deny' }]`, which can only add friction. A grant that still reads one in `where` is refused with `tighten: ...`. To keep an existing grant working while you migrate, set `model_polarity: 'legacy'` on its envelope (or on the verifier's v2 policy); it then verifies, the `tighten` check is reported as degraded in `assurance`, and any `requireAssurance` policy refuses it. Move the condition into `tighten[]` and drop the flag.

**Units (rule 20, new `units` check).** Add `units` to the envelope, `{ 'action.params.amount': { kind: 'money', currency: 'USD', exponent: 2 } }`, to tag every policy term that reads a unit-bearing parameter. The verifier refuses an action whose signed schema declares another unit (cents against dollars, EUR against USD) and a `where` term that reads such a parameter untagged. Grants without `units` are unchanged.

Native verifiers (Go, Rust, Python) decide these rules inside `authorize()` exactly as the TypeScript verifier does: the signed envelope's `units`, `tighten` and `model_polarity` are evaluated (a native verifier used to ignore them, so a grant that asked for a human behaved as if it did not), a verdict with several failing checks keeps every reason so a multi-check escalation stays an escalation, and an `EscalationAnswer` may be signed under any suite the verifier implements. What may need changing in a native host:

- **A grant that reads a model-derived value in `where` is refused** by the native verifiers too, unless it carries `model_polarity: 'legacy'` (or the verifier's v2 policy does); the pass is then reported degraded (`Degraded["tighten"]` in Go and Rust, the assurance report in Python).
- **Escalation needs a store that can read the holder's history.** Rust: implement the now required `StateStore::last(&self, key) -> Option<Option<u64>>` (`MemoryStateStore` and `SqliteStateStore` do). Go: your `StateStore` must implement `LastStore` (`Last(key) (*int64, error)`; `MemoryStateStore` and `SQLStateStore` do) when `EscalationPrincipals` / `EscalationPinned` is set; otherwise `Authorize` refuses with `authorize_config` and `RequirePCA` panics at construction. Python: the store needs `last(key)` when `escalation_principals` is set (otherwise `authorize_config`, and `AuthorizeOptions` raises `ValueError`).
- **Pins.** Go: `VerifyEscalationAnswer` takes `[]PinnedSigner` (`Ed25519Pins(keys...)` for the old behaviour) and `AuthorizeInput` / `AuthorizeOptions` gain `EscalationPinned` for principals that sign with a post-quantum suite. Rust: `verify_escalation_answer` takes `&[PinnedSigner]` (`PinnedSigner::ed25519(pk)`, `PinnedSigner::with_pq(pk, pq_pk)`); `AuthorizeInput::escalation_principals` is `&[PinnedSigner]` (`AuthorizeOptions::with_escalation_principals` still takes Ed25519 keys). Python: `escalation_principals` entries may be a key or `{"pk": ..., "pq_pk": ...}`.
- **`Verdict` gains `Reasons` / `reasons` and `LegacyModelPolarity` / `legacy_model_polarity`** (Rust struct literals need the new fields); the Go and Rust escalation request `reasons` carry every failing check's reason; `BuildEscalationRequest` / `build_escalation_request` take a TTL (`EscalationRequestTTLMs`, `escalation_request_ttl_ms`).
- **`DecideTighten` / `decide_tighten` return the reason**, and `DecideUnits` / `decide_units` the reference's exact reason text; a JSON `null` `tighten` or `polarity` is malformed (it used to be read as absent).

## Native SDKs and Python

### Upgrading to 0.5

Version 0.5 makes two breaking changes in the Python package, its seven agent-framework adapters and the Go, Rust, Java, Kotlin, .NET, PHP, Ruby and Swift SDKs. The TypeScript package follows the same rules for the check names and the denial reasons; its guard defaults are covered in the TypeScript sections of this guide.

**1. The guards run the full `authorize` path by default.** Until 0.4 a middleware or guard verified the signature, the capability chain, the audience and the validity window, and nothing else: it did not evaluate the grant's limits and caveats, did not check revocation and did not stop a replayed proof. From 0.5 the default is `authorize`: the proof must be for the exact operation you are about to execute (verb, resource and parameters, which come from your own routing and parsed request, never from the proof), the grant's predicates and caveats must hold for those parameters, your revocation source must say the grant is not revoked, and the replay counter is claimed in one atomic step.

- Without a state store, a revocation check or an operation mapping, the guard refuses every request with HTTP 403 `authorize_config` and lists what is missing. It never falls back to checking the signature only.
- Signature-only is still available, as an explicit opt-in: `signature_only=True` (Python; Django: `PCA_SIGNATURE_ONLY = True`), `SignatureOnly: true` (Go), `with_signature_only()` (Rust), `signatureOnly(...)` (Java), `SignatureOnly = true` (.NET), `signatureOnly: true` (PHP), `signature_only: true` (Ruby). Giving it together with authorize options is a configuration error, raised when the guard is built.
- Kotlin and Swift ship no middleware. Call `authorize` where you handle the request; the core verifier is signature-only in both.
- The Python adapters (`atlas-pca-fastmcp`, `-langgraph`, `-crewai`, `-pydantic-ai`, `-google-adk`, `-haystack`, `-agent-framework`) depend on `atlas-pca>=0.5,<0.6`. Their tool guards default to `authorize`; a custom `verifier=` now needs `signature_only=True`.

If you cannot supply the three components yet, add the opt-in flag and plan the move: that keeps today's behaviour, and nothing more.

**2. The `counter` check is split, and denials name the limit.**

| 0.4 | 0.5 |
|---|---|
| core check `counter` (the counter is a non-negative safe integer) | `counter_format` |
| `authorize` check `counter` (strictly greater than the last counter seen) | `replay` |
| reason `counter: 5 is not greater than last seen 5 (replay)` | `replay: 5 is not greater than last seen 5 (replay)` |
| reason `counter: missing or not a non-negative safe integer` | `counter_format: missing or not a non-negative safe integer` |
| `require: ["counter"]` | still accepted: it means `replay` in `authorize` and `counter_format` where no state is kept |
| reason `no predicate permits stripe.refund on charge:ch_1` for an over-limit amount | `amount <= 500 not satisfied for stripe.refund on charge:ch_1` |

`counter` is no longer a key of any `checks` map; code that reads `checks.counter` must read `counter_format` (core verifier) or `replay` (`authorize`). The default required list is now `counter_format, replay, revocation, plan_root_authorized, audience, validity, grant_ref_bound` (plus `operation`, `params_digest` and `policy` in `authorize`). A denial that names the limit identifies the first condition of the first predicate that covers the verb and resource and is not met: `amount <= 500`, `currency in ["usd", "eur"]`, `any of (...)`. A verb or resource that no predicate covers keeps `no predicate permits ...`. The wording is the same in every language.

The per-language sections below show the change in code.

#### Python (`atlas-pca` and the `atlas-pca-*` agent-framework adapters)

**What changes in 0.5**

- `require_pca`, FastAPI `RequirePCA` and Django `PCAMiddleware` run the full `authorize` pipeline by default (predicates, caveats, revocation, replay, binding to the executed operation). A guard built without `authorize` options refuses every request with 403 `authorize_config` and names the missing components. Signature-only is the explicit opt-in `signature_only=True` (Django: `PCA_SIGNATURE_ONLY = True`). Passing both `signature_only` and `authorize` raises at construction (`ValueError`; Django `ImproperlyConfigured`).
- The core check `counter` is now `counter_format` (in `verdict.checks`, `CHECK_ORDER` and its reason `counter_format: missing or not a non-negative safe integer`). The stateful check in `authorize` is `replay`; its reasons start with `replay:`. `counter` in `authorize(require=[...])` still works as an alias of `replay`. `counter` is never emitted in a `checks` map.
- An unmet predicate limit is named: `amount <= 100 not satisfied for payments.send on payments/acme` instead of `no predicate permits payments.send on payments/acme` (unchanged when no predicate is in scope).
- The adapters (`atlas-pca-fastmcp`, `-langgraph`, `-crewai`, `-pydantic-ai`, `-google-adk`, `-haystack`, `-agent-framework`) depend on `atlas-pca>=0.5,<0.6`. Their tool guards default to `authorize`; a guard built without `authorize` options refuses calls with `authorize_config`; `signature_only=True` is the opt-in, and a custom `verifier=` now needs it. `pca_guard_node` (LangGraph) is a routing pre-check and stays signature-level: authorize on the node that runs the tools.

**Before**

```python
guard = require_pca(audience="payments-rs", resolve_grant=grants.get)           # signature only
guard = require_pca(audience="payments-rs", resolve_grant=grants.get,
                    authorize=AuthorizeOptions(state_store=store, is_revoked=is_revoked), operation=op)
```

**After**

```python
# keep the old behaviour, explicitly
guard = require_pca(audience="payments-rs", resolve_grant=grants.get, signature_only=True)

# or move to the default (recommended)
guard = require_pca(audience="payments-rs", resolve_grant=grants.get,
                    authorize=AuthorizeOptions(state_store=store, is_revoked=is_revoked), operation=op)
```

**Rename**

- `verdict.checks["counter"]` -> `verdict.checks["counter_format"]`; `result.checks["counter"]` (authorize) -> `result.checks["replay"]`.
- Code matching reasons: `counter: N is not greater than last seen M (replay)` -> `replay: N is not greater than last seen M (replay)`; `no predicate permits ...` for a limit -> `<limit> not satisfied for <verb> on <resource>`.

#### Go

`pca-go` 0.5 changes three things.

**1. `RequirePCA` runs `Authorize` by default.** Signature-only is an explicit opt-in. A guard built with no `Authorize`
options and no `SignatureOnly` refuses every request with 403 `authorize_config`; the JSON body names what is missing
(`StateStore`, `IsRevoked`). Setting both `SignatureOnly` and `Authorize` panics at construction.

```go
// before (0.4): signature, chain and freshness only
mw := pca.RequirePCA(pca.RequirePCAOptions{Audience: "payments-rs", ResolveGrant: resolve})

// after (0.5), keep the old behaviour explicitly
mw := pca.RequirePCA(pca.RequirePCAOptions{Audience: "payments-rs", ResolveGrant: resolve, SignatureOnly: true})

// after (0.5), recommended: the full authorize path
mw := pca.RequirePCA(pca.RequirePCAOptions{
	Audience:     "payments-rs",
	ResolveGrant: resolve,
	Authorize: &pca.AuthorizeOptions{
		StateStore: store,
		IsRevoked:  isRevoked,
		Operation:  operationFor, // from your routing and parsed body, never from the PCActn
	},
})
```

**2. Check names.** The core verifier's `counter` check is now `counter_format` (in `Verdict.Checks` and in its reason,
`counter_format: missing or not a non-negative safe integer`). `Authorize` reports replay under `replay`; its reasons start
with `replay:`. `DefaultRequiredChecks()` is now `counter_format, replay, revocation, plan_root_authorized, audience, validity,
grant_ref_bound, operation, params_digest, policy`. In `AuthorizeInput.Require`, `counter` is still accepted as an alias of
`replay`. Rename any code that reads `Checks["counter"]` or matches the prefix `counter:`.

**3. Denials name the limit.** When a predicate matches the action's verb and resource but a `where` limit is not met, the
reason is `amount <= 100 not satisfied for payments.send on payments/acme` (it was `no predicate permits ...`). With no
predicate in scope the old text is unchanged.

#### Rust

`atlas-pca` 0.5 changes three things.

**1. The `axum` guard runs `authorize` by default.** Signature-only is an explicit opt-in. A `GuardConfig` without
`with_authorize` refuses every request with 403 `authorize_config`, naming the missing components (`state_store`,
`is_revoked`). Calling both `with_signature_only` and `with_authorize` panics at construction.

```rust
// before (0.4): signature, chain and freshness only
let cfg = GuardConfig::new("payments-rs", |grant_ref| grants.get(grant_ref));

// after (0.5), keep the old behaviour explicitly
let cfg = GuardConfig::new("payments-rs", |grant_ref| grants.get(grant_ref)).with_signature_only();

// after (0.5), recommended: the full authorize path
let cfg = GuardConfig::new("payments-rs", |grant_ref| grants.get(grant_ref))
    .with_authorize(AuthorizeOptions::new(store, |_pcactn, grant| Ok(revocations.contains(grant))))
    .with_operation(|parts, body| Some(Operation::new("payments.send", "payments/acme", params_from(parts, body))));
```

**2. Check names.** The core verifier's `counter` check is now `counter_format` (in `Verdict::checks` and in its reason,
`counter_format: missing or not a non-negative safe integer`). `authorize` reports replay under `replay`; its reasons start
with `replay:`. `DEFAULT_REQUIRED_CHECKS` is now 10 entries: `counter_format, replay, revocation, plan_root_authorized,
audience, validity, grant_ref_bound, operation, params_digest, policy` (the array type is `[&str; 10]`). In
`AuthorizeInput::require`, `counter` is still accepted as an alias of `replay`. Rename any code that reads
`checks["counter"]` or matches the prefix `counter:`.

**3. Denials name the limit.** When a predicate matches the action's verb and resource but a `where` limit is not met, the
reason is `amount <= 100 not satisfied for payments.send on payments/acme` (it was `no predicate permits ...`). With no
predicate in scope the old text is unchanged.

#### Java

What changes in 0.5:

- `PcaFilter` and `PcaInterceptor` run the full `Authorize.authorize` path by default. Built without `Authorize.Options`, every request is refused with `403 authorize_config` (it names the missing `stateStore`, `isRevoked`); the signature is never verified on its own.
- Signature-only is an explicit opt-in: `PcaFilter.signatureOnly(...)` / `PcaInterceptor.signatureOnly(...)`. Giving `signatureOnly` together with `Authorize.Options` or an operation mapper throws `IllegalArgumentException`.
- The core verifier check `counter` is now `counter_format`; `Authorize` reports the stateful check as `replay`. `counter` is accepted as an alias of `replay` in `Input.require(...)` only.
- A denied envelope limit is named in the reason: `amount <= 100 not satisfied for payments.send on payments/acme`.

Before:

```java
PcaFilter filter = new PcaFilter("payments-rs", resolver, Clock.systemUTC()); // signature only
```

After (full path, the default):

```java
Authorize.Options options = new Authorize.Options(store, (p, g) -> revoked(g));
PcaFilter filter = new PcaFilter("payments-rs", resolver, Clock.systemUTC(), options,
    (request, body) -> operationFor(request, body));
```

After (keep signature-only):

```java
PcaFilter filter = PcaFilter.signatureOnly("payments-rs", resolver, Clock.systemUTC());
```

Rename `counter` to `counter_format` where you read `Verdict.checks` or the reason, and to `replay` where you read an `authorize` result; update any `require` list that names `counter` (still accepted, now an alias of `replay`).

#### Kotlin

What changes in 0.5:

- The core verifier check `counter` is now `counter_format` (in `Pca.Verdict.checks` and in its reason `counter_format: missing or not a non-negative safe integer`).
- `Authorize.authorize` reports the stateful check as `replay`; `counter` is accepted as an alias of `replay` in `Input.require` only. `Authorize.DEFAULT_REQUIRED_CHECKS` is `counter_format, replay, revocation, plan_root_authorized, audience, validity, grant_ref_bound, operation, params_digest, policy`.
- A denied envelope limit is named in the reason: `policy: amount <= 100 not satisfied for payments.send on payments/acme` (no predicate in scope keeps `no predicate permits ...`).
- Kotlin ships no middleware: use `Authorize.authorize` as the entry point; the core verifier `Pca.verifyPcactn` is signature-only.

Before:

<!-- pca-core-verify: allow the snippet shows the core verifier check rename, not an authorization decision -->
```kotlin
val v = Pca.verifyPcactn(pcactn, grant, now, Pca.Audience.Of("payments-rs"))
if (v.checks["counter"] != true) deny()
val r = Authorize.authorize(pcactn, input)
if (r.checks["counter"] == "fail") /* replay */ deny()
```

After:

<!-- pca-core-verify: allow the snippet shows the core verifier check rename, not an authorization decision -->
```kotlin
val v = Pca.verifyPcactn(pcactn, grant, now, Pca.Audience.Of("payments-rs"))
if (v.checks["counter_format"] != true) deny()
val r = Authorize.authorize(pcactn, input)
if (r.checks["replay"] == "fail") deny()
```

#### .NET

What changes in 0.5:

- `PcaMiddleware` runs the full `Pca.AuthorizeAsync` pipeline by default. Without `PcaOptions.Authorize` it refuses every request with 403 `authorize_config` naming the missing components (state store, revocation check, ...). Signature-only is the explicit opt-in `PcaOptions.SignatureOnly = true`. Setting both throws `InvalidOperationException` at construction.
- The core check `counter` is renamed `counter_format` (`Verdict.Checks`, and the failure reason `counter_format: missing or not a non-negative safe integer`). In `Authorize` results the stateful check is `replay` (reasons start with `replay:`). A `Require` entry `counter` is an alias of `replay`. `Pca.DefaultRequiredChecks` lists the new names.
- An envelope-limit refusal names the limit: `policy: amount <= 100 not satisfied for payments.send on payments/acme` (was `policy: no predicate permits payments.send on payments/acme`).

Before (0.4, signature only by default):

```csharp
app.UsePca(o =>
{
    o.Audience = "https://api.example.com";
    o.GrantResolver = grantRef => grants.FindAsync(grantRef);
});
```

After, keep the old behaviour explicitly:

```csharp
app.UsePca(o =>
{
    o.Audience = "https://api.example.com";
    o.GrantResolver = grantRef => grants.FindAsync(grantRef);
    o.SignatureOnly = true;
});
```

After, the recommended full path:

```csharp
app.UsePca(o =>
{
    o.Audience = "https://api.example.com";
    o.GrantResolver = grantRef => grants.FindAsync(grantRef);
    o.Authorize = new PcaAuthorizeOptions
    {
        StateStore = store,                                    // MemoryStateStore or SqlStateStore
        IsRevoked = (pcactn, grant) => revoked.Contains((string)grant["id"]!),
        Operation = async ctx => new Operation("payments.send", "payments/acme", await ReadBodyAsync(ctx)),
    };
});
```

Rename: `verdict.Checks["counter"]` becomes `verdict.Checks["counter_format"]`; `result.Checks["counter"]` of an `Authorize` result becomes `result.Checks["replay"]`; match refusals on `replay:` instead of `counter:`.

#### PHP

- `PcaMiddleware` runs the full `Authorize::authorize` pipeline by default. With no `authorize:` and no
  `signatureOnly: true` it refuses every request with a 403 `authorize_config` that names the missing components.
  `signatureOnly: true` is the explicit opt-in for the old signature-and-chain-only check; giving it together with
  `authorize:` throws `InvalidArgumentException`.
- The core `counter` check is now `counter_format` (verdict `checks`, failure reason). `Authorize::authorize` reports the
  stateful check as `replay` (reasons start with `replay:`); a `require` entry `counter` still works and means `replay`.
- An unmet envelope limit is named in the denial reason: `amount <= 100 not satisfied for payments.send on payments/acme`
  (instead of `no predicate permits ...` when a predicate covers the verb and resource).

Before:

```php
$mw = new PcaMiddleware('payments-rs', $resolveGrant);
```

After, to keep signature-only verification:

```php
$mw = new PcaMiddleware('payments-rs', $resolveGrant, signatureOnly: true);
```

After, the recommended full check:

```php
$mw = new PcaMiddleware('payments-rs', $resolveGrant, authorize: new AuthorizeOptions(
    stateStore: new MemoryStateStore(),
    isRevoked: fn ($pcactn, $grant) => in_array($grant->get('id'), $revokedGrantIds, true),
    operation: fn ($request) => ['verb' => 'payments.send', 'resource' => 'payments/acme',
        'params' => Json::parseLax((string)$request->getBody())],
));
```

Rename `counter` to `counter_format` wherever you read the verdict's `checks`, and to `replay` wherever you read
`$result->checks` from `authorize`.

#### Ruby

- `AtlasPca::RackMiddleware` runs the full `AtlasPca.authorize` pipeline by default. With no `authorize:` and no
  `signature_only: true` it refuses every request with a 403 `authorize_config` that names the missing components.
  `signature_only: true` is the explicit opt-in for the old signature-and-chain-only check; giving it together with
  `authorize:` raises `ArgumentError`.
- The core `counter` check is now `counter_format` (verdict `checks`, `CHECK_ORDER`, failure reason). `authorize` reports
  the stateful check as `replay` (reasons start with `replay:`); a `require:` entry `counter` still works and means `replay`.
- An unmet envelope limit is named in the denial reason: `amount <= 100 not satisfied for payments.send on payments/acme`
  (instead of `no predicate permits ...` when a predicate covers the verb and resource).

Before:

```ruby
use AtlasPca::RackMiddleware, audience: "payments-rs", resolve_grant: ->(ref) { grants[ref] }
```

After, to keep signature-only verification:

```ruby
use AtlasPca::RackMiddleware, audience: "payments-rs", resolve_grant: ->(ref) { grants[ref] }, signature_only: true
```

After, the recommended full check:

```ruby
use AtlasPca::RackMiddleware,
    audience: "payments-rs",
    resolve_grant: ->(ref) { grants[ref] },
    authorize: {
      state_store: AtlasPca::MemoryStateStore.new,
      is_revoked: ->(_pcactn, grant) { revoked_grant_ids.include?(grant["id"]) },
      operation: ->(env) { { verb: "payments.send", resource: "payments/acme", params: JSON.parse(env["rack.input"].read) } }
    }
```

Rename `counter` to `counter_format` wherever you read `verdict.checks`, and to `replay` wherever you read
`result.checks` from `authorize`.

#### Swift

Swift ships no middleware. `PCA.authorize` is the recommended entry point (call it where you handle the request); the core verifier (`PCA.verify`) is signature-only: signature, chain, audience, validity and counter format, nothing about the operation, predicates, caveats, revocation or replay.

What changes in 0.5:

- The core check `counter` is renamed `counter_format` (`verdict.checks`, and the failure reason `counter_format: missing or not a non-negative safe integer`).
- In `PCA.authorize` results the stateful check is `replay` (reasons start with `replay:`, e.g. `replay: 1 is not greater than last seen 1 (replay)`). A `require` entry `counter` is an alias of `replay`. `PCA.DEFAULT_REQUIRED_CHECKS` is `counter_format, replay, revocation, plan_root_authorized, audience, validity, grant_ref_bound, operation, params_digest, policy`.
- An envelope-limit refusal names the limit: `policy: amount <= 100 not satisfied for payments.send on payments/acme` (was `policy: no predicate permits payments.send on payments/acme`).

Before / after:

```swift
// before
if verdict.checks["counter"] == false { ... }
if result.reason?.hasPrefix("counter:") == true { /* replay */ }

// after
if verdict.checks["counter_format"] == false { ... }
if result.reason?.hasPrefix("replay:") == true { /* replay */ }
```

If you only called the core verifier, switch to `PCA.authorize` (operation binding, predicates and caveats, revocation, atomic replay store) as in the README sample.


## Moving from slot-based goals to ontology templates (0.5)

`slotsToPolicy` filled free-form slots with no check that a unit, a currency or a resource type made sense, and an ambiguous number was silently guessed. Goals now go through a signed ontology and a template: pick the template for the task, fill its typed slots, and answer the questions for every slot left open. A goal with an open slot is a draft and cannot be signed. A task no template covers is not auto-signed: every action under it escalates until a template exists. Amounts are integers in minor units with an explicit currency, and an amount in another currency is never converted.

### 12. Goal flow: one IR, one signer

- The goal review flow, the intent-fidelity modules and the adversarial oracle share one Goal IR. The mirror types, the second reference semantics and the Ed25519-key-object signer are gone: confirmed examples, policy pins, ontologies, approvals and precedents are signed with the suite-agile signer and verified against pinned signer ids.
- The review card function is `renderPolicyCard` (the plain text card stays `renderCard`). `approveGoal` and `loadApprovedGoal` take the ontology in the submission and a proved-compiler kernel by default.
- `ResourceSel.all_of` is a flat list of `parts`; there is no `Bound.count_over` (a merged goal counts the actions its admitting grants were recorded for).
- Precedents are recorded escalation answers; the answer wire is the one in section 11.
