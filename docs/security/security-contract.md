---
title: Security contract
order: 32
---

# Security contract

**Audience: security reviewers, auditors and resource-server owners.** This page states the nineteen invariants a resource server can rely on when it authorizes an agent's action with PCA, and for each one: the function that enforces it, the inputs it must trust, the state it needs, what happens when it fails, the tests and conformance vectors that establish it, and its **current status on every verifier surface**. It is deliberately blunt about where an invariant does not hold yet.

Read it with the [Threat model](./threat-model.md) (attacks T-001 to T-057 and T-110 to T-165, guarantees G-1 to G-24) and the [Trust model](./trust-model.md) (who is trusted for what). The test files behind each invariant are listed per row, as `C-1` to `C-29` and `C-40` to `C-97`, in [Traceability](./traceability.md), whose checker fails the build when a listed test no longer exists.

## Surfaces

The same invariant can hold on one entry point and not on another. The columns below are:

- **Full TS**: `requirePCA` and the TypeScript HTTP adapters built on it (Express, Fastify, Hono, Next.js, fetch, the site guard), and `authorizeToolCall` for MCP tool calls.
- **`verifyPCActn`**: the full TypeScript verifier called directly, without `requirePCA`.
- **Core**: `verifyPCActnCore` and PCA Core. It checks the proof only.
- **Gateway**: `pca-gateway` (Envoy external authorization, Workers, Lambda).
- **Guards**: the execution guards for Mastra, the Vercel AI SDK and OpenAI Agents.
- **Native**: the Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby and Swift verifiers, their HTTP middleware, and the Python agent-framework guards.
- **Hosted**: the hosted `/v1/pca/actions` endpoint.

### C-50 Escalate never yields allow

**Statement.** A verifier decision is one of deny, escalate or allow, ordered deny < escalate < allow and combined only by the minimum. A verdict that is not allowed is `escalate` only when every failing check is an escalate-class check (an unanswered question or a tighten rule that asks for a human); any other failure is `deny`. `escalate` is never `allow` on any entry point: `allow` is exactly `decision === allow`, and a guard result for `escalate` is `ok: false` (403).

| | |
|---|---|
| Enforced by | `decisionOf`, `meet`, `pepDecision` (decision.ts); `authorize`, `createAuthorizer`, `requireAuthorized` and `requirePCA` carry `decision`; the framework adapters refuse on `ok: false` and report the decision and the escalation request. |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | `allow: false`, `decision: escalate` or `deny`, status 403; the body carries the escalation request when one can be answered. |
| Established by | Tests: "escalate is absorbing against allow", "escalate -> not admitted" (every guard entry point), "below the tighten threshold: allow; above: escalate". Vectors: `decision_of` and `decision_lattice` in `decision-vectors.json` (TypeScript, Go, Rust and Python). Proofs: `GoalTighten.dfy` (EscalateNeverAllow, MeetAllowIff), `VerdictDecision.dfy` (NotAllowedNeverAllow, EscalateImpliesNotAllow), `PolicyVmDecision.dfy` (UnknownNeverAllows). |
| Guarantees | G-22 (threat T-120). |
| Status | **Full TS: enforced.** Native: decision primitives in Go, Rust and Python; the native request guards already refuse every non-allow. Gateway and guards refuse any non-allow. |

---

### C-51 An escalation is answered only by a bound, signed principal answer

**Statement.** A guard admits an `escalate` decision only when the request carries an `EscalationAnswer` signed by a pinned principal key, saying `allow`, unexpired (at most 24 h), and bound to the digest of this grant (policy), this exact PCActn (action) and the holder's history head. An answer cannot be replayed onto another policy, action or history state; the replay counter that admits the action spends it; an answer never upgrades a `deny`.

| | |
|---|---|
| Enforced by | `verifyEscalationAnswer`, `escalationPolicyDigest`, `escalationActionDigest`, `escalationHistoryHead` (escalation.ts); `requirePCA({ escalation })` and `authorize` (`escalationAnswer`). |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | `escalation: <reason>` (unpinned principal, bad signature, another policy, another action, another history state, from the future, expired, deny answer); the decision stays `escalate`. |
| Established by | Tests: "no answer, a wrong-action answer", "a valid answer bound to this policy", "an answer can never upgrade a deny", "verifyEscalationAnswer". Model checking: `formal/tla/Escalation.tla` (esc_good holds; the five bad_* configurations produce counterexamples). |
| Guarantees | G-22 (threat T-121). |
| Status | **Full TS: opt-in** (`escalation.principals`). Without it every escalate is refused. |

---

### C-52 Policy terms and action schemas agree on units (rule 20)

**Statement.** When the grant envelope carries `units`, the action is authorized only if, for every parameter of the verb that the signed action schema gives a unit, the policy tag equals the schema unit (kind, currency, exponent), and no `where` term in scope of the verb reads a unit-bearing parameter without a tag. A currency, scale or kind mismatch is refused; nothing is converted.

| | |
|---|---|
| Enforced by | `decideUnits` (decision.ts), run as the `units` check of `decideIntentV2` (rule 20). |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | `units: <reason>` fails the check; the verdict is `deny` (not answerable). |
| Established by | Tests: "matching tag passes; cents vs dollars", "a where term that reads a unit-bearing parameter without a tag is refused". Vectors: `intent_units` (20) in `decision-vectors.json`, run by TypeScript, Go, Rust and Python. |
| Guarantees | G-23 (threat T-122). |
| Status | **Full TS: enforced when `envelope.units` is present** (opt-in per grant). Native: rule 20 primitive in Go, Rust and Python. |

---

### C-53 A model can only tighten (rule 21)

**Statement.** A model-derived env value (`env.class.*`, `env.prov.*`, `env.judge.*`, and `env.world.*` of a world decided by one oracle) is refused inside a grant `where` (and the ceilings) and may appear only in `tighten[]` rules, which can only escalate or deny. For every policy and every model oracle the final decision is at most the oracle-free decision, and equals it when the oracle is absent or says ok. A grant minted before this rule keeps working under `model_polarity: legacy`, reported as a degraded check that any high-assurance requirement refuses.

| | |
|---|---|
| Enforced by | `decideTighten`, `tighten`, `modelPathsRead` (decision.ts), run as the `tighten` check of `decideIntentV2` (rule 21); `unmetAssurance` refuses a degraded check. |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | `tighten: <reason>`: a deny reason for a typing refusal or a deny rule; `escalate: ...` for an escalating or undecidable rule. |
| Established by | Tests: "a model signal can only tighten", "an adversarial oracle", "a model-derived path in a grant where is refused", "a grant whose where reads env.class.* is refused". Vectors: `intent_tighten` (20). Proof: `GoalTighten.dfy` (OracleNeverWidens, FoldAllowImpliesBase, FoldAllowImpliesOk). |
| Guarantees | G-24 (threat T-123). |
| Status | **Full TS: enforced.** Native: rule 21 primitive in Go, Rust and Python. |

---

### C-54 Unknown never yields allow

**Statement.** A condition that cannot be decided (a missing or ill-typed value) is never allow: in a grant it does not match, in a `tighten[]` rule it escalates.

| | |
|---|---|
| Enforced by | `evaluateConditionTri` and `decideTighten`. |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | The rule does not match (grant) or escalates (`tighten[]`). |
| Established by | Tests: "rules: true -> signal, unknown -> escalate". Proof: `PolicyVmDecision.dfy` (UnknownNeverAllows, AllowIffAllTrue). |
| Guarantees | G-24. |
| Status | **Full TS and native: enforced** (the Kleene evaluator is shared). |

---

### C-55 A guard refuses an escalation it cannot ask

**Statement.** When a verdict escalates and no `escalation` option is configured, or the answer cannot be read, the result is `escalate` with `ok: false`; a malformed answer is treated as no answer.

| | |
|---|---|
| Enforced by | `requirePCA`. |
| Trusted inputs | The verifier's stored grant and configuration (pinned principal keys, action schema documents) and its clock; never the PCActn or a model output. |
| State | The replay counter and trust budget of the holder (an answer is spent by the counter that admits the action). |
| On failure | Refused, `decision: escalate`, the request attached. |
| Established by | Tests: "no answer, a wrong-action answer", "the answer can come from the request (header)". |
| Guarantees | G-22. |
| Status | **Full TS: enforced.** |

---

Status values: **enforced**; **opt-in** (enforced only when you configure it); **partial** (the condition is stated in the row); **gap** (not enforced; planned for 0.5 unless stated otherwise); **n/a** (the surface does not take this decision).

## Summary

| Invariant | Full TS | `verifyPCActn` | Core | Gateway | Guards | Native | Hosted |
|---|---|---|---|---|---|---|---|
| C-1 No invalid proof authorizes | enforced | enforced | enforced | enforced | enforced | enforced | enforced |
| C-2 Nothing outside the capability chain authorizes | enforced | enforced | enforced | enforced | enforced | enforced | enforced |
| C-3 Caveats hold, the root is never exceeded | enforced | enforced | gap | enforced (full mode, default) | enforced (full mode, default) | gap | enforced |
| C-4 Exact parameters | enforced with `operation` (required since 0.5) | partial | gap | enforced (full mode) | enforced (full mode) | gap | partial |
| C-5 Agent-supplied risk is never authoritative | enforced | enforced | n/a | n/a | n/a | n/a | enforced |
| C-6 Single-use actions are accepted once | enforced (one process, or an atomic or locking store) | enforced by default | gap | enforced (full mode, or `replayGuard`) | enforced (full mode, default) | gap | enforced |
| C-7 Revocation staleness is bounded | partial | opt-in | opt-in | opt-in | opt-in | gap | enforced |
| C-8 Approvals cannot be bypassed through risk claims | enforced | enforced | n/a | n/a | n/a | gap | enforced |
| C-9 Missing mandatory checks never downgrade to allow | enforced | enforced by default | partial | enforced (a missing component denies) | enforced (a missing component throws) | gap | enforced |
| C-10 Every success is bound to its execution | gap | gap | gap | gap | gap | gap | partial |
| C-11 Attestation evidence is verified, bound, fresh and honestly labelled | enforced | enforced | partial | gap | gap | gap | partial (software only) |
| C-12 An agent passport authorizes only when signed, in window, bound to the presenting key, unrevoked and, if hardware-rooted, proven | opt-in | n/a | n/a | gap | gap | partial (software passports) | gap |
| C-15 An action is bound to a signed intent | enforced when carried; opt-in to require | enforced when carried; opt-in to require | refuses (fail closed) unless handed the extension | n/a | n/a | enforced in Go, Python and Rust; partial elsewhere | partial |
| C-16 Caps and sequences cannot be evaded by splitting | enforced given a linearizable store | enforced given a linearizable store | refuses (fail closed) | n/a | n/a | enforced in Go, Python and Rust (verification of the host's pre-state); the history store is the host's | partial |
| C-17 Assertions used by a decision are pinned, bound and fresh | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced in Go, Python and Rust | partial |
| C-18 Intent revocation staleness is bounded | enforced when a revocation authority is named | enforced when a revocation authority is named | refuses (fail closed) | n/a | n/a | enforced in Go, Python and Rust | partial |
| C-19 Missing intent components never downgrade to allow | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced in Go, Python and Rust | partial |
| C-20 Untrusted lineage is never counted as trusted by the harness mediator | hardened (`pca-harness`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-21 A control-evaluation gate never passes vacuously | hardened (`pca-control-evals`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-40 The compiled policy decides exactly as the signed goal | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-41 Adding a constraint never widens the compiled policy | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-42 Every Allow carries a checkable witness and Unknown never allows | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-43 Goals are unit-safe and closed-world | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-44 A goal with unresolved questions is never signable | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-45 The card is lossless | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-46 Compilation is canonical | hardened (`pca-goal`) | n/a | n/a | n/a | n/a | n/a | n/a |
| C-70 An aggregate cap holds across sessions, agents and sites | hardened (`BudgetLedger`) | n/a | n/a | n/a | n/a | host's pre-state | n/a |
| C-71 Spent budget is never freed; only a never-started reservation expires | hardened | n/a | n/a | n/a | n/a | n/a | n/a |
| C-72 A non-session aggregate is refused a non-durable ledger | hardened | n/a | n/a | n/a | n/a | n/a | n/a |

In short: the TypeScript server path (`requirePCA`, `authorize`, `authorizeToolCall`), the gateway and the execution guards in their default full-policy modes, and the hosted endpoint enforce the contract except for C-10 and the parts of C-4 and C-7 stated below. The proof-only surfaces (Core, the gateway's and guards' explicit signature-only modes, and every native SDK) establish C-1 and C-2 and leave the rest to the integrator. A resource server on a proof-only surface that does not add those checks itself does **not** have C-3 to C-9.

---

### C-1 No invalid proof authorizes

**Statement.** An action is authorized only if its PCActn is in the one canonical wire form, carries a valid leaf signature under the declared suite from the holder of the last capability, opens to the signed plan root with a valid inclusion proof, is addressed to this verifier's audience, and is inside its validity window and not future-dated.

| | |
|---|---|
| Enforced by | `verifyPCActnCore` (checks `wire`, `version`, `audience`, `validity`, `cap_chain`, `grant_ref_bound`, `plan_inclusion`, `leaf_signature`, `counter_format`, in that order; `wire` is terminal). `verifyPCActn` and `requirePCA` run it first. |
| Trusted inputs | The verifier's own `audience`, its clock, its suite policy (`allowedSuites`) and PQ pins. |
| State | None. |
| On failure | The named check is `fail` and `allow` is false. `requirePCA` answers `401` with `WWW-Authenticate: PCA` for proof failures (`wire`, `version`, `audience`, `validity`, `cap_chain`, `grant_ref_bound`, `leaf_signature`) and `403` for `plan_inclusion`. A verifier that is given no audience fails `audience` when the PCActn carries one; only an explicit `audience: null` turns the check off. |
| Established by | Tests: "denies an out-of-plan action", "denies a tampered body", "401 on tampered signature", "an EXPIRED PCActn", "an audience MISMATCH is rejected". Vectors: the 547 negative core vectors (`tampered-*`, `out-of-plan-action`, `audience-*`, `expired`, `iat-future`, `forge-smallorder*`, `merkle-*`, `wire-*`, `json-*`, `mut-*`) and the adversarial families (`adv-time`, `adv-merkle`, `adv-ed`, `adv-alg`, `adv-key`, `adv-b64`, `adv-dupkey`, `adv-num`, `adv-uni`, `adv-size`), run by every language. Formal: the Dafny verdict model (audience, validity, chain and leaf soundness, wire terminality) and the Tamarin and ProVerif models of the action protocol. |
| Guarantees | G-1, G-2, G-4, G-5 (audience and lifetime). |
| Status | Enforced on every surface. |

### C-2 Nothing outside the capability chain authorizes

**Statement.** Authority comes only from a capability chain rooted at a grant the verifier itself holds: the root must be byte-identical to the stored grant (or, for a post-quantum root, match a verifier-side pin), each hop must be signed by its parent's holder and only append caveats, the depth is capped, and the signed `grant_ref` must equal the root capability's id.

| | |
|---|---|
| Enforced by | `verifyPCActnCore` (`cap_chain`: the root's hash equals the supplied grant's, then `verifyChain` with the grant as trusted root; `grant_ref_bound`: `grant_ref === cap_chain[0].id`). `verifyPCActn` adds `grant_ref` (equal to the stored grant's id) and `pq_pin`, and the policy step refuses an unverified chain. |
| Trusted inputs | The grant, loaded from the resource server's own store by `grant_ref` (`resolveGrant`), never from the request or from the presented chain; PQ pins configured on the server. |
| State | The grant store. |
| On failure | `cap_chain`, `grant_ref_bound`, `grant_ref` or `pq_pin` is `fail`; `requirePCA` answers `401`. |
| Established by | Tests: "is part of the default-deny profile", "a child that DROPS a parent caveat is rejected", "a hop issued by a key that is NOT the parent holder", "only resolves grants IT enrolled". Vectors: `chain-*` (dropped, edited and reordered caveats, broken links, depth 17), `grant-ref-*`, the 31 `chain_pin` primitives, `malformed` and `depth` primitives, and the adversarial `adv-gref`, `adv-atten` and `adv-depth` families. Formal: the Dafny chain model, the Lean chain-link and attenuation proofs, the TLA+ attenuation model. |
| Guarantees | G-3, G-9. |
| Status | Enforced on every surface, **provided the grant comes from your store**. A verifier given a grant taken from the request verifies a self-issued chain; the shipped templates are scanned in CI for that mistake. |

### C-3 Caveats hold, and the root grant is never exceeded

**Statement.** Every caveat in force is satisfied before an action is authorized: the envelope's predicates and caveats, the caveats placed directly on the root grant, and every caveat a delegation hop appended. Root and delegated caveats go through the same evaluator, so the tighter one wins. A caveat type the evaluator does not implement, a second `envelope` caveat, or a caveat whose input is missing is unsatisfied.

| | |
|---|---|
| Enforced by | The policy step of `verifyPCActn` (`decide`: envelope predicates, envelope caveats, `rootCaveats`, delegated caveats), plus `evaluateAgentCaveats` on hop caveats (check `delegated_caveats`). For integrators of proof-only verifiers: `policyCaveats` + `evaluateCaveats` (TypeScript) and `policy_caveats` + `evaluate_caveats` in every native SDK. |
| Trusted inputs | The plaintext parameters the server will execute (`context.params`, needed by `max_spend` and predicates), `subject`, `env`, the server's blast radius and reversibility class, recent action times for `rate`. |
| State | Recent action times (for `rate`), the budget. |
| On failure | `policy: fail` or `delegated_caveats: fail`; `requirePCA` answers `403`. A missing amount makes `max_spend` unsatisfied, and a predicate on a missing field is false. |
| Established by | Tests: "verifyPCActn DENIES an action that exceeds a root max_spend", "a root caveat type the policy layer does not implement fails closed", "root and hop caveats both apply", "unknown delegated caveat types still fail closed", and for MCP "an over-limit amount". Vectors: the 41 `caveat_eval` primitives (for example `r041-root-max-spend-exceeded-root-only`, `r041-root-note-fail-closed`, the `*-missing` cases), run by every language. Formal: the Dafny Policy VM and caveat models, the Lean Policy VM proofs, the Tamarin scope models. |
| Guarantees | G-3, G-18. |
| Status | **Full TS, `verifyPCActn`, Hosted: enforced.** **Core: gap by design** (caveats are opaque; use the helpers). **Gateway: opt-in**, only through an operator-written `checkProof`. **Guards: gap.** **Native: gap**: the evaluators exist in every SDK, but no native middleware, Python `require_pca` or Python agent-framework guard calls them. A full policy mode for the gateway and guards and an `authorize` entry point per native SDK are planned for 0.5. Envelope `predicates` and the `predicates` / `tool_schema` caveat types are evaluated by TypeScript only; the native evaluators treat them as unsatisfied (fail closed, but a different decision), and there are no cross-language vectors for a whole policy decision yet. |

### C-4 Exact parameters

**Statement.** The operation that executes is the one that was signed: the executed parameters hash to the signed `params_digest`, and the executed verb and resource equal the signed ones.

| | |
|---|---|
| Enforced by | `verifyPCActn` check `params_digest` (`hashCanonical(context.params)` against `action.params_digest`). `authorizeToolCall` first matches the tool call to the signed verb and resource, then passes the tool arguments as `params`. `pca-gateway` binds the request (method, path, query, body hash) through `params_digest` and maps routes to verb and resource. |
| Trusted inputs | The parameters the server will actually execute, and its own route-to-action mapping. |
| State | None. |
| On failure | `params_digest: fail` and `403` (`request-mismatch` on the gateway). If no parameters are supplied the check is `not-enforced`, and it is **not** in the default required list, so the action is allowed. |
| Established by | Tests: "denies params that do not open the digest", "another tool, another resource or other arguments", "bindRequest denies a proof used on a different path". Vectors: `tampered-params*` and the `params_digest_empty` primitive (the plan leaf commits to the digest, so a changed digest also breaks inclusion). There is no test yet of an HTTP adapter whose request body differs from the signed parameters. |
| Guarantees | G-1, G-4. |
| Status | **Full TS: partial.** `authorizeToolCall` enforces it. `requirePCA` checks parameters only when your `context()` returns them, never takes them from the request body by itself, and does not match the route to the signed verb and resource; do both in `context()` and your route. **`verifyPCActn`: partial**, same condition. **Core: gap.** **Gateway: partial**: the request is bound, but the grant's limits on its parameters are not evaluated (see C-3). **Guards: gap**: an optional verb check only. **Native: gap.** **Hosted: partial**: checked when the request carries `params`. Binding the result to the operation (verb, resource, parameters) by default is planned for 0.5. |

### C-5 Agent-supplied risk is never authoritative

**Statement.** Nothing the agent asserts about its own risk can lower the risk the verifier acts on. Risk inputs come from the resource server; the agent's claims can only raise them.

| | |
|---|---|
| Enforced by | `verifyPCActn` reads risk inputs only from `context.risk`: it never reads the PCActn's `risk_claim` or `provenance.taint_level`, and prices a missing input at the worst case, 1. The final score is `max(r, caution)`, so the signed `caution` only raises it. A declared reversibility class less severe than the server's fails `reversibility`. `createThresholdVerifier` cannot be built without a server-side `t` or `requiredT`. The hosted endpoint derives every input on the server and lets claims only make an input worse. |
| Trusted inputs | `context.risk`, the server's reversibility class, its taint context. |
| State | None (the budget is C-6 and C-8 state). |
| On failure | Higher risk raises the required threshold and drains the budget: `threshold: fail` or `policy: fail`, `403`. An understated class: `reversibility: fail`. |
| Established by | Tests: "the agent cannot lower risk through taint", "caution is MONOTONE", "the RS-authoritative reversibility class wins", "never lowers", "an agent CANNOT forge low taint". Formal: the Dafny Policy VM and taint models, the TLA+ trust-budget model. Vectors cover only the shape of `risk_claim`, `caution` and `provenance`. |
| Guarantees | G-7, G-13. |
| Status | **Full TS, `verifyPCActn`, Hosted: enforced.** **Core, Gateway, Guards, Native: n/a**: they compute no risk. The standalone taint gate (`enforce.taint`) is available on Core and the gateway; `verifyPCActn` and `requirePCA` do not yet forward `enforce` (planned for 0.5). Missing inputs are priced at the worst case rather than refused by name; an option to require named inputs is planned for 0.5. |

### C-6 Single-use actions are accepted once

**Statement.** A PCActn is accepted at most once per (grant, agent) counter stream: each accepted counter is strictly greater than the last, and of two concurrent presentations of the same action at most one succeeds.

| | |
|---|---|
| Enforced by | `requirePCA` (with a `budgetStore`): the `replay` check; `counter` must exceed the stored last counter for `grant id : leaf holder`. `guardPCActnReplay` over an atomic `ReplayStore.consumeOnce` / `CounterStore.advance`, keyed on audience, grant, holder (and nonce). `authorizeToolCall` uses `requirePCA` with its `state`. Gateway: `replayGuard`. Hosted: a row-locked counter in the admission transaction. |
| Trusted inputs | A durable store shared by every node of the same audience, with an atomic claim. |
| State | The last counter per (grant, holder); nonces until `exp` plus skew. |
| On failure | `replay: fail` and `403`. Without a store, `requirePCA` reports `replay: not-enforced`, which its default required list denies. A store error fails closed (`store_unavailable` in `guardPCActnReplay`, `503 replay-guard-unavailable` on the gateway). |
| Established by | Tests: "replay is denied with a store; budget drains", "without a store the counter is reported not-enforced", "two independent guard instances over ONE store also admit exactly one", "its failure fails CLOSED", "exactly one accepted" (200 concurrent submissions), "a replayed proof", "replayed-proof". The hosted endpoint is tested with parallel copies across several servers and processes on one database. The store conformance kit checks linearizability and crash behaviour of `ReplayStore` / `CounterStore` adapters. Formal: the TLA+ replay contract and `requirePCA` lock models (the unlocked multi-node and unfenced-lease configurations produce the double-accept counterexamples), the store models, the Tamarin store-race models. No conformance vector covers state: the corpus checks only that the counter is well formed. |
| Guarantees | G-5. |
| Status | **Full TS: enforced within one process, or across processes when the store implements `withKeyLock`** (an exclusive per-key lock that does not expire under its holder). `requirePCA` reads, then writes, its state; without `withKeyLock` the default lock is in-process and two processes can accept the same counter. Its key has no audience, so two resource servers sharing one store interfere (they deny, never double-accept). The store conformance kit does not yet cover `PcaStateStore`. **`verifyPCActn`: gap** (no store). **Core: gap**: `counter: pass` means a well-formed integer, **not** "not replayed". **Gateway: opt-in** (`replayGuard`). **Guards: gap.** **Native: gap**: no native SDK has a replay store; `counter: pass` is a format check there too. **Hosted: enforced.** The guarantee is **at most once**, not exactly once: the counter is consumed before your handler runs, so a crash after authorization uses it up. An atomic state store for `requirePCA`, a native replay store and operation records (C-10) are planned for 0.5. |

### C-7 Revocation staleness is bounded

**Statement.** A revoked capability (leaf or any ancestor) is refused, and the revocation state the verifier relies on is no older than a known bound.

| | |
|---|---|
| Enforced by | `createRevocationChecker`: a missing root or proof, or a revoked id, fails. With a signed epoch, `checkRevocationEpoch` refuses an epoch not signed by the pinned guardian, for another grant, past its `not_after`, issued in the future, older than the last accepted epoch, or newer than the epoch the PCActn signed in `freshness.epoch` (an action signed before the revocation). `requirePCA` lists `revocation` in its default required checks, requires `freshness` once an epoch source is configured, and pins the last accepted epoch in its store. |
| Trusted inputs | The guardian's public key (and PQ pin), the revocation root and non-membership proofs, the clock. |
| State | The last accepted epoch. |
| On failure | `revocation: fail` or `freshness: fail`, `403`. `requirePCA` without a revocation hook: `revocation: not-enforced`, denied by the default list. |
| Established by | Tests: "rejects stale/expired/rollback epochs", "fails closed on missing root, missing proof, or a forged proof", "denies when a RevocationChecker hook reports revoked", "allows only when counter, revocation and plan_root_authorized are all ENFORCED". The hosted endpoint is tested with revocations racing parallel admissions. Formal: the CryptoVerif revocation-epoch model, the TLA+ revocation-safety property. No conformance vector covers grant revocation epochs. |
| Guarantees | G-8. |
| Status | **Full TS: partial.** Revocation is required, but the bound is the one the signer chose: a signed epoch is valid for 5 minutes (re-signed every 60 seconds by the reference signer), the verifier has no maximum age of its own, a checker given a bare root with no signed epoch applies no staleness check at all, and there is no stricter window for irreversible actions. `authorizeToolCall` requires `isRevoked`, a yes/no callback with no staleness bound. **`verifyPCActn`, Core, Gateway, Guards: opt-in** (a hook, and for the gateway `requireChecks`). **Native: gap**: no native middleware has a revocation hook. **Hosted: enforced**: revocation is checked synchronously against its database inside the admission transaction, and `freshness` is required. A verifier-side maximum age and class-dependent windows are planned for 0.5. |

### C-8 Approvals cannot be bypassed through risk claims

**Statement.** The number of approvals an action needs (`t`: agent, guardian, human) is derived by the verifier from its own risk, and an action is accepted only with valid, role-bound shares meeting that `t`. No claim by the agent can lower `t`.

| | |
|---|---|
| Enforced by | The policy step derives `requiredThreshold.t` from the server's `r` (missing inputs: worst case, `t = 3`). `verifyPCActn` records the `t` the threshold hook says it enforced and fails when it is lower than the derived `t`, when the hook rejects the shares, or when `t > 1` and no hook enforced it. `createThresholdVerifier` requires an explicit `t` or `requiredT`. Shares sign a message bound to the role, the signer-set hash, `t` and the suite. |
| Trusted inputs | The registered signer set; the server-derived `t`. |
| State | Pending step-ups (hosted). |
| On failure | `threshold: fail`, `403` (`202` with a step-up on the hosted endpoint at `t = 3`). |
| Established by | Tests: "refuses to be built without an explicit server-side t", "a hook configured BELOW the server-derived t is rejected", "without an enforced threshold verifier is denied", "there is NO risk_claim-derived default". Vectors: `threshold_share` (56), `threshold_set` (65), `signer_set_hash` (8), `r041-share-*` (20), `mut-threshold-*`: they establish share validity, not how `t` is derived. Formal: the Dafny threshold and verdict models, the TLA+ threshold-safety property, the Tamarin and ProVerif threshold models (a step-up to `t = 3` needs the principal). |
| Guarantees | G-6, G-17. |
| Status | **Full TS, `verifyPCActn`, Hosted: enforced.** **Core, Gateway, Guards: n/a** (no risk is computed; a threshold hook can be supplied but nothing derives `t`). **Native: gap**: the native SDKs can verify threshold shares (the shared share vectors), but no native verifier derives `t` from server-side risk or requires it. |

### C-9 Missing mandatory checks never downgrade to allow

**Statement.** A check the deployment requires that is not enforced (a missing store, revocation source, plan authority, attestation, compliance verifier or risk input) denies the action; it is never treated as a pass.

| | |
|---|---|
| Enforced by | `enforceRequired`: every check named in `require` must be `pass`. `requirePCA` defaults `require` to `STATEFUL_REQUIRED_CHECKS` (`counter_format`, `replay`, `revocation`, `plan_root_authorized`, `audience`, `validity`, `grant_ref_bound`), adds `freshness` and `beacon` when those sources are configured, refuses to start without an `audience`, and can be loosened only with the explicitly named `insecureAllowUnenforced`. Independently of `require`: a carried `zk_compliance` proof with no verifier fails; with an attestation gate, absent evidence fails unless the gate is marked optional; a grant with a non-empty `agent_binding` requires a bound attestation; missing risk inputs are priced at the worst case; a missing budget never auto-admits. |
| Trusted inputs | The required-check list from server configuration, frozen when the guard is built. |
| State | None. |
| On failure | `403` with the reason `<check>: required check is not-enforced (default-deny: not enforced by this resource server)`. |
| Established by | Tests: "allows only when counter, revocation and plan_root_authorized are all ENFORCED", "required-but-not-enforced check DENY", "omitted budget does NOT auto-admit", "present zk_compliance + NO hook", "require-when-bound". Formal: the Dafny verdict model (required-check enforcement is monotone, the compliance and attestation gates are sound, a missing binding denies). |
| Guarantees | G-10, G-15. |
| Status | **Full TS: enforced.** `verifyPCActn` requires `DEFAULT_REQUIRED_CHECKS` by default (since 0.5; `require: []` reports only), and `requirePCA`, `authorize`, `authorizeToolCall` and `authorizeRequest` apply them as above (`authorizeToolCall` makes `isRevoked` a required option). **Core: partial**: the compliance and attestation gates fail closed, other unconfigured checks report `not-enforced` and allow. **Gateway: enforced by default** (since 0.5: full-policy mode requires `isRevoked`, a replay store and the grant's limits; signature-only mode is explicit, requires a `replayGuard`, and `requireChecks` defaults to `['revocation']`). **Guards: enforced by default** (`pca-mastra`, `pca-vercel-ai`, `pca-openai-agents` run `authorize`; signature-only is the explicit `mode: 'signature-only'`). **Native: gap**: the middleware allows whenever the core verifier allows. **Hosted: enforced** (its own required list, plus the counter in the admission transaction). A feature a proof carries but a verifier does not implement reports `unsupported` and denies in `verifyPCActn`. |

**Assurance (0.5).** A pass says the check held, not on what. The verdict's `assurance` report labels each pass (software or hardware attestation, SNARK or attested-VM compliance, multisig or preview threshold, Ed25519 or post-quantum signatures) and lists unimplemented features as `unsupported`. With `requireAssurance`, evidence that is missing, invalid, expired, unlabelled, weaker or unsupported denies. See the [Trust model](./trust-model.md#what-a-pass-rests-on-assurance-labels).

### C-10 Every success is bound to its execution

**Statement.** Each authorization is tied to exactly one execution of the operation it authorized: the result names the operation, and a crash or retry between authorization and execution can neither run the operation twice nor lose the record of it.

| | |
|---|---|
| Enforced by | Nothing yet in the library. The verdict carries no operation id or digest, and no API ties the authorization to the side effect. |
| Trusted inputs | n/a |
| State | n/a (would be a durable operation record keyed on the PCActn digest). |
| On failure | n/a. Today, `requirePCA` consumes the counter before your handler runs, so authorization is at most once and a handler crash burns it. |
| Established by | No automated test (listed in [Traceability](./traceability.md) under gaps). The hosted endpoint commits the counter, budget and ledger entry in one transaction and its tests show a failed admission burns nothing, but the downstream side effect is outside that transaction. |
| Guarantees | none. |
| Status | **Gap on every library and native surface.** **Hosted: partial**: each admitted action has a ledger entry and a receipt, but execution is not idempotent. Operation records (an operation id equal to the PCActn digest, `commit` / `abort`, a re-check of revocation before commit) are planned for 0.5. Until then, make downstream calls idempotent on the PCActn digest (`pcactnDigest`). |

---

### C-11 Attestation evidence is verified, bound, fresh and honestly labelled

**Statement.** Attestation evidence (a signed software document, a hardware quote, a vendor token, an attested-VM compliance statement) authorizes only when it verifies against a pinned trust anchor, is bound to this holder, grant, epoch and server-issued nonce, is fresh by the server's clock, and matches an allowlisted measurement. Missing, malformed, expired, replayed or unverifiable evidence denies. The verdict says what a pass rests on, and a pass is never labelled stronger than the verifier that produced it.

| | |
|---|---|
| Enforced by | `createAttestationVerifier` and `verifyAttestation` (software documents; hardware evidence through a `HardwareAttestationVerifier` such as `createAmdSnpVerifier`, `createIntelDcapVerifier`, `createAzureMaaVerifier`, `createGcpConfidentialSpaceVerifier`, `createNvidiaSpdmVerifier`, or `createMultiRootVerifier` for N-of-M roots); `verifyAllowlistManifest`, `verifyAllowlistDurable` and `verifyAllowlistAnchored` for the measurement allowlists and their rollback state; `createZkVerifier({ proverAttestation })` for an attested-VM prover key; the `assurance` report and `requireAssurance`. |
| Trusted inputs | The attestor keys and vendor root pins from configuration; the measurement allowlist; the expected binding and the nonce issue time from the server (never from the evidence); the verifier clock. Labels come from the verifier configuration, never from the evidence. |
| State | The single-use nonce store; the allowlist high-water mark per issuer; the verifier's cached transparency-log head. |
| On failure | The `attestation` (or `zk_compliance`) check is `fail` and the action is denied with the verifier's reason, for example `attestation nonce expired (stale quote)`, `hardware verifier did not confirm report_data binding`, `report length 1185 is not the canonical 1184`. Allowlist verification returns a typed `{ ok: false, code }`. A verifier that throws, resolves nothing, or is not labelled `hardware` where hardware is required, denies; nothing downgrades to a weaker label. |
| Established by | Tests: "software attestation: missing or invalid X => exact denial", "hardware seam: missing or invalid X => exact denial, labels honest", "verifyAllowlistManifest: missing or invalid X => exact result", "allowlist-anchor conformance vectors" (74 wire-level vectors; TypeScript, Go and Rust agree), "attested-VM mode bound to hardware evidence", "malformed and non-minimal encodings: exact rejection" (differential against OpenSSL and pkijs), "targeted strictness rules (each fails without its check)", "recorded real-evidence canary". Formal: the Dafny attestation model (stage order, nonce age, single-use consume, anchored head freshness) through `@atlasauth/pca-verified-core`. |
| Guarantees | G-10, G-11. |
| Status | **Full TS and `verifyPCActn`: enforced**, with the gate configured; a non-empty `agent_binding` requires a bound attestation without any hook. **Core: partial**: the gate fails closed, hardware verifiers are not part of Core. **Gateway, guards, native: gap** (none verifies attestation evidence; the Go and Rust verifiers check allowlist-anchor evidence against the shared vectors). **Hosted: partial**: software attestors only; hardware verification runs in the resource server. The software path is covered as above; the vendor verifiers parse attacker-supplied binary structures, are unaudited and remain experimental. |

### C-12 An agent passport authorizes only when signed, in window, bound to the presenting key, unrevoked and, if hardware-rooted, proven

**Statement.** When a resource server requires a passport, the presenting agent is admitted only if the passport is signed by a trusted issuer (under a supported suite, with any post-quantum key pinned), is inside its validity window, names the PCActn's leaf holder as its subject, is not revoked, and has an id equal to the fingerprint of its identity fields. A `hardware_rooted` claim is accepted only with attestation evidence that a configured hardware verifier validates, bound to the subject key and the passport id, whose measured identity equals the claims and whose age is within the evidence ceiling. Anything else denies with a distinct reason; a refused passport does not consume the PCActn's replay counter.

| | |
|---|---|
| Enforced by | `verifyPassport` (signature, issuer, window, subject, revocation, evidence age and the hardware-evidence checks) and `authorize` / `createAuthorizer` with `requirePassport`, which checks the passport before the PCActn is verified or its counter advanced. Native wire-level verifiers in Go, Rust and Python implement the same checks; their hardware branch needs a verifier supplied by the caller or the vendor verifier configured as the default. |
| Trusted inputs | The issuer keys and any post-quantum pins from configuration; the revocation source; the hardware verifier and its trust roots; the verifier clock. The subject comes from the PCActn's leaf holder, never from the passport. |
| State | The revocation source. The replay counter is untouched by a passport refusal. |
| On failure | `passport: <reason>` with one of `malformed`, `unsupported_version`, `unsupported_suite`, `unknown_issuer`, `bad_signature`, `id_mismatch`, `not_yet_valid`, `expired`, `subject_mismatch`, `revocation_unavailable`, `revoked`, `hardware_evidence_missing`, `hardware_evidence_stale`, `hardware_verifier_missing`, `hardware_attestation_failed`, `hardware_identity_mismatch`. A missing trust list or revocation source denies; a hardware claim is never downgraded to software. |
| Established by | Tests: "signed passport: reason codes", "every signed field is covered: tampering any of them fails", "rejects a forged flag (signed false->true by hand) and a flag with no evidence", "hardware evidence age is re-checked at verify time (exact boundaries, default 24 h, skew for the future)", "passport conformance vectors" (74 vectors across every suite and the hardware branch; TypeScript, Go, Rust and Python agree), "a refused passport never consumes the PCActn: the same PCActn is then allowed with a valid passport". |
| Guarantees | G-19 (threat T-052), with G-9 for the suite and G-10 for the hardware evidence. |
| Status | **Full TS: opt-in** (`requirePassport`). **Native: partial**: Go, Rust and Python verify every suite they implement for PCActns and run the hardware branch through a verifier you supply (Go, Rust and Python also ship the vendor verifiers, selected as the default verifier; without either, a hardware-rooted passport is refused). **Gateway, guards, hosted: gap.** The hardware path relies on vendor verifiers that remain experimental. |

---

### C-15 An action is bound to a signed intent

**Statement.** When a PCActn carries an `intent` or `intent_session` member, or the verifier requires one, the action is authorized only if the member opens the root grant's goal commitment (statement reference, map digest and salt), the action conforms to the signed action schema (closed world), the session root and every delta grant are signed by a session principal and chain from the admitting grant, and the action lies inside the grant's organisation, site and standard ceilings.

| | |
|---|---|
| Enforced by | `decideIntentBinding` (rule 12), `decideIntentV2` (`schema`, `intent_session`, `layers`, rule 13 and 14), run by the root entry's `verifyPCActnCore` (and so `verifyPCActn`, `requirePCA`, `authorize`). |
| Trusted inputs | The verifier's own schema documents and the site keys that sign them, its session store and pinned post-quantum keys, its clock, and its policy (`require`, `closed_world`, the fidelity and residual-risk bounds). |
| State | The accepted schemas, the session root and the earlier grants of the session (verifier-held). |
| On failure | The named check is `fail` and `allow` is false; a malformed verifier context fails every check that would be reported. |
| Established by | Tests: "bound intent passes; absent intent without policy reports no check (back-compat)", "policies fail closed", "binding mismatches fail the intent check only", "an active policy fails closed on a PCActn without the member", "closed world: an undeclared parameter is a terminal schema deny", "no verifier context at all for a PCActn that carries intent_session: schema, session and accumulators all fail". Vectors: the `intent-*`, `schema-*`, `session-*` and `layers-*` PCActn vectors and the `intent_schema` and `intent_map` tables, run by the TypeScript, Go, Python and Rust verifiers. |
| Guarantees | G-20. |
| Status | **Full TS and `verifyPCActn`: enforced for a PCActn that carries the member; opt-in to require it.** Core refuses a member it does not evaluate. The proof of the binding is not a proof that the statement is what the principal meant. |

### C-16 Caps and sequences cannot be evaded by splitting

**Statement.** The post-action value of every accumulator an action feeds equals the value the verifier recomputes from its own state, or from a sequencer-signed reservation receipt for this action, and stays inside its declared domain; every monitor has a valid verifier-supplied state.

| | |
|---|---|
| Enforced by | `decideIntentV2` (`accumulators`, rule 15), with `accPreState` and `admitIntentAction` computing the pre-state under the session lock, and `verifyReceiptAgainstHolder` for sequenced accumulators. |
| Trusted inputs | The session history store (linearizable; durable when caps must survive a restart), the sequencer's root key and its signed key sets, the verifier's clock. |
| State | The session's events and statuses, the highest receipt sequence accepted per accumulator, the newest key-set version per sequencer root. |
| On failure | `accumulators` fails with the reason; an event with an unreadable time or value fails the admission instead of being dropped from the sum. |
| Established by | Tests: "accumulators: the claim must equal the verifier post; unknown, unselected and wallet-held claims are refused", "sequenced accumulators: the claim carries a sequencer receipt bound to this action, audience and session", "receipt freshness: a leaked retired key, an old receipt, an old or superseded key set, an over-long lifetime are refused", "T11 (property): any split of any amounts, admitted concurrently, never pushes the counted sum over the cap", "a counted event (or a candidate) with a non-integer time throws instead of being dropped from the cap", "requireDurable refuses a volatile store". Vectors: `intent-state-vectors.json` (accumulators, windows, pre-states, monitors, receipts, key sets) and the `acc-*` PCActn vectors, run by the TypeScript, Go, Python and Rust verifiers. |
| Guarantees | G-20. |
| Status | **Full TS: enforced given a linearizable store.** The in-process store is volatile; pass `requireDurable: true` with a durable store when caps must outlive the process. Natives verify against the host's pre-state; the history store is the host's. |

### C-17 Assertions used by a decision are pinned, bound and fresh

**Statement.** A world fact, offer set, classifier verdict or data-class label influences a decision only if it is signed by a key the verifier pinned, bound to the session, subject or content it is about, committed by digest in the signed `intent_session` member and, for facts and offer sets, fresh; an unsupported suite, an unpinned or off-subject artifact, a stale artifact and a quorum short of its threshold deny.

| | |
|---|---|
| Enforced by | `decideIntentWorld` (rule 16), `decideOfferSet`, `decideParamProvenance` and `verifyLabels` (rule 17), `decideClassifierDimensions` (rule 18), composed by `decideIntentWB`. |
| Trusted inputs | The verifier's pinned oracle, site, label and classifier keys (and their post-quantum pins), its clock and its skew bound. |
| State | None beyond the pins. |
| On failure | `facts`, `provenance` or `classes` fails with the reason, or a question is raised (`intent_required`) for a tainted value; never a pass. |
| Established by | Tests: "fails closed when fewer than min_oracles facts are fresh (stale and future facts are not counted)", "refuses an unpinned oracle, a key that is not the pinned one, another subject, a duplicate oracle and an undeclared world", "an expired fact (older than freshness_ms): not counted, so the quorum is missed: denied; a future fact likewise", "a verdict from a judge not on the allowlist, for an undeclared classifier, with a label outside the set: denied", "a receipt signed by a key that is not pinned, or bound to another session: denied". Vectors: the `intent_world`, `intent_provenance` and `intent_classifier` tables, run by the TypeScript, Go, Python and Rust verifiers. |
| Guarantees | G-21. |
| Status | **Enforced** on the full TypeScript path and in Go, Python and Rust. What it establishes is authenticity, binding and freshness. Correctness of the asserted value is the issuer's (non-goal N-6). |

### C-18 Intent revocation staleness is bounded

**Statement.** When the session root names a revocation authority (or the policy sets an age bound), an action is admitted only with an epoch from that authority no older than the stricter bound whose revoked list is exactly the signed set, that extends the verifier's tracked epoch, and that lists none of the ids the action relies on.

| | |
|---|---|
| Enforced by | `checkSessionRevocation` (rule 13 step 7), called by `decideIntentV2`. |
| Trusted inputs | The authority key named in the session root (and its post-quantum pin), the verifier's clock, its tracked last epoch. |
| State | The last accepted epoch (an append-only sequence). |
| On failure | `intent_session` fails with a `revocation:` reason; no evidence at all is a denial. |
| Established by | Tests: "refuses: no epoch, a stale epoch, a revoked session / map / delta, a co-principal or stranger signer, a list that is not the signed set", "append-only: an epoch that drops an id revoked in the tracked last epoch, or rolls back, or equivocates, is refused", "a policy age bound without a revocation authority in S fails closed", "no epoch evidence: denied". Vectors: the `intent_revocation` table and the `session-*` PCActn vectors, run by the TypeScript, Go, Python and Rust verifiers. |
| Guarantees | G-20. |
| Status | **Enforced when a revocation authority is named or an age bound is set**; otherwise the check is not performed (the verifier chose no revocation). The exposure window is the age bound plus the clock-skew limit. |

### C-19 Missing intent components never downgrade to allow

**Statement.** A component the intent layer needs that is absent, malformed, of an unknown version or signed under an unsupported suite (the schema, the session root, the plaintext parameters, a pre-state, a monitor state, a receipt, a key set, a revocation epoch, an oracle, a classifier, a label key, the clock) denies; it is never treated as a pass and never replaced by a weaker check.

| | |
|---|---|
| Enforced by | Every function of the layer, which returns a typed refusal instead of an exception, and `decideIntentV2`, which converts an internal error into a failed check. |
| Trusted inputs | The verifier's configuration, frozen when the verifier is built. |
| State | None. |
| On failure | The check that needed the component fails with a reason naming it; a malformed verifier context fails every check that would be reported. |
| Established by | The "missing X gives Y" tests of the intent layer, listed per module in the [Intent layer](../concepts/intent-layer.md) failure table; the strictness tests "every numeric field is a safe integer or the check fails closed (null / string / fraction / -0 / NaN clock)" and "absent means empty / default; present with null is malformed and fails closed". |
| Guarantees | G-20, G-21. |
| Status | **Enforced.** Two opt-in settings remain: a verifier that never configures an intent policy does not require the member, and `verifyIntentRequired` without a clock checks only the signature (use `verifyIntentRequiredAt`). |

### C-20 Untrusted lineage is never counted as trusted by the harness mediator

**Statement.** The harness mediator (`@atlasauth/pca-harness`) treats the oracle as adversarial. An input counts as trusted only when it is exactly an object with a string `ref` and `provenance: 'trusted'`; anything else (null, a misspelt label, a missing `ref`, a non-object) is untrusted lineage and raises the taint label to 1. A malformed candidate, an oracle that throws, or a bad configuration produces a typed refusal or a constructor error and nothing is signed.

| | |
|---|---|
| Enforced by | `Harness.step` and the `Harness` constructor. |
| Trusted inputs | The principal-authorised plan, the signing key and the budget given at construction; never the oracle's output. |
| State | The trust budget and the action counter, both updated only after a successful signature. |
| On failure | `bad_candidate`, `out_of_plan` or `over_budget`; no PCActn is produced and the counter and budget do not advance (except the budget leak to now). |
| Established by | The harness tests: the fail-closed table (oracle throws or rejects, null or partial candidates, non-array inputs, unknown node, constructor refusals) and the test that typo, null and ref-less provenance count as untrusted. |
| Status | **Hardened.** The harness measurement is self-asserted by the signer, not hardware-rooted; an allowlisting resource server trusts the operator's choice of build. No independent audit. |

### C-21 A control-evaluation gate never passes vacuously

**Statement.** `controlEval` refuses an empty red suite, fewer than one episode and a non-finite seed. `assertControlGate` throws unless the report covers every required strategy, every strategy's one-sided 95% Wilson lower bound on safety and the overall bound clear the threshold, and usefulness meets its minimum. Any non-finite or missing value fails the comparison. A passing gate certifies only the modeled red suite and environment.

| | |
|---|---|
| Enforced by | `controlEval`, `wilsonLowerBound` and `assertControlGate` in `@atlasauth/pca-control-evals`. |
| Trusted inputs | The red policies, environment and blue protocol the deployer encodes. |
| State | None; deterministic given a seed. |
| On failure | A thrown error listing every violation. |
| Established by | The control-evaluation tests: refusal of vacuous runs, known Wilson values, every gate violation with its exact message, the gap-exploit red failing the gate, and a NaN report value failing the gate. |
| Status | **Hardened.** It is an empirical bound over a modeled adversary, not a proof, and it is complementary to the analytic budget bound. |

### C-70 An aggregate cap holds across sessions, agents and sites

**Statement.** For an accumulator with scope principal, org or fleet, the counted total of all sessions and agents of that scope never exceeds its cap, however admissions interleave.

| | |
|---|---|
| Enforced by | `admitAggregateAction` over a `BudgetLedger`: one state per scope id, an atomic reserve that checks the cap and the version, retry on conflict, rollback across scopes. |
| Trusted inputs | A linearizable per-key ledger; the host names the scope ids. |
| State | The ledger documents (reservations with status), one per key. |
| On failure | The admission is denied (`aggregate: over_cap`, `scope_unbound`) or throws; never an allow without a reservation. |
| Established by | Tests: "100 x $19 from 100 different sessions under a $200 principal cap: exactly 10 are admitted, however they interleave", "sessions, grants and agents do not appear in the key: only the principal does", "org and principal caps hold together; a deny at the second key frees the first key again", the budget-ledger conformance suite and its defective ledgers, TLA+ `PrincipalAggregate` and the Lean theorems `no_overspend` and `sessions_share_one_cap`. |
| Guarantees | G-70, G-71 |
| Status | **Hardened.** The model checks and the store conformance run are CI gates; the tier moves to production only when they and the mutation gate have passed. |

### C-71 Spent budget is never freed; only a never-started reservation expires

**Statement.** A reservation whose effect has started is never expired by any clock; a released reservation can neither start nor commit; a committed one is never released; releasing an unknown id credits nothing.

| | |
|---|---|
| Enforced by | `start`, `commit`, `release` and `expire` of the `BudgetLedger`; `startAggregate` before the effect; signed `release` events. |
| Trusted inputs | The host releases only when the effect did not happen. |
| State | Reservation status and the started flag. |
| On failure | The settlement is refused with the current status. |
| Established by | Tests: "a started reservation is never expired by any clock; an expired one can never start (the ledger orders them)", the conformance checks "start-rules", "settle-rules", "a-late-commit-cannot-overspend", TLA+ mutants `expire_started`, `release_committed`, `release_unreserved`, `late_commit`, Lean `ran_counted` and `spent_bounded`. |
| Guarantees | G-71 |
| Status | **Hardened.** The model checks and the store conformance run are CI gates; the tier moves to production only when they and the mutation gate have passed. |

### C-72 A non-session aggregate is refused a non-durable ledger

**Statement.** Admission against any non-session scope throws when the ledger does not declare durability, and the conformance kit fails a ledger whose claim does not match its behaviour.

| | |
|---|---|
| Enforced by | `admitAggregateAction` (`not_durable`); the conformance checks "durable-claim-matches-the-adapter", "state-survives-reopen" and "acknowledged-writes-survive-a-crash". |
| Trusted inputs | The operator runs the conformance kit against the production ledger. |
| State | None. |
| On failure | A thrown `not_durable` error. |
| Established by | Tests: "refuses a volatile ledger for any non-session scope", conformance defects "amnesia" and "volatile ledger claiming durability". |
| Guarantees | G-72 |
| Status | **Hardened.** The model checks and the store conformance run are CI gates; the tier moves to production only when they and the mutation gate have passed. |

## Extension invariants

C-1 to C-10 are the contract of PCA Core and the server path. Two optional extensions make their own claims, under the same rules (each states what enforces it, what it trusts, what state it needs, what happens on failure, and what establishes it). They are **hardened, not production**: finished and tested, not independently audited. They live under `@atlasauth/pca/ext/optimistic` and `@atlasauth/pca/ext/ledger`; no Core verifier evaluates them.

| Invariant | Full TS (`StoreBondLedger` / `StoredLedger`) | Wire members in Go, Python, Rust | Other surfaces |
|---|---|---|---|
| C-13 A bond moves atomically, once, on evidence the ledger re-derived | hardened | verified (claim, fraud proof structure, settlement record) | n/a |
| C-14 The ledger is append-only and checkpoint-consistent; tamper evidence needs an honest independent witness | hardened | verified (inclusion, consistency, tree head, cosignatures, chains) | n/a |

### C-13 A bond moves atomically, once, on evidence the ledger re-derived

**Statement.** In the optimistic path's internal accounting (no money moves), a bond transition (open, release, slash) is applied in full or not at all; repeating a transition that already committed returns the stored record and moves nothing; a conflicting transition is refused; a slash is authorized only by a verdict the ledger recomputed itself, never by the challenger's assertion; the challenge window runs on the ledger's own clock and cannot be moved by the claimant; and a missing store, guardian key or clock denies instead of downgrading.

| | |
|---|---|
| Enforced by | `StoreBondLedger` plans each transition with `BondSettlementPlanner` and commits it through `BondStore.commit`, an all-or-nothing compare-and-swap on the bond's phase that also applies every balance move and re-checks overdrafts and the per-depositor caps. `openClaim` stamps `registeredAt` from the ledger clock; `release` and the challenger-driven slashes compare against `registeredAt + windowMs` using `max(clock, store high-water mark)`. |
| Trusted inputs | The guardian key, the ledger's clock, the frozen open-time snapshot and the grant the settlement layer holds, and the revocation set for a revocation slash. |
| State | A `BondStore`: bonds, balances, settlement records and the time high-water mark, durable and atomic. |
| On failure | A `BondStoreError` with a stable code (`store_missing`, `guardian_key_missing`, `clock_invalid`, `store_unavailable`, `store_corrupt`, `invalid_claim`, `window_open`, `window_closed`, `unregistered`, `claim_mismatch`, `conflict`), or the plain refusal of a slash whose verdict does not hold. Nothing is written on a refusal; a transition whose acknowledgement was lost is repaired by retrying it. |
| Established by | Tests: the bond store tests (fail-closed table, window clock, idempotence of every transition, racing transitions, crash recovery in process and by `SIGKILL`), the store conformance suite with five positive controls, the wire vectors. Vectors: the extension layer, `optimistic_claim`, `optimistic_window`, `optimistic_fraud_proof`, `optimistic_settlement`, reproduced by TypeScript, Go, Python and Rust. |
| Guarantees | G-14. |
| Status | Hardened. **Internal accounting only; real-money settlement is outside the claim.** Effects are not rolled back. The in-memory `BondLedger` that predates the store is a test double and still has an in-memory default. The shared fraud-proof vectors check structure; the recomputation that convicts is TypeScript-only. No independent audit. |

### C-14 The ledger is append-only and checkpoint-consistent; tamper evidence needs an honest independent witness

**Statement.** A `StoredLedger` serves only a log that reproduces every checkpoint it holds: each checkpoint is signed by the pinned guardian, hash-chained by `prev_root`, connected to the one before by an RFC 9162 consistency proof, and equal to the Merkle root of the stored entries at its size. A log that lost entries, edited one or holds a forged checkpoint is refused. A reader that requires a witness cosignature accepts no checkpoint a witness has not cosigned, and a witness cosigns only a checkpoint consistent with the last it cosigned. **Given at least one honest witness independent of the operator, a rewritten, truncated or forked history is detected.** Censorship by omission is not.

| | |
|---|---|
| Enforced by | `StoredLedger.open` and `checkpoint` (`verifyCheckpointChain` over the stored chain, the stored entries against every checkpoint root, the store against the handle before signing); `LedgerStore.append` and `appendCheckpoint` (compare-and-swap on the length, whole batch or none); `verifyTreeHead` with a `WitnessPolicy` on the reader; the witness service's cosign rule. |
| Trusted inputs | The guardian public key pin, the witness keys the reader pins, the witness's own configuration of which logs it follows. |
| State | A `LedgerStore` (entries and checkpoints) and, for a witness, the last cosigned head per log. |
| On failure | `LedgerStoreError` codes `rollback`, `tamper`, `forged_checkpoint`, `inconsistent`, `store_corrupt`, `store_unavailable`, `conflict`; the witness answers `403`, `404`, `409` (`rollback`, `equivocation`, `proof_required`, `inconsistent`) or `500` and never returns a cosignature for a head it did not record. |
| Established by | Tests: the ledger store tests (rollback, tamper, forged and inconsistent checkpoints at every boundary, racing writers, `SIGKILL` recovery), the checkpoint chain and equivocation tests, the witness tests and container test, the store conformance suite with six positive controls, the wire vectors. Vectors: the extension layer, eight ledger tables, reproduced by TypeScript, Go, Python and Rust. |
| Guarantees | G-12. |
| Status | Hardened. **No independent witness is operated by the project**, so the end-to-end claim is conditional on someone else operating one. First sight of a log is trusted. No independent audit. |

## Research-unit invariants

Eight units of the experimental `research` and `attestation` features make their own claims under the same rules. They are **experimental**: finished and tested, no mutation gate recorded, no audit.

### C-22 No unsigned natural-language policy is ever loaded

**Statement.** A policy proposed by a model is a draft. It becomes an agent only when a reviewer key the loader pinned has signed the exact compiled policy (permissions, limits and catalog digest) inside a bounded window, every verb is in the catalog, and the static lints raise no error. Nothing the model said is enforced otherwise.

| | |
|---|---|
| Enforced by | `loadApprovedPolicy`, `agentFromApprovedNL`. |
| Trusted inputs | The pinned reviewer keys; the catalog. |
| State | None (the approval is a signed document). |
| On failure | `loadApprovedPolicy` returns a refusal with a reason (`reviewer_not_pinned`, digest mismatch, expired, unknown verb, analyzer error, empty); `agentFromApprovedNL` throws with it. |
| Established by | Tests: "every refusal row gives its exact reason", "valid approval loads exactly the drafted policy", "unknown verbs are reported and block approval". |
| Status | **Hardened tooling, experimental feature.** It does not prove the model understood the instruction; the reviewer does. No audit. |

### C-23 A safety certificate states a signed scope and which checks ran, never that a system is safe

**Statement.** The certificate is the arithmetic consequence of the signed risk parameters (`scope: risk-budget-bound`) plus signed check records with evidence links. The verifier recomputes the bound, refuses any other scope, and can require named checks to have passed.

| | |
|---|---|
| Enforced by | `verifySafetyCertificate`. |
| Trusted inputs | The pinned guardian key. |
| State | None. |
| On failure | Verification returns `ok: false` with a reason (unknown scope, bound mismatch, bad signature, missing required check, too old). |
| Established by | Tests: "scope is risk-budget-bound and the statement disclaims safety", "checks are signed: removing or changing one breaks the signature", "wrong scope is refused", "requireChecks on a certificate with no checks is refused". |
| Status | **Experimental feature.** Evidence links are references; the verifier does not fetch them. |

### C-24 Guardian fencing is monotonic and a stale leader is refused

**Statement.** Each lease takeover raises the epoch; the epoch never goes down. A signer or resource that checks the fence refuses an ex-leader, an expired holder window, a lost lease, and any store failure (no leader).

| | |
|---|---|
| Enforced by | `acquireLease`, `renewLease`, `assertFence`, `fencedSigner`, `createFenceGuard`. |
| Trusted inputs | A store with linearizable compare-and-swap and a trustworthy clock. |
| State | The lease record in the store. |
| On failure | `assertFence` and `fencedSigner` refuse with `FenceError`; an acquire against a failing store is `store-error`. |
| Established by | Tests: "epochs are strictly monotone over repeated takeovers", "assertFence: current leader ok; stale epoch, expired window and no lease are refused", "FencedSigner signs for the leader and refuses a stale ex-leader without running sign", "cas refuses to lower the epoch". |
| Status | **Experimental feature.** Safety depends on the store being linearizable; the conformance suite checks that. |

### C-25 A latched contract violation clears only on the principal's signed reset

**Statement.** A contract violation observed on an admitted trace latches in durable state, refuses every later action, survives a restart, and clears only with a reset signed by the contract principal for that exact sequence number. Two processes cannot admit the same sequence number.

| | |
|---|---|
| Enforced by | `ContractEnforcer`, `authorize({ contracts })`. |
| Trusted inputs | The pinned principal key; an atomic key-value store. |
| State | The monitor state and the latch. |
| On failure | `check` and `peek` return `violated`, `latched`, `state-error` or `store-error`; `authorize` refuses with `contract: <reason>` before the replay counter is spent. |
| Established by | Tests: "a violation is refused, names the clause, and latches", "reset needs the principal signature at the latched seq", "two enforcers on one kv racing the same actions", "state and the latch survive a restart on file-backed state". |
| Status | **Experimental feature.** Safety properties only (no liveness). |

### C-26 Adaptive risk tightening never widens a policy

**Statement.** An adapted or applied risk policy has kappa not below, thetas not above, and every other parameter equal to the base. An invalid state assesses as high threat. A signed proposal binds the base and a strictly increasing epoch. In `authorize`, an adaptive policy can only add a refusal.

| | |
|---|---|
| Enforced by | `adapt`, `applyTightening`, `authorize({ adaptivePolicy })`. |
| Trusted inputs | The pinned guardian key (proposals). |
| State | The immune state and the last applied epoch. |
| On failure | The adaptation is rejected with a reason and the base stays in force; `authorize` refuses with `adaptive: <reason>`. |
| Established by | Tests: "a correctly signed but widening proposal is refused", "adapt never widens, never NaN, and reversal at score 0 is the base", "a higher score is never looser", "a tightened policy that requires a higher threshold refuses with the exact reason", "a looser policy cannot widen: it is ignored". |
| Status | **Experimental feature.** The anomaly score is a heuristic a slow attacker can game; only the no-widen property is guaranteed. |

### C-27 Reputation counts only verified settlements

**Statement.** Disputes feeding a reputation come from settlement records whose guardian signature verifies; forged, wrong-key and unknown-subject records are rejected and counted, a repeated dispute id counts once, and a coverage quote is accepted only when the underwriter signature, window and recomputed premium all match. A reputation is advisory and never an authorization input.

| | |
|---|---|
| Enforced by | `disputesFromSettlements`, `verifyCoverageQuote`. |
| Trusted inputs | The pinned guardian and underwriter keys. |
| State | None. |
| On failure | Rejected records are counted in `rejected`; a quote fails with a reason (for example `price-mismatch`). |
| Established by | Tests: "forged, wrong-key, and unknown-subject records are rejected, not counted", "a repeated dispute id counts once", "a correctly signed but mispriced quote is refused (recomputation)". |
| Status | **Experimental feature.** |

### C-28 Entropy health tests fail closed and an external source can never weaken a seed

**Statement.** Every quantum buffer passes the SP 800-90B repetition-count and adaptive-proportion tests or is dropped; a seed is always HKDF over the local CSPRNG bytes too, so the result is never weaker than the local source; `requireQuantum` turns a missing or rejected source into a typed error; a source over plain http or one that redirects is refused.

| | |
|---|---|
| Enforced by | `healthTestBytes`, `secureSeed`, `HttpQrngSource`. |
| Trusted inputs | The local CSPRNG. |
| State | None. |
| On failure | `EntropyError` (`quantum_required`, health failure) or a CSPRNG-only seed. |
| Established by | Tests: "fails closed: constant, run, skewed, empty and bad parameters", "matches HKDF-SHA256 over the length-prefixed local||quantum", "never follows redirects", "http is refused, https allowed, loopback http only with the opt-in". |
| Status | **Experimental feature.** Not a quantum root of trust; real devices are owner action O-3. |

### C-29 A PUF root never counts as hardware assurance

**Statement.** The PUF verifier is labelled software, accepts only a device in the pinned, unrevoked, unexpired enrollment registry with a non-empty measurement allowlist, and in the gate and the multi-root level it reports software, never hardware or multi-root.

| | |
|---|---|
| Enforced by | `createPufVerifier`, `createPufEnrollmentRegistry`. |
| Trusted inputs | The enrollment registry and the measurement allowlist. |
| State | The registry (revocations are permanent). |
| On failure | The verifier fails with a reason (unknown, revoked, expired, binding mismatch, malformed). |
| Established by | Tests: "a PUF root is never hardware assurance: verifier, gate and multi-root all report software", "the registry revokes for good: re-registering does not un-revoke", "an empty or missing measurement allowlist is refused at construction (no accept-all)". |
| Status | **Experimental feature.** Real PUF and TPM runs are owner action O-3. |
## Research-grade cryptography packages

Four separate packages make narrower claims under the same rules. They are **hardened, awaiting independent audit**: finished and tested, never production. No Core verifier evaluates them; they are used where an operator wants confidentiality or a delay on top of an authorisation decision.

### C-81 Attribute-based encryption opens only for a key whose attributes satisfy the policy, and a malformed input never opens

**Statement.** A payload sealed with `@atlasauth/pca-abe` decrypts only for a key issued by the same master secret whose attribute set satisfies the ciphertext's policy; keys of different holders cannot be pooled; a tampered header, tree, row or payload yields no plaintext; a policy that names one attribute twice is refused at encryption rather than approximated; every malformed key, ciphertext or master key is refused with a typed error or a `null`, never a partial result.

| | |
|---|---|
| Enforced by | The FAME scheme (Agrawal and Chase, 2017) on BLS12-381 with subgroup-checked points; the span program derived from the threshold tree; AES-256-GCM over a header that contains the policy tree and every ciphertext row. |
| Trusted inputs | The master secret holder (it can decrypt everything), the random-oracle behaviour of the hash-to-curve oracle, the capability attributes handed to key issuance. |
| State | None in the library. |
| On failure | `decrypt` returns `null`; `encryptForPolicy` and `keygenForAttributes` throw `PcaEncryptionError`. |
| Established by | Tests: the fail-closed table (every missing or malformed input and its exact outcome), the access-structure oracle test over every subset, the collusion tests. Differential: keys and ciphertexts for six policies recomputed with py_ecc and compared byte for byte, with the reference decrypting by Gaussian elimination. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. The scheme has a published adaptive-security proof; the tree-to-span-program step, the wire format and the AEAD layer are this project's own. Policy is public in the ciphertext, no revocation, not post-quantum. |

### C-82 A homomorphic risk-gate evaluation reveals only the verdict to the key holder, and only a pinned signer's inputs are evaluated

**Statement.** With `@atlasauth/pca-fhe` the evaluator computes the risk gate on encrypted inputs without the secret key; an input ciphertext is evaluated only if it carries a valid signature from a pinned signer over the context, the action binding and the policy, and its nonce has not been seen; the key holder learns the risk value and the verdict.

| | |
|---|---|
| Enforced by | Microsoft SEAL BFV through node-seal with the 8192-degree, 218-bit-modulus parameter set of the Homomorphic Encryption Security Standard; strict Ed25519 verification of the claim; a single-use nonce guard that fails closed when full. |
| Trusted inputs | The pinned signer key, the key holder, the evaluator's honesty about which circuit it ran (BFV is not verifiable computation). |
| State | A nonce guard (in memory by default; the integrator supplies a durable one for several evaluators). |
| On failure | A typed refusal reason for every unsigned, mis-signed, replayed, wrong-context or malformed claim; a wrong key throws rather than yielding a verdict. |
| Established by | Tests: the signed-claim tests (forgery, swap, replay, wrong context), the fail-closed input tests, the exact integer oracle, the cross-implementation check against an independent SEAL build. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. It does not prove the evaluator ran the agreed circuit or that the signer's inputs are true. |

### C-83 A timelock proof verifies only for the exact action, beacon and step count, over a modulus the library accepts

**Statement.** `@atlasauth/pca-vdf` accepts a delay proof only if it is a Wesolowski proof of the stated number of sequential squarings of an input derived from the action and the beacon, in canonical form, over a modulus that passes the production screen; the challenge prime comes from a deterministic Baillie-PSW style test. Verification never throws and never accepts a degenerate proof.

| | |
|---|---|
| Enforced by | The Wesolowski verifier over the RSA-2048 challenge modulus (or a supplied modulus that passes the screen), canonical-unit checks on `y`, `pi` and `x`, the primality test, and the input binding to the action digest and beacon. |
| Trusted inputs | That nobody holds the factors of the modulus, and that the beacon was unpredictable and published after the action. |
| State | None. |
| On failure | `verifyTimelock` returns `false`; the detailed verifier names the reason. |
| Established by | Tests: the production-path refusals, the degenerate-proof regression, the primality tests (sieve comparison, Lucas and base-2 pseudoprimes, Carmichael numbers). Differential: an independent Python implementation reproduces `y`, `pi` and the challenge prime on committed vectors. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. The delay is a floor under an assumption about the fastest squarer, not a clock; a class-group variant without trusted setup is not provided. |

### C-84 Multi-party composition aborts rather than returns a wrong answer, and runs without a dealer unless the operator opts in

**Statement.** `@atlasauth/pca-mpc` returns the composed decision of the parties' private policies or aborts. Its default offline phase is dealer-free (generated from oblivious transfer); the trusted-dealer phase, where one process sees every share and key, runs only when the operator sets `insecureTrustedDealer: true`, and the result states which phase was used. An online lie about a share, tag or MAC is detected and, where the evidence is first-hand, attributed to the party that made it.

| | |
|---|---|
| Enforced by | SPDZ-style information-theoretic MACs with a batched check, a sacrifice check on every Beaver triple, KOS-checked OT extension, an endemic Module-LWE base OT whose key generation is FIPS 203 K-PKE.KeyGen, mutual-TLS transport with pinned certificates, pairwise tags for identifiable abort. |
| Trusted inputs | At least the party's own process; in dealer mode also the dealer. The Module-LWE and random-oracle assumptions. |
| State | Per-run material only. |
| On failure | `MacCheckAbort` or a `NetAbort` naming the culprit where it is known; no output on any abort; a request for the dealer without the opt-in is refused before any network use. |
| Established by | Tests: the default-phase tests, the malicious-deviation and identifiable-abort suites, the selective-failure test, the networked fault-injection tests, the FIPS 203 key-generation known-answer test. Cross-check: an MP-SPDZ run of the same circuit agrees. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. No formal proof exists for the composition; timing is not constant. |

## Goal-to-decision invariants

C-40 to C-46 are the contract of the goal compiler (`@atlasauth/pca-goal`, `formal/dafny/Goal*.dfy`). They are **hardened**: machine-checked, pending the first green CI run of the Dafny proofs and the five-target differential.

### C-40 The compiled policy decides exactly as the signed goal

**Statement.** For every action and history, the policy the compiler produces returns the same decision as the goal's reference semantics; it therefore never allows more than the goal.

| | |
|---|---|
| Enforced by | `GoalCompile.Compile`, `SoundnessT1` (formal/dafny/GoalCompile.dfy), exposed as `compileGoal`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T1; the random test comparing the extracted compiler, the reference semantics and an independent TypeScript semantics. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-41 Adding a constraint never widens the compiled policy

**Statement.** If a goal refines another (grants narrowed, prohibitions, bounds and escalation triggers only added, validity and delegation only tightened), its decision is never higher. The facade bugs that violated this (a second count limit removing the rate caveat; a `$` limit removing co-sign tiers) are fixed.

| | |
|---|---|
| Enforced by | `GoalCompile.Monotonicity`; `compilePolicy` and `liftLegacy`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T2; the random monotonicity test; the facade regression tests. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-42 Every Allow carries a checkable witness and Unknown never allows

**Statement.** The decision function returns, for an Allow, the grant that admitted the action and the bounds that applied; a separate small checker accepts only true witnesses. A clause that evaluates to Unknown yields Escalate or Deny, never Allow, and an Escalate is not an Allow at the enforcement point without a signed answer bound to the policy, action and history.

| | |
|---|---|
| Enforced by | `GoalWitness.DecideW`, `VerifyWitness`, `PepAllows`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorems G-T3 and G-T4 (compiler half); the witness checks in the extracted-code tests. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-43 Goals are unit-safe and closed-world

**Statement.** A well-typed goal never mixes currencies or units and names only verbs and parameters the ontology declares; an ill-typed goal is rejected, never coerced. A `$` limit on a verb with no amount field is an error.

| | |
|---|---|
| Enforced by | `GoalIr.IsWellTyped`, `UnitSafety`; `compilePolicy` and `liftLegacy` refusals. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T6; the typing tests; the facade regression tests. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-44 A goal with unresolved questions is never signable

**Statement.** A goal with holes is a draft; its compiled policy is no wider than the same goal without the clauses that depend on a hole.

| | |
|---|---|
| Enforced by | `GoalCompile.Strip`, `HoleSafety`; `GoalIr.Signable`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T7; the draft test. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-45 The card is lossless

**Statement.** Parsing the rendering of a goal gives back exactly that goal, so two goals never share a card and everything the policy permits is shown.

| | |
|---|---|
| Enforced by | `GoalRender.Render`, `RenderParse`, `RenderInjective`; `renderTape`, `renderCard`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T10; the round-trip and field-by-field card tests. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-46 Compilation is canonical

**Statement.** Equal goal bytes give a byte-identical policy, so the policy digest the principal signs is well defined.

| | |
|---|---|
| Enforced by | `GoalCompile.Canonicity`; `policyDigest`. |
| Trusted inputs | The signed ontology the goal is typed against; the Dafny toolchain and the thin TypeScript glue. |
| State | None; the compiler is a pure function. |
| On failure | Ill-typed goals are rejected with reasons; nothing is compiled. |
| Established by | Dafny theorem G-T5; the determinism test. |
| Status | **Hardened.** Machine-checked in Dafny; CI must show `dafny verify` with zero errors, a byte-identical regenerated `pca_goal.js` and equal differential transcripts before this is called production. |

### C-60 A goal is enforceable only after a pinned reviewer signed exactly what is enforced

**Statement.** A Goal becomes loadable policy only through `loadApprovedGoal`, which recomputes the goal digest, recompiles the policy, re-renders the review card and re-derives the tests, instruction and model-set digests from the submission, and refuses unless a reviewer key the host pinned signed all of them (and the ontology, reviewer and validity window) and the signature is unexpired. A goal with an unresolved question, an unacknowledged wildcard, a compile or analyzer error, or a confirmed example the compiled policy contradicts is refused. Nothing the submission or the approval says about itself is trusted. The reviewer reading the card is not guaranteed.

| | |
|---|---|
| Enforced by | `approveGoal`, `loadApprovedGoal`, `renderPolicyCard`. |
| Trusted inputs | The pinned reviewer keys; the compiler. |
| State | None. |
| On failure | `{ ok: false, reason }`, never a throw; one distinct reason per field (`goal_digest_mismatch`, `policy_digest_mismatch`, `card_digest_mismatch`, `ontology_mismatch`, `tests_digest_mismatch`, `nl_digest_mismatch`, `model_set_digest_mismatch`, `instruction_mismatch`, `holes`, `reviewer_not_pinned`, `expired`, `bad_signature`, and the rest). |
| Established by | Tests: a tamper test for every approved field and every Goal member, the re-derived policy digest, holes and wildcards. |
| Status | **Hardened, not production.** The card, the diff and the approval are tested here; the compiler they call is a separate component. The CI proof and mutation gates must pass before any stronger label. |

### C-61 The grant's goal commitment binds the approved goal and its compiled policy

**Statement.** When a verifier is configured with `approved_goal` (the goal digest and the compiled-policy digest), the root grant's goal commitment must open to `pca-intent:v3:<goal_digest>:<policy_digest>` and to nothing else: a grant minted for the same statement under the older identity commitment, for another goal, for another compiled policy, or with another salt is refused, and a malformed `approved_goal` fails closed. A verifier without `approved_goal` keeps the v1 and v2 rules unchanged, so existing grants still verify.

| | |
|---|---|
| Enforced by | `decideIntentBinding`, `intentGoalCommitV3`. |
| Trusted inputs | The verifier's own `approved_goal` configuration. |
| State | None. |
| On failure | The `intent` check fails with a reason. |
| Established by | Tests and the vectors `goal-commit-vectors.json`. |
| Status | **Hardened.** Reference implementation in TypeScript; the native verifiers do not yet read `approved_goal`. |

### C-62 A review that is too large to read is refused, never shortened

**Statement.** The review card and the semantic diff have hard caps (grants, prohibitions, bounds, triggers, examples, lines, bytes, changes, widenings). A goal or diff over a cap is refused with `card_too_large`, `diff_too_large` or `too_many_widenings`; nothing is truncated, so everything a reviewer signs was shown. A caller can only tighten a cap. A diff counts every change it cannot prove narrower as a widening and lists widenings first.

| | |
|---|---|
| Enforced by | `renderPolicyCard`, `diffGoals`, `effectiveLimits`. |
| Trusted inputs | None. |
| State | None. |
| On failure | A typed refusal. |
| Established by | Tests: the cap boundaries, overrides that cannot loosen, widening classification. |
| Status | **Hardened.** The caps limit what is shown; they do not make a person read it. |

### C-63 A natural-language approval binds the instruction, the model and the prompt

**Statement.** An approval v2 signs a digest that includes the instruction text, the model id and the exact prompt. A draft cannot be re-pointed at another instruction, a different model or prompt is a different draft, and `agentFromApprovedNL` refuses a goal text other than the approved instruction. A v1 approval (signed before 0.5) still loads for one release and is flagged `legacy_unbound_instruction`, because its signature never covered the instruction.

| | |
|---|---|
| Enforced by | `approveDraft`, `loadApprovedPolicy`, `agentFromApprovedNL`. |
| Trusted inputs | The pinned reviewer keys. |
| State | None. |
| On failure | `tampered_draft`, `digest_mismatch`, or `goal_mismatch`. |
| Established by | Tests: re-pointed instruction, pinned model and prompt, goal mismatch, legacy loading. |
| Status | **Experimental feature** (the natural-language path); the typed successor is C-60. |

### C-85 The adversarial corpus is deterministic and committed

**Statement.** Every vector is generated from fixed seeds; the committed files are byte-identical to a fresh generation, so a vector cannot be edited to make a verifier pass.

| | |
|---|---|
| Enforced by | `adversarial/src/vectors.ts --check`, the corpus determinism tests. |
| Trusted inputs | The reference semantics in the adversarial suite; the Goal compiler under test is NOT trusted. |
| State | n/a |
| On failure | The suite or the vector runner of the failing language exits non-zero and the release gate is red. |
| Established by | Tests: "generator is deterministic (same seeds, byte-identical corpus)", "committed vectors equal a fresh generation (no drift, no stale files)". |
| Status | **Hardened.** Production requires the cross-language CI matrix (goal-vectors workflow) and the compiler mutation gate to have run green against the real compiler. |

### C-86 Four languages agree on goal digests and decisions

**Statement.** TypeScript, Go, Rust and Python reproduce every goal digest and every probe decision (with witness) of the shared corpus byte for byte; any disagreement fails the matrix.

| | |
|---|---|
| Enforced by | `runners/goal/{py,go,rust}`, `adversarial/test/vectors.test.ts`. |
| Trusted inputs | The reference semantics in the adversarial suite; the Goal compiler under test is NOT trusted. |
| State | n/a |
| On failure | The suite or the vector runner of the failing language exits non-zero and the release gate is red. |
| Established by | Tests: "vectors replay through the reference subject with zero disagreements". |
| Status | **Hardened.** Production requires the cross-language CI matrix (goal-vectors workflow) and the compiler mutation gate to have run green against the real compiler. |

### C-87 Every weakness W1..W23 has an executable post-spec test

**Statement.** Each weakness in the goal-to-decision catalogue is asserted by a test of the post-spec behaviour; with the real subject required, a missing capability fails rather than skips.

| | |
|---|---|
| Enforced by | `adversarial/test/weaknesses.test.ts`, `GOAL_REQUIRE_SUBJECT`. |
| Trusted inputs | The reference semantics in the adversarial suite; the Goal compiler under test is NOT trusted. |
| State | n/a |
| On failure | The suite or the vector runner of the failing language exits non-zero and the release gate is red. |
| Established by | Tests: "W1 a grant minted for another goal text fails goal_commit opening", "W21 escalate with no valid bound answer is refused by the PEP". |
| Status | **Hardened.** Production requires the cross-language CI matrix (goal-vectors workflow) and the compiler mutation gate to have run green against the real compiler. |

### C-88 Compiler mutants are killed

**Statement.** Every widening or breaking mutation of a goal (drop a prohibition, widen a cap or window, narrow a scope, drop a hole) changes a decision on some probe, or is recorded as search-equivalent and survives an independent re-search; the real compiler must follow the oracle on every mutant.

| | |
|---|---|
| Enforced by | `adversarial/src/mutants.ts`, mutation tests. |
| Trusted inputs | The reference semantics in the adversarial suite; the Goal compiler under test is NOT trusted. |
| State | n/a |
| On failure | The suite or the vector runner of the failing language exits non-zero and the release gate is red. |
| Established by | Tests: "the corpus kills every mutant not recorded as search-equivalent". |
| Status | **Hardened.** Production requires the cross-language CI matrix (goal-vectors workflow) and the compiler mutation gate to have run green against the real compiler. |

### C-89 Adding a constraint never widens the policy

**Statement.** For random goals and added constraints (prohibit, bound, narrower condition, shorter validity, narrower delegation, hole), no probe that is allowed after the change was not allowed before.

| | |
|---|---|
| Enforced by | `adversarial/test/corpus.test.ts` monotonicity property. |
| Trusted inputs | The reference semantics in the adversarial suite; the Goal compiler under test is NOT trusted. |
| State | n/a |
| On failure | The suite or the vector runner of the failing language exits non-zero and the release gate is red. |
| Established by | Tests: "W7 monotonicity: for random G and constraint c". |
| Status | **Hardened.** Production requires the cross-language CI matrix (goal-vectors workflow) and the compiler mutation gate to have run green against the real compiler. |

### C-90 The enforced goal policy is within every interpreter reading

**Statement.** The merged policy of a panel of interpreters allows an action only if every reading allows it; if one reading is faithful, the others cannot widen it.

| | |
|---|---|
| Enforced by | The goal merge (cross product of grants, union of prohibitions, minimum of caps). |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Mechanized: the merge containment theorem (Lean), plus tests over cells and cap sequences. Tests: "meet is within every reading, on every cell and cap sequence", "a wildcard reading cannot widen the meet". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-91 Ontology-checked templates; unresolved ambiguity is a hole

**Statement.** Ontologies are checked for total typing, closed units, a function-shaped alias map without chains or cycles, an effect class for every verb and non-empty bounded templates; a slot the interpreter cannot fill or type becomes a hole, and a goal with holes is not signable.

| | |
|---|---|
| Enforced by | The ontology checker and template instantiation. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests: the checker rejects each defect class and accepts all five shipped domains. Tests: "rejects defects", "template goals have holes limited to declared slots". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-92 Model output cannot widen beyond the principal's words

**Statement.** A model-produced slot value is accepted only when it is grounded in the principal's own text; untrusted sources are not instructions; the hostile corpus widening rate is gated per domain.

| | |
|---|---|
| Enforced by | The interpreters and the grounding check. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests and benchmark gates on recorded outputs; a scheduled live evaluation. Tests: "ambiguous literal and missing slot become holes", "homoglyph ids never match". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-93 Confirmed examples and the policy pin

**Statement.** A recompile must reproduce every principal-confirmed boundary example, and a pin refuses a silent change of goal, policy, tests or ontology.

| | |
|---|---|
| Enforced by | Boundary example generation, signed goal tests and the pin check. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests: the coverage property on the decided fragment, regression refusal and pin refusal. Tests: "coverage theorem: any policy over the same literals that differs on a cell differs on an example", "the pin refuses a silent policy, goal, test or ontology change". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-94 Precedents widen only with a principal signature bound to policy, cell and ceiling

**Statement.** A recorded answer (the signed escalation answer, bound to the policy digest, the exact action digest and the history head) widens only the exact cell of the action it answered, with ceilings taken from that action's own parameters, under the same policy digest, within the signed quantity ceilings and units, before expiry and revocation; it never turns a Deny into an Allow, and a tampered log gives no widening.

| | |
|---|---|
| Enforced by | The precedent log and `authorizeWithPrecedents`. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests for replay, ceiling, unit, expiry, revocation, forgery and tamper cases. Tests: "widens only with a signature bound to policy, cell and ceiling", "deny is never widened; flipping needs a signed revocation; tamper locks". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-95 Drift monitors only tighten

**Statement.** A drift monitor can turn Allow into Escalate and never the reverse; its strikes never decrease and a failed seal locks it down.

| | |
|---|---|
| Enforced by | The drift monitor and `applyDrift`. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests: the pointwise order property and the ratchet. Tests: "applyDrift is pointwise <= (property)", "magnitude spike and sealed state". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-96 The policy card is lossless

**Statement.** The card tape decodes back to exactly the goal (G-T10), and the text card prints every field the tape carries, so nothing the policy permits is missing from the card.

| | |
|---|---|
| Enforced by | `renderTape` / `decodeGoal` (proved) and `renderCard`. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Tests on every template example and on merged and hole-carrying goals. Tests: "card is injective on every template example (parse . render = id)", "distinct goals have distinct cards". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

### C-97 Published widening rates carry their assumptions

**Statement.** The per-domain widening rate is reported with a Clopper-Pearson upper bound; the threshold choice satisfies the conformal condition proved in Lean, and the report states exchangeability, label quality, probe coverage and non-adaptivity.

| | |
|---|---|
| Enforced by | The calibration and the report generator. |
| Trusted inputs | The ontology as a faithful model of the site API; the principal key. |
| State | None beyond the signed artifacts. |
| On failure | The goal stays a draft, the decision stays Escalate, or the policy is refused. |
| Established by | Mechanized inequality (Lean) plus per-domain benchmark gates on recorded outputs. Tests: "picks the least conservative feasible level and falls back to the top", "too few calibration samples are infeasible and fall back to escalate-all". |
| Status | **Hardened.** The CI proof, benchmark and mutation gates must pass before it is called production. |

## How this page is kept honest

- Each invariant's tests are listed by file in [Traceability](./traceability.md) (rows `C-1` to `C-97`); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
- A retired-statement check fails the build when a public page or README repeats a statement that is no longer true (for example a stale corpus size, or a feature described as unimplemented that now ships).
- No external security audit has been performed. The tests, vectors and models above are the project's own.

Next: [Trust model](./trust-model.md) and [Traceability](./traceability.md).
