---
title: Security contract
order: 32
---

# Security contract

**Audience: security reviewers, auditors and resource-server owners.** This page states the nineteen invariants a resource server can rely on when it authorizes an agent's action with PCA, and for each one: the function that enforces it, the inputs it must trust, the state it needs, what happens when it fails, the tests and conformance vectors that establish it, and its **current status on every verifier surface**. It is deliberately blunt about where an invariant does not hold yet.

Read it with the [Threat model](./threat-model.md) (attacks T-001 to T-057, T-110 to T-165 and T-340 to T-349, guarantees G-1 to G-24) and the [Trust model](./trust-model.md) (who is trusted for what). The test files behind each invariant are listed per row, as `C-1` to `C-29`, `C-40` to `C-97` and `C-240` to `C-256`, in [Traceability](./traceability.md), whose checker fails the build when a listed test no longer exists.

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

### C-220 A third-party caveat is discharged only by a pinned, bound, fresh, signed discharge

**Statement.** `needs_discharge` is satisfied only by a discharge signed by the key the VERIFIER pinned under the caveat's issuer label (never a key in the token), of the pinned class, bound to the hop that carries the caveat (and for `bind: action` to the digest of this exact PCActn), inside its window and the caveat's `ttl_ms`, not revoked, and whose claims meet every requirement. The verifier never contacts the issuer.

| | |
|---|---|
| Enforced by | `verifyDischarge`, `evaluateK1` (caveat-lang.ts); the native `verify_discharge` / `evaluate_k1`; `verifyPCActn({ k1 })`, `requirePCA({ k1 })`. |
| Trusted inputs | pins, clock, revocation list; never the discharge or the token for who may sign. |
| State | none (C-224: the replay store). |
| On failure | `needs_discharge: <reason>` (unpinned, wrong class, bad signature, another hop, another action, future, expired, too long-lived, revoked, claim unmet, no discharge); the caveat is unsatisfied and the action refused. |
| Established by | Tests: caveat-lang-vectors.json `discharge_verify` and `k1_eval` (all languages), `k1-integration.test.ts`. |
| Guarantees | (T-320 (forged, lifted or replayed discharge)). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-221 A caveat the verifier cannot evaluate refuses the chain

**Statement.** A K1 caveat that is malformed, has a duplicate id, or arrives with no K1 input is unsatisfied; so is any unknown type. Stock evaluators never skip a K1 type: it is taken out of their list only to be evaluated by the caveat language.

| | |
|---|---|
| Enforced by | `evaluateK1`, `decide`, `verifyPCActn`. |
| Trusted inputs | the chain only. |
| State | none (C-224: the replay store). |
| On failure | `<type>` appears in the failed list. |
| Established by | Tests: `k1_eval` malformed and duplicate vectors; `k1-integration.test.ts` last case. |
| Guarantees | (T-321). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-222 A sealed hop is the last hop

**Statement.** `sealed` is satisfied only by the leaf hop that carries it; a hop appended below is structurally valid but never satisfies the seal; a holder cannot drop or edit it (prefix rule).

| | |
|---|---|
| Enforced by | `evaluateK1`; `verifyChain`. |
| Trusted inputs | the chain. |
| State | none (C-224: the replay store). |
| On failure | `sealed`. |
| Established by | Tests: `k1_eval` sealed vectors; `offline attenuation hardening` in caveat-lang.test.ts. |
| Guarantees | (T-322). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-223 A narrow block only restricts and only the leaf holder can issue it

**Statement.** Signed by the leaf holder, bound to the leaf hop and optionally one PCActn, at most 24 h, 1..16 caveats, none of `envelope`, `sealed`, `budget_alloc`, `intent_session`; an invalid or expired block present with the action is refused, never ignored.

| | |
|---|---|
| Enforced by | `verifyNarrow`, `evaluateK1`. |
| Trusted inputs | the chain, the clock. |
| State | none (C-224: the replay store). |
| On failure | `narrow: <reason>`. |
| Established by | Tests: `k1_eval` narrow vectors. |
| Guarantees | (T-323). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-224 A `max_uses` count is spent atomically and never exceeds n

**Statement.** The caveat takes the first free of n consume-once slots in the verifier's replay store after the action is otherwise admitted (after the counter claim in `requirePCA`); concurrent actions never share a slot; an exhausted, expired, malformed or store-less caveat refuses.

| | |
|---|---|
| Enforced by | `reserveMaxUses`, `requirePCA({ usesStore })`. |
| Trusted inputs | the replay store, the clock. |
| State | none (C-224: the replay store). |
| On failure | `max_uses: <reason>` and `checks.max_uses = fail`. |
| Established by | Tests: `uses_reserve` vectors; concurrency test in caveat-lang.test.ts; `k1-integration.test.ts`. Depends on the store's atomicity (replay-store verification). |
| Guarantees | (T-324). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-225 A derived-fact check is bounded and unknown never allows

**Statement.** `derive` has at most 8 defs, 32 nodes, depth 4, no recursion; facts come only from the action, the verifier's history and verified discharges; the check must be exactly true under Kleene logic, so false and unknown both refuse.

| | |
|---|---|
| Enforced by | `deriveError`, `evaluateDerive`. |
| Trusted inputs | the verifier's history and the verified discharges. |
| State | none (C-224: the replay store). |
| On failure | `derive`. |
| Established by | Tests: `caveat_shape` and `k1_eval` derive vectors. |
| Guarantees | (T-325). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

---

### C-226 A SPIFFE-bound caveat compares an identity the verifier verified

**Statement.** `spiffe_bound` is satisfied only when the SPIFFE ID the verifier derived from a verified SVID bound to the PCActn leaf holder equals (or lies below) the caveat's ID; the ID syntax follows the SPIFFE standard; a workload discharge issuer must carry the pinned `spiffe_id` the caveat names.

| | |
|---|---|
| Enforced by | `spiffeBoundError`, `evaluateK1`, `spiffeIdForHolder`. |
| Trusted inputs | the verified SVID, the pins. |
| State | none (C-224: the replay store). |
| On failure | `spiffe_bound`. |
| Established by | Tests: `spiffe_id` and `k1_eval` spiffe vectors; pca-spiffe index.test.ts. |
| Guarantees | (T-326). |
| Status | **Full TS and native: enforced** when the chain carries the caveat; without K1 input the chain is refused. |

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
| C-220 A third-party caveat is discharged only by a pinned, bound, fresh, signed discharge | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-221 A caveat the verifier cannot evaluate refuses the chain | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-222 A sealed hop is the last hop | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-223 A narrow block only restricts and only the leaf holder can issue it | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-224 A `max_uses` count is spent atomically and never exceeds n | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-225 A derived-fact check is bounded and unknown never allows | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
| C-226 A SPIFFE-bound caveat compares an identity the verifier verified | enforced | enforced | refuses (fail closed) | n/a | n/a | enforced | n/a |
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
| Status | **Production, pending CI.** The harness measurement is self-asserted by the signer, not hardware-rooted; an allowlisting resource server trusts the operator's choice of build. |

### C-21 A control-evaluation gate never passes vacuously

**Statement.** `controlEval` refuses an empty red suite, fewer than one episode and a non-finite seed. `assertControlGate` throws unless the report covers every required strategy, every strategy's one-sided 95% Wilson lower bound on safety and the overall bound clear the threshold, and usefulness meets its minimum. Any non-finite or missing value fails the comparison. A passing gate certifies only the modeled red suite and environment.

| | |
|---|---|
| Enforced by | `controlEval`, `wilsonLowerBound` and `assertControlGate` in `@atlasauth/pca-control-evals`. |
| Trusted inputs | The red policies, environment and blue protocol the deployer encodes. |
| State | None; deterministic given a seed. |
| On failure | A thrown error listing every violation. |
| Established by | The control-evaluation tests: refusal of vacuous runs, known Wilson values, every gate violation with its exact message, the gap-exploit red failing the gate, and a NaN report value failing the gate. |
| Status | **Production, pending CI.** It is an empirical bound over a modeled adversary, not a proof, and it is complementary to the analytic budget bound. |

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

C-1 to C-10 are the contract of PCA Core and the server path. Two optional extensions make their own claims, under the same rules (each states what enforces it, what it trusts, what state it needs, what happens on failure, and what establishes it). Optimistic execution is **production** (pending CI); the ledger is **hardened, awaiting independent witnesses and independent audit**. They live under `@atlasauth/pca/ext/optimistic` and `@atlasauth/pca/ext/ledger`; no Core verifier evaluates them.

| Invariant | Full TS (`StoreBondLedger` / `StoredLedger`) | Wire members in Go, Python, Rust | Other surfaces |
|---|---|---|---|
| C-13 A bond moves atomically, once, on evidence the ledger re-derived | production (pending CI) | verified (claim, fraud proof structure, settlement record) | n/a |
| C-14 The ledger is append-only and checkpoint-consistent; tamper evidence needs an honest independent witness | hardened, awaiting independent witnesses | verified (inclusion, consistency, tree head, cosignatures, chains) | n/a |

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
| Status | **Production (pending CI).** **Internal accounting only; real-money settlement is outside the claim.** Effects are not rolled back. The in-memory `BondLedger` that predates the store is a test double under `ext/optimistic-testing` and is not a default. The shared fraud-proof vectors check structure; the recomputation that convicts is TypeScript-only. No independent audit. |

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
| Status | **Hardened, awaiting independent witnesses and independent audit.** No independent witness is operated by the project, so the end-to-end claim is conditional on someone else operating one. First sight of a log is trusted. |

### C-180 A grant opens only to the approved goal and policy it was issued for

**Statement.** A verifier configured with `approved_goal = { goal_digest, policy_digest }` accepts a root grant only when its goal commitment opens to `pca-intent:v3:<goal_digest>:<policy_digest>`; a v1 or v2 grant, a grant for another goal or policy, and a malformed `approved_goal` (non-canonical or short digest, extra member) are refused. A verifier without it is unchanged.

| | |
|---|---|
| Enforced by | The intent check of `authorize` in TypeScript and in all nine native SDKs. |
| Trusted inputs | The verifier configuration (policy, pins, clock, stores). |
| State | Operation, plan or revocation state held by the host's atomic store, where the claim needs it. |
| On failure | A denial with a distinct reason, or a typed refusal; nothing is written. |
| Established by | Tests in TypeScript and in the nine native SDKs, replaying shared vectors (extension layer). |
| Guarantees | G-20. |
| Status | Hardened. Native SDK results await CI. |

### C-181 Revocation state older than the verifier allows is refused

**Statement.** With a staleness policy, revocation state older than the verifier-side window for the action class (default 5 min; 2 min irreversible; unknown class counts as irreversible) is refused even before its signed `not_after`; an unsigned root is refused for an irreversible action unless allowed, and an unknown age denies.

| | |
|---|---|
| Enforced by | The `freshness` check in the native SDKs; `createRevocationChecker` and `requirePCA` in TypeScript. |
| Trusted inputs | The verifier configuration (policy, pins, clock, stores). |
| State | Operation, plan or revocation state held by the host's atomic store, where the claim needs it. |
| On failure | A denial with a distinct reason, or a typed refusal; nothing is written. |
| Established by | Tests in TypeScript and in the nine native SDKs, replaying shared vectors (extension layer). |
| Guarantees | G-20. |
| Status | Hardened. Native SDK results await CI. |

### C-182 An authorized operation executes at most once and its outcome is recorded

**Statement.** Of any number of concurrent or repeated executions of one authorization exactly one runs the side effect; an irreversible operation needs a passing re-check immediately before it runs; a crash never causes a re-run (a stale `pending` becomes `aborted`, a stale `executing` becomes `uncertain` for reconciliation); a missing store refuses.

| | |
|---|---|
| Enforced by | `executeAuthorized` and `createExecutor` over an atomic `OperationStore`. |
| Trusted inputs | The verifier configuration (policy, pins, clock, stores). |
| State | Operation, plan or revocation state held by the host's atomic store, where the claim needs it. |
| On failure | A denial with a distinct reason, or a typed refusal; nothing is written. |
| Established by | Tests in TypeScript and in the nine native SDKs, replaying shared vectors (extension layer). |
| Guarantees | G-20. |
| Status | Hardened. Native SDK results await CI. |

### C-183 A plan executes only while authorized, unexpired and unchanged

**Statement.** A plan moves draft, validated, committed, authorized in that order only; revocation is terminal; it is executable only while authorized, within the principal approval window and with nodes that still hash to the committed root; changed parameters are refused.

| | |
|---|---|
| Enforced by | The plan registry and the `plan_state` check. |
| Trusted inputs | The verifier configuration (policy, pins, clock, stores). |
| State | Operation, plan or revocation state held by the host's atomic store, where the claim needs it. |
| On failure | A denial with a distinct reason, or a typed refusal; nothing is written. |
| Established by | Tests in TypeScript and in the nine native SDKs, replaying shared vectors (extension layer). |
| Guarantees | G-20. |
| Status | Hardened. Native SDK results await CI. |

### C-184 The verdict says what a pass rests on, and unsupported is never a pass

**Statement.** Assurance labels come from the verifier configuration, never from presented evidence; an unlabelled verifier satisfies no requirement; features the verifier does not implement (for example `bond_ref`) are reported `unsupported`; a `require_assurance` policy fails the `assurance` check, before any replay state is written, when evidence is weaker, missing, preview, degraded or unsupported.

| | |
|---|---|
| Enforced by | The assurance report and the `assurance` check. |
| Trusted inputs | The verifier configuration (policy, pins, clock, stores). |
| State | Operation, plan or revocation state held by the host's atomic store, where the claim needs it. |
| On failure | A denial with a distinct reason, or a typed refusal; nothing is written. |
| Established by | Tests in TypeScript and in the nine native SDKs, replaying shared vectors (extension layer). |
| Guarantees | G-20. |
| Status | Hardened. Native SDK results await CI. |

## Research-unit invariants

Eight units of the product layer (production, pending CI), the QRNG entropy module and the PUF verifier (hardened, awaiting hardware evaluation) make their own claims under the same rules. Each Status row below says what a unit still awaits.

### C-22 No unsigned natural-language policy is ever loaded

**Statement.** A policy proposed by a model is a draft. It becomes an agent only when a reviewer key the loader pinned has signed the exact compiled policy (permissions, limits and catalog digest) inside a bounded window, every verb is in the catalog, and the static lints raise no error. Nothing the model said is enforced otherwise.

| | |
|---|---|
| Enforced by | `loadApprovedPolicy`, `agentFromApprovedNL`. |
| Trusted inputs | The pinned reviewer keys; the catalog. |
| State | None (the approval is a signed document). |
| On failure | `loadApprovedPolicy` returns a refusal with a reason (`reviewer_not_pinned`, digest mismatch, expired, unknown verb, analyzer error, empty); `agentFromApprovedNL` throws with it. |
| Established by | Tests: "every refusal row gives its exact reason", "valid approval loads exactly the drafted policy", "unknown verbs are reported and block approval". |
| Status | **Production (pending CI).** It does not prove the model understood the instruction; the reviewer does. |

### C-23 A safety certificate states a signed scope and which checks ran, never that a system is safe

**Statement.** The certificate is the arithmetic consequence of the signed risk parameters (`scope: risk-budget-bound`) plus signed check records with evidence links. The verifier recomputes the bound, refuses any other scope, and can require named checks to have passed.

| | |
|---|---|
| Enforced by | `verifySafetyCertificate`. |
| Trusted inputs | The pinned guardian key. |
| State | None. |
| On failure | Verification returns `ok: false` with a reason (unknown scope, bound mismatch, bad signature, missing required check, too old). |
| Established by | Tests: "scope is risk-budget-bound and the statement disclaims safety", "checks are signed: removing or changing one breaks the signature", "wrong scope is refused", "requireChecks on a certificate with no checks is refused". |
| Status | **Production (pending CI).** Evidence links are references; the verifier does not fetch them. |

### C-24 Guardian fencing is monotonic and a stale leader is refused

**Statement.** Each lease takeover raises the epoch; the epoch never goes down. A signer or resource that checks the fence refuses an ex-leader, an expired holder window, a lost lease, and any store failure (no leader).

| | |
|---|---|
| Enforced by | `acquireLease`, `renewLease`, `assertFence`, `fencedSigner`, `createFenceGuard`. |
| Trusted inputs | A store with linearizable compare-and-swap and a trustworthy clock. |
| State | The lease record in the store. |
| On failure | `assertFence` and `fencedSigner` refuse with `FenceError`; an acquire against a failing store is `store-error`. |
| Established by | Tests: "epochs are strictly monotone over repeated takeovers", "assertFence: current leader ok; stale epoch, expired window and no lease are refused", "FencedSigner signs for the leader and refuses a stale ex-leader without running sign", "cas refuses to lower the epoch". |
| Status | **Production (pending CI).** Safety depends on the store being linearizable; the conformance suite checks that. |

### C-25 A latched contract violation clears only on the principal's signed reset

**Statement.** A contract violation observed on an admitted trace latches in durable state, refuses every later action, survives a restart, and clears only with a reset signed by the contract principal for that exact sequence number. Two processes cannot admit the same sequence number.

| | |
|---|---|
| Enforced by | `ContractEnforcer`, `authorize({ contracts })`. |
| Trusted inputs | The pinned principal key; an atomic key-value store. |
| State | The monitor state and the latch. |
| On failure | `check` and `peek` return `violated`, `latched`, `state-error` or `store-error`; `authorize` refuses with `contract: <reason>` before the replay counter is spent. |
| Established by | Tests: "a violation is refused, names the clause, and latches", "reset needs the principal signature at the latched seq", "two enforcers on one kv racing the same actions", "state and the latch survive a restart on file-backed state". |
| Status | **Production (pending CI).** Safety properties only (no liveness). |

### C-26 Adaptive risk tightening never widens a policy

**Statement.** An adapted or applied risk policy has kappa not below, thetas not above, and every other parameter equal to the base. An invalid state assesses as high threat. A signed proposal binds the base and a strictly increasing epoch. In `authorize`, an adaptive policy can only add a refusal.

| | |
|---|---|
| Enforced by | `adapt`, `applyTightening`, `authorize({ adaptivePolicy })`. |
| Trusted inputs | The pinned guardian key (proposals). |
| State | The immune state and the last applied epoch. |
| On failure | The adaptation is rejected with a reason and the base stays in force; `authorize` refuses with `adaptive: <reason>`. |
| Established by | Tests: "a correctly signed but widening proposal is refused", "adapt never widens, never NaN, and reversal at score 0 is the base", "a higher score is never looser", "a tightened policy that requires a higher threshold refuses with the exact reason", "a looser policy cannot widen: it is ignored". |
| Status | **Production (pending CI).** What is enforced is the no-widen property; the anomaly score is an advisory heuristic by design and a slow attacker can game it. |

### C-27 Reputation counts only verified settlements

**Statement.** Disputes feeding a reputation come from settlement records whose guardian signature verifies; forged, wrong-key and unknown-subject records are rejected and counted, a repeated dispute id counts once, and a coverage quote is accepted only when the underwriter signature, window and recomputed premium all match. A reputation is advisory and never an authorization input.

| | |
|---|---|
| Enforced by | `disputesFromSettlements`, `verifyCoverageQuote`. |
| Trusted inputs | The pinned guardian and underwriter keys. |
| State | None. |
| On failure | Rejected records are counted in `rejected`; a quote fails with a reason (for example `price-mismatch`). |
| Established by | Tests: "forged, wrong-key, and unknown-subject records are rejected, not counted", "a repeated dispute id counts once", "a correctly signed but mispriced quote is refused (recomputation)". |
| Status | **Production (pending CI).** A reputation is advisory by design and never an authorization input; what is enforced is that only verified records count. |

### C-28 Entropy health tests fail closed and an external source can never weaken a seed

**Statement.** Every quantum buffer passes the SP 800-90B repetition-count and adaptive-proportion tests or is dropped; a seed is always HKDF over the local CSPRNG bytes too, so the result is never weaker than the local source; `requireQuantum` turns a missing or rejected source into a typed error; a source over plain http or one that redirects is refused.

| | |
|---|---|
| Enforced by | `healthTestBytes`, `secureSeed`, `HttpQrngSource`. |
| Trusted inputs | The local CSPRNG. |
| State | None. |
| On failure | `EntropyError` (`quantum_required`, health failure) or a CSPRNG-only seed. |
| Established by | Tests: "fails closed: constant, run, skewed, empty and bad parameters", "matches HKDF-SHA256 over the length-prefixed local||quantum", "never follows redirects", "http is refused, https allowed, loopback http only with the opt-in". |
| Status | **Hardened, awaiting hardware evaluation** (a run against a real quantum source needs a device). Not a quantum root of trust. |

### C-29 A PUF root never counts as hardware assurance

**Statement.** The PUF verifier is labelled software, accepts only a device in the pinned, unrevoked, unexpired enrollment registry with a non-empty measurement allowlist, and in the gate and the multi-root level it reports software, never hardware or multi-root.

| | |
|---|---|
| Enforced by | `createPufVerifier`, `createPufEnrollmentRegistry`. |
| Trusted inputs | The enrollment registry and the measurement allowlist. |
| State | The registry (revocations are permanent). |
| On failure | The verifier fails with a reason (unknown, revoked, expired, binding mismatch, malformed). |
| Established by | Tests: "a PUF root is never hardware assurance: verifier, gate and multi-root all report software", "the registry revokes for good: re-registering does not un-revoke", "an empty or missing measurement allowlist is refused at construction (no accept-all)". |
| Status | **Hardened, awaiting hardware evaluation** on a real PUF or TPM. |
### C-780 A data-loss-prevention check never allows a flow whose taint or ceiling it cannot read

**Statement.** A taint that is not a finite number is treated as maximally tainted, a ceiling that is present but not a number denies, and a malformed policy denies. The most specific class wins and, among equals, the strictest.

| | |
|---|---|
| Enforced by | `evaluateDlp`. |
| Trusted inputs | The policy you supply. |
| State | None. |
| On failure | `deny` with a reason naming the malformed policy, or `step_up` / `deny` above the ceilings. |
| Established by | Tests: "NaN taint against a hard ceiling is a hard deny", "class ceiling is a string", "default ceiling is NaN", "a taint smuggled in as a string is treated as maximally tainted (never beats the ceiling)". |
| Status | **Production (pending CI).** A flow with no ceiling at all is unconstrained by design. |

### C-781 An unknown verb is the most dangerous verb, and a catalog extension cannot soften a known one

**Statement.** A verb the catalog does not know resolves to an irreversible, maximum-blast-radius spec marked uncatalogued. `extendCatalog` refuses to replace a verb with a lower reversibility class or a lower blast radius. A catalog can be pinned by digest. An alias resolves only when exactly one action of the connector carries it.

| | |
|---|---|
| Enforced by | `resolveAction`, `extendCatalog`, `assertCatalogPinned`, `defineAction`. |
| Trusted inputs | The catalog digest you pinned. |
| State | None. |
| On failure | A thrown error naming the refused change, or the uncatalogued spec. |
| Established by | Tests: "an unknown verb resolves to the most dangerous spec and says it is not catalogued", "extending cannot relabel an existing verb as less cautious", "a pin mismatch throws; the matching digest passes", "an ambiguous alias resolves to nothing". |
| Status | **Production (pending CI).** The catalog describes actions; the verifier recomputes what it relies on. |

### C-782 An agent with no identity, or a malformed freeze set, is frozen

**Statement.** The kill switch fails closed: `isFrozen` returns true for an empty or non-string agent id and for a set that is null or malformed. Freezing is idempotent and sorted; unfreezing removes only the named agent.

| | |
|---|---|
| Enforced by | `isFrozen`, `freezeAgent`, `unfreezeAgent`. |
| Trusted inputs | The freeze set your control plane stores. |
| State | The freeze set (serializable). |
| On failure | `isFrozen` returns true; `freezeAgent` throws a `TypeError` on an empty id. |
| Established by | Tests: "null set", "frozen not an array", "freezing needs a non-empty agent, is idempotent and sorted; unfreezing removes only that agent". |
| Status | **Production (pending CI).** Applying the freeze to the action path is the integrator's call. |

### C-783 A mesh witness never starts empty over a damaged state file

**Statement.** The file-backed witness store writes a temporary file, syncs it, renames it and syncs the directory; the file carries a digest of its state. A file that does not parse, has the wrong shape or fails its digest makes `load` throw, so a witness cannot silently forget a head it already cosigned. A missing file is a first run.

| | |
|---|---|
| Enforced by | `FileMeshWitnessStore`. |
| Trusted inputs | The local file system. |
| State | The witness state file (single process). |
| On failure | `load` throws and names the problem; nothing is cosigned. |
| Established by | Tests: "not JSON", "digest does not match", "a saved state loads back exactly and leaves no temporary file", "persists and restores witness memory; refuses corrupt state". |
| Status | **Production (pending CI).** Two witnesses must not share one file. |

### C-784 A mesh proof verifies only against a pinned human, witnessed heads and a domain allow-list

**Statement.** A cross-domain proof is accepted only when the chain narrows monotonically from the pinned human key, every hop is in its issuing domain log, each head is cosigned by at least the threshold of pinned witnesses (a witness cosigns only a verified append-only extension), every hop carries a revocation non-membership proof, the domain is on the allow-list, and the head and action are fresh. Anything else is a rejection with a reason; the verifier never throws.

| | |
|---|---|
| Enforced by | `verifyMeshProof`, `checkCosignedHead`, `checkHeadAdvance`, `MeshWitness`. |
| Trusted inputs | The human key, the witness set and threshold, the allowed domains. |
| State | Optional per-domain pins and witness memory. |
| On failure | A verdict with `ok: false` and a reason. |
| Established by | Tests: "rejects when the source domain head lacks enough trusted witness cosignatures", "R2-04: allowedDomains and rootDomain are required (no accept-all default)", "refuses equivocation (same size, different log) and rollback", "never throws under deterministic structural fuzzing, and every rejection has a reason". |
| Status | **Production (pending CI).** Witness independence is the operator's to arrange. |

### C-380 Published rate bounds are exact upper bounds, and an intent map commits every cell

**Statement.** A rate the intent layer publishes (a miss or divergence rate with a confidence level) is an exact one-sided Clopper-Pearson upper bound, computed in integer arithmetic and rounded outward, and it is 1 when there is no evidence. A malformed count or confidence level is refused, never clamped. An intent map is committed only when it lists every cell of every verb, with the right arity and in-range indices. Drift detection only ever raises an alarm that stays raised. None of this makes a classifier, an oracle or a label issuer right: their outputs are signed assertions by their issuers.

| | |
|---|---|
| Enforced by | `clopperPearsonUpper`, `commitIntentMap`, `DriftDetector`, `verifyOutcome`, `routeAction`. |
| Trusted inputs | The counts and confidence level the caller supplies; the principal's signing key for the map commitment. |
| State | The learner state and the drift statistic. |
| On failure | A thrown error naming the problem (bounds, commitment, outcome space), or a `deny` route for a verb outside the outcome space. |
| Established by | Tests: "k=%s n=%s is refused", "alpha=%s is refused", "no trials, or every trial failed, is the widest bound", "a dropped cell", "a first divergence moves the statistic", "once raised, the alarm stays raised", "verifyOutcome for a verb not in the outcome space throws". Lean: the Clopper-Pearson definition and coverage theorem the bound is stated against. |
| Status | **Production (pending CI).** |

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

## Threshold, proof-system and post-quantum primitives

These invariants cover cryptographic building blocks that are **hardened, awaiting independent audit** (or, for the proof systems, a multi-party ceremony). The engineering for the review is complete; the review is the remaining gate. None of the statements claims more than the tests and cross-implementation checks establish.

### C-160 Threshold signing uses one-shot nonces, a fixed-width scalar path and vector-exact arithmetic

**Statement.** FROST signing in `@atlasauth/pca` reproduces the RFC 9591 vectors byte for byte, produces an aggregate that is an ordinary Ed25519 signature under the group key, and never signs twice with the same nonce pair: a spent or byte-cloned nonce is refused, a networked signer marks a session spent before it computes its share, and a restart or a failing store can lose a session but never reuse a nonce. Every secret-dependent scalar operation runs on a fixed-width, branch-free path.

| | |
|---|---|
| Enforced by | The RFC 9591 signing functions, the fixed-width scalar module, the one-shot nonce handling in the signing function, and the durable nonce store contract used by the guardian signer service. |
| Trusted inputs | The curve library, the random source, the store the operator supplies for restart recovery. |
| State | Per-session secret nonces in the signer; the optional durable spent-marker store. |
| On failure | Signing throws or the signer service returns a typed refusal; no commitment or share is released when the store fails. |
| Established by | Tests: the RFC vectors, "a byte-clone of spent nonces is refused for a second message", "a crash after the spent marker and before the share leaves the session unusable, not reusable", "a store that fails on spend means no signature share is released, and the nonces were not consumed", the scalar-arithmetic tests against BigInt. Cross-check: an independent Rust implementation reproduces keys, shares and aggregates for 2-of-3 and 3-of-5. A timing harness with a leaking control. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. A JIT runtime cannot be proved constant-time and point multiplication is the library's. Signing and key generation exist only in TypeScript; the native verifiers check the aggregate as Ed25519. |

### C-161 The DKG accepts a message only from its authenticated sender, once, for this session, and aborts rather than finishing on a partial or divergent view

**Statement.** The DKG driver runs over a channel that supplies the sender's identity; a message whose content names a different participant, another session or a different addressee is refused, a second message from one sender is refused (a repeat as a duplicate, a different one as equivocation), an oversize or non-strict-JSON message is refused before use, a missing message at the timeout aborts the run, and a transcript echo that differs between recipients aborts it. A bad share is blamed on its sender only when the sender's own signature is on it; otherwise the run aborts. A run returns a key package only after every qualified participant has echoed the identical transcript.

| | |
|---|---|
| Enforced by | The channel interface and driver, the strict envelope and body decoders, the per-sender inbox, the signed-share blame round and the echo agreement round; the reference mutual-TLS channel (TLS 1.3 only, peer certificates pinned to participant ids). |
| Trusted inputs | The channel's authentication and confidentiality (for the reference channel, the pinned certificates and the TLS library). |
| State | One inbox per participant for the run; no state survives the run. |
| On failure | A typed channel error naming the code and the peer; no key package is returned. |
| Established by | Tests: honest 2-of-3 and 3-of-5 runs over the in-memory channel and over loopback mutual TLS whose keys then sign and verify; "claims another identifier than its authenticated sender is refused with `identity`", "stamped with another session is refused with `wrong-session`", "is `duplicate`; a different second message is `equivocation`", "a broadcast echo that differs per recipient aborts with `equivocation`", "a missing message at the timeout aborts the run with `timeout` and no key", "an oversize message is refused with `oversize` before it is parsed", "a peer with an unpinned certificate gets no link", "a plaintext client is dropped and never becomes a link", "a TLS 1.2 client is refused". |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. The DKG is a custom construction with no standard vectors. The reference channel leaves certificate issuance, rotation and revocation to the deployer. A cheater who sends garbage without a valid signature aborts the run instead of being convicted. |

### C-162 The networked-signing wire decoders and verifiers are total on hostile input

**Statement.** The decoders for commitments, verification shares, signing requests and DKG channel messages, and the allow-token and proof-of-possession verifiers, answer any input with a typed refusal or a boolean: never an untyped runtime error, a hang, or a large allocation, and a verifier never accepts a mutated message. The signing set a signer or coordinator will decode is capped.

| | |
|---|---|
| Enforced by | Strict base64url and point decoding, exact member sets, a maximum signing-set size, and the strict JSON profile on channel messages. |
| Trusted inputs | None: these functions face the network. |
| State | None. |
| On failure | A typed error from the decoder; `false` from a verifier; a refusal response from the signer service. |
| Established by | Tests: "decodeCommitments refuses a non-list and a list above the maximum signing set", "decodeCommitment refuses", "reject %j with a typed error" over every DKG body decoder, "decodeCommitment refuses" and "decodeVerificationShares refuses non-lists, oversize lists and malformed entries". Fuzzing: structure-aware targets for each decoder and verifier, seeded with real messages, run as a regression gate on every pull request and as a weekly time-bounded exploration. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. Fuzzing finds crashes, not logic flaws. |

### C-171 The post-quantum threshold step-up shares one classical-half implementation with the core hybrid module

**Statement.** `@atlasauth/pca-pq-threshold` accepts a step-up only when a FROST aggregate verifies under the verifier's pinned group key (with a signed group descriptor binding `t`) and a pqT-of-m quorum of distinct pinned ML-DSA-65 keys verifies over the same action. Both halves are decided by core code (the hybrid-FROST verifier and the ML-DSA quorum counter), so the two packages cannot disagree. The artifact is format version 2: an explicit version is checked strictly (a missing, older or unknown version is refused) and the co-signatures cover a domain-separated representative, so a pre-0.5 artifact cannot be accepted or relabelled.

| | |
|---|---|
| Enforced by | The hybrid verifier in the package, the core hybrid-FROST verifier it calls, the signed group descriptor check and the core ML-DSA quorum counter. |
| Trusted inputs | The pinned group key, the pinned setup-authority keys and the pinned ML-DSA key pool. |
| State | None. |
| On failure | A refusal verdict with the reason; signing throws on a short or empty quorum. |
| Established by | Tests: "a version 1 artifact (no pq version, bare-message co-signatures) is refused with the version 1 reason", "relabelling a version 1 artifact as version 2 fails", "under-threshold, duplicate and wrong-set quorums are refused with exact counts", "an aggregate produced by core signHybridFrostCosign is accepted as the classical half", "both verifiers agree on valid, flipped, truncated, non-canonical and wrong-key aggregates", "a non-string aggregate is refused without throwing", plus the package's fail-closed tests. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. The ML-DSA quorum is a multi-signature, not a threshold scheme; a compromised setup authority can certify a false `t`. |

### C-163 A Policy-VM proof authorizes only a statement whose gate holds, whose commitments and risk inputs are bound, and whose circuit version is pinned

**Statement.** A full Policy-VM proof (circuit version 1 or the risk-bound version 2, BN254; version 1 also on BLS12-381) verifies only if its released-allow signal is 1, its context signals are canonical and satisfy the verifier's pins, and the Groth16 equation holds under the supplied verifying key. A deny witness has no proof, because the circuit makes the allow signal unsatisfiable. With version 2 the proof also carries the SHA-256 of the five risk magnitudes (reversibility score, taint, confidence, age, risk floor) the prover supplies; a verifier that pins that digest refuses any proof made from other magnitudes, and refuses a version-1 proof outright. The two circuit versions are never confused: a backend for one refuses an envelope of the other before any pairing check, and each circuit's version (the SHA-256 over its whole source set and the pinned compiler) is committed and recomputed.

| | |
|---|---|
| Enforced by | The Policy-VM and risk-bound circuits; `verifyPolicyVmProof` and the two backends, which check circuit id, signal count, allow bit, canonical encodings, context pins, struct-hash pins and the risk pin before calling the Groth16 verifier; the circuit version record and its recomputation check. |
| Trusted inputs | The verifying key and how it was made (a single-party key lets its maker forge proofs; the backend reports `single-party` unless a pinned multi-party transcript names the key), the verifier's own clock and ledger values for the pinned context signals, and whoever supplies the attested risk magnitudes. |
| State | None in the library. |
| On failure | `false` for every refusal; proving throws for a witness that violates the gate. |
| Established by | Tests: perturbing every private input of every circuit on the compiled witness calculators refuses the witness or changes a public signal; the risk-pin, circuit-confusion and label tests; the committed circuit versions equal their recomputation; real proving and verification of the risk-bound circuit in CI. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit and ceremony. The circuits cover a quantised subset of the policy language and hash a fixed layout, not canonical JSON; the shipped keys are single-party development keys. |

### C-164 An independent verifier agrees with the reference verifier on valid and malformed Groth16 proofs

**Statement.** For the committed BN254 and BLS12-381 Policy-VM proofs and a fixed set of malformed variants, a verifier written against arkworks with no code shared with snarkjs returns the same verdict as the package verifier on every case: valid proofs verify; changed, non-canonical (value plus the field order, leading zero), missing and extra signals, off-curve points, points outside the prime-order subgroup, infinity, non-affine encodings, swapped or negated proof elements, wrong curve or protocol tags and altered keys are all rejected, none by a crash.

| | |
|---|---|
| Enforced by | The independent verifier's strict decoding (canonical decimals below the modulus, on-curve and prime-order-subgroup checks for every point of the key and the proof, affine-only encodings, signal count equal to the key's) and the package verifier's canonical-encoding gate. |
| Trusted inputs | Both implementations of the pairing equation and the curve libraries beneath them. |
| State | None. |
| On failure | The independent verifier prints a rejection with a reason and exits 1; usage errors exit 2. |
| Established by | Tests: every case compares both verdicts; the case count is pinned so the list cannot shrink silently. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. Agreement on these cases is not a proof of agreement everywhere. |

### C-165 Hybrid key encapsulation agrees with the NIST ML-KEM vectors, refuses non-reduced keys and rejects implicitly

**Statement.** The ML-KEM component under the X25519 hybrids and X-Wing reproduces the NIST ACVP FIPS 203 results for ML-KEM-768 and ML-KEM-1024 (key generation, encapsulation, decapsulation including implicit rejection, and both key checks). Encapsulation to an ML-KEM key with a non-reduced coefficient throws; a modified ciphertext decapsulates to a different 32-byte secret and never to the real one; a wrong-length ciphertext or key throws. `mlKemEncapsulationKeyCheck` and `mlKemDecapsulationKeyCheck` return false, and never throw, for any key the FIPS 203 checks refuse.

| | |
|---|---|
| Enforced by | The ML-KEM primitive (modulus check at encapsulation, re-encryption check at decapsulation), the domain-separated HKDF combiners of the two X25519 hybrids, the X-Wing SHA3-256 combiner, and the two key-check functions. |
| Trusted inputs | The recipient's own locally generated secret key (decapsulation does not re-run the key check; imported keys must go through the check functions). |
| State | None. |
| On failure | A typed error for wrong lengths and non-reduced encapsulation keys; a different but well-formed secret for a modified ciphertext (implicit rejection); `false` from the key checks. |
| Established by | Tests: the NIST ACVP vectors for key generation, encapsulation, decapsulation and both key checks, the hybrid known answers produced with OpenSSL, the abuse tests. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. The X25519 hybrid combiner is this project's own construction (X-Wing is the draft standard); neither is constant-time in a JavaScript runtime. |

### C-166 Only keys that proved possession of their secret count in a BLS aggregate

**Statement.** `@atlasauth/pca-aggsig` counts a public key in an aggregate only if it is a canonical, non-identity, prime-order point and carries a valid proof of possession made by the holder of its secret. A key derived from another key, a proof replayed for another key, a message signature offered as a proof, an identity or off-subgroup signature or key, an empty signer set, and a signer counted twice in a same-message aggregate are all refused.

| | |
|---|---|
| Enforced by | `registerKey` and `KeyRegistry` (KeyValidate plus a proof-of-possession check under its own domain tag), the opaque registered-key type, the canonical-encoding gate on signatures, and the public aggregate verifiers. |
| Trusted inputs | The application's decision about which keys may register; the channel that carried the proof. |
| State | The registry of admitted keys. |
| On failure | `registerKey` returns `{ ok: false, reason }`; the verifiers return false; aggregation of an empty or malformed set throws a `RangeError`. |
| Established by | Tests: the rogue-key, proof-replay, domain-separation, identity, off-subgroup, duplicate-signer and empty-set cases; the community reference vectors; the cross-implementation check. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. BLS12-381 is not post-quantum and the implementation is not constant-time. |

### C-167 A BBS proof verifies only for the exact issuer key, header, presentation header and disclosed messages and indexes

**Statement.** `@atlasauth/pca-bbs` accepts a signature or selective-disclosure proof only if every point and scalar is canonical, in range, non-identity and in the prime-order subgroup, and the proof's challenge binds the issuer key, the header, the presentation header, the message count, and each disclosed index and value. A change to any of them, an index list that is duplicated or out of range, or a degenerate blinding scalar is refused with a stable reason.

| | |
|---|---|
| Enforced by | The signature and proof parsers, `verifyDetailed` and `proofVerifyDetailed`, the challenge calculation, and the credential layer's attribute encoding. |
| Trusted inputs | The issuer's public key as pinned by the verifier; the verifier's own presentation header. |
| State | None. |
| On failure | A rejection reason (`malformed-signature`, `malformed-public-key`, `malformed-proof`, `disclosed-length-mismatch`, `invalid-disclosed-indexes`, `pairing-mismatch`, `challenge-mismatch`) or `false`; generation throws a typed error on hostile arguments. |
| Established by | Tests: the draft's official signature and proof fixtures, the cross-implementation check, the malformed-encoding, subgroup, index, binding, replay and malleability cases. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit and the final CFRG standard; the draft may still change. BLS12-381 is not post-quantum; scalar arithmetic is not constant-time. |

### C-168 An oblivious evaluation is accepted only when the server's proof verifies for the pinned key, and malformed group elements never decode

**Statement.** `@atlasauth/pca-oprf` decodes only canonical, non-identity group elements and in-range scalars; in verifiable and partially oblivious modes an evaluation without a valid proof for the pinned public key (and, for the partially oblivious mode, the stated public info) yields no output; the private revocation and rate-limit flows fail closed when the service omits the proof. Base mode is not verifiable, and this is stated.

| | |
|---|---|
| Enforced by | The element and scalar decoders, the discrete-log-equality proof check and its transcript, the mode-specific domain separation, and the flow wrappers. |
| Trusted inputs | The pinned server public key; in base mode, the server's honesty. |
| State | A per-window counter for rate limiting (the integrator supplies durability). |
| On failure | A typed error from decoders and `finalize`; the flows refuse the response. |
| Established by | Tests: all RFC 9497 vectors, the cross-implementation corpus, the malformed-element and scalar, proof-tamper, bit-flip, identity, zero-blind, cross-mode and misuse cases. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. Only the ristretto255-SHA512 suite is implemented; the multiply is not constant-time in a JavaScript runtime. |

### C-169 A ratchet leaf signs once for its holder, a verifier detects reuse, and a budget proof verifies only for a total at or under the ceiling

**Statement.** With `@atlasauth/pca-ratchet`, a leaf signature verifies offline only under the root commitment it was made for, at the stated leaf index, with its own nullifier. A state refuses to sign a spent, out-of-range or fractional leaf with a typed code. A holder that kept an old state can sign a spent leaf again; a verifier using a spent-leaf store accepts the first signature and reports the second as replay (same message) or equivocation (different message), and a store failure denies. A budget proof verifies only when the committed total is at or under the ceiling, and every malformed input is refused or verifies false.

| | |
|---|---|
| Enforced by | The puncturable key tree (a spent leaf's seed is dropped from the state), strict Ed25519 verification, Merkle inclusion against the root, the nullifier check, the spent-leaf store claim, and the Pedersen range proof with per-bit proofs. |
| Trusted inputs | The holder discarding old state copies (not enforceable in JavaScript), a shared durable spent-leaf store at the verifier, the discrete-logarithm hardness of ristretto255. |
| State | The ratchet state at the holder; the spent-leaf store at the verifier. |
| On failure | `RatchetError` codes `invalid_depth`, `invalid_seed`, `leaf_out_of_range`, `leaf_punctured`; `verifyLeafSignatureOnce` results `invalid`, `replay`, `equivocation`, `store-error`; `AccumulatorError` codes `invalid_value`, `length_mismatch`; verification functions return false and never throw. |
| Established by | Tests: the fail-closed table tests (construction codes, out-of-order spending, rolled-back state, foreign nullifier, throwing store, budget refusals), the forward-secrecy audit suite, the reuse-detection tests. |
| Guarantees | None claimed beyond the statement. No post-compromise security. |
| Status | Hardened, awaiting audit. The composition is this project's own and needs independent cryptographic review. |

### C-170 FN-DSA artifacts verify only with a correctly sized, canonically encoded key and signature, and a missing or faulty backend never yields acceptance

**Statement.** `@atlasauth/pca-fndsa` accepts a leaf signature only for a known suite, with a public key and signature of exactly the suite's padded length in canonical base64url, over a message that binds the suite id and public key; a hybrid suite needs both halves. Malformed input is rejected before the backend is called. With no backend registered, or a backend that cannot sign or returns a wrong-length signature, signing and verification throw rather than succeed. `@atlasauth/pca-fndsa-wasm` refuses wrong-size buffers and over-long messages with a typed error naming the field, returns false for undecodable keys and signatures, and fails to load at all if its module is missing or corrupt.

| | |
|---|---|
| Enforced by | The suite registry and length guards, strict base64url decoding, the leaf message binding, the wasm binding's size checks, and the vetted `fn-dsa` Rust crate compiled to WebAssembly. |
| Trusted inputs | The `fn-dsa` crate and the draft FIPS 206 encodings. |
| State | The registered backend. |
| On failure | `verifyPcaFndsa` and `fndsaVerify` return false for malformed input; signing throws typed errors; `FnDsaError` from the binding; importing the binding throws if the module is unavailable. |
| Established by | Tests: the fail-closed table tests in both packages, the real-backend round trips, the C implementation cross-check, the Falcon round-3 key vectors. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. FIPS 206 is a draft and its encodings may change; the wasm binding awaits independent review; constant-time behaviour of signing on wasm is not measured. |

### C-172 Attestation evidence is accepted only when signed, fresh, on the live channel and appraised, and a failed hardware check never yields an affirming tier

**Statement.** `@atlasauth/pca-attest-eat` refuses to emit evidence without an issuer, a nonce and a channel binding. It accepts evidence only if the signature verifies under the expected key and algorithm, the issuer and type are accepted, the nonce equals the verifier's challenge, the issue time is inside the window, the channel binding matches the live channel, and the appraisal policy is met. Any failed gate returns not ok with no tier, and a failed AMD report or certificate chain returns the contraindicated tier.

| | |
|---|---|
| Enforced by | Strict compact-JWS handling with a single accepted spelling, the freshness and channel gates, the appraisal policy, and the hardened AMD verifier with pinned per-family roots. |
| Trusted inputs | The attester's verification key, the verifier's own nonce and clock, the pinned AMD roots, the policy. |
| State | None in the library; the verifier issues and remembers its own nonces. |
| On failure | `verifyEAT` throws "EAT invalid: ..."; gate results carry a named reason; the verdict has `ok: false` and the failing gate last in its reasons. |
| Established by | Tests: the fail-closed table tests (build, signature, freshness, channel, end-to-end, hardware), the forged-chain tests, the standards vectors, the real captured report test. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit. Awaits independent review and a real-hardware evidence canary. The AMD root is classical. |

### C-174 The wasm cores of the multi-party packages refuse malformed input with typed errors and never load with a missing module

**Statement.** `@atlasauth/pca-mpc-wasm` and `@atlasauth/pca-mpc-lwe-ot-wasm` refuse every operand of the wrong size, type or curve membership with a typed error naming the operation and operand (predicates return false), leave no state behind after a refusal, and throw on import if their module is missing or corrupt. The packages `pca-abe`, `pca-fhe`, `pca-vdf` and `pca-mpc` are in the mutation plan and the audit evidence.

| | |
|---|---|
| Enforced by | The binding's size and type checks, the curve core's validation, and the vetted Rust cores (`curve25519-dalek`, `pqc_kyber`). |
| Trusted inputs | The Rust cores; the constant-time claim is inherited from them and not measured here. |
| State | None. |
| On failure | `PointValidationError` and `LatticeOtError` with the messages in each package's fail-closed table. |
| Established by | Tests: the fail-closed table tests in both packages, the group-law and fuzz suites, the FIPS 203 vectors. |
| Guarantees | None claimed beyond the statement. |
| Status | Hardened, awaiting audit of the cores they wrap. |

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
| Status | **Production (pending CI)** (the natural-language path; the typed successor is C-60). |

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

## Credential, commerce and agent client invariants

### C-120 The agent client reports an allow only on a verified receipt

**Statement.** `act` returns `allowed` only when the status is 2xx, `allow` and `verdict.allow` are both the boolean `true`, and the receipt's inclusion proof verifies (and its disclosed salt reproduces its commit for this action).

| | |
|---|---|
| Enforced by | `act` and `verifyReceipt` in `@atlasauth/pca-agent`. |
| Trusted inputs | The resource server's ledger root, checked by the caller against a pinned tree head. |
| State | The per-client action counter, which only grows. |
| On failure | `denied` or `error` with a typed code; never `allowed`. |
| Established by | Tests: "200 with a receipt whose inclusion proof does not verify: error bad_response, not allowed", "allow:true at top level but verdict.allow false: denied", "a truthy non-boolean allow (\"true\", 1): denied". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-121 The agent client commits only a plan the server echoed

**Statement.** A plan is kept only when the server echoes exactly the locally computed plan root; a missing or different root discards it.

| | |
|---|---|
| Enforced by | `commitPlan` in `@atlasauth/pca-agent`. |
| Trusted inputs | The local Merkle computation. |
| State | The committed plan, copied at commit time. |
| On failure | `commitPlan` throws `bad_response`; later actions return `no_plan`. |
| Established by | Tests: "missing plan_root in the commit response: commitPlan throws bad_response and no plan is kept", "mutating the node array after commit does not change the plan the agent acts on". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-122 A step-up is approved only by a 2xx answer that says so

**Statement.** A non-2xx answer is never an approval, a 4xx (not 429) ends polling as denied, and a network failure throws.

| | |
|---|---|
| Enforced by | `awaitStepUp` in `@atlasauth/pca-agent`. |
| Trusted inputs | The resource server. |
| State | None. |
| On failure | `denied`, `timeout` or a thrown `network` error. |
| Established by | Tests: "awaitStepUp: 404 stops polling and is denied with the status", "awaitStepUp: denied and expired are passed through; a network failure throws network". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-123 Autonomous payment spend never exceeds the signed cumulative cap

**Statement.** Over any sequence of charges, the sum of auto-approved amounts is at most the cumulative cap signed into the grant, and only an integer-minor-unit charge to a plain listed merchant inside the ceiling can be auto-approved.

| | |
|---|---|
| Enforced by | `authorizeCharge`, `authorizeChargeAtomic` and `applyHumanCosignAtomic` in `@atlasauth/pca-payments`. |
| Trusted inputs | The verified grant; the durable budget store's compare-and-set. |
| State | The cumulative budget, in a durable store for the atomic path. |
| On failure | `deny` or `step_up`, or a typed store error; the budget is not debited. |
| Established by | Tests: "concurrent atomic charges commit exactly what the store debited, never more than the cap", "mandate terms must be integer minor units by default", "a merchant id containing a star on the charge side matches no allowlist entry", "a stored balance above bMax is clamped to the signed bMax". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-124 A delegated payment token settles once, for the server's own terms

**Statement.** Settlement is strict by default: it needs a single-use store and an expected currency, the x402 verifier never reads the client's merchant or amount, and a grant without the proof to re-verify is refused.

| | |
|---|---|
| Enforced by | `verifyDelegatedPaymentToken` and `acpX402Verifier` in `@atlasauth/pca-acp`. |
| Trusted inputs | The single-use store's atomic claim; the verification key. |
| State | The redeemed-token set. |
| On failure | `{ ok: false, reason }`. |
| Established by | Tests: "no single-use store: refused with the exact reason", "with both, the token redeems exactly once", "a grant without the pcActn to re-verify is refused, not silently skipped". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-125 Emitted payment wire objects are complete or refused

**Statement.** An x402 challenge always carries the payee, asset, timeout and error the v1 requirement needs, and the ACP allowance is emitted only when every field is expressible in the ACP shape.

| | |
|---|---|
| Enforced by | `x402Challenge` and `toAcpAllowance` in `@atlasauth/pca-acp`. |
| Trusted inputs | None. |
| State | None. |
| On failure | A thrown `TypeError` or `AcpAuthorityError`. |
| Established by | Tests: "carries maxTimeoutSeconds and a body error, and refuses a missing payee or asset", "maps to the ACP delegate_payment allowance exactly". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-126 Every property check has a negative control

**Statement.** Each registered invariant property fails against a core broken on purpose, and a registry entry without a control fails the suite.

| | |
|---|---|
| Enforced by | The teeth suite in `@atlasauth/pca-invariants`. |
| Trusted inputs | The real core. |
| State | None. |
| On failure | The teeth suite fails. |
| Established by | Tests: "every registered invariant has a negative control above (a new invariant without one fails here)". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-127 A notarized fact is admitted only when every binding holds

**Statement.** `evaluateAttestedFactCaveat` returns `ok: true` only when the attestation verifies under the caveat's notary key, the key is in the keyring window and not revoked, the attestation is fresh, the URL matches, the disclosed field is included under the attested root with the committed leaf count, its path and value equal the caveat, and (if asked) the fact is bound to the PCActn both ways.

| | |
|---|---|
| Enforced by | `evaluateAttestedFactCaveat`, `verifyDisclosedField`, `verifyNotaryAttestation` in `@atlasauth/pca-notary`. |
| Trusted inputs | The notary public key the relying party chose; the keyring. |
| State | None. |
| On failure | `{ ok: false, reason }`; no trust label. |
| Established by | Tests: "a LIE about the disclosed value fails inclusion", "a proof whose size differs from the committed leaf count is refused even when its path has the right length", "an unlisted key is refused with the exact reason", "a revoked key is refused for any observation time, including backdated ones", "an admitted fact is labelled notary-trusted; a refusal carries no trust label". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-128 An SD-JWT bridge result is allow only when the JWT layer and PCA Core both pass

**Statement.** `verifyPcaSdJwt` accepts only a correctly signed, unexpired token whose disclosures match their digests, with the key binding, audience, nonce and age the caller required; `verifyRecovered` re-verifies the recovered claims with PCA Core against the caller's stored grant and audience, and denies when any required claim was withheld.

| | |
|---|---|
| Enforced by | `verifyPcaSdJwt`, `verifyRecovered` in `@atlasauth/pca-sdjwt`. |
| Trusted inputs | The issuer key, the stored grant and the audience the caller supplies. |
| State | None (the caller owns replay state). |
| On failure | `{ ok: false, reason }` or `{ allow: false, reason }`. |
| Established by | Tests: "requireKeyBinding without a KB-JWT: the exact reason", "a required disclosure that was withheld: the exact reason", "key binding: wrong nonce, wrong key, stale iat", "a withheld %s is denied with the exact reason". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-129 A passport credential is accepted only under its own pinned vocabulary

**Statement.** `verifyPassportVC` accepts only an EdDSA-signed `vc+sd-jwt` whose `@context` is exactly the VC 2.0 context followed by the bundled agent-passport context, whose type, subject binding, issuer (when pinned), disclosures and expiry all check; every emitted term is defined by the bundled, protected context.

| | |
|---|---|
| Enforced by | `verifyPassportVC`, `passportToVC` and `AGENT_PASSPORT_CONTEXT_DOC` in `@atlasauth/pca-vc`. |
| Trusted inputs | The issuer key and (optionally) the expected issuer DID the caller supplies. |
| State | None. |
| On failure | A thrown `Error` naming the failed check. |
| Established by | Tests: "vc claim checks", "disclosures: digest membership, duplicates, shape, names and values", "a JWT sub that differs from credentialSubject.id is refused", "expectedIssuerDid: matching passes, any other issuer is refused", "accepts the emitted pair; the issuer emits exactly it", "defines every term the issuer emits in credentialSubject". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-130 An HTTP request signature is valid only for what was covered and when

**Statement.** `verifyRequestSignature` returns true only for an Ed25519 signature over the covered components, with required components covered, an allowed clock window, and a well-formed signature-agent; a malformed input returns false and never throws.

| | |
|---|---|
| Enforced by | `verifyRequestSignature` in `@atlasauth/pca-vc`. |
| Trusted inputs | The verification key the caller supplies. |
| State | None (replay of an in-window signature is the caller's). |
| On failure | `false`. |
| Established by | Tests: "verifies an honest signature and rejects any tamper", "requiredComponents", "freshness window: maxAgeSec and 5 s of allowed clock lead, inclusive at the edges", "a malformed URL or header set never throws". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-131 A key directory is trusted only through a valid signature when one is required

**Statement.** With `requireSignature`, a fetched directory yields only the keys that carry a valid Ed25519 signature over `"@authority";req` for the requested host, with the directory tag, a bounded lifetime and the key inside its validity window; an unsigned, expired, mis-hosted or malformed response throws.

| | |
|---|---|
| Enforced by | `verifyDirectoryResponse` and `fetchKeyDirectory` in `@atlasauth/pca-webbotauth`. |
| Trusted inputs | The host the caller requested; the clock. |
| State | None. |
| On failure | `{ valid: false, reason }` or a thrown error; no key is returned. |
| Established by | Tests: "a different authority (replay at another host) is refused", "only keys with a valid signature are returned (an unsigned key is ignored)", "a signature that covers anything other than @authority;req is refused", "throws when the response is unsigned, or signed for another host". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-132 The transparency log is durable, append-only and agrees with RFC 9162

**Statement.** `DurableTransparencyService` keeps all state in a caller-supplied store: an append is a compare-and-set that stores the entry and its subtree hashes together, the root, inclusion proofs and consistency proofs equal the RFC 9162 reference at every size, a restart continues the same log, and a missing or malformed stored hash fails as `store_corrupt` instead of yielding a wrong root. There is no in-memory default and the in-memory log is only on the testing entry.

| | |
|---|---|
| Enforced by | `DurableTransparencyService`, `FileScittLogStore` and `checkScittLogStore` in `@atlasauth/pca-scitt`. |
| Trusted inputs | The store's atomic compare-and-set append. |
| State | The store. |
| On failure | A thrown `ScittLogError` with a code. |
| Established by | Tests: "roots, inclusion receipts and consistency proofs for 1..70 entries", "a new service over the same store continues the same log (restart)", "a missing subtree hash is store_corrupt, never a wrong root", "a store is required, with the right shape", "appends and proofs do not read the whole log: store reads stay logarithmic at 1024 entries", "a torn final record (crash mid-append) is discarded and the log stays consistent", "corruption before the end of the file is store_corrupt, never silently dropped", "the in-memory reference log and store are only on /testing, never on the main entry". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-133 A receipt verifies only against an anchor and the exact statement bytes

**Statement.** `verifyReceipt` returns true only when an anchor (pinned root and/or the service key) is supplied, the inclusion proof binds the exact statement bytes to the root, the service signature and (if asked) the statement signature verify; it never throws.

| | |
|---|---|
| Enforced by | `verifyReceipt` in `@atlasauth/pca-scitt`. |
| Trusted inputs | The pinned root or the transparency service public key. |
| State | None. |
| On failure | `false`. |
| Established by | Tests: "requires at least one anchor (no treeRoot and no verificationKey => false)", "a tampered statement fails (inclusion binding + signature both break)", "a forged receipt fails (bad TS signature, and a tampered inclusion proof)", "a wrong root fails". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-134 An Agent Card signature covers RFC 8785 bytes and, on request, a valid A2A 1.0 card

**Statement.** `issueSignedAgentCard` signs the RFC 8785 (JCS) canonical bytes of the card without its `signatures`, so any A2A 1.0 verifier recomputes the same bytes; a card with no JSON form is refused, never signed; with `schema: 'a2a-1.0'` a card that does not match the A2A 1.0 `AgentCard` message is not signed and does not verify.

| | |
|---|---|
| Enforced by | `issueSignedAgentCard`, `verifyAgentCard`, `jcsBytes`, `validateAgentCard1` in `@atlasauth/pca-a2a` and `@atlasauth/pca-agentcard`. |
| Trusted inputs | The verification key or JWKS the caller supplies. |
| State | None. |
| On failure | `{ ok: false, reason }` or a thrown error before signing. |
| Established by | Tests: "section 3.2.2: the published example", "section 3.2.3: members sort by UTF-16 code units (the emoji sorts before U+FB33)", "agrees with an independent reference on a generated corpus", "issue refuses an invalid card under schema a2a-1.0 and signs a valid one; verify enforces it too", "a card whose keys differ in UTF-16 vs UTF-8 order signs over the JCS bytes (a JCS verifier would accept it)", "reports each wrong type with its exact path". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-135 An A2A payment mandate is bound field by field to the proof that authorized it

**Statement.** `verifyA2APaymentMandate` accepts a mandate only when its `x_pca` backreference, amount, currency, merchant and payment method equal what the PCActn committed, the params plaintext opens the committed digest, the amounts are integer minor units, and the full PCA verifier admits the action under an authority the caller trusts.

| | |
|---|---|
| Enforced by | `verifyA2APaymentMandate`, `verifyA2ATask`, `pcaA2AMiddleware` in `@atlasauth/pca-a2a`. |
| Trusted inputs | The stored grant or the pinned root issuer; the caller's plan, budget and revocation hooks. |
| State | None (the caller owns replay state). |
| On failure | `{ ok: false, reason }`; a config with no authority throws `A2AAuthorityError`. |
| Established by | Tests: "another amount or currency around the same valid PCActn is refused", "the params plaintext is required, and must open the committed params_digest (even when requireChecks omits it)", "every x_pca field must be the PCActn", "human_present: a boolean, and true only with a verified t=3 principal co-signature", "a self-minted chain naming the victim as issuer is refused (signed by the attacker key)", "verifyA2ATask / verifyA2APaymentMandate / pcaA2AMiddleware refuse a config with neither grant nor expectedRootIssuer". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-136 A signed agent card or AgentFacts document verifies only under the right key, subject and window

**Statement.** `verifyAgentCard` and `verifyAgentFacts` accept only a document whose every signature verifies under the supplied key or JWKS, whose attestation is about this subject and unexpired; unsigned, mutated or wrong-key documents are refused.

| | |
|---|---|
| Enforced by | `verifyAgentCard`, `verifyAgentFacts` in `@atlasauth/pca-agentcard`. |
| Trusted inputs | The key or JWKS the caller supplies. |
| State | None. |
| On failure | `{ ok: false, reason }`. |
| Established by | Tests: "rejects a forged card (body mutated after signing)", "rejects a mutated passport pointer (the whole card body is signed)", "rejects an unsigned card (fail closed)", "fails closed on an attestation about a DIFFERENT subject", "fails closed on an EXPIRED attestation". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-137 An AP2 purchase is accepted only when the PCA grant, terms and action proof bind exactly it

**Statement.** `verifyPcaBinding` accepts a verified AP2 payment chain only when the open mandate's grant is signed by the expected principal, its terms (integer minor units of the mandate currency) match the grant envelope and risk policy and are not narrower than the AP2 constraints, the PCActn is valid for this audience and commits to this transaction, payee, amount, instrument, open mandate and agent key, does not understate the risk, carries a verified threshold when a human co-sign is needed, and the live PCA decision allows it.

| | |
|---|---|
| Enforced by | `verifyPcaBinding`, `buildPcaPaymentBinding`, `paymentConstraintsFromTerms` in `@atlasauth/pca-ap2`. |
| Trusted inputs | The expected principal key, the verifier's own mandate state and charge history, the threshold hook. |
| State | The live mandate budget, supplied by the verifier. |
| On failure | `{ ok: false, reason }`; a missing mandate or history throws `PcaBindingError`. |
| Established by | Tests: "refuses a grant not signed by the expected principal, and a wrong PCA audience", "refuses x_pca terms that do not match the grant envelope or risk policy", "refuses an open mandate whose AP2 constraints are wider than the PCA terms", "refuses a PCActn that does not commit to this AP2 charge", "refuses when the AP2 amount, payee or instrument no longer matches what the PCActn committed", "an agent that understates its own risk is refused", "a legacy fractional major-unit mandate is refused with the exact reason", "JPY (0): budget is cap / 100, so the SDK x100 read is exactly the cap (a major-unit reader reads less); amount_range stays in yen", "27999 minor (USD 279.99) with a human co-sign verifies". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-138 x402 v1 and v2 are negotiated, and a v2 payment settles only for what the server offered

**Statement.** The server speaks the highest x402 version both sides support; a v2 challenge is emitted only if it is valid under the v2 specification (CAIP-2 network, atomic string amount, payee, asset, timeout, resource info limits); a v2 payload settles only if its echoed `accepted` is exactly one of the offered requirements, and the merchant is never read from the client; the HTTP transport headers (`PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`) are accepted and emitted only when valid, with a missing signature header answered 402 and a malformed one 400.

| | |
|---|---|
| Enforced by | `x402Negotiate`, `x402ChallengeV2`, `normalizeX402Payload`, `acpX402Verifier` in `@atlasauth/pca-acp`. |
| Trusted inputs | The requirements the server offered. |
| State | The single-use store. |
| On failure | `settled: false` with status 402 and the reason; a challenge that would be invalid throws. |
| Established by | Tests: "the specification PaymentRequired example is valid, and its header round-trips", "picks the highest common version; a client that says nothing gets v1; no overlap is undefined", "a v2 payload that accepted something the server did not offer is refused", "a v2 payload settles under a strict verifier; the client merchant is never read", "v1 still settles exactly as before", "a missing header is 402; an undecodable or invalid one is 400 with the reason; it never throws", "the specification SettlementResponse example round-trips", "a settled outcome is 200 with success true; a failure is 402 with success false, the reason and an empty transaction". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

### C-139 A Stripe Shared Payment Token is no wider than the PCA authority behind it

**Statement.** A Shared Payment Granted Token is used or accepted only if it is well formed per the Stripe API reference, not deactivated or expired, in the right mode and currency, within its remaining `max_amount`, and (when tied to a delegated payment token) no wider in amount, currency or time; the limits requested for a mandate never exceed its auto-approve threshold or remaining autonomous budget.

| | |
|---|---|
| Enforced by | `stripeSptUsable`, `stripeSptWithinClaims`, `stripeUsageLimitsFor` in `@atlasauth/pca-acp`; `sharedPaymentTokenLimits` in `@atlasauth/pca-payments`. |
| Trusted inputs | Stripe as the authority on whether it accepts the token. |
| State | None (the caller records captures). |
| On failure | `{ ok: false, reason }`; limits that would need a co-sign throw. |
| Established by | Tests: "the published example object is well formed", "usability: exact boundary of the amount, expiry, currency, mode and deactivation", "a token may be no wider than the delegated payment token it serves", "is the auto-approve threshold, in lowercase minor units, expiring with the period", "refuses when no autonomous capacity is left, after the period ended, and for a bad clock". |
| Status | **Production, pending CI.** Every item of the production definition is met except the green CI run and the clean mutation gate. |

## Operational plane invariants

### C-260 A decision never rests on state older than the consistency token it was shown

**Statement.** A `fresh_at` token carried by a request makes the verifier refuse to decide against revocation, ledger, budget or policy state older than the token: the answer is escalate (`stale_state`, refresh and retry), never allow. A token for another scope, from the future, too old, forged, or at the same policy revision with a different digest is a deny.

| Enforced by | `checkFreshAt` and `gateDecision` in `@atlasauth/pca-grants`. |
| Trusted inputs | The token signer key; the verifier's own state counters and clock. |
| State | The verifier's four counters (revocation epoch, ledger size, budget version, policy revision). |
| On failure | Escalate with the lagging field named, or deny. |
| Established by | Tests: "NEW ENEMY: a verifier at an older revocation epoch escalates stale_state, naming the field", "wrong scope, forgery, future and over-age tokens are denied", "gateDecision only tightens". Shared vectors: `k3-vectors.json` `fresh_at`. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-261 Consistency tokens are signed, scoped and monotone

**Statement.** A token verifies only under the pinned signer over exactly its content; folding tokens is a field-wise maximum so an older token can never lower a fresher one; the issuer's counters only move forward.

| Enforced by | `signFreshAt`, `verifyFreshAt`, `mergeFreshAt`, `FreshAtIssuer`. |
| Trusted inputs | The signer key. |
| State | The issuer's counters. |
| On failure | The token is refused (`bad_token`). |
| Established by | Tests: "a token verifies for its signer and for nobody else", "mergeFreshAt is the field-wise max and never lowers", "the issuer advances monotonically and its own tokens check ok at once; an old token still passes, a revoke token makes a lagging peer stale". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-262 Listing never exceeds the capability; a relationship only narrows

**Statement.** `listAuthorized` returns an object only if the grant's capability permits it AND (when configured) the relation source agrees. Pages are bound by a signed cursor to subject, type, filter, policy and limit; a changed parameter, a forged cursor or an out-of-range limit is refused, and no object is skipped or repeated across pages.

| Enforced by | `listAuthorized` in `@atlasauth/pca-grants`. |
| Trusted inputs | The capability predicate and the relation source as supplied by the host. |
| State | None beyond the signed cursor. |
| On failure | The call throws `bad_cursor`, `bad_limit` or `read_budget_exhausted`; nothing is returned. |
| Established by | Tests: "returns exactly the capability-permitted objects across pages, each once and in order", "the relationship can only narrow the capability", "a cursor cannot be reused with a different subject, filter, policy or limit, or forged". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-263 A list is receipted and enumeration is budgeted

**Statement.** Every page carries a signed receipt binding the policy digest, the consistency token, the filter and the exact returned objects; every page is charged to a read accumulator for what was scanned, not only what was returned, so scraping through a filter drains the budget.

| Enforced by | `listAuthorized`, `verifyListReceipt`, `ReadAccumulator`. |
| Trusted inputs | The receipt signer; the accumulator's durability. |
| State | The accumulator. |
| On failure | `read_budget_exhausted`. |
| Established by | Tests: "the receipt binds policy, freshness, filter and the exact objects", "enumeration by scraping is stopped by the read accumulator, counting scanned objects not returned ones". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-264 A policy bundle needs k pinned signers, only moves forward and names the verifier it needs

**Statement.** A bundle is accepted only with at least k valid signatures from distinct pinned keys over its exact content; a lower revision (rollback), a same-revision different content, a revision that does not chain by `prev`, and a verifier older than `min_verifier_version` are refused.

| Enforced by | `verifyBundle`. |
| Trusted inputs | The pinned signer set and threshold; the verifier's accepted revision. |
| State | The last accepted revision and digest. |
| On failure | The bundle is refused with a code. |
| Established by | Tests: "accepts k-of-n distinct pinned signatures and reports who signed", "one signer twice, an unpinned signer, or a signature over other content do not count", "rollback, broken chain, an old verifier and malformed bundles are refused". Shared vectors: `k3-vectors.json` `bundle`. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-265 Decision records are chained, committed and masked by data class

**Statement.** Each record cites the bundle revision and digest, is hash-chained to its predecessor and committed to a Merkle log whose head is signed; a receiver detects gaps, replays, reordering, truncation against the head and any edit; masked data classes never appear in the log in clear.

| Enforced by | `DecisionLog`, `verifyBatch`, `verifyRecordInclusion`, `maskRecord`. |
| Trusted inputs | The log signer key. |
| State | The log. |
| On failure | The batch or proof is refused. |
| Established by | Tests: "records are hash-chained and inclusion-provable against a signed head, offline", "the stream is gap-free, replay-proof and tamper-evident", "masks by data class, not by path". Shared vectors: `k3-vectors.json` `decision_log`. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-266 Nothing widens in place

**Statement.** A grant amendment that is not wider is a signed attenuation (holder or principal) that revises the grant in place and cannot be replayed on the next revision; one that is wider, or incomparable, needs the principal's signature over the current revision AND a satisfied step-up, and creates a new grant id that supersedes the old one.

| Enforced by | `GrantService.amend` and the comparator. |
| Trusted inputs | The principal and holder keys; the step-up verifier (absent means widening is refused). |
| State | The grant store. |
| On failure | `not_narrower`, `signature_required`, `bad_signature` or `step_up_required`. |
| Established by | Tests: "narrow by the HOLDER revises in place; the same signature cannot be replayed on the next revision", "widening needs the PRINCIPAL signature AND a step-up, and makes a new grant id with supersedes (nothing widens in place)", "orders verbs, resources, ceilings and expiry; incomparable and unbounded-to-bounded are classified". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-267 Revocation is authorised and bounded by its scope

**Statement.** A grant is revoked only by the principal's signature over (grant id, scope) or by a host-authenticated admin; a signature for one scope does not authorise another; a principal-scoped HTTP caller sees and touches only its own grants. In the hosted API a principal signature covers one grant reference and `scope=agent` needs the operator key.

| Enforced by | `GrantService.revoke`, `grantResourceHandler`, and the hosted `DELETE /v1/pca/grants/:grantRef`. |
| Trusted inputs | The principal key; the host's admin authentication. |
| State | The grant store and the revocation registry. |
| On failure | `bad_signature`, `forbidden` or 404. |
| Established by | Tests: "revoke: signed by the principal or admin; agent and subtree scopes reach the right grants; the host hook fires", "a principal only sees its own grants; an admin sees all; routes map to statuses". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-268 Incremental authorization can only be lowered by the approver

**Statement.** A need becomes authority only by a principal signature over the approved needs and a satisfied step-up; the approver may lower an amount of an adjustable need but never raise it, change its target, or lower a non-adjustable one.

| Enforced by | `GrantService.approveNeeds`. |
| Trusted inputs | The principal key; the step-up verifier. |
| State | The need request. |
| On failure | `need_not_lowered_only`, `need_not_adjustable`, `bad_signature`, `step_up_required`. |
| Established by | Tests: "the agent files typed needs; the principal approves a LOWERED amount of an adjustable need and gets a new grant", "an approval cannot raise an amount, change the target, lower a non-adjustable need, or come from anyone but the principal". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-326 A caller sees and changes only its own grants, need requests and leases

**Statement.** The hosted grant and lease routes act only for an authenticated caller. A principal-scoped caller reads, amends, revokes and files needs only on its own grants, and approves or denies only the need requests of its own grants; a grant or need request that belongs to someone else answers exactly as one that does not exist (404, same message), so existence is not disclosed. A list is forced to the caller's own principal whatever filter it sends. Leases are issued and revoked by an admin only, and read or checked only by the holder or an admin. An authenticator that throws is a 500 with no detail.

| | |
|---|---|
| Enforced by | `grantResourceHandler`, `GrantService.needGrantId`, `leaseResourceHandler` (`@atlasauth/pca-grants`). |
| Trusted inputs | The host's `authenticate` result (who the caller is). |
| State | The grant, need and lease stores. |
| On failure | 401 (no caller, or a caller with neither principal nor admin), 403 (a non-admin lease write), 404 (not yours or absent), 500 `server_error`. |
| Established by | Tests: "a principal-scoped caller cannot learn that another principal grant exists", "needs: file, approve (principal only, with a signature and an array), deny; another principal cannot touch the need request", "no caller, a caller without principal or admin, and a throwing authenticator are 401 / 401 / 500". |
| Guarantees | G-1. |
| Status | **Production, pending CI.** The mutation and CI gates must pass before the flag is removed. |

### C-327 Revocation, kill and break-glass state has no process-local default

**Statement.** `LeaseRegistry`, `BreakGlassRegistry` and `BlueprintRegistry` hold revocations, group kills, use budgets and freezes. A process-local default would forget them on restart and let a killed blueprint, a revoked lease or a frozen holder act again, so each constructor requires a store and throws a `TypeError` without one. A store opened with another shard count is refused, and a store that fails makes accept, use and check deny.

| | |
|---|---|
| Enforced by | The `LeaseRegistry`, `BreakGlassRegistry` and `BlueprintRegistry` constructors and `ready()` shard-count pin. |
| Trusted inputs | The integrator-supplied durable store (the lease store conformance kit checks one). |
| State | The store. |
| On failure | `TypeError` at construction; `store_unreachable` or a deny at use. |
| Established by | Tests: "a registry without a store is refused at construction", "a throwing store fails closed", "the in-memory store passes" (conformance kit), "a store opened with another shard count is refused". |
| Guarantees | G-1. |
| Status | **Production, pending CI.** The mutation and CI gates must pass before the flag is removed. |

### C-328 An action is accepted as coming from an attested harness only when its measurement is allowlisted

**Statement.** `createHarnessAttestationVerifier` accepts a PCActn only when its signed `attestation.measurement` is in the operator's allowlist. An empty, missing or junk allowlist accepts nothing; an absent measurement fails unless the operator sets `required: false`, in which case it is reported as not enforced; a present measurement that is not allowlisted always fails; a pinned `model_id` that differs fails before the allowlist is consulted. The allowlist is copied at construction. The measurement is self-asserted by the signer and rests on the leaf signature verifying.

| | |
|---|---|
| Enforced by | `createHarnessAttestationVerifier` (`@atlasauth/pca-harness`). |
| Trusted inputs | The operator's allowlist; the surrounding verdict requiring `leaf_signature`. |
| State | None (the allowlist is copied). |
| On failure | `{ enforced: true, ok: false, reason }`, or `{ enforced: false }` for an absent measurement with `required: false`. |
| Established by | Tests: "createHarnessAttestationVerifier: exact results" (empty allowlist, absent measurement, unallowlisted measurement, model id pinning, allowlist copy). |
| Guarantees | G-1. |
| Status | **Production, pending CI.** Hardware rooting of the harness measurement is a deployment choice (attest the process with the hardware verifiers), not a gap in this check. |

### C-269 A pushed-revocation claim needs a verified stream

**Statement.** A receiver asserts that no pushed revocation was missed within a window only when the stream is enabled and a verification round trip, answered with a state it issued (single use, expiring), completed inside that window; paused, disabled, unverified and failing streams never make the claim.

| Enforced by | `StreamHealth.revocationFreshWithin`. |
| Trusted inputs | The transmitter's signing key; the receiver's clock. |
| State | The receiver's pending verification states. |
| On failure | The verifier falls back to the signed revocation epoch bound. |
| Established by | Tests: "unverified -> healthy on a matching single-use state -> degraded after the window", "refuses unknown, expired and non-string states; expiry counts toward failing", "honours min_verification_interval, the pending cap and the status; paused and disabled never claim revocation freshness". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-270 A GNAP interaction is bound to its request and its reference is single use

**Statement.** The AS answers only with interaction modes the client asked for and the AS supports; the finish callback carries the RFC 9635 interaction hash over both nonces, the interaction reference and the grant endpoint, and a client that cannot validate it must not send the reference; a reference presented twice finalizes the grant.

| Enforced by | `InteractionServer`, `acceptFinish`, `interactionHash`. |
| Trusted inputs | The client and AS nonces. |
| State | The interaction state machine. |
| On failure | `unknown_interaction`, `too_many_attempts`, `expired`, `wrong_state`. |
| Established by | Tests: "matches the RFC example for sha-256 and sha3-512", "REDIRECT finish end to end: user code lookup is case-insensitive, the callback hash validates at the client, the ref is single use", "PUSH finish carries {hash, interact_ref}; a forged hash or foreign nonce does not validate and the ref must not be sent". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-271 AuthZEN search results are typed, bounded and never steered by the queried id

**Statement.** A search answers only entities of the searched type, de-duplicated and within the page limit; the id of the queried entity is ignored; a provider that ignores the limit fails closed; the member table of each search type is enforced.

| Enforced by | `authzenSearchHandler`. |
| Trusted inputs | The host's search provider. |
| On failure | 400 for a malformed request, 500 for a provider that breaks the contract. |
| Established by | Tests: "the queried entity id is ignored (stripped before the provider sees it)", "results are only entities of the searched type, de-duplicated", "the member table per search type is enforced (400)", "an unsupported search is 404, a non-search path falls through, a provider that ignores the limit fails closed". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-272 A consistency token inside a PCActn is signed by the leaf and a stale verifier escalates

**Statement.** The `fresh_at` member is part of the signed PCActn body, so it cannot be stripped, swapped or re-ordered after signing; a verifier with a `fresh_at` policy checks it against its own counters and a verifier behind the token fails the `fresh_at` check with an escalate-class reason (the decision fold gives `escalate`, never allow). A PCActn carrying the member that meets a verifier with no policy is refused. With neither a member nor a policy the check is absent and the output is unchanged. The side-carried form is read for one release only when the PCActn has no member, and the member wins.

| Enforced by | `decideFreshAt` in the core verifier, replayed by all nine native verifiers. |
| Trusted inputs | The pinned token signer; the verifier's own counters. |
| State | The verifier's counters. |
| On failure | `fresh_at` fails; escalate for staleness or a missing required token, deny otherwise. |
| Established by | Tests: "is signed by the leaf signature: swapping the token breaks leaf_signature", "a lagging verifier fails fresh_at with an ESCALATE-class reason (decision escalate, never allow)", "a PCActn that carries the member with no policy is refused; no member and no policy is byte-identical (check absent)", "require: no token escalates; the side-carried form is still read for one release, but the member wins". Shared vectors: `fresh-at-vectors.json` (28 cases) and `k3-vectors.json`, replayed in Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby and Swift. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-273 A hosted authority statement is a signed tighten-only ceiling, and a widening is a new grant

**Statement.** The principal-signed authority statement of an enrolled grant is enforced at admission on top of the envelope (verbs, resources, expiry); it is revised in place only by signed attenuations bound to the current revision; a widening needs the principal's signature, a spent single-use step-up challenge and a registered successor grant of the same principal and agent, and it supersedes and revokes the old grant in the same transaction. A refused attempt leaves the step-up spendable.

| Enforced by | The hosted grant routes and the admission gate. |
| Trusted inputs | The principal and holder keys; the registered successor grant. |
| State | The authority overlay, the challenges, the needs. |
| On failure | 403, 401, 400, 409 or 422 with the grant-management error name; admission denies with `grant_authority`. |
| Established by | Tests: "enrolment needs the principal signature at revision 0, is once, and is enforced at admission as a tighten-only ceiling", "widening: principal signature + a spent step-up + a registered successor; the old grant is superseded and killed, the new one carries the wider authority", "step-up challenges: unknown, foreign-grant, wrongly signed and replayed approvals are refused". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-274 An event stream belongs to one receiver

**Statement.** In the SSF management API a stream is visible and changeable only by the receiver that owns it (everyone else gets 404), transmitter-supplied members must match before a change is applied, the delivery method cannot change, status and subjects are validated, and a verification request on a disabled stream is refused.

| Enforced by | `ssfManagementHandler`. |
| Trusted inputs | The host's receiver authentication. |
| State | The stream store. |
| On failure | 400, 401, 404, 409 or 429 per the SSF section. |
| Established by | Tests: "read: one stream, all streams, none; another receiver sees 404, unauthenticated is 401", "PATCH changes only what is present; transmitter-supplied members must match; push delivery is receiver-set; method cannot change", "create refuses transmitter-supplied members, unsupported or insecure delivery, unsupported-only events; a second stream is 409". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-275 Authority limits are enforced at admission, atomically

**Statement.** A principal-signed authority statement may carry only limits the admission path can enforce (`max.<param>`, `sum.<param>`, `count`, `rate.<seconds>`; any other key is refused when written). At admission the per-action ceilings are checked against the digest-bound parameters, and the lifetime and window counters are charged by one atomic conditional upsert inside the admission transaction, so a burst cannot overshoot and a refused or rolled-back action costs nothing. A missing parameter plaintext denies.

| Enforced by | `enforceLimits` in the hosted admission path. |
| Trusted inputs | The parameter plaintext (digest-bound to the signed PCActn); the statement's signature. |
| State | The usage counters. |
| On failure | Denied with `grant_limits`. |
| Established by | Tests: "keys outside the closed grammar are refused when written, so nothing is silently unenforced", "max.<param> is a per-action ceiling and needs the parameter plaintext", "sum.<param> is a lifetime total: the action that would cross it is refused and costs nothing", "count caps the number of admitted actions, and concurrent admissions cannot overshoot". |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

## Policy analysis and authoring invariants

### C-240 Forbid wins, whoever signed and whatever the order

**Statement.** In a clause list, any matching `forbid` denies, however many permits match and whichever signer wrote either. A forbid or escalate clause that cannot be decided counts as matched (veto polarity); a permit that cannot be decided is not matched. The decision does not depend on clause order, and adding a forbid never moves a decision up.

| Enforced by | `decideClauses`. |
| Trusted inputs | The clause list and the evaluators of the predicate language. |
| On failure | `deny` with the winning clause named; a malformed clause list or action is a `deny` that names nothing. |
| Established by | Property: "forbid-monotone" (adding a forbid never grows the admit set; a matching forbid always denies; order does not matter). Tests: "forbid beats permit, whoever signed either", "an order-independent decision", "forbid-monotone: a decision procedure that lets a permit beat a forbid". |
| Status | **Production (pending CI).** Not called by `requirePCA`: a host opts in. |

### C-241 A forbid-wins certificate is recomputed, never trusted

**Statement.** A decision can be returned with a certificate that lists the value of every clause, the winner and the shadowed clauses. `checkForbidCertificate` re-derives the whole certificate from the clauses and the action and requires it to match byte for byte; `certificateConsistent` checks, with no evaluator at all, that the certificate's own table entails its decision, winner and shadowed list.

| Enforced by | `certify`, `checkForbidCertificate`, `certificateConsistent` (TypeScript); `certificate_consistent` (Python), `ForbidCertificateConsistent` (Go), `forbid_certificate_consistent?` (Ruby). |
| Trusted inputs | The clause list and the action the certificate is checked against. |
| On failure | `{ ok: false, reason }`; a certificate that cannot be read is not consistent. |
| Established by | Tests: "refuses a certificate whose table does not entail its decision", "refuses a self-consistent forgery that does not match the recomputed decision", "refuses a certificate for another action or another policy". Vectors: `forbid-certificate-vectors.json` (`decide` and `table`), replayed by the TypeScript, Python, Go and Ruby verifiers. |
| Status | **Hardened (library).** TypeScript reference; the table check is in Python, Go and Ruby. The other verifiers have not ported it yet. |

### C-242 A linked grant holds exactly the policy its template and slots denote

**Statement.** A grant may carry a `template_ref` (template id, version digest, slot values). A verifier that resolves it in a registry of templates signed by trusted organisation keys rebuilds the policy from the template and the slots and requires the grant's `predicates` and `caveats` to equal it exactly. The grant signature covers the reference.

| Enforced by | `resolveLink`, `verifyLinkedPolicy`, `instantiateTemplate`, `verifyTemplate`; the same functions in Python, Go and Ruby. |
| Trusted inputs | The trusted organisation keys and the registry of signed templates. |
| On failure | `{ ok: false, reason }`: unknown version, untrusted signer, a digest that does not match, a slot that is unfilled, undeclared, mistyped or outside its closed domain, or a grant whose policy differs. |
| Established by | Tests: "the grant carries the reference, covered by the grant signature, and verifies against the registry", "a grant whose policy was edited after linking is refused". Vectors: `policy-link-vectors.json` (digest, instantiate, verify, resolve), replayed by TypeScript, Python, Go and Ruby. |
| Status | **Hardened (library).** Not called by `requirePCA`: a host opts in. |

### C-243 A link can only tighten after it is made

**Statement.** A template version is immutable and named by its digest, so a new version applies to new grants only. An existing link changes only through a signed tighten overlay, which may add `where` conditions and caveats and nothing else. A slot value that would put a wildcard or a regex into a verb or resource is refused.

| Enforced by | `resolveLink`, `tightenOverlayError`, `instantiateTemplate`. |
| Trusted inputs | The trusted organisation keys. |
| On failure | The link is refused; an overlay that names this version and fails verification is a refusal rather than a silent skip. |
| Established by | Tests: "a new template version does not touch an existing link; a tighten overlay narrows it", "overlays can only add conditions and caveats", "a slot used for a verb or resource cannot carry a wildcard or regex". Vectors: `policy-link-vectors.json`. |
| Status | **Hardened (library).** |

### C-244 Analysis answers are re-checked by the real evaluator, and no solver is in the trusted base

**Statement.** Every witness, counterexample, repair and proposed grant that the analysis tools return has been run through the real evaluator. An optional external solver is used only to look for a counterexample; a witness it returns is discarded if the evaluator disagrees, and its "no such action" is labelled as an unchecked claim and never upgraded to a verdict.

| Enforced by | `findWithBackend`, `decideAction` and the witness checks in `maxExposure`, `diffPolicies`, `escalationSurface`, `minimalFlip`. |
| Trusted inputs | The real predicate and caveat evaluators of `@atlasauth/pca`. |
| On failure | The witness is dropped (`rejected`) or the result is marked `approximate`; the analysis never reports a safer answer than it proved. |
| Established by | Tests: "accepts a witness the evaluator confirms", "rejects a witness the evaluator refuses", "labels an unsat claim as unchecked", "widens: names the actions that moved from deny to allow". |
| Status | **Production (pending CI)** as tooling outside the verifier. |

### C-245 Exposure bounds are upper bounds

**Statement.** `maxExposure` reports the most that can leave as an upper bound: the per-action ceiling composed with rate limits, the `cap` and `rate` invariants that provably apply to every action of the verb and, when the budget is denominated in the amount's unit, the grant's budget allocation. Anything it cannot model (a cap that may not apply, an invariant that needs history, an undecided feature, a grid over the bound) can only raise the number, and is listed or flagged `approximate`.

| Enforced by | `maxExposure`. |
| Trusted inputs | The policy and the constitution given to it. |
| On failure | The bound is `Infinity` or flagged `approximate`; the reason is returned. |
| Established by | Tests: "composes the per-action ceiling with a rate limit over a window", "applies a universal cap invariant, and leaves out one that does not provably apply", "an exclusive bound is a supremum for a real, and the largest integer below it for an integer", "separates the autonomous ceiling from the one with a human". |
| Status | **Hardened (tooling).** |

### C-246 A diff never calls a widening equivalent

**Statement.** `diffPolicies` reports, for every kind of ternary change (deny, escalate, allow), concrete actions that moved. A diff that could not be decided exactly is `approximate` and never `equivalent`, and the CI gate fails on a widening, on a rise in the maximum exposure, and on an inconclusive diff. A delegation envelope is the meet of the whole chain and lists any hop wider than its parent.

| Enforced by | `diffPolicies`, `diffGate`, `delegationEnvelope`, `escalationSurface`. |
| Trusted inputs | The real evaluator. |
| On failure | `ok: false` with the reasons; exit code 1 in `pca-policy-ci diff`. |
| Established by | Tests: "is ternary: a drop from allow to escalate is a tightening, escalate to allow a widening", "is inconclusive, never equivalent, when the grid overflows", "reports the exposure delta and gates on it", "flags a child that is wider than its parent", "passes a narrowing and an identical policy, fails a widening with a witness line". |
| Status | **Hardened (tooling).** |

### C-247 A residual policy is exact and never prunes a veto

**Statement.** `residual(policy, known)` specialises a policy to the known facts. For every way of filling in the unknown fields it decides exactly what the original decides, so the residual admits nothing the original does not. An unknown that reaches a prohibition or a model-signal rule keeps it; only facts remove a clause.

| Enforced by | `residual`, `evaluateResidual`. |
| Trusted inputs | The real evaluator, used with the three-valued rules unchanged. |
| On failure | The residual is `never` or keeps the unknown clause; a delegation chain keeps every ancestor. |
| Established by | Tests: "the residual decides exactly what the original decides, for every completion of the unknown parameters" (600 randomized cases against the real evaluator), "an unknown that reaches a veto keeps the veto (never prunes it)", "a delegation chain keeps every ancestor". |
| Status | **Hardened (tooling).** |

### C-248 Capability discovery is advisory and bound to a policy digest

**Statement.** `whatMayIDo` returns, per verb, whether the principal can act autonomously, needs approval or is denied, and the parameter values still allowed. It is advice for building tool lists and constraints; the verifier stays authoritative. The answer carries the digest of the policy it was computed from and says `approximate` where the policy has features it cannot decide.

| Enforced by | `whatMayIDo`. |
| Trusted inputs | The policy and the schema shapes given to it. |
| On failure | `status: denied` with the reason, or `approximate: true`; no domain is claimed when the grid is too large. |
| Established by | Tests: "returns the allowed parameter domains and the policy digest", "shows the approval threshold and the enum values", "a regex resource makes the answer approximate rather than wrong", "denied for a verb the policy does not grant, with the reason; passes through budget and discharges". |
| Status | **Hardened (tooling).** Advisory by design. |

### C-249 A data filter never selects more than the evaluator allows

**Statement.** `toFilter` compiles a residual to a parameterized SQL fragment. It uses the same three-valued logic as the evaluator (an unresolvable permit condition drops the row, an unresolvable prohibition still excludes it). A condition it cannot express exactly (regex resource, field-to-field reference, string ordering, a field with no column) makes the whole compile fail with a reason; it never emits a looser filter.

| Enforced by | `toFilter`, `evalFilter`. |
| Trusted inputs | The column map and the column types and collation the policy assumes. |
| On failure | `{ ok: false, reason }`; the caller checks rows one at a time. |
| Established by | Tests: "refuses what it cannot express exactly, instead of widening", "the filter selects exactly the rows the evaluator allows (Kleene logic, nulls, vetoes, nested not)", "escapes LIKE metacharacters and supports ? placeholders". |
| Status | **Hardened (tooling).** |

### C-250 A least-privilege proposal is proven narrower than the grant it replaces

**Statement.** `suggestNarrowing` builds a proposal as the original clauses plus extra conditions and then proves it subsumed by the original with the analyzer. If the proof is not exact there is no proposal. The proposal is never applied by any function in the package.

| Enforced by | `suggestNarrowing`, `subsumes`. |
| Trusted inputs | The original policy. |
| On failure | No proposal, with the reason. |
| Established by | Tests: "proposes a narrower grant, proven subsumed by the original, and lists what was never used", "property: a proposal is never wider than the original, whatever was observed", "an observation the policy does not admit cannot widen it", "says why there is no proposal when nothing observed matches". |
| Status | **Hardened (tooling).** |

### C-251 Only the ledger counts, and a denial is a request, never a widening

**Statement.** Observations the agent merely claims are counted as rejected and never used. A refused attempt becomes an access request, which is signed by its holder and read by a human; nothing in the package turns an access request into authority.

| Enforced by | `suggestNarrowing`, `signAccessRequest`, `verifyAccessRequest`. |
| Trusted inputs | The ledger the observations came from. |
| On failure | The observation is ignored; the access request is only data. |
| Established by | Tests: "counts, and never uses, observations the agent merely claims", "a refused attempt becomes an access request for a human, and never loosens the grant", "decay: the re-minted grant lapses". |
| Status | **Hardened (tooling).** |

### C-252 Policy coverage reports what the tests cannot see

**Statement.** `coverage` reports clauses that never decided, clauses the analyzer proves unreachable, thresholds never probed on both sides, and mutations of the policy (widen a cap, drop a prohibition, flip an operator) that the traffic cannot tell from the original, each with the action that would kill it. A mutant the analyzer proves equivalent is excluded from the score.

| Enforced by | `coverage`, `coverageGate`, `witnessOf`. |
| Trusted inputs | The traffic or tests it is given. |
| On failure | The gate fails (`pca-policy-ci coverage` exits 1) below the thresholds you set. |
| Established by | Tests: "reports clauses, boundaries and surviving mutants, with the action that kills each", "boundary traffic and a trigger for each prohibition kill the mutants", "a mutant the analyzer proves equivalent is not counted against the score", "a gate fails on missing coverage, and on an unreachable clause". |
| Status | **Hardened (tooling).** |

### C-253 A policy is checked against the action schema it is written for

**Statement.** `validatePolicyAgainstSchema` compares a policy with a signed action schema or action definitions: undeclared verbs and parameters, type and range mismatches, enum values the schema lacks, a predicate that can never match, a money verb with no ceiling, and (rule 20) a missing or different unit tag.

| Enforced by | `validatePolicyAgainstSchema`, the `schema-mismatch` rule of `pca-policy-ci`. |
| Trusted inputs | The schema (its signature is checked elsewhere). |
| On failure | Error findings fail the CI gate. |
| Established by | Tests: "type mismatches", "bounds the schema makes impossible or redundant", "rule 20: a unit-bearing parameter needs the matching unit tag", "--schema checks each linted policy against an action schema file". |
| Status | **Hardened (tooling).** |

### C-254 A counterfactual repair is verified by the real decision

**Statement.** `minimalFlip` proposes the smallest change that gets a denied or escalated action to the wanted decision (wait, change a parameter or the resource, obtain a named fact, or with explicit opt-in split the action) and returns only candidates the real decision accepts. A denial with no repair becomes an access request, not an invented fix. Splitting is offered only when nothing meters the total.

| Enforced by | `minimalFlip`. |
| Trusted inputs | The real evaluator and caveat evaluator. |
| On failure | No repair; an access request or an approval ask. |
| Established by | Tests: "lowers the amount to the largest admissible value and verifies it with the real decision", "a hard deny with no repair becomes an access request, not an invented fix", "splitting is opt-in and only when nothing meters the total", "waits for a time caveat to open, verified by the caveat evaluator". |
| Status | **Hardened (tooling).** |

### C-255 Counterfactuals are shown only to the authenticated holder, rate-limited and redacted

**Statement.** A repair teaches the asker about the policy, so `minimalFlip` refuses anyone but the authenticated holder, stops when a probe budget is spent, and by default hides the value of a `critical` parameter behind "a repair exists".

| Enforced by | `minimalFlip`. |
| Trusted inputs | The caller's authentication and the probe history it supplies. |
| State | The probe history (timestamps) kept by the caller. |
| On failure | `refused` with the reason; redacted repairs. |
| Established by | Tests: "refuses anyone but the authenticated holder, and rate-limits probing", "redacts the value of a critical parameter to \"a repair exists\"". |
| Status | **Hardened (tooling).** The probe budget must be charged by the caller's own rate caveat. |

### C-256 Policy examples are pinned to the policy they were confirmed against

**Statement.** A policy test document names the policy digest it was confirmed against and may be signed. A run fails when an example fails, and with `requireDigest` it also fails when the policy changed even though every example still passes, so a recompile that drifts does not slip through.

| Enforced by | `runPolicyTests`, `signPolicyTests`, `verifyPolicyTests`, `generateBoundaryTests`. |
| Trusted inputs | The principal's key for a signed document. |
| On failure | A failed run (exit 1 in `pca-policy-ci test`). |
| Established by | Tests: "a policy that drifts but passes every case still fails when the digest is required", "signed examples verify, and any edit breaks the signature", "the generated examples pass the policy they came from, and catch a widened cap". |
| Status | **Hardened (tooling).** |

## Action kit invariants

### C-200 Traits only add restrictions

**Statement.** The restriction profile of an action is the join of what its author declared and the floors of every trait it carries, directly, by implication or through a trait it implies. Adding a trait, or raising a declared value, can only raise the profile; a declared value below a floor is clamped, never honoured; a trait tagged on a later action gives that action the floor with no change to any policy.

| Enforced by | The trait algebra of `@atlasauth/pca-actions` (`effective`, `floorOf`, `closure`). |
| Trusted inputs | The trait registry (the core table is embedded and digest-pinned; custom traits are checked on load, C-202). |
| On failure | The def is refused at load (unknown trait, bad registry); there is no failure mode that lowers a profile. |
| Established by | Lean (`TraitAlg`: join is the least upper bound, traits only add, inheritance) and Dafny (`TraitExpand`, the same statements on executable sets), both without `sorry`, assumption or axiom. Property tests of 100,000 cases each. Tests: "S subset S2 implies F(S) <= F(S2)", "eff(d + t) >= eff(d) for every def d and every trait t", "eff(d) >= floor(t) for every t in T(d) and in its closure", "a declared value below its floor is clamped and flagged". |
| Guarantees | G-20. |
| Status | **Library: enforced and machine-checked.** Verifier wiring is C-204. |

---

### C-201 The floor decision falls as the profile rises

**Statement.** For a stored grant and a call, the floor decision (deny, escalate, allow) is antitone in the effective profile, and the final decision is the meet of the policy decision and the floor decision. Tagging an action with another trait, or tightening one of its declared fields, never turns a deny or an escalate into an allow.

| Enforced by | `floorDecision` and `meetDecision`. |
| Trusted inputs | The verifier's stored grant and the facts it observed about the call (never an agent claim). |
| On failure | A missing caveat or context key escalates; a tier above the grant's maximum denies. |
| Established by | Lean (`fd_antitone`, `T4_tagging`) and Dafny (`FDAntitone`, `T4Tagging`). Tests: "rho <= rho2 implies FloorDecision(rho2) <= FloorDecision(rho)", "adding a trait or tightening a declared field never raises Dec". |
| Guarantees | G-20. |
| Status | **Library: enforced and machine-checked.** |

---

### C-202 A custom trait cannot weaken a core trait

**Statement.** A custom trait is accepted only if its floor is at least the floor of everything it implies, it does not use the reserved `pca.` namespace, the implication graph is acyclic and at most eight deep. No combination of custom and core traits yields a profile below the core floors, and extending a registry leaves the floor of every core set unchanged.

| Enforced by | `registryError`, `buildRegistry`, `extendRegistry`. |
| Trusted inputs | The core table (embedded). |
| On failure | The registry is refused (`bad_registry`). |
| Established by | Lean (`T5_core_preserved`, `T5_custom_cannot_lower`) and Dafny (`T5NoLowering`); shared vectors with custom-trait cycles, unknown implies, namespace reuse and depth 8 and 9. Tests: "well formed custom traits are accepted and never reduce a core floor", "rejects the reserved namespace, cycles, unknown implies and depth > 8". |
| Guarantees | G-20. |
| Status | **Library: enforced and machine-checked.** |

---

### C-203 Registry growth never grants; allow selectors are positive and pinned

**Statement.** A prohibit selector floats (it covers every present and future action it matches); an allow selector is pinned to a pack digest and may not use negation. An action outside the pinned pack is never allowed, a matching prohibit always denies, and the decision for an existing action does not change when other actions are added.

| Enforced by | `allowSelectorError`, `policyDecision`. The policy compiler that applies it is the policy-integration track. |
| Trusted inputs | The pinned pack digest in the grant. |
| On failure | The grant is refused at compile time (negation or unpinned `any_of` in an allow); an unpinned action is denied or escalated. |
| Established by | Lean (`new_action_not_allowed`, `prohibit_denies`, `growth_stable`, `matches_mono`, `not_selector_not_mono`) and Dafny (`NewActionNotAllowed`, `HoldsMono`). Tests: "an action outside the pinned pack is never allowed", "rejects not and unpinned any_of in an allow". |
| Guarantees | G-20. |
| Status | **Library: enforced and machine-checked.** Compiler wiring is partial until the policy track lands. |

---

### C-204 A signed schema's floors are checked against its traits

**Statement.** A version 2 action schema carries each verb's effects, traits, definition digest and materialized floors. A verifier recomputes, from the verb's own visible facts, the traits that must be present and the floor of the carried traits, and refuses a verb whose floors are below it or that omits an implied trait.

| Enforced by | `schemaVerbFloorError` (integrity half of rule 22). |
| Trusted inputs | The embedded core table and the document's signed custom traits. |
| On failure | `schema_floor_forged`, `schema_traits_forged` or `unknown_trait`: the verb is refused. |
| Established by | Tests: "rejects lowered floors, dropped implied traits, unknown traits and a lowered reversibility floor"; shared vectors `schema-verb-adv-*`. |
| Guarantees | G-20. |
| Status | **Library: enforced; verifier: enforced in TypeScript (C-360).** The native verifiers follow the shared vectors (`rule22_schema`, `rule22`). |

---

### C-205 One action has one digest

**Statement.** Every authoring form of an action normalizes to the same canonical object, so the definition digest (the unit grants pin) is independent of key order, defaults spelled out, and the members that do not define the action (review state, examples, provenance, introduction version).

| Enforced by | `normalize`, `defDigest`, `packRoot`. |
| On failure | A def that is not strict JSON (float, lone surrogate, non-NFC, unknown member) is refused before it is digested. |
| Established by | Tests: "two authoring forms of one action have one digest", "digests are stable under normalization for generated defs"; 423 shared vectors replayed byte for byte. |
| Guarantees | G-20. |
| Status | **Library: enforced.** Native ports follow the shared vectors. |

### C-320 An authoring file has one meaning

**Statement.** The authoring forms of an action (YAML, JSON, the TypeScript builder, the shorthands) all expand to the same strict definition, so a file is read the same way by every tool. The loader refuses everything that could change meaning between parsers or exhaust a machine: aliases, anchors and merge keys, duplicate keys, unknown tags, a `__proto__` member, floats, non-normalized strings, unknown members, and a file above 1 MiB. Shorthands expand deterministically, so each way of writing an action gives one digest.

| | |
|---|---|
| Enforced by | `loadActionsText`, `loadActionsValue`, `expandAction`, `parseParamShorthand`, `parseResourceShorthand`, `validateDef`. |
| Trusted inputs | None: the file is untrusted. |
| State | None. |
| On failure | The file yields no definitions and a typed error naming the action; `lint` reports it as LD-000 and `build` does not run. |
| Established by | Tests: "refuses aliases and anchors (no entity expansion), merge keys, duplicate keys and unknown tags", "a billion-laughs document is refused quickly", "refuses a '__proto__' member anywhere, in YAML and in JSON", "refuses floats, non-NFC and lone surrogates (strict JSON profile)", "refuses a file above the size limit", "builder == YAML == JSON == full def for generated actions", "every shorthand form". |
| Guarantees | G-20. |
| Status | **Library: enforced.** |

---

### C-321 Nothing with a lint error is built, and what is signed is what was built

**Statement.** `build` refuses a project with a lint error and writes nothing. `sign` signs only a build that re-derives exactly: the pack is internally consistent (every definition valid and unique, Merkle root and trait digest recomputed), the schema equals the schema derived from that pack, and the schema's floors match its traits. A pack marked stable must also be free of warnings. An edited build file is refused, not signed.

| | |
|---|---|
| Enforced by | `cmdBuild`, `cmdSign`, `packConsistencyError`, `schemaFloorError` (C-204). |
| Trusted inputs | The signing key supplied by the operator. |
| State | The build directory. |
| On failure | Nothing is signed or published; the message names the first inconsistency. |
| Established by | Tests: "build refuses a project with lint errors and writes nothing", "a changed schema floor", "a changed pack def", "a pack with an invalid def, a missing build, and a bad key", "a stable pack must be lint-clean even of warnings". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** |

---

### C-322 A pack signature covers the whole pack and cannot stand in for another signature

**Statement.** A pack is signed over its canonical bytes (definitions, root, trait digest, version, stability, chain fields) under its own domain, `atlas-pca/action-pack/v1`, different from the schema domain. A signature of one artifact never verifies as the other, and any change to the pack, its key id or its key invalidates it. `publish` verifies both signatures against the listed keys before it writes or sends anything.

| | |
|---|---|
| Enforced by | `signPack`, `verifyPack`, `cmdPublish`. |
| Trusted inputs | The registry key entry (the suite comes from the pinned entry, never from the document). The pack signature is Ed25519; a post-quantum suite follows with the registry track. |
| State | None. |
| On failure | `pack signature invalid`, `no registry key with kid`, or the consistency reason. |
| Established by | Tests: "a tampered def, root, version, key id, key and signature are refused", "a schema signature is not a pack signature, and the other way round", "an inconsistent pack is not signed", "publish refuses a tampered signed file and a pack signed by an unlisted key". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** Transparency-log append and rollback detection belong to the registry track. |

---

### C-323 The lint rules are fixed, versioned and each is exercised

**Statement.** There are 24 lint rules with stable ids (14 errors, 10 warnings). The ordered list is digested and the digest is pinned, so changing, adding or removing a rule is a visible, versioned change. Every rule has at least one definition that triggers it and one that does not; the clean definition has no finding of any kind. Output is deterministic and sorted.

| | |
|---|---|
| Enforced by | `LINT_RULES`, `lintDefs`, `lintRulesDigest`. |
| Trusted inputs | None. |
| State | None. |
| On failure | An error fails the run; a warning fails it under `--strict`. |
| Established by | Tests: "has 24 stable rules: 14 errors LD-001..014 and 10 warnings LW-001..010", "the rule list digest is pinned (changing a rule is a versioned change)", "lint rules: every rule has a fixture that triggers it and one that does not", "findings are sorted and stable across runs and input order". |
| Guarantees | G-20. |
| Status | **Library: enforced.** Lint is advisory to the verifier; the floors (C-200) are what bind. |

---

### C-324 An imported action is a draft

**Statement.** Every definition an importer produces has review state `unreviewed`, so it carries the most restrictive floor until a human confirms it; tool annotations and HTTP methods only choose the initial draft effects and are treated as untrusted lower bounds. Importers are offline (an external reference is a to-do, never a fetch), bounded in operations, nodes, reference depth and nesting, and never fail open: a source that cannot be digested or exceeds a bound is refused.

| | |
|---|---|
| Enforced by | The importers (`importMcp`, `importOpenApi`, `importGraphql`, `importGrpc`, `importAsyncApi`, `importJsonSchema`) and the `IMPORTERS` registry. |
| Trusted inputs | None: the source document is untrusted. |
| State | None. |
| On failure | The import throws or lists a to-do; a def that fails validation is dropped with a to-do. |
| Established by | Tests: "an unreviewed def is held at the most restrictive floor", "every def is well formed and unreviewed, with its source recorded", "arbitrary JSON never throws anything but ActionKitError", "documents with fuzzed schemas validate, are unreviewed, and stay within bounds", "treats hints as untrusted lower bounds". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** Suggestion is C-342 and review is C-343. |

---

### C-325 The definition diff does not understate widening

**Statement.** `diff` classifies a change to a definition as equal, narrow, widen or incomparable. It is conservative: a change it cannot show to be no wider is a widening, and an incomparable change counts as a widening. For ranges, a diff of equal or narrow never accepts a call the old definition refused.

| | |
|---|---|
| Enforced by | `diffDefs`, `diffPacks`, `cmdDiff`. |
| Trusted inputs | None. |
| State | None. |
| On failure | The CLI exits non-zero when any action widens, is incomparable or is removed. |
| Established by | Tests: "soundness against a brute-force oracle: an equal or narrow diff never accepts a call the old def refused", "reflexive on generated defs; a narrowing mutation is never a widening, and its inverse never narrows", "range changes", "params added and removed; breaking changes are flagged". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced** as an author tool. The signed, pinned form (evolution records) is the registry track. |
---

### C-340 Every importer output is a draft, whatever the source

**Statement.** All six importers (MCP, OpenAPI and Swagger 2, GraphQL, gRPC and protobuf, AsyncAPI, JSON Schema) return definitions whose review state is `unreviewed`, with the source kind, address (digest of the source), licence and import time recorded. Nothing in a source (a hint, a method, an extension, an annotation) can produce an `authored` or `confirmed` definition or a lower floor. An input the importer cannot read is refused with a typed error, never a partial draft that looks complete.

| | |
|---|---|
| Enforced by | The importers and the `IMPORTERS` registry. |
| Trusted inputs | None. |
| State | None. |
| On failure | `ActionKitError` (`bad_source`, `import_limit`, ...), or a to-do and a dropped definition. |
| Established by | Tests: "tool lists with fuzzed schemas validate and are unreviewed", "grpc: random token soup, mutated proto and random bytes", "covers every source kind, returns string todos, and its defs are unreviewed". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** |

---

### C-341 Importers are bounded and offline

**Statement.** An importer reads only what it is given: a reference that is not local is never followed. Source bytes, parsed nodes, nesting, operations and per-operation schema expansion are bounded by fixed limits (caller limits are clamped to hard ceilings); a source over a bound is refused whole, a shortfall inside one operation is a to-do and a string placeholder that rejects every non-string value. Cycles, reference bombs, deep nesting and truncated binary descriptors terminate in bounded work without a stack overflow.

| | |
|---|---|
| Enforced by | `resolveLimits`, `checkParsed`, the bounded `$ref` resolver, the GraphQL and protobuf parsers. |
| Trusted inputs | None. |
| State | None. |
| On failure | `import_limit` or `bad_source`; or a to-do. |
| Established by | Tests: "an allOf fan-out bomb is bounded by the node budget", "refuses a parsed source over the byte, node or depth limit", "terminates on a cyclic object without a stack overflow", "a recursive GraphQL input type and a recursive proto message terminate and note it", "a deeply nested GraphQL list type or value does not overflow the stack", "a binary descriptor with a length beyond the buffer, a bad varint or a wire type 7 is refused". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** |

---

### C-342 Suggestions only add and are never trusted

**Statement.** The suggestion engine (signed, versioned rules, and an optional pinned model) can add traits, add a role to a parameter that has none, and add tags. It cannot remove or replace anything, cannot add a trait outside the registry vocabulary, and cannot mark a definition confirmed: a suggested definition keeps `pca.unreviewed`, hence the most restrictive floor. A rule set is well formed (closed members, bounded regular expressions) and, when signed, verified against pinned publisher keys; a model sees only names and types, its answer is parsed against the closed vocabulary, and its prompt, input and output are digested into the definition.

| | |
|---|---|
| Enforced by | `suggestWithRules`, `applySuggestion`, `suggestRulesError`, `signRules`, `verifyRules`, `suggestWithModels`. |
| Trusted inputs | The pinned rules publisher keys (to accept a rule set as published). |
| State | None. |
| On failure | The suggestion is dropped; a malformed or unsigned rule set is refused. |
| Established by | Tests: "for any def and any rule subset: traits grow, params keep their roles, no state becomes confirmed, floors never fall", "a suggested def is still unreviewed for floor purposes: the unreviewed floor is never lost", "the closed vocabulary: a rule naming a trait outside the registry cannot add it", "an injection in the description cannot widen the vocabulary or confirm anything", "sign, verify, and detect a changed rule, a changed digest, a wrong key and an unsigned set", "rejects regular expressions outside the bounded subset". |
| Guarantees | G-20. |
| Status | **Library: enforced.** Recall is measured, not guaranteed (`eval-suggest`). |

---

### C-343 Only a pinned reviewer's signature lowers the unreviewed floor

**Statement.** `pca.unreviewed` is removed from a definition only when its review state is `confirmed` and its attestation (a) covers this definition's digest, (b) names an accepted trait registry digest, (c) attests exactly the definition's declared traits, (d) is signed by a key pinned with the `reviewer` role (never one that is also an importer or model key, even under another key id) inside that key's validity, and (e) verifies. Any change to the definition or the registry makes the confirmation stale and the definition behaves as unreviewed. A trait that was suggested and is left out of the final set must be recorded with a reason. This is the single non-monotone step; it removes the review marker and nothing else.

| | |
|---|---|
| Enforced by | `verifyAttestation`, `attestationVerifier`, `confirmDef`, `reviewerPinsError`. |
| Trusted inputs | The pinned reviewer keys. |
| State | None. |
| On failure | The definition stays at the unreviewed floor; `confirmDef` throws. |
| Established by | Tests: "for any def claiming to be confirmed, with any garbage attestation, the review marker stays", "any change to the def after the review: the def reverts to unreviewed", "the attestation does not move to another def (replay)", "a forged signature, a tampered body, an unsigned attestation and a signature by a different key", "a machine key, an unknown key and a key outside its validity cannot confirm", "a changed trait registry (a raised floor) makes the attestation stale unless the pins accept the old digest", "a key cannot be both a reviewer and an importer or model", "a suggested trait left out must be dismissed with a reason". |
| Guarantees | G-20. |
| Status | **Library and CLI: enforced.** The registry layer must call `attestationVerifier` where defs are loaded (rule 22 wiring is A4). |
---

### C-360 Rule 22: a verifier recomputes the floors, it never trusts the document's

**Statement.** When a version 2 action schema is accepted for an action, the verifier recomputes the traits that the verb's own facts imply and the floor of the carried traits (with the document's signed custom traits), and refuses a schema whose materialized floors are lower, that omits an implied trait, that names an unknown trait, or whose trait digest does not match its registry. It then runs the floor decision of the verb's floors against what the grant provides (its caveat kinds, its highest authorized and highest pre-authorized escalation tier) and the context the verifier itself observed, and meets it into the decision: a missing caveat or context, or a tier above the pre-authorized one, escalates; a tier above the authorized one denies. A verifier that cannot recompute the floors (no trait engine configured) refuses a version 2 schema.

| | |
|---|---|
| Enforced by | `decideIntentV2`: the `schema` check (integrity, through `ctx.rule22.schemaError`) and the `traits` check (decision, through `ctx.rule22.decide`); `RULE22_ENGINE` of `@atlasauth/pca-actions` implements both. A grant that carries `actions` makes `authorize` run the pipeline. |
| Trusted inputs | The embedded core trait table (digest-pinned); the call context (verifier state, never the agent's claims). |
| State | None. |
| On failure | `schema_floor_forged`, `schema_traits_forged`, `unknown_trait`, `traits_digest_mismatch`, `schema_floor_unchecked` (refused); `escalate: ...` or a deny from the `traits` check. |
| Established by | Tests: "a site-signed schema whose floors were lowered is refused (schema_floor_forged), by the schema check and by the pin", "a dropped implied trait is refused (schema_traits_forged)", "a lowered reversibility floor is refused", "a custom trait document that weakens a core trait is refused", "without the trait engine a v2 schema is refused: a verifier that cannot recompute the floors does not trust them", "a grant missing a required caveat escalates (never allows)", "a tier above preauth_esc escalates; above max_esc denies", "a required context key the verifier did not observe escalates", "rejects a malformed rule22 engine, call_context and actions evidence"; the shared vectors `rule22-*` and `rule22-schema-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** Native verifiers follow the shared vectors; the zkVM guest does not run rule 22. |

---

### C-361 A pinned definition cannot widen without the principal

**Statement.** A grant may pin the definition digests of the verbs it authorizes (`envelope.actions`). A presented definition that differs from the pin is `def_changed` unless a chain of registry-signed evolution records, each of class `equal` or `narrow`, leads from the pinned digest to the presented one, or the grant's principal signed a re-approval of the widening step. Records that are unsigned, signed by another key, for another verb or namespace, or that do not chain, never move the pin. A schema that is not from the pinned pack namespace, or that carries no definition digest, is refused.

| | |
|---|---|
| Enforced by | `decidePin` (`@atlasauth/pca`), called by `decideIntentV2` as the `pin` check. |
| Trusted inputs | The registry keys the verifier pins; the grant (signed by the principal). |
| State | None. |
| On failure | `def_changed` (with the diff to re-approve), `pack_mismatch`, `unknown_verb`, `bad_pin`: the action is refused. |
| Established by | Tests: "a changed definition with no evolution chain is def_changed", "a registry-signed narrowing chains and is admitted", "a widening is blocked without the principal even with a signed record, and names the diff to approve", "the principal re-approving that exact step for this grant admits it", "follows equal/narrow steps across several hops; a missing hop breaks the chain", "an unblocked path is preferred over a blocked shortcut", "for random definitions and mutations (property, signed records, 3x10^4 cases in CI)"; the shared vectors `pin-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** Native verifiers follow the shared vectors. |

---

### C-362 A pack is signed, rooted and verifiable at any size

**Statement.** An action pack is signed by the registry key (the suite comes from the pinned key entry), pins the digests of the trait, role and rule tables it was built against, lists its definitions (inline, or by shard digest) in sorted order, and commits to them with a Merkle root, so one inclusion proof shows a definition belongs to a pack of any size. A changed definition, root, version, source, evolution record or shard, an unsorted or duplicated list, an unknown member, a downgraded suite claim or another key is refused. A pack may be appended to a SCITT transparency log and carries a receipt.

| | |
|---|---|
| Enforced by | `verifyPack`, `packRoot`, `packProof`, `verifyPackProof`, `appendPackToLog`, `verifyPackLogEntry`. |
| Trusted inputs | The pinned registry keys; the pinned log key and tree root. |
| State | None. |
| On failure | The pack is refused (`ok: false`); nothing is partially loaded. |
| Established by | Tests: "a built pack verifies and returns its defs and digest", "rejects a changed def, a changed root, a swapped key and an unknown kid", "rejects a downgraded suite claim, unknown members, unsorted or duplicate defs, and bad vocabulary digests", "a pack signed over valid content but re-signed by another key is refused", "a pack above the inline limit is sharded automatically and verifies with its shards only", "verifies across shards; a missing, altered or foreign shard is refused", "one inclusion proof shows a def belongs to the pack root, whatever the shard", "appends a pack statement and verifies the receipt against the pinned keys and tree root", "refuses a receipt for another pack, a wrong log key, a wrong registry key and a wrong tree root"; the shared vectors `pack-verify-*` and `pack-proof-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** Native verifiers follow the shared vectors. |

---

### C-363 Rollback, fork and chain gap are refused

**Statement.** Each pack names the digest of the version it replaces. A verifier keeps the highest version and digest it accepted per namespace and refuses an older pack (rollback), a second different pack at an accepted version (fork), and a newer pack that does not chain to the accepted one (chain gap). The same pack again is accepted as already seen.

| | |
|---|---|
| Enforced by | `PackTracker`, `verifyUpgrade`. |
| Trusted inputs | The verifier's own accepted state (`snapshot`/`restore` persist it). |
| State | The highest accepted version and digest per namespace. |
| On failure | `rollback`, `fork`, `chain_gap`, `bad_pack`, `bad_upgrade`. |
| Established by | Tests: "refuses a rollback to an older signed pack", "refuses a fork: a second pack at an accepted version", "refuses a chain gap: a newer pack that skips a version", "refuses a forged pack and one with a lying evolution", "survives a restart through snapshot and restore", "rejects a chain gap, a non-increasing version and a different namespace"; the shared vectors `tracker-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** The first pack of a namespace is trusted on first use. |

---

### C-364 The registry cannot sign a false class for a change

**Statement.** The signed evolution of a pack is exactly the computed semantic diff between the previous and the new version: every record verifies, none is missing or extra, and each carries the class the diff computes. The diff is conservative: `equal` or `narrow` only when every call the new definition accepts was accepted by the old one and the effective profile did not fall; anything it cannot order is `incomparable`, which a pin treats as `widen`.

| | |
|---|---|
| Enforced by | `diffDefs`, `evolutionRecords`, `evolutionError`, `verifyUpgrade`. |
| Trusted inputs | None beyond the registry keys. |
| State | None. |
| On failure | `bad_upgrade`: the new pack is not accepted as the successor. |
| Established by | Tests: "equal/narrow implies the new definition accepts only calls the old one accepts and never lowers the floors" (100,000 random mutations, sampled calls and floor decisions), the three "negative control" tests (classifiers with a deliberate hole are caught by the same oracle), "a registry cannot sign narrow for a widening, drop a record, or add an extra one", "a pack whose evolution lies about a widening fails verifyUpgrade", and the class tests of "semantic diff: classes". |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** The diff is TypeScript tooling: natives verify the signatures and do not recompute it. |

---

### C-365 Registry growth never grants

**Statement.** A verb that a pack gains after a grant was minted is not covered by the grant's pin: it is `new_action` (a terminal deny, or an escalation when the grant says so), whatever the pack contains.

| | |
|---|---|
| Enforced by | `decidePin` (`on_new_action`). |
| Trusted inputs | The grant. |
| State | None. |
| On failure | `new_action`. |
| Established by | Tests: "registry growth never grants: any verb a pack gains is new_action to every pinned grant", "a verb the grant does not name is denied or escalated by on_new_action", "a verb the pin does not name follows on_new_action; pack-level pin needs the exact root"; the algebra property "an action outside the pinned pack is never allowed" (C-203). |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** |

---

### C-366 A re-approval is bound to one grant, one verb and one change

**Statement.** The principal's approval of a widening is a signature over the grant's content address, the verb and the digest of the evolution record's diff. It cannot be replayed on another grant, another verb, or another change, and only the key that minted the grant can produce it.

| | |
|---|---|
| Enforced by | `signReapproval`, `reapprovalValid`, `decidePin`. |
| Trusted inputs | The grant issuer key. |
| State | None. |
| On failure | The widening step stays blocked (`def_changed`, naming the diff to approve). |
| Established by | Tests: "is bound to the grant, the verb and the diff", "a re-approval for another grant, another diff, or by another key does not admit it"; the shared vectors `reapproval-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript).** |

---

## Auth and token bridge invariants

### C-100 An ID token is verified only against keys that are fresh, fetched over https and bounded

**Statement.** `verifyIdToken` accepts a token only against a key set that was fetched over https, is within its size cap, answered within its timeout, is a JWK Set, and is no older than `cacheMaxAgeSec`. A key set that is unreachable, stale, oversize, malformed or timed out refuses the token with code `keys`; an http issuer, `jwks_uri` or `jwksUri` is refused unless `requireHttps: false` is passed. A stale key set is never served, even when the refetch fails.

| | |
|---|---|
| Enforced by | `createOidcJwks`, `createOidcJwksFromIssuer`, `discoverOidc`, `verifyIdToken` (key resolution). |
| Trusted inputs | The issuer string the relying party pins; the clock. |
| State | The cached key set, per resolver instance, in process memory (a cache of public keys, rebuilt by a refetch). |
| On failure | `OidcVerificationError` `keys` or `config`; `OidcDiscoveryError` for discovery. |
| Established by | Tests: stale and unreachable keys, timeout abort, https default, size cap boundary, non-finite clock and options. |
| Status | **Hardened.** Signature verification itself is delegated to `jose`. |

### C-101 An ID token binds issuer, audience, nonce, authorized party and the code and access-token hashes

**Statement.** A verified ID token has the pinned `iss` (exact string), contains the configured `aud`, carries `sub`, `iat` and `exp`, uses an allowed asymmetric algorithm in its canonical spelling, and, when the relying party supplies them, matches the `nonce`, the `azp` rule and the `at_hash` and `c_hash` of the values it holds. Symmetric algorithms and `none` are never accepted by default.

| | |
|---|---|
| Enforced by | `verifyIdToken`, `assertCanonicalCompactJws`, `oidcPrincipal`. |
| Trusted inputs | The pinned issuer, audience, nonce, access token and code that the relying party supplies. |
| State | None. |
| On failure | `OidcVerificationError` with a distinct `code` per cause. |
| Established by | Tests: one row per claim, algorithm confusion, `none`, canonical-spelling aliases, the Core `at_hash` example pair. |
| Status | **Hardened.** The nonce, `at_hash` and `c_hash` checks run only when the caller passes the value. |

### C-102 Protected-resource metadata is used only when it is the document asked for

**Statement.** `protectedResourceMetadata` refuses a resource identifier that is not an https URL without a fragment, and `parseProtectedResourceMetadata` refuses any document unless the caller names the `expectedResource` and both the document's `resource` and its embedded audience equal it exactly (RFC 9728 section 3.3). Challenge parameters containing quotes, backslashes or control characters are refused, and token audiences are compared by exact string equality.

| | |
|---|---|
| Enforced by | `protectedResourceMetadata`, `parseProtectedResourceMetadata`, `resourceIdentifierProblem`, `wwwAuthenticate`, `checkTokenAudience`, `checkResourceIndicator`. |
| Trusted inputs | The `expectedResource` the caller derived from the URL it fetched. |
| State | None. |
| On failure | A thrown `Error`, or `{ ok: false, reason }` for the two checks. |
| Established by | Tests: the RFC 9728 examples, mismatched resource and audience, strict defaults, header-injection rows, exact audience matching. |
| Status | **Hardened.** The package fetches nothing and verifies no token signature. |

### C-103 The AuthZEN decision point permits only a verified proof with replay and revocation state

**Statement.** `authzenPdp` permits only when the request carries a signed PCActn that verifies, matches the requested verb, resource and parameters, and is admitted by the policy decision and by the configured `authorizer` (replay counter, budget, revocation). A request with no proof is denied unless `requireProof: false`; a proof with no `authorizer` is denied unless `requireAuthorizer: false`. Every thrown error is a deny with `error.status` 500.

| | |
|---|---|
| Enforced by | `authzenPdp` (`evaluate`, `evaluations`, `evaluateTool`), `authzenHandler`. |
| Trusted inputs | The `resolve` callback (grant, policy, budget), the configured audience, the `authorizer`. |
| State | Held by the `authorizer`'s store, which the integrator supplies. The PDP holds none. |
| On failure | `decision: false` with a stage, or an HTTP 400, 404 or 500 from the handler. |
| Established by | Tests: whole-response rows for every stage, replay denied after one permit, default-deny rows, throwing resolver and authorizer. |
| Status | **Hardened.** Only as strong as `resolve` and the store behind the `authorizer`. |

### C-104 An AuthZEN boxcar is bounded and every item is decided on its own

**Statement.** An Access Evaluations request with more than `maxEvaluations` items (default 100) or an unknown `evaluations_semantic` has every item denied with `error.status` 400. An item missing a subject, action or resource is denied with 400. Short-circuit semantics stop where AuthZEN specifies and never turn a deny into a permit.

| | |
|---|---|
| Enforced by | `authzenPdp.evaluations`, `isAccessEvaluationRequest`, `isAccessEvaluationsRequest`. |
| Trusted inputs | None. |
| State | None. |
| On failure | Per-item deny with a 400 error member; HTTP 400 for a malformed body. |
| Established by | Tests: the 100 and 101 boundary, `Infinity` opt-out, missing pieces, semantics rows. |
| Status | **Hardened.** |
### C-105 A Transaction Token is accepted once, or the verifier says it keeps no replay state

**Statement.** `fromTransactionToken` refuses to run without a replay store: a call with neither `seenTxn` nor the explicit `replayCheck: 'unchecked'` throws `TxnTokenError` (`replay_store_required`) before the token is read. With a store, the `txn` (draft-11) or `jti` (legacy) is passed to it last, after every other check has passed, so a token refused for another reason is not consumed; a repeat, a missing identifier, or a store that throws is refused.

| | |
|---|---|
| Enforced by | `fromTransactionToken`. |
| Trusted inputs | The `seenTxn` store, which must be shared and durable across verifier instances. |
| State | Held by the caller's store; the package keeps none. |
| On failure | `TxnTokenError` (missing store) or a thrown refusal (replayed, no identifier, store failure). |
| Established by | Tests: the missing-store throw, the opt-out literal, first sight / repeat, consume-last. |
| Status | **Enforced**, pinned to draft-ietf-oauth-transaction-tokens-11. The store's durability is the caller's. |

### C-106 The transaction context is a JSON object, and the PCA action keys are never half-present

**Statement.** The draft-11 profile accepts the draft's free-form `tctx` (any JSON object) and returns it unchanged; a `tctx` that is missing, null, an array or a scalar is refused, as is a present `rctx` that is not an object. The names `verb`, `resource` and `aud` are reserved for the PCA action: a `tctx` using any of them must carry all three as strings, so a partial action is never read as an action. The legacy profile still requires the PCA action.

| | |
|---|---|
| Enforced by | `fromTransactionToken` (`tctx` and `rctx` shape gate). |
| Trusted inputs | None beyond the verified signature. |
| State | None. |
| On failure | A thrown refusal (`missing or malformed tctx`, `malformed rctx`). |
| Established by | Tests: the draft Figure 4 payload, the reserved keys, non-object contexts, the independent token vectors. |
| Status | **Enforced.** The package never decides authority from `tctx`; the PCActn chain does. |

### C-107 An ID-JAG is verified in the draft's strict shape by default, and its `jti` is single-use

**Statement.** `verifyIdJag` requires header `typ` `oauth-id-jag+jwt`, a `client_id` equal to the configured `clientId`, and a `jti` that the caller's `consumeJti` store accepts as fresh. Strict mode is on unless the caller passes the literal `strictDraft: false`; in strict mode a missing `consumeJti` or `clientId` is a `config` error, never a quieter verification. The `jti` is consumed last, after the signature, audience, actor, scope and client checks.

| | |
|---|---|
| Enforced by | `verifyIdJag`. |
| Trusted inputs | The issuer key source and the `consumeJti` store. |
| State | Held by the caller's store; the package keeps none. |
| On failure | `IdJagVerificationError` with code `config`, `grant`, `audience`, `actor`, `scope` or the OIDC code. |
| Established by | Tests: strict-by-default, the opt-out literal, consume-last, replay, the independent signed vectors. |
| Status | **Enforced**, pinned to draft-ietf-oauth-identity-assertion-authz-grant-04. |

### C-108 A `jwsd` request proof is accepted once, and only the supported key-proof subset is accepted

**Statement.** `verifyGnapRequest` requires a replay store (`seenProof`) or the explicit `replayCheck: 'unchecked'`; without either it throws `GnapError`. The store receives the hash of the canonical detached JWS and its expiry and is called last; a repeat or a store failure is refused. Only the `jwsd` method with EdDSA and `typ` `gnap-binding-jwsd` is accepted, and every other client key-proof method is refused at grant time even with a holder override.

| | |
|---|---|
| Enforced by | `verifyGnapRequest`, `resolveHolder`. |
| Trusted inputs | The `seenProof` store; the holder key. |
| State | Held by the caller's store; the package keeps none. |
| On failure | `GnapError` (missing store, unsupported method) or `{ ok: false, reason }`. |
| Established by | Tests: the missing-store throw, first sight / repeat, consume-last, the independent detached-JWS vectors, the method refusals. |
| Status | **Enforced** for the documented subset of RFC 9635. |

### C-109 An oversize bridge token is refused before it is parsed

**Statement.** `fromTransactionToken` refuses a token string over 16384 characters, `verifyIdJag` over 16384, and `verifyGnapRequest` a detached JWS over 8192, each before any decoding or signature work. The limit is exact: a string of exactly the limit proceeds to the next gate.

| | |
|---|---|
| Enforced by | `fromTransactionToken`, `verifyIdJag`, `verifyGnapRequest`. |
| Trusted inputs | None. |
| State | None. |
| On failure | A thrown refusal or `{ ok: false, reason }` naming the size limit. |
| Established by | Tests: one over the limit and exactly at it, in each package. |
| Status | **Enforced.** |
### C-110 A DPoP proof is accepted once, only under the key it declares

**Statement.** `verifyDpopProof` refuses a proof when no replay store is configured (`replay_store_required`, the default), when the header `alg` does not belong to the embedded key's type (`alg_jwk_mismatch`), and when its `<jkt>.<jti>` was already recorded (`jti_replay`). A replay store that throws, including the bounded in-memory store when full, refuses the proof (`replay_store_error`); nothing is recorded on any refusal.

| | |
|---|---|
| Enforced by | `verifyDpopProof`, `assertPcaDpop`, `dpopAlgMatchesJwk`, `createInMemoryDpopReplayStore`. |
| Trusted inputs | The verifier clock and the replay store the operator supplies. |
| State | The replay store: atomic `addIfAbsent`, shared across processes in a multi-process deployment (checked by `runDpopReplayStoreConformance`). The in-memory store is bounded and never evicts a live entry. |
| On failure | `DpopVerificationError` with code `replay_store_required`, `alg_jwk_mismatch`, `jti_replay` or `replay_store_error`. |
| Established by | Tests: exact code and message per refusal, the algorithm and key type table, the store capacity and expiry boundary, the conformance suite; an independent resource-server implementation agrees on the verdict matrix. |
| Status | **Hardened.** The in-memory store is single-process; the operator must supply a shared store for more than one verifier. |

### C-111 A certificate-bound token is honoured only for the certificate it names

**Statement.** `assertMtlsBound` parses the presented client certificate as X.509 and compares the SHA-256 of its DER with the token's `cnf` `x5t#S256` in constant time. An unparseable certificate (`cert`), a `cnf` without a usable thumbprint (`x5t_missing`) or a different certificate (`x5t`) is refused.

| | |
|---|---|
| Enforced by | `assertMtlsBound`, `mtlsThumbprint`. |
| Trusted inputs | The certificate bytes the TLS layer authenticated; the token's `cnf`. |
| State | None. |
| On failure | `DpopVerificationError` with code `cert`, `x5t_missing` or `x5t`. |
| Established by | Tests: whole-result outcomes, one-character and padded thumbprint variants, a certificate built at test time; a cross-check against thumbprints computed by Python `cryptography` and OpenSSL. |
| Status | **Hardened.** The TLS handshake and chain validation are the operator's. |

### C-112 A passkey assertion must prove a counter the operator stored, from the right frame

**Statement.** `verifyAssertion` refuses an assertion when the operator did not supply `storedSignCount` (`storedSignCount is required`), when the signature counter did not increase (unless both are zero), and, by default, when the ceremony ran cross-origin or carries a non-boolean `crossOrigin`. The counter rule runs only after the signature verified, so forged input cannot trigger the regression hook.

| | |
|---|---|
| Enforced by | `verifyAssertion`. |
| Trusted inputs | The stored counter, the registered public key, the relying party id and origin allow-list. |
| State | The per-credential counter, kept by the operator. The verifier keeps none. |
| On failure | `{ ok: false, reason }`; never throws. |
| Established by | Tests: exact reasons, counter boundaries including uint32 max, authenticator shapes (platform passkey, hardware key with extension data, user-presence-only key, Ed25519); agreement with `@simplewebauthn/server` on stored and freshly generated assertions. |
| Status | **Hardened.** Registration and attestation are out of scope. |

### C-113 A pushed security event is applied once, only if it verifies and is fresh

**Statement.** `receiveSET` applies a SET to the revocation state only after the size cap, canonical spelling, EdDSA signature, `typ`, `iss`, `aud`, `iat` window and an atomic `jti` replay check all pass, and records the `jti` only after every other check. A missing option, a replay store that throws (including the bounded in-memory store when full) or an event that cannot be mapped under `failOnUnmapped` is a refusal and applies nothing.

| | |
|---|---|
| Enforced by | `receiveSET`, `createInMemorySetReplayStore`. |
| Trusted inputs | The transmitter's public key, the verifier clock, the replay store. |
| State | The replay store (atomic, shared across processes) and the revocation state. |
| On failure | A value `{ ok: false, code, reason }` with a named code; never throws. |
| Established by | Tests: one exact verdict per failure row, state untouched on every failure, the store capacity and conformance. |
| Status | **Hardened.** Delivery, stream management and key distribution are the operator's. |

### C-114 Revocation signals reach the authorize() decision and fail closed

**Statement.** `createRevocationHook` and `createIsRevoked` turn the revocation state into the revocation source of `authorize()`, `requirePCA` and `authorizeExecution`. A revoked `grant_ref` or root capability id, a killed agent (the leaf holder key, or `agentOf`), an undeterminable `grant_ref` or agent, and any error deny; the hook always reports itself enforced. Standard CAEP and RISC events become agent kills through `standardRevocations`; a malformed snapshot is refused and merges nothing.

| | |
|---|---|
| Enforced by | `createRevocationHook`, `createIsRevoked`, `planStandardRevocations`, `applyStandardRevocations`, `restoreRevocationState`. |
| Trusted inputs | The revocation state, fed only by `receiveSET`, `applySET` or a restored snapshot. |
| State | In-memory revocation state; the operator persists `snapshotRevocationState` and restores it before serving. An empty state after a restart revokes nothing. |
| On failure | The hook returns `{ enforced: true, ok: false, reason }`; the snapshot functions throw `SignalsError`. |
| Established by | Tests: whole-result hook outcomes for every revocation source and every undeterminable input, live state reads, event mapping, monotone restore. |
| Status | **Hardened.** Push is best effort; the signed revocation epoch is the pull-side bound. |
### C-115 A revoked SVID, or a revocation source that cannot answer, is refused

**Statement.** When a caller configures `revocation` on `verifyX509Svid` or `verifyJwtSvid`, it is consulted last, for the leaf and every presented signing certificate (X.509) or for the token (JWT-SVID), and only for an SVID that passed every other check. Only a boolean `false` admits. A revoked SVID is refused with `svid_revoked` (`chain_revoked` for a signing certificate). A check that throws, rejects, returns a non-boolean, or is not a function, and a `createRevocationSource` that has no snapshot, a snapshot older than `maxStaleMs`, a failed or a malformed fetch, is refused with `revocation_unavailable`. A revoked SVID never yields an object that `svidToHolder` accepts.

| | |
|---|---|
| Enforced by | `verifyX509Svid`, `verifyJwtSvid`, `createRevocationSource`. |
| Trusted inputs | The revocation data the caller supplies. Revocation is opt-in: without `revocation`, expiry is the only bound. |
| State | The cached snapshot and its fetch time, in the process. |
| On failure | `svid_revoked`, `chain_revoked` or `revocation_unavailable`. |
| Established by | Tests: whole-outcome checks for revoked leaf, revoked signer, throwing, rejecting and non-boolean checks, stale and malformed snapshots, and agreement with go-spiffe on accept/reject for IDs, chains and JWT-SVIDs. |
| Status | **Hardened.** Parsing CRL or OCSP data is out of scope. |

### C-116 A decision is applied once, and an approval redeems once, across processes

**Statement.** The durable CIBA broker applies state changes only through compare-and-set on a versioned store. Of any number of concurrent `resolve` calls, even through separate brokers over one shared store, exactly one wins and its decision stands; an approval redeems exactly once. A store is accepted as a shared store only if it passes the store conformance suite, which flags a `cas` that ignores the version, a check-then-write race, shared object references and a store that forgets on restart.

| | |
|---|---|
| Enforced by | `createDurableCibaBroker`, `createKvApprovalStore`, `approvalStoreCases`, `approvalBrokerCases`. |
| Trusted inputs | The store's atomic compare-and-set. |
| State | The versioned approval records in the store. |
| On failure | `already <status>` for a late decision, `invalid_grant` for a second redemption. |
| Established by | Tests: the conformance suite over the memory, file and KV stores, and defective stores that the suite must flag. |
| Status | **Hardened.** Correctness of a third-party store is the operator's to prove by running the suite. |

### C-117 A missing or corrupt approval store is a refusal, never an approval

**Statement.** `createDurableCibaBroker` has no default store: construction without one throws. A stored record that is not valid versioned JSON throws `corrupt_record`; a directory store whose lock cannot be taken throws `lock_timeout` and writes nothing; any throw or rejection from the store reaches the caller. A decision is never inferred from a missing or unreadable record.

| | |
|---|---|
| Enforced by | `createDurableCibaBroker`, `createKvApprovalStore`, `createDirectoryKv`. |
| Trusted inputs | None. |
| State | None beyond the store. |
| On failure | `TypeError`, `ApprovalStoreError` (`corrupt_record`, `lock_timeout`, `bad_key`). |
| Established by | Tests: construction without a store, malformed and versionless records, stale lock, escaping keys. |
| Status | **Hardened.** The human decision itself is unauthenticated data (the caller authenticates the decider). |

### C-118 A SCIM filter the server does not support is refused, never ignored

**Statement.** `scimHandler` evaluates only `attr eq "value"` and `attr eq true|false` on a fixed attribute set. Every other filter form, including every RFC 7644 section 3.4.2.2 example that uses another operator, a logical operator or a value path, a non-string filter and an unknown attribute, is a 400 `invalidFilter`. It is never treated as absent, so a client cannot receive an unfiltered list in place of a filtered one.

| | |
|---|---|
| Enforced by | `parseFilter`, `scimHandler`. |
| Trusted inputs | None. |
| State | None. |
| On failure | 400 `invalidFilter`. |
| Established by | Tests: the RFC filter examples with exact bodies, malformed filters, unsupported attributes. |
| Status | **Hardened.** |

### C-119 SCIM access needs authentication, and the attested identity cannot be changed

**Statement.** `scimHandler` cannot be constructed without an `authenticate` function (or the explicit `allowUnauthenticated: true`); only an exact `true` admits, and a denied request never touches the store. PUT and PATCH change governance attributes only: the `id` and the attested passport are immutable, and an attribute that is immutable or unknown is a 400 `mutability`.

| | |
|---|---|
| Enforced by | `scimHandler`. |
| Trusted inputs | The `authenticate` hook. |
| State | The agent store. |
| On failure | `TypeError` at construction, 401, 400 `mutability`. |
| Established by | Tests: false, throwing, Promise and non-boolean authenticate results, untouched store on denial, RFC PatchOp examples refused as immutable. |
| Status | **Hardened.** The Agent schema URN is a PCA-defined extension, not an IANA registration. |
## Production-tier feature invariants (intent frontier, software attestation, optimistic execution)

### C-140 Frontier results can only tighten

**Statement.** The result of a semantic judge quorum, an objective risk resolution or a proof-of-progress step is typed as `ok`, `escalate` or `deny` and can only lower a decision. A malformed or unrecognised result is `deny`, never `ok`.

| Enforced by | `frontierSignals.semanticSignal`, `progressSignal`, `objectiveSignal` with `tighten` (G-T9). |
| Trusted inputs | The pinned judge, state-source and verifier keys. |
| On failure | `deny`, or `escalate` when only a human can settle it. |
| Established by | Tests: "G-T9 over the frontier signals: no result of any frontier module can widen a decision". |
| Status | **Production**, `pending_ci` (the mutation gate and the CI jobs must pass once). |

### C-141 Objective risk can only raise risk

**Statement.** When a grant commits objective-risk facts, the server folds them with its own class baseline: the lower reversibility and the higher blast radius count, a non-finite value is the worst case. A committed fact that cannot be reproduced is denied unless the grant chose the heuristic.

| Enforced by | `frontierSignals.tightenRiskInputs` in the server risk derivation. |
| Trusted inputs | The instance's committed registry and graph. |
| On failure | Denied (`objective_risk`), or the heuristic when the grant says so. |
| Established by | Tests: "tightenRiskInputs: the objective path can only raise risk". |
| Status | **Production**, `pending_ci`. |

### C-142 Every attestation chain runs the strict profile

**Statement.** The MAA x5c and key-set chains, the GCP x5c chain and the NVIDIA device chain refuse a leaf that is a CA, an issuer that is not a CA or lacks keyCertSign, an exceeded pathLenConstraint and any unrecognised critical extension, exactly as the AMD and Intel chains do.

| Enforced by | `strictChainError` in each chain verifier. |
| Trusted inputs | The configured trust anchors and pins. |
| On failure | The chain, step or admission is refused with a typed reason. |
| Established by | Tests: "strictChainError: the shared profile". |
| Status | **Production**, `pending_ci`. |

### C-143 Intent and progress defaults fail closed

**Statement.** The intent session store must be durable unless the caller opts out, `verifyIntentRequired` needs a clock, `verifyProgressStep` refuses self-reported state unless the caller opts out, and a grant cannot choose the heuristic fallback for objective risk: only the verifier can.

| Enforced by | `admitIntentAction`, `verifyIntentRequired`, `verifyProgressStep`, `resolveObjectiveRisk`. |
| Trusted inputs | The configured trust anchors and pins. |
| On failure | The chain, step or admission is refused with a typed reason. |
| Established by | Tests: "B16: requireDurable defaults to true and refuses a volatile store". |
| Status | **Production**, `pending_ci`. |

### C-144 Bond settlement has no in-memory default

**Statement.** The shipped optimistic extension has no in-memory bond ledger: settlement needs a durable `BondStore`; the Map-backed ledger exists only behind the testing entry.

| Enforced by | `StoreBondLedger` and the `ext/optimistic` export surface. |
| Trusted inputs | The configured trust anchors and pins. |
| On failure | The chain, step or admission is refused with a typed reason. |
| Established by | Tests: "B17: no in-memory default in ext/optimistic". |
| Status | **Production**, `pending_ci`. |

## Adapters, guards, tooling and stable-package invariants

The framework adapters, execution guards, gateway, tooling packages and stable support packages each make their own claim under the same rules. The Status row of each entry names the tier of the units it covers.

### C-145 A framework adapter runs your handler only for a proof bound to the operation your route executes

**Statement.** The Express, Fastify, Hono, Next.js and Fetch adapters make no decision of their own. Built with an `operation` mapping, each request goes through the strict `authorize` pipeline: the handler runs only if the PCActn is for exactly the verb, resource and params the mapping returns from the server's own routing, and the audience, grant resolver, state store and revocation hook are all present. No proof, an unknown grant, a proof for another operation or other params, an over-limit, replayed or revoked one, an `operation` mapping that returns nothing or throws, and a missing component each end in a 401 or 403 before the handler. An adapter built without `operation` (or without `audience`) is refused at construction unless the loudly named migration opt-in is set. The `executeAuthorized` helper then runs the side effect at most once per authorization id.

| | |
|---|---|
| Enforced by | `pcaExpress` (pca-express), `pcaFastify` (pca-fastify), `pcaHono` (pca-hono), `withPCA` (pca-next), `withPCA` and `createPcaFetchGuard` (pca-fetch), over `requireAuthorized` / `authorize` in `@atlasauth/pca`. |
| Trusted inputs | The `operation` mapping (the server's routing, never the proof), `resolveGrant`, the `budgetStore` and the revocation hook. |
| State | The replay counter and trust budget in `budgetStore`; operation records in the `OperationStore` used with `executeAuthorized`. |
| On failure | 401 with a `WWW-Authenticate` challenge (no or unreadable proof, unknown grant), 403 (operation, params, limit, replay, revocation or configuration), a thrown `TypeError` at construction; the handler does not run. |
| Established by | Tests: the shared adapter acceptance matrix run against each adapter, the per-adapter 401 and unknown-grant tests, the construction refusals, and the once-per-id README flow. |
| Status | **Production (pending CI).** Replay and budget protection are only as shared and durable as the store the integrator supplies; the cryptography has not been independently audited. |

### C-146 The MCP agent side signs a proof only for the exact call it makes, and forges nothing where it cannot

**Statement.** `pcaFetch` and `withPCA` from `@atlasauth/pca-mcp` add a fresh PCActn to a `tools/call` request, committing to the tool arguments by digest and taking the verb and resource from the integrator's mapping. Where no proof can be built (an unmapped tool, a request that is not a JSON `tools/call`) the request goes out unchanged with no proof, so a server that requires PCA refuses it. A `withPCA` tool whose agent's own grant does not permit the call returns an MCP tool error and does not run the handler. The package authorizes nothing; the server's verifier decides.

| | |
|---|---|
| Enforced by | `pcaFetch`, `withPCA`, `guardToolResult`, `conformToolCall` (pca-mcp). |
| Trusted inputs | The agent's own grant and key, and the integrator's `toolAction` mapping (the server must use the same one). |
| State | None kept by the package; each proof takes a new counter from the agent. |
| On failure | No `PCA-Action` header (server refuses), an MCP tool error with `isError: true` (local deny), `unknown_verb` from `conformToolCall` for an undeclared tool, a thrown error for a decision about a verb or parameter the draft lacks. |
| Established by | Tests: per-call proof binding, pass-through of unmapped or non-tool requests, the audience override, the local over-cap deny that does not run the handler, and the schema draft and closed-world check. |
| Status | **Production (pending CI).** It is the agent half only; the guarantee that a call is authorized is the server's (C-147). |

### C-147 An MCP resource server refuses any tool call not covered by a verified proof for exactly that call

**Statement.** `authorizeToolCall` is the complete check for one MCP tool call. The PCActn must be present and well formed, chain to a grant from the server's own store, be signed by the holder, name this server as its audience (RFC 8707), come from a trusted issuer (RFC 9207) and carry the scopes the tool needs. Its signed verb and resource must equal what the server's `toolAction` maps the tool to, and the arguments must hash to the signed params digest; the grant's limits, caveats, revocation, replay counter and trust budget then apply, with a money-moving call priced by the server from the verified amount. A missing component (`tool`, `toolAction`, `resolveGrant`, `state`, `isRevoked`), an unmapped tool or a throwing callback is refused, never downgraded to admission. Admission alone is available only by the explicit `admissionOnly: true`.

| | |
|---|---|
| Enforced by | `authorizeToolCall`, `authorizeRequest`, `admitRequest`, `toolCallRisk` (pca-mcp-rs). |
| Trusted inputs | `resolveGrant`, `isRevoked`, `toolAction`, the `state` store, the `resource` and `authorizationServers` the server configures. |
| State | Replay counters and trust budgets in `state`. |
| On failure | 401 (no or invalid proof), 403 (policy, binding, scope, configuration, callback error), each with a `WWW-Authenticate` challenge that carries only an error code. |
| Established by | Tests: refusal of an unpermitted verb, an over-limit amount, a replay, another tool, resource or arguments, a missing component, a throwing callback, a process-local store under `multiInstance`, and of what admission alone would admit. |
| Status | **Production (pending CI).** Replay and budget protection are only as shared as `state`. Step-up is verified when presented but never driven by this call. |

### C-148 The gateway verifies against the grant by default, and an unconfigured or unmatched request is denied

**Statement.** `pca-gateway` requires an explicit `policy`. The default mode is full policy: the agent signs the request's real params with the request binding inside them, and the gateway runs the full verifier (the grant's predicates, limits and caveats, a required revocation check, a required replay counter and trust budget). A gateway built without a `policy`, or in full mode without `state`, `isRevoked` or `params`, throws at construction and its `authorize` denies every request; it never falls back to signature-only. A route not in the route map is denied (`unmatchedRoute: 'deny'` by default), a proof for another audience, verb, resource, request or body is refused, and ambiguous request paths (dot segments, doubled slashes, path parameters, encoded separators) are refused before route matching. On allow, the adapters overwrite or remove every `x-pca-*` header so a client cannot forge one to the upstream.

| | |
|---|---|
| Enforced by | `createGateway`, `authorize`, `envoyExtAuthz`, `envoyGrpcExtAuthz`, `cloudflareWorker`, `lambdaAuthorizer`, `lambdaSimpleAuthorizer` (pca-gateway). |
| Trusted inputs | `resolveGrant`, `isRevoked`, the route map, the `state` store, the configured audience. |
| State | Replay counters and trust budgets in `state`; an optional `replayGuard`. |
| On failure | 400 `invalid-path`, 401 (`no-proof`, `invalid-proof`, `unknown-grant`, `verify-failed`), 403 (`wrong-audience`, `unmapped-route`, `insufficient-capability`, `request-mismatch`, `proof-rejected`, `replayed-proof`), 503 `replay-guard-unavailable`. |
| Established by | Tests: no-policy construction error, the over-limit refusal and single use in full mode, deny-by-default routing, header scrubbing, path hardening, and the recorded Envoy, Lambda and Worker runs. |
| Status | **Production (pending CI).** The deployed AWS API Gateway service, TLS between Envoy and the check service, load behaviour and Istio's gRPC provider are not validated. |

### C-149 Signature-only gateway mode is an explicit opt-out and still needs single use and revocation

**Statement.** `policy: { mode: 'signature-only' }` is the only way to run the gateway without evaluating the grant's limits. In it the proof and its request binding are verified, but limits, a trust budget and plan-root authorization are not, so the verified proof is a bearer for the matched route and the resource server's own guard stays the authority. The mode refuses to start without a `replayGuard` (each proof single-use) and a revocation check (`requireChecks` defaults to `['revocation']`; waiving it is an explicit `requireChecks: []`). A required check that is merely not enforced is a deny.

| | |
|---|---|
| Enforced by | `createGateway`, `authorize` (pca-gateway), in signature-only mode. |
| Trusted inputs | `replayGuard`, `hooks.revocation`, `resolveGrant`, the route map. |
| State | The `replayGuard` claims (process-local for `memoryReplayGuard`). |
| On failure | A thrown construction error without `replayGuard` or the revocation hook; 403 `proof-rejected` for a required check that is not enforced; 403 `replayed-proof`; 503 when the guard throws or is full. |
| Established by | Tests: the construction errors, the default required revocation check, single use of a proof, and the documented gap (a $400 body admitted) that full mode closes. |
| Status | **Production (pending CI).** A pre-filter by design: it does not read the grant's limits, and `memoryReplayGuard` does not span instances or restarts. |

### C-150 The conformance kits report a defective implementation as failing, and never an unobserved one as passing

**Statement.** `pca-testing` stands a real verifier in for the resource server: `fakeVerify` is the core verifier unchanged, `expectVerifies` throws when it denies, `expectDenied` throws when it allows, and `runAdapterAcceptance` returns outcomes that differ from `ADAPTER_ACCEPTANCE_EXPECTED` for an adapter that allows an over-limit, rebound, replayed or misconfigured request. `pca-store-conformance` records concurrent histories against a replay or counter store and checks them for linearizability: a double accept, a forgotten nonce after restart, an early eviction or an equal counter accepted twice is a `fail` (exit 1), and a run in which nothing definite was observed or the search ran out of budget is `unresolved` (exit 3), never `pass`. A skipped test (a non-durable declaration, no module path for the crash test) is reported as skipped with its reason.

| | |
|---|---|
| Enforced by | `fakeVerify`, `expectVerifies`, `expectDenied`, `runAdapterAcceptance` (pca-testing); `runConformance`, `checkHistory`, `describeStoreConformance` and the `pca-store-conformance` command (pca-store-conformance). |
| Trusted inputs | The adapter or store under test, and the integrator's choice to run the kit. |
| State | None kept; each run records its own history. |
| On failure | A thrown assertion error, a `fail` / `unresolved` report, exit codes 1, 3 or 2 (usage or adapter error). |
| Established by | Tests: the tamper and wrong-audience cases for the test kit; the known-defective reference stores (read-then-write, volatile, evicting, non-strict counter) that the store kit must flag; the unresolved-is-not-pass and exit-code tests. |
| Status | **Production (pending CI).** A pass is evidence for the histories generated, not a proof for every schedule; test-only helpers are not for production use. |

### C-151 An attach-side tool adapter signs the call it is about to make and never runs a tool it could not bind

**Statement.** `withPCA`, `withPCATools`, `handleToolUse`, `dispatchToolCall` and the LangChain and LlamaIndex `withPCA` wrap a tool so that each call first builds a PCActn bound to that call's own verb, resource and arguments, then runs the tool with the proof in hand. A tool the mapping declines, a tool with nothing to execute, or a call whose proof cannot be built does not run. The wrappers that dry-run (`withPCA` in the AI SDK, LangChain and LlamaIndex packages) throw `PcaDenied` before the tool when the agent's local policy would refuse, unless `failFast` is turned off. They sign; they never authorize: the resource server's verifier decides.

| | |
|---|---|
| Enforced by | `withPCA` and `withPCATools` in the AI SDK adapter; `handleToolUse` and `handleToolUses` in the Anthropic adapter; `dispatchToolCall` and `dispatchToolCalls` in the OpenAI adapter; `withPCA` in the LangChain and LlamaIndex adapters. |
| Trusted inputs | The `Agent` that holds the grant and key; the caller's tool-to-capability mapping. |
| State | None kept by the adapters. |
| On failure | `PcaDenied` (dry-run), `Error` (no `execute`, unmapped tool, malformed arguments), or an error-shaped `tool_result` (Anthropic). |
| Established by | Tests: each adapter emits a verifiable PCActn, fast-fails an over-cap call without running the tool, refuses an unmapped tool and keeps the tool's other fields. |
| Status | **Production (pending CI).** The Anthropic and OpenAI adapters do not dry-run, so an over-cap call is signed and refused only by the server |

### C-152 An execution guard refuses to run a tool without a proof for exactly this call

**Statement.** In full-policy mode (the default) `withPcaTool` and `pcaTools` in the Mastra, OpenAI Agents and Vercel AI SDK guards run the tool only when a PCActn is present, decodes, is for the guard's verb, verifies against the grant and audience, is within the grant's limits and caveats, is bound to the tool input the agent signed, is not revoked and has not been used before. Each refusal throws `PcaToolDenied` with a `kind` (`missing`, `malformed`, `binding`, `verify`, `policy`, `replay`, `revoked`, `config`) before the tool body runs. A throw or rejection from the grant resolver, the revocation check, the state store or the clock is a refusal, never an approval.

| | |
|---|---|
| Enforced by | `withPcaTool`, `pcaTools` and `authorizeExecution` in the Mastra, OpenAI Agents and Vercel AI SDK guard packages. |
| Trusted inputs | The grant (or `resolveGrant`), the `isRevoked` callback and the shared `state` store. |
| State | Replay counters and trust budgets in the `state` store. |
| On failure | `PcaToolDenied` with the `kind` above; the tool does not run. |
| Established by | Tests: no, malformed, wrong-audience and wrong-verb proofs; a $400 refund under a $100 grant; a replay; a revoked grant; a tool input that differs from the signed params; a resource mismatch. |
| Status | **Production (pending CI).** Replay safety across processes needs a shared store; the guard is the local boundary, not the remote resource server. |

### C-153 A guard that is misconfigured fails at construction and never downgrades to signature-only

**Statement.** Full-policy mode needs a grant or `resolveGrant`, a `state` store, an `isRevoked` check, a string `audience` and an operation or `verb`; a guard built without any of them throws `TypeError` when it is built. Signature-only checking is reachable only by `mode: 'signature-only'` together with `verify`; `authorize` with `verify`, `verify` without the mode, the mode without `verify`, `authorize` with the mode, and an unknown mode are all refused at construction. In signature-only mode a guard with no verifier refuses every call. The OpenAI Agents input guardrail and tool guard always check the signature only and say so.

| | |
|---|---|
| Enforced by | `withPcaTool`, `pcaTools`, `pcaInputGuardrail` and `pcaToolGuard` in the Mastra, OpenAI Agents and Vercel AI SDK guard packages. |
| Trusted inputs | The operator's guard options. |
| State | None. |
| On failure | `TypeError` at construction; `PcaToolDenied` of kind `verify` or `config` at call time. |
| Established by | Tests: the construction-matrix test and the per-tool `verify` override test. |
| Status | **Production (pending CI).** Signature-only mode does not read limits, bind the input or stop a replay; the guardrails are a pre-filter only. |

### C-154 A risky step or tool waits for an approval, and a forbidden one is refused

**Statement.** `guardStep` (Mastra) throws `PcaStepDenied` when the agent's policy forbids a step and `PcaStepUpRequired` when it needs a co-sign that `approved` does not supply, before the step runs. `pcaNeedsApproval` and `withApproval` (OpenAI Agents) mark a risky or forbidden tool as needing approval; `pcaPrepareStep` (Vercel AI SDK) removes a tool that needs a co-sign from the next step's `activeTools` and reports it. These are risk gates on the agent's own policy, not proof checks.

| | |
|---|---|
| Enforced by | `guardStep`, `reviewStep`, `pcaNeedsApproval`, `withApproval`, `pcaPrepareStep` and `pendingStepUps`. |
| Trusted inputs | The `approved` callback; the `intent` mapping; the agent's policy. |
| State | None. |
| On failure | `PcaStepDenied`, `PcaStepUpRequired`, `needsApproval: true`, or the tool removed from `activeTools`. |
| Established by | Tests: a risky step is flagged and routed to step-up, a safe step runs, an approved step-up passes, a forbidden step is denied. |
| Status | **Production (pending CI).** A step or tool whose `intent` returns nothing is treated as safe; `pcaPrepareStep` acts after the step that made the call and does not act on a denial; the SDK honours `needsApproval` and `activeTools`. |

### C-155 A Python agent-framework guard runs no tool without a proof for exactly this call

**Statement.** The Microsoft Agent Framework, CrewAI, FastMCP, Google ADK, Haystack, LangGraph and Pydantic AI guards run a tool only when a proof is present and decodes, resolves to a known grant, verifies for the guard's audience, authorizes the tool's required capability, and (in the default authorize mode) is for exactly this call: within the grant's limits and caveats, bound to the call arguments, not revoked and not replayed. Missing authorize options, store or revocation check refuse every call with `authorize_config`; a tool with no exact capability or with unbindable positional arguments is refused in authorize mode; signature-only checking is the explicit `signature_only=True`, refused alongside `authorize`. Tools left out of a CrewAI or Haystack `require` map are not wrapped.

| | |
|---|---|
| Enforced by | `pca_tool` and `pca_function_middleware` (agent-framework-pca); `pca_tool`, `guard_tools`, `guard_crew` and `PcaToolGuard` (crewai-pca); `pca_guard` (fastmcp-pca); `pca_tool` and `pca_before_tool_callback` (google-adk-pca); `pca_tool`, `guard_tools` and `guard_tool_invoker` (haystack-pca); `PcaToolNode`, `guard_tool_node`, `pca_tool` and `pca_guard_node` (langgraph-pca); `pca_tool` and `PCAGuard` (pydantic-ai-pca). |
| Trusted inputs | `resolve_grant`, `is_revoked` and the `state_store`; the `require` mapping. |
| State | Replay counters in the `state_store`. |
| On failure | `PcaToolDenied`, `PCAAccessDenied` or `PCARejected` (or a deny result the framework returns to the model); `ValueError` at construction. |
| Established by | Tests: the shared authorize cases (a $400 call under a $100 grant, a $50 proof used for $400, a proof for another tool, a replay, a revoked grant, a missing store) in each package, and per-package missing, undecodable, wrong-audience, unknown-grant and insufficient-capability cases. |
| Status | **Production (pending CI).** Verification is delegated to the Python reference; the risk score and agent binding are not evaluated; `pca_guard_node` is a signature-level routing check. |

### C-157 A key rotation re-issues only what the old chain carried, and only with the right keys

**Statement.** `rotateAgentKey`, `rotatePrincipalKey`, `revokeAndReissueSubtree` and `compromisedKeyFlow` re-issue a capability chain with the real `mintRoot` and `delegate` builders, carrying exactly the caveats of the hops they replace, so a re-issue never widens authority and carried budget allocations stay monotone. Each hop is re-signed only by a secret whose public key is that hop's issuer (or the safe ancestor's holder); a wrong secret, a wrong number of hop secrets, a root-only chain for an agent rotation, an unknown or root holder for a subtree re-issue, a new key equal to the key being rotated out (or one held inside the compromised subtree), a child with fewer caveats than its parent and a non-finite `now` all throw, and the error names public keys only.

| | |
|---|---|
| Enforced by | `rotateAgentKey`, `rotatePrincipalKey`, `revokeAndReissueSubtree`, `compromisedKeyFlow` in `@atlasauth/pca-rotate`. |
| Trusted inputs | The chain being rotated and the signing secrets the caller supplies; the core `verifyChain` that accepts the result. |
| State | None. The functions are pure and return a new chain with a revocation record. |
| On failure | The call throws; no chain and no record is returned. |
| Established by | Tests: caveat-preserving re-issue verified by `verifyChain`, re-root of a deep chain with monotone budgets, wrong-secret and wrong-count refusals, and an end-to-end rotation against a revocation registry. |
| Status | Production (pending CI): producing and distributing the new chain is the caller's. |

### C-158 A rotation's revocation is applied all or nothing

**Statement.** `applyRotation` revokes every capability id a rotation replaced in a revocation registry, or leaves the registry as it found it. It refuses, before any write, a record that names no capability, an invalid id, and a re-issued chain that shares an id with the revoked set. If a write fails part-way, the ids this call added are removed again and the original error is rethrown; ids that were already revoked are kept. It revokes capability ids only, never the holder or issuer key, because the old key still signs a re-issued agent leaf.

| | |
|---|---|
| Enforced by | `applyRotation` in `@atlasauth/pca-rotate`. |
| Trusted inputs | A registry sink whose `revoke`, `unrevoke` and `lookup` behave as documented. |
| State | The revocation registry the caller passes. |
| On failure | Throws; the ids this call added are unrevoked (best effort), the original error is the one reported. |
| Established by | Tests: rollback after a mid-way failure, refusals before any write, and a registry end-to-end where the old chain is denied and the new one is not. |
| Status | Production (pending CI): rollback is best effort if the undo write itself fails. |

### C-159 A step-up webhook delivery is accepted only if it is authentic, fresh, well-formed and new

**Statement.** `verifyWebhook` returns false, and never throws, for a secret under 16 bytes, a malformed, oversized or conflicting-timestamp header, a timestamp outside the tolerance, a non-finite tolerance or clock, and a signature that matches no `v1` entry (compared in constant time). `parseEvent` refuses an event whose `id` is not the digest of its fields. `verifyDelivery` additionally takes the event id once from a replay store, so a replay inside the tolerance window is refused; a missing store, a throwing store, a bad signature or a malformed event is a refusal. A bad signature does not burn the event id, and no refusal reason contains the secret or the payload.

| | |
|---|---|
| Enforced by | `signWebhook`, `verifyWebhook`, `verifyDelivery`, `parseEvent` in `@atlasauth/pca-events`. |
| Trusted inputs | The shared secret, the clock, and the replay store's atomic `consumeOnce`. |
| State | The replay store (event ids until the tolerance window closes). |
| On failure | `verifyWebhook` is false; `verifyDelivery` returns `{ ok: false, reason }`; `parseEvent` and `signWebhook` throw. |
| Established by | Tests: forged, tampered, stale, truncated and oversized signatures, the empty-key forgery, id forgery, replay, and a throwing or absent store. |
| Status | Production (pending CI): the HMAC scheme; anyone holding the secret can sign, and replay protection is as strong as the store passed in. |

### C-175 Telemetry observes a verification and neither changes its outcome nor leaks a credential

**Statement.** `instrumentGuard` returns the guard's result (or rethrows its exception) unchanged whatever the tracer, the meter or the redactor does; a result that is not an explicit `ok: true` is reported as a deny; non-finite numbers and non-string verb, resource or reason are not exported; the span is ended exactly once on every path. Every string put in a span attribute, a status message or a recorded exception goes through `redactSecrets` (or the supplied redactor), which removes JWTs, bearer and basic credentials, URL userinfo, secret-named pairs and long token runs and cuts text to 256 characters; a thrown error is recorded as a fresh error with only the redacted message.

| | |
|---|---|
| Enforced by | `instrumentGuard`, `pcaSpanAttributes`, `redactSecrets` in `@atlasauth/pca-otel`. |
| Trusted inputs | The wrapped guard's own decision; the tracer and meter are not trusted. |
| State | None. |
| On failure | Telemetry errors are swallowed; with no tracer and no meter the wrapper is a pass-through. |
| Established by | Tests: throwing tracer, span and meter, rethrow unchanged, single span end, redaction of a recorded exception, non-finite values dropped. |
| Status | Production (pending CI): redaction is a pattern net, not a proof. |

### C-176 A stored third-party token is released only to a verified, in-scope, unreplayed, unrevoked PCActn

**Statement.** `TokenVault.getConnectionToken` releases an access token only when the PCActn's chain is rooted at the connection's bound principal, passes the core verifier (including the pinned audience and any post-quantum pin), is not reported revoked, is a use action for exactly that provider connection, and the requested scopes are within the intersection of the chain's `oauth_scope` caveats. With the default strict profile it also takes the action once from a replay store, and the constructor refuses to build without an encrypting store, a replay store, a revocation source and an audience. A revocation or replay source that throws refuses. A stale token with no refresh token, or an expiry or clock that is not finite, is never released as fresh; a refresh failure leaves the stored token unchanged; concurrent refreshes share one request. Tokens at rest in `EncryptedConnectionStore` are sealed per field with a key bound to the connection and field, so plaintext, tampered, moved or unknown-key records are refused; store and provider errors never carry a token or client secret.

| | |
|---|---|
| Enforced by | `TokenVault`, `EncryptedConnectionStore`, `LocalKeyWrapper`, `grantedOAuthScopes` in `@atlasauth/pca-connect`. |
| Trusted inputs | The bound principal recorded with the connection, the replay and revocation sources, the key wrapper or KMS, and the provider's token endpoint. |
| State | The connection store, the replay store, the in-flight refresh map. |
| On failure | A typed `VaultError` (`not_authorized`, `scope_exceeded`, `expired_no_refresh`, `refresh_failed`, `unknown_connection`, `store_error`); no token is returned. |
| Established by | Tests: forged signature, wrong root, scope excess and attenuation, replay, revocation, stale and NaN clocks, refresh single-flight and redaction, envelope-encryption refusals, a forged post-quantum root. |
| Status | Production (pending CI): the returned token is not narrowed except on a provider that supports it. |

### C-177 Authorization and token requests cannot be redirected or altered by caller-supplied values

**Statement.** The connector catalog builds authorize URLs, code exchanges, refreshes and token placement only from validated manifests. A URL variable must be a single DNS label so it cannot move a request to another host; manifest URLs with credentials, fragments or a placeholder host are refused; the builders own `client_id`, `redirect_uri`, `scope`, `state`, PKCE and grant parameters and refuse `extraParams` that set them; scopes must be well-formed, unique and offered by the manifest; a caller `state` is at least 16 characters; PKCE is S256 with an RFC 7636 verifier unless `plain` is allowed on purpose; the redirect URI must be absolute, https (or localhost http), with no fragment or credentials; an access token with whitespace or control characters is not placed in a header. A registered provider is not replaced silently and can be pinned by digest. A token endpoint failure, a malformed body or a body without an access token is refused and any echoed secret is redacted.

| | |
|---|---|
| Enforced by | `validateManifest`, `ProviderRegistry`, `buildAuthorizeUrl`, `applyAccessToken`, `exchangeCode`, `refresh` in `@atlasauth/pca-connectors`. |
| Trusted inputs | The registered manifests (review and pin their digest) and the provider's token endpoint. |
| State | The provider registry. |
| On failure | `ConnectorError`, `UnknownProviderError` or `ManifestValidationError`; no URL or connection is produced. |
| Established by | Tests: host-injection variants, reserved parameters, state and PKCE rules, redirect rules, registry swap and digest pinning, redaction of echoed secrets. |
| Status | Production (pending CI): manifests describe public endpoints and can go stale; keeping and checking `state` on the callback is the caller's. |

### C-178 A report never says more than the evidence it was given

**Statement.** The reporting packages do not turn missing or contradicted evidence into success. `explainVerification` and `explainDecision` report an allow only for an explicit `allow: true` (or `admit: true`) with per-check evidence and no failing check, and explain a truthy non-boolean, a contradicted allow, an allow with no evidence, a missing or malformed input and an explainer that throws as denials; a check the verifier did not enforce is never shown as passed; chains are labelled `UNVERIFIED` unless verified. `toAuditEvent` records a deny unless the verifier result is an explicit allow, reports human approval only when the core verifier ran a threshold check that passed, and `toComplianceReport` marks every control `not-evidenced` with no events and rejects an unknown framework; `frameworkReport` warns where the records do not evidence a control. `runDoctor` treats a run in which nothing was checked, an invalid configuration, or a check that throws as a failure, and scrubs credentials from everything it prints.

| | |
|---|---|
| Enforced by | `explainVerification`, `explainDecision`, `explainChain` in `@atlasauth/pca-explain`; `toAuditEvent`, `toComplianceReport`, `frameworkReport` in `@atlasauth/pca-compliance`; `runDoctor`, `verdictOf` in `@atlasauth/pca-doctor`. |
| Trusted inputs | The verifier result, policy decision and records the caller passes; the deployment under check for the doctor. |
| State | None. |
| On failure | A denial, `not-evidenced`, `warn` or `fail` result; a thrown error only for an unknown framework or a usage error. |
| Established by | Tests: allow contradicted by a failing check, truthy non-booleans, malformed input, unverified shares, empty event sets, skip-only and throwing doctor runs, scrubbed output. |
| Status | Production (pending CI): these describe a result produced elsewhere; they are not a certification, and a skipped doctor check is not a pass. |

### C-179 An untrusted value cannot reach an exfiltrating sink

**Statement.** Every value carries a capability recording its sources and whether it is trusted; a derived value is trusted only if every input is, and capabilities are frozen so a holder cannot add a sink or remove a source. `classifyFlow` and `checkAction` deny a value that was not made by the module, a sink that is not valid or has no policy, a governor that throws, an argument list that is not a list, has a hole or has the wrong length, and any value whose provenance is forbidden at that sink; an untrusted value at an external-send sink is a hard deny and at a sensitive sink a step-up. `tag` refuses a trusted capability with no sources or with a tool source, and `dualContext` refuses an untrusted query or a quarantined result that is not tagged.

| | |
|---|---|
| Enforced by | `tag`, `derive`, `combineCaps`, `classifyFlow`, `checkAction`, `dualContext` in `@atlasauth/pca-dataflow`. |
| Trusted inputs | Correct tagging at the boundary: a value tagged as trusted is trusted. |
| State | None; capabilities are immutable. |
| On failure | `deny` (or a thrown `TypeError` for `derive`, `tag` and `dualContext` misuse); never an allow. |
| Established by | Tests: look-alike and revived values, immutable sets, throwing or invalid governors, holes in argument lists, worst-outcome-wins, readers meet, tool output never trusted. |
| Status | Production (pending CI): guarantee voided by wrong tagging, which it cannot detect; no content inspection. |

### C-185 A policy translation never allows what its source refuses, and an incomplete one allows nothing

**Statement.** The Cedar, Rego and OpenFGA translators compile a policy into PCA predicates only for the constructs they model. A construct they do not model is dropped, never approximated: a dropped permit or rule grants nothing, a Cedar condition that reads an absent attribute makes the policy not apply, and a dropped Cedar `forbid` or any parse error is recorded in `report.errors`. `decide` denies every action while `report.errors` is not empty, applies `forbid` over `permit`, and an empty predicate list allows nothing. A malformed OpenFGA model or tuple list, an unterminated Rego block and a cyclic model produce an error or an empty grant, not an allow.

| | |
|---|---|
| Enforced by | `cedarToPca`, `regoToPca`, `openfgaToPca` and `decide` in `@atlasauth/pca-policy-bridge`. |
| Trusted inputs | The policy text, model and tuples are untrusted; the caller reads `report` and consults `decide` (or enforces `denies`). |
| State | None. |
| On failure | The construct is listed in `report.skipped` or `report.errors`; `decide` returns `translation incomplete (fail closed)` or denies. |
| Established by | Tests: "still fails closed on genuinely unmodeled constructs (arithmetic / method calls)", "drops an entire rule containing an unmodeled construct (fail closed)", "fails closed on a malformed model", "terminates and fails closed on a cyclic model", and the `decide` cases for an incomplete translation. |
| Status | Production (pending CI): the supported subset is deliberately small. |

### C-186 On the checked corpus the bridge never allows what the real engine denies

**Statement.** For a generated corpus of Cedar policy sets, Rego modules and OpenFGA models, decided by the real engines (the Cedar authorizer, OPA and an OpenFGA server), the bridge never allows a request the engine denies, and when a translation reports nothing skipped and no errors its decision equals the engine's. The corpus, the engine versions and the regeneration script are pinned with the package.

| | |
|---|---|
| Enforced by | `cedarToPca`, `regoToPca`, `openfgaToPca`, `decide`; the replay in the differential suite of `@atlasauth/pca-policy-bridge`. |
| Trusted inputs | The recorded engine decisions in the fixtures; the pinned engine versions that produced them. |
| State | None. |
| On failure | The differential suite fails the build on the first request the bridge allows and the engine denies, or on a complete translation that disagrees. |
| Established by | Tests: "replays every generated request" for each of the three engines, and "the corpus is large and mixed enough to mean something". |
| Status | Production (pending CI): the evidence covers a generated corpus and the pinned engine versions, not every policy. |

### C-187 Retrieval hands the model only documents the principal is authorized to see

**Statement.** `filterDocuments` and the retriever wrappers admit a candidate document only when a permit predicate matches one of its ACL entries for the principal and no deny predicate matches. A missing or empty principal, an unusable policy, a policy translation with errors, a document with no decidable ACL, a metadata reader that throws, a predicate that throws, and a candidate list or retriever result that is not an array all end with the document dropped, never with an exception during retrieval. Candidates that share an id are told apart by position, and the decision digest commits to exactly which candidates passed.

| | |
|---|---|
| Enforced by | `filterDocuments`, `withPcaFilter`, `withLangChainPcaFilter`, `withLlamaIndexPcaFilter`, `compilePolicy` in `@atlasauth/pca-rag`. |
| Trusted inputs | The principal identity and policy the caller supplies; the ACL metadata on each document. |
| State | `lastDecision()` of a wrapper keeps the previous decision when a retriever throws. |
| On failure | The document is dropped with a reason (`no principal identity (fail closed)`, `no decidable ACL metadata (fail closed)`, `policy translation incomplete (fail closed)`). |
| Established by | Tests: the fail-closed table cases ("no ACL, an empty ACL list, entries that are not {relation, object} strings"), "a matching deny wins", "duplicate ids are told apart by position", "fails closed on an incomplete policy translation". |
| Status | Production (pending CI): it filters retrieval only. |

### C-188 A revoked capability, holder or issuer in an action's chain is denied, and an unreadable chain or store is a denial

**Statement.** `checkRevocation` walks every hop of the action's `cap_chain` and reports revoked when a capability id, holder key or issuer key (or a chain prefix) is revoked and active. A missing or empty chain, a hop without an id, issuer or holder, a non-finite clock and a store that throws or rejects all come back as revoked with a reason starting `revocation check failed closed`, without copying the store's error text. `verifyWithRevocation` allows only when the core result allowed and the chain is clean. A revocation is visible to the next check once `revoke` has resolved. `revoke` refuses a non-finite time or a malformed prefix and stores nothing, and `FileRevocationStore` refuses to start on a corrupt file instead of starting empty.

| | |
|---|---|
| Enforced by | `RevocationRegistry`, `checkRevocation`, `verifyWithRevocation`, `ingestCaepEvent`, `FileRevocationStore` in `@atlasauth/pca-revoke`. |
| Trusted inputs | The store's atomic add and read-after-write visibility (checked by `revocationStoreCases`); the clock; the event handed to `ingestCaepEvent`, which the caller has already verified. |
| State | The revocation entries in the store. |
| On failure | `revoked: true` with a `revocation check failed closed` reason; `revoke` throws; the file store throws on construction. |
| Established by | Tests: "denies a missing or empty chain", "denies when the store throws, and does not leak the store error text", "denies the action whose chain contains the revoked leaf", "a prefix revoke is one store write that denies every chain below it and none beside it", "refuses to start on a corrupt file instead of starting empty". |
| Status | Production (pending CI): a revocation reaches other resource servers only as fast as the operator's push channel. |

### C-189 Exporting a decision to a SIEM never throws into the authorization path and never leaks a credential

**Statement.** `exportDecision` and `exportBatch` catch every serialization, sink and `onError` failure and return it as `{ ok: false, ... }`; one record that cannot be serialized does not take the others with it, and a batch where none can be serialized delivers nothing. A request header such as an authorization value never appears in a result, and error text that quotes a URL with userinfo, a bearer, Basic or Splunk credential, a key pair or a long token-like run is scrubbed before it is returned or handed to `onError`. An HTTP delivery that exceeds its timeout is aborted. A missing `fetch` is a failed result.

| | |
|---|---|
| Enforced by | `exportDecision`, `exportBatch`, `httpSink`, `consoleSink`, `scrubError` in `@atlasauth/pca-siem`. |
| Trusted inputs | The sink and its endpoint; the caller's `onError`, which is wrapped so it cannot throw back. |
| State | None. Delivery is at most once. |
| On failure | `{ ok: false, delivered: 0, error }` with scrubbed text, and `skipped` for records left out. |
| Established by | Tests: "swallows a thrown fetch error, reports via onError, returns ok:false", "an onError callback that itself throws cannot escape", "a fetch error that quotes the url is scrubbed in the result and in onError", "request headers never appear in a result", "the good records are delivered, the bad one is counted and reported", "when nothing can be serialized nothing is delivered". |
| Status | Production (pending CI): delivery has no retry or queue, and the scrubber is pattern-based. |

### C-190 An exported event records what the verifier said, and attacker-controlled fields cannot forge a record

**Statement.** The exported outcome is `allow` only when the supplied verify result is an explicit `allow: true`; a missing or otherwise shaped result is exported as a `deny`. Values are escaped for their format (CEF header pipes and backslashes, CEF extension equals signs and newlines, NDJSON by JSON encoding), so a newline or delimiter in a verb, resource or other field cannot start a second record or forge a field. The leaf signature is logged as a 16-character prefix unless the operator chooses otherwise.

| | |
|---|---|
| Enforced by | `toOcsfEvent`, `toCef`, `toEcs`, `formatDecision` in `@atlasauth/pca-siem`. |
| Trusted inputs | None for field content; the caller supplies the verify result as evidence and the exporter does not re-verify it. |
| State | None. |
| On failure | The event is a `deny`; a record that cannot be serialized is skipped and reported (see C-189). |
| Established by | Tests: "missing verify record is a deny (proof failed verification)", "a newline or a CEF delimiter in attacker-controlled fields cannot forge a second line or a field", "is a 16-character prefix by default, in every format". |
| Status | Production (pending CI): field mappings are not validated against any SIEM product. |

### C-191 A LESS signature verifies only when it is well-formed, canonical and valid, and a hostile encoding never traps or reads past the buffer

**Statement.** `@atlasauth/pca-less-wasm` returns `false` from `verify` (and `ok: false` from `open`) for any signature that is empty, truncated, oversized, garbage, carries a seed count above the published maximum, sets a padding bit in a coset row, carries an extra seed slot with a raised count, or does not authenticate the message under the key. These cases never throw and never leave the wasm instance unusable. A public key or secret key of the wrong length is refused (`verify` returns `false`; `open` and `sign` throw `LessError`).

| | |
|---|---|
| Enforced by | The wrapper guards in `open` and `verify` (length, padding-bit, seed-count and zero-filled tail checks, the canonical seed count test), layered over the three fixes in the compiled reference verifier. |
| Trusted inputs | The pinned wasm artifact and the LESS reference it was built from. The public key supplied by the caller. |
| State | None; verification consumes no randomness. |
| On failure | `false` / `{ ok: false }`; `LessError` for a wrong-sized key or an uninitialised or unreadable wasm. |
| Established by | Tests: the robustness suite (garbage and truncated inputs, padding-bit rows, trailing leaf-count flips, seed-padded signature refused, no tested alternative encoding verifies, honest signatures never refused), the official known-answer tests, and the native-versus-wasm differential. |
| Status | Hardened, awaiting independent audit and the NIST selection. No second implementation exists; signing and key generation are not constant time. |

### C-192 LESS key generation and signing never run on weak randomness, and the shipped wasm is the pinned build

**Statement.** `keygen` and `sign` obtain randomness only from Web Crypto. When it is absent they throw `LessError` rather than seed from anything weaker, while verification keeps working. The wasm imports exactly one host function (`random_get`), and the embedded copy equals the shipped file by pinned SHA-256.

| | |
|---|---|
| Enforced by | `seedFromEntropy` and the `random_get` import over `crypto.getRandomValues`; the build record and the embedded-equals-shipped check. |
| Trusted inputs | The platform's Web Crypto; the pinned build toolchain. |
| State | The reference CSPRNG inside the wasm instance, seeded per instance. |
| On failure | `LessError` ("getentropy failed" or an uninitialised-wasm message). |
| Established by | Tests: the portable loader suite (fails closed when Web Crypto is unavailable, single host import, embedded wasm equals the shipped file, distinct keys from entropy seeding). |
| Status | Hardened, awaiting independent audit. `seedWith` is deterministic by design and for tests only. |

### C-193 Schema validation reports every structural defect and never calls a payload authorized

**Statement.** `validate` in `@atlasauth/pca-schema` returns `valid: false` with a named error for a non-object top-level value, a missing required property, a wrong JSON type, a value outside an enum, and a `$ref` that is not a resolvable local pointer. It never throws on a malformed value. A valid result means well-formed only; it never establishes that a signature verifies, that a capability chain attenuates or that an action is in the plan.

| | |
|---|---|
| Enforced by | `validate` and its internal node checker over `PCACTN_SCHEMA`, `CAPABILITY_SCHEMA` and `DISCOVERY_SCHEMA`. |
| Trusted inputs | The schema objects shipped with the package. |
| State | None. |
| On failure | `{ valid: false, errors }` naming the path. |
| Established by | Tests: a real minted PCActn validates; removing a required field, a wrong nested type and a non-object root are each rejected with the field named. |
| Status | Stable core, structural check only (no `pattern`, `format`, `oneOf` or numeric bounds); authorization is the job of the verifier. |

### C-194 The conformance harness reports a divergent verifier as failing, on the first-failed check and every per-check status

**Statement.** `runConformance` marks a vector matched only when `allow`, the first failed check and the whole per-check map equal the expectation, and reports `ok: false` if any vector diverges, including a verifier that returns no per-check detail. The vector set is generated deterministically (fixed keys, fixed clock) and the committed file equals a fresh generation byte for byte.

| | |
|---|---|
| Enforced by | `runConformance`, `firstFailedCheck`, `generateVectorSet`, `serializeVectorSet`. |
| Trusted inputs | The reference verifier used to produce the expectations. |
| State | None. |
| On failure | `matched: false` with the divergences; `ok: false`. |
| Established by | Tests: one canonical valid vector plus one per failure mode, every vector matches the reference, a blanket-allow verifier diverges on every vector, regeneration is byte-identical and the committed file round-trips. |
| Status | Stable core. Agreement with the reference on these vectors is not an audit; an empty vector list reports `ok: true`. |

### C-195 The verified decision core agrees with the reference verifier and fails closed on a bad clock, chain, threshold or budget

**Statement.** `@atlasauth/pca-verified-core` decides chain validity, thresholds, replay order and the check fold with logic proved in Dafny and compiled to JavaScript. Its verdict and reason equal the reference verifier on the conformance corpus and on random mutations. A clock that is `NaN`, infinite or not an integer fails the validity check; a chain deeper than the bound or one that drops a caveat is refused; a regular expression without a document budget is refused; a throwing oracle counts as unsafe or false.

| | |
|---|---|
| Enforced by | `validityDecision`, `decideChain`, `decideThreshold`, `replayDecide`, `enforceRequired`, `reMatchesVerified` and the policy-VM entry points. |
| Trusted inputs | The glue's results for signatures, hashes and parsing (this package does none); the Dafny toolchain that produced the committed generated file. |
| State | None in the decision functions; the replay model is a specification. |
| On failure | `fail`, `expired`, `future`, `too-long` or a typed error; never a pass by default. |
| Established by | Tests: the differential suites (chain, threshold, replay and verdict agree with the reference, including 6000 random chain mutations), the bad-clock test, the window-boundary and constants tests, the regex budget test, and the policy-VM fail-closed oracle tests. |
| Status | Stable core. The proofs cover the decision logic, not the glue or the compiler. |

### C-196 A harness-built PCActn is accepted only when its measurement is on a non-empty allowlist and, if pinned, under the harness identity

**Statement.** The hook from `createHarnessAttestationVerifier` in `@atlasauth/pca-harness` denies an action when the allowlist is empty, when a measurement is required and absent, when the measurement is not allowlisted, or when a pinned model identity differs. Only with `required: false` is an absent measurement reported as not enforced, and a present wrong measurement still fails.

| | |
|---|---|
| Enforced by | `createHarnessAttestationVerifier` and `computeHarnessMeasurement`. |
| Trusted inputs | The operator's choice of allowlisted measurements; the harness signer's self-asserted measurement. |
| State | None. |
| On failure | The hook result `{ enforced: true, ok: false, reason }`. |
| Established by | Tests: the attestation suite (accepts an allowlisted measurement, denies a mismatch, an absent required measurement, an empty allowlist and a wrong model identity; an end-to-end accept). |
| Status | Hardened, awaiting independent audit. A hardware attestation of the harness build would remove the self-asserted measurement. The measurement is self-asserted. |

## How this page is kept honest

- Each invariant's tests are listed by file in [Traceability](./traceability.md); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
- Each invariant's tests are listed by file in [Traceability](./traceability.md) (rows `C-1` to `C-97`, `C-200` to `C-205`, `C-320` to `C-325` and `C-340` to `C-343`); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
- Each invariant's tests are listed by file in [Traceability](./traceability.md) (rows `C-1` to `C-97`, `C-200` to `C-205`, `C-360` to `C-366` and `C-440` to `C-442`); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
### C-420 Every verifier derives the same digest and the same floor

**Statement.** Each native verifier (Go, Rust, Python, Ruby, PHP, Java, Kotlin, .NET, Swift) computes the same definition digest, pack root, inclusion proof, trait closure, trait floor, floor decision and schema-integrity verdict as the reference implementation for every shared vector, and validates the same v2 parameter domains (string formats, datetime, duration, object reference).

| | |
|---|---|
| Enforced by | The actions module of each native SDK; the ActionSchema v2 parsing and conformance code of each native SDK. |
| Trusted inputs | The shared vector set, produced by the reference implementation and checked byte for byte against a fresh generation. |
| State | None. |
| On failure | A vector that does not reproduce fails that language's `actions-vectors` job; a missing vector directory fails it too (it is never skipped). |
| Established by | Tests: every native replays all 496 shared vectors (parse, digest, trait expansion, floor decision, conform, pack proof, schema floor integrity, effective profile), pinned registry digests, pack-proof tampering, whole-document schema integrity; a guard checks that all nine workflows keep the job. |
| Guarantees | G-20. |
| Status | **Enforced in all nine native SDKs.** Differential oracles for trait expansion are ported in Rust, Ruby, Kotlin, .NET and Swift. |

## How this page is kept honest

- Each invariant's tests are listed by file in [Traceability](./traceability.md) (rows `C-1` to `C-97` and `C-200` to `C-205` and `C-420`); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
- A retired-statement check fails the build when a public page or README repeats a statement that is no longer true (for example a stale corpus size, or a feature described as unimplemented that now ships).
- No external security audit has been performed. The tests, vectors and models above are the project's own.

Next: [Trust model](./trust-model.md) and [Traceability](./traceability.md).

### C-440 An action nobody confirmed has every trait

**Statement.** The effective trait set of an action is decided by a human, never by a machine. An action definition without a valid human confirmation (a review attestation signed by a key pinned with the reviewer role, covering this definition's digest and an accepted trait registry digest) has as its effective traits the top of the registry: every core trait (so every high-risk one: money_moving, destructive, irreversible, external_communication, code_execution, privilege_change, data_export, financial_data_read, credential_access, public_exposure, bulk, impersonation, regulated_data and the rest) and `pca.unreviewed`, plus every custom trait of the registry. Traits that a machine wrote (an importer, a catalog pack, a suggestion rule, the fail-strict union, a model, a hand declaration that nobody signed) are hints for the reviewer and can never lower that set. Only a valid signed confirmation sets the effective traits, to exactly the traits the reviewer signed (their dismissals are part of the signed act) plus the traits the signed definition's own facts imply. Any failure of the confirmation (absent, unsigned, wrong digest, stale registry digest, unknown or unpinned key, a machine key, outside the key's validity window, a changed definition) means unconfirmed. A classifier that misses a trait therefore changes only how much work a reviewer has, never what is enforced.

| | |
|---|---|
| Enforced by | `effective` / `traitsOf` and `topTraits` (`@atlasauth/pca-actions`); `verifyAttestation` and `attestationVerifier` decide `confirmed`; the schema derivations `toSchemaVerb` / `toSchemaDoc` emit the top as the verb's traits and floors for an unconfirmed definition. |
| Trusted inputs | The reviewer keys the verifier pins (role `reviewer`; a key that is also an importer or model key is refused). The built-in definitions are confirmed only by the release attestation (`scripts/sign-builtins.ts`, key supplied at release time); without it they are unconfirmed. |
| State | None. |
| On failure | Nothing is refused at definition level: the definition is treated as the most dangerous action there is (step-up, every caveat, every context key). |
| Established by | Tests: "without a valid signed confirmation the effective traits are the TOP of the registry, whatever the def says", "only a signed confirmation sets the traits, to exactly the declared set plus what the signed facts imply", "an unconfirmed def has the TOP trait set whatever its machine traits", "no machine-authored input (declared traits, provenance, suggestion records, review state) lowers the effective set", "the final decision for an unconfirmed def is at most the decision for any confirmed version (antitone)"; the Lean theorems `unconfirmed_is_top`, `no_machine_input_lowers`, `unconfirmed_above_confirmed`, `unconfirmed_final_antitone` and the Dafny lemmas `UnconfirmedIsTop`, `NoMachineInputLowers`, `UnconfirmedFinalAntitone`; the shared vectors `effective-confirmed-*`, `effective-unconfirmed-*` and `effective-adv-*`. |
| Guarantees | G-20. |
| Status | **Enforced (TypeScript and the nine native verifiers).** The zkVM guest enforces the verb-level half (C-441). |

---

### C-441 Rule 22 refuses a schema that gives an unconfirmed action fewer traits

**Statement.** When a version 2 action schema is accepted, the verifier decides for each verb whether it is human-confirmed: it carries a `confirmation` that verifies against the reviewer keys the verifier itself pins (`ctx.reviewers`), covers the verb's definition digest and an accepted trait registry digest, signs exactly the digest of the facts the verb presents (the verb as published minus its traits, floors, def and confirmation: name, kind, parameters with roles, units and domains, effects, reversibility, bindings, description), and the verb carries every trait the reviewer signed. The verifier recomputes that facts digest from the verb itself, so editing any fact after confirmation, or claiming the definition digest of another action, makes the verb unconfirmed with no help from a grant pin. A verb that is not confirmed must carry every trait of the document's registry and floors at least the floor of that set; a schema that states fewer traits, or lower floors, for it is refused (`schema_traits_forged`, `schema_floor_forged`). A verifier with no reviewer keys therefore treats every verb as unconfirmed. A confirmation cannot be moved from one definition to another.

| | |
|---|---|
| Enforced by | `schemaVerbFloorError` / `schemaFloorError` and `verbConfirmationError` (`@atlasauth/pca-actions`), through `ctx.rule22.schemaError(doc, ctx.reviewers)` in `decideIntentV2`; the native `schemaVerbFloorError` / `schemaFloorError` of each SDK; the zkVM guest `rule22`. |
| Trusted inputs | The reviewer keys the verifier pins. The document's `confirmation` is data. |
| State | None. |
| On failure | `schema_traits_forged: unconfirmed action must carry every trait (missing X)`, `schema_floor_forged` (refused). |
| Established by | Tests: "the same document is refused when no reviewer is pinned (nothing is confirmed)", "dropping the confirmation from a document that claims the reviewed traits is refused", "an unconfirmed def whose schema claims low machine traits and floors is refused", "an unconfirmed verb missing a single trait is refused, naming it", "a forged signature, a stale def digest, a stale registry digest and an altered trait list are all unconfirmed", "a confirmation by an unpinned key, a machine key or a key outside its validity window is unconfirmed", "a confirmation lifted from another action does not transfer", "custom traits are part of the top", "the same confirmed schema is refused when the verifier pins no reviewer", "an unconfirmed def whose schema claims the reviewed traits is refused"; the "editing any fact after confirmation, or claiming another definition digest, makes the verb unconfirmed"; the Lean theorems `facts_mismatch_is_top`, `facts_edit_never_lowers` and the Dafny lemmas `FactsMismatchIsTop`, `FactsEditNeverLowers`; the shared vectors `schema-verb-conf-facts-*`, `schema-verb-conf-*`, `schema-verb-unconf-*`, `rule22-conf-*`, `rule22-unconf-*`, `rule22-schema-conf-*`, `rule22-schema-unconf-*`, `schema-shape-conf-*`. |
| Guarantees | G-20. |
| Status | **Enforced.** No residual on the verb's facts: the confirmation is bound to the presented facts by the reviewer's signature (facts digest) and to the whole definition by the signed definition digest; the grant pin (C-361) is defence in depth, not a dependency. |

---

### C-442 Trait selectors: forbid and cap cover an unconfirmed action, allow never does

**Statement.** In a trait policy or a goal, a forbid or cap selector (a prohibition, a bound over a trait selector) matches an unconfirmed action whatever it says, including a selector with a carve-out or a negation; an allow selector (a grant over a trait class) never matches an unconfirmed action by trait. Registry growth only adds unconfirmed actions to the covered set. Pin and evolution: a definition that goes from confirmed to unconfirmed is a tightening (never needs the principal); one that goes from unconfirmed to confirmed lowers the floors and is a widening (the principal re-approves), except that the same digest with a newly valid signed confirmation follows the pin because the verifier checks the signature itself (C-441).

| | |
|---|---|
| Enforced by | `selectorMatchesFor` / `policyDecision` (`@atlasauth/pca-actions`); `allowClassVerbs` / `floatClassVerbs` and the catalog built by `selCatalogOfDefs` (`@atlasauth/pca-goal`); the Dafny model `GoalSelect.dfy` (`FloatCoversUnrev`, `AllowExcludesUnrev`); `diffDefs` (`confirmation`, `effective.traits`, `effective.profile` dimensions). |
| Trusted inputs | The catalog the goal pins (its digest). |
| State | None. |
| On failure | A matching forbid or cap denies; an allow selector simply does not match (the action is outside the allowed set). |
| Established by | Tests: "a trait policy: forbid and cap selectors match an unconfirmed def, allow selectors never do", "a class ALLOW never covers an unreviewed verb, even one that matches its traits", "a class PROHIBITION and a bound cover an unreviewed verb whatever their all_of and none_of say", "a classifier miss changes nothing", "confirmed -> unconfirmed only tightens; unconfirmed -> confirmed (fewer traits) is a widening"; the Lean theorems `unconfirmed_never_allowed`, `prohibit_covers_unconfirmed`; the shared selector vectors `select-unreviewed-*` (replayed by the Ruby, .NET, Java, Kotlin and Swift goal runners). |
| Guarantees | G-20. |
| Status | **Enforced.** |

### C-480 A `pca_need` hint never grants, widens or breaks the plain challenge

**Statement.** The `pca_need` challenge parameter is advisory and unsigned: it is strictly validated and bounded (version, kind, field shapes and sizes, unknown members refused, at most 2048 encoded characters), a malformed value is a typed failure the client treats as absent, and a resource server never treats a presented need as authority. A server that cannot build a valid need drops the hint and returns the same denial.

| | |
|---|---|
| Enforced by | `encodePcaNeed`, `decodePcaNeed`, `validatePcaNeed`, `pcaNeedFromChallenge` (`@atlasauth/pca`); the drop-on-failure path of `admitRequest` (`@atlasauth/pca-mcp-rs`). |
| Trusted inputs | None (the value is untrusted input). |
| State | None. |
| On failure | The client falls back to the plain `scope` step-up; the server returns the unchanged 403. |
| Established by | Tests: "pca_need challenge parameter" (round trip, 19 refusals, size bound), "pca-need-additive" in the conformance matrix. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-481 A `pca_grant` authorization detail is a pointer, validated closed

**Statement.** A `pca_grant` entry in OAuth `authorization_details` (RFC 9396) is accepted only with the exact members `type`, `chain_digest` (canonical base64url of 32 bytes), `chain_len` (1 to 16) and optionally `chain_ref`, `bundle_revision`, `locations` (https URLs by one portable rule). RFC 9396 common members that would restate authority (`actions`, `datatypes`, `identifier`, `privileges`) and any unknown member are refused; one malformed `pca_grant` entry, or a non-object entry, refuses the whole array; entries of other types are left to their owners.

| | |
|---|---|
| Enforced by | `validatePcaGrantDetail`, `parsePcaGrantDetails` (`@atlasauth/pca`) and the same functions in the nine native verifiers. |
| Trusted inputs | None. |
| State | None. |
| On failure | The array is refused with a typed code. |
| Established by | Shared vectors `pca-grant-vectors.json` (68 cases) replayed by TypeScript, Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET and Swift. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-482 The MCP conformance matrix is a test result

**Statement.** Each requirement of each MCP authorization revision (2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28, draft) that applies to a resource server or a client step-up is a row with the level the revision gives it, and a check runs for every applicable cell: PRM served, `resource_metadata` on the 401, 401 and 403 statuses, audience validation, no foreign bearer token, the `insufficient_scope` challenge, scope in the first 401, one challenge for all scopes, scope hierarchy, and (client) challenge parsing, scope union, retry limit and the RFC 9207 `iss` table.

| | |
|---|---|
| Enforced by | `MCP_AUTH_RS_ROWS` and its test (`@atlasauth/pca-mcp-rs`); `MCP_AUTH_CLIENT_ROWS` and its test (`@atlasauth/pca-mcp`). |
| Trusted inputs | The revision texts as fetched on the date recorded in the source comment; `draft` must be re-fetched before it is relied on. |
| State | None. |
| On failure | A failing cell names its revision and row. |
| Established by | Tests: "MCP authorization conformance matrix (resource-server rows)" (43 cells), "(client rows)" (23 cells). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-483 A broader granted scope satisfies a narrower one, never the reverse

**Statement.** With a `scopeHierarchy` configured, the granted scopes are expanded transitively (cycle-safe) before the scope check; a narrow scope never satisfies a broad one, and the expansion never widens the PCActn's own verified authority. The first 401 names the scopes the resource needs.

| | |
|---|---|
| Enforced by | `expandScopes` and the scope check in `admitRequest`. |
| Trusted inputs | The server's hierarchy table. |
| State | None. |
| On failure | 403 `insufficient_scope` naming all required scopes in one challenge. |
| Established by | Tests: "scope-hierarchy", "scope-in-first-401", "scopes-one-challenge" in the conformance matrix. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-484 A client step-up is bounded and compares issuers exactly

**Statement.** A client treats only a 403 `insufficient_scope` on a Bearer challenge as a step-up, requests the union of its earlier scopes and the challenge scopes, stops at a retry limit and when the union adds nothing; the RFC 9207 `iss` check compares by simple string comparison with no normalization and refuses when no issuer was recorded before the redirect.

| | |
|---|---|
| Enforced by | `planStepUp`, `parseChallenges`, `checkAuthorizationResponseIss` (`@atlasauth/pca-mcp`). |
| Trusted inputs | The recorded issuer. |
| State | Attempt counter held by the caller. |
| On failure | `give_up` with a reason, or the response is refused. |
| Established by | Tests: "planStepUp", "checkAuthorizationResponseIss: the RFC 9207 table". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-485 An OAuth access token carrying `pca_grant` never authorizes on its own

**Statement.** `authorizePcaGrantToken` allows only when the details are well formed, some detail names a prefix of the presented chain, the detail's locations (if any) include this resource, and a verified per-action PCActn is present. A token for another chain is a 401, for another location a 403, and a good token without a verified proof is a 401.

| | |
|---|---|
| Enforced by | `checkPcaGrantPresentation` (`@atlasauth/pca`), `authorizePcaGrantToken` (`@atlasauth/pca-oauth`). |
| Trusted inputs | The caller's statement that the PCActn was verified; the token must already be authenticated by the caller. |
| State | None. |
| On failure | 401 `invalid_token` or 403 `insufficient_scope` with a typed code. |
| Established by | Tests: "end to end: an OAuth server carries the grant", presentation vectors (12), "a truthy string is not a verified proof". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-486 AUTH_REQUIRED authorizes nothing; a task resumes only on a proof for exactly the parked need

**Statement.** A2A's `TASK_STATE_AUTH_REQUIRED` transition is never authorization (A2A 7.6.4). `resumeAuthRequired` resumes a task only when it is in AUTH_REQUIRED, its status carries a decodable need, the answer cites that need's digest, the answer's PCActn is for the need's exact verb and resource, and the PCActn passes the full verifier for this agent. INPUT_REQUIRED, WORKING and terminal tasks never resume on a proof.

| | |
|---|---|
| Enforced by | `resumeAuthRequired`, `authRequiredStatus`, `readAuthRequiredNeed`, `answerMessage` (`@atlasauth/pca-a2a`). |
| Trusted inputs | The agent's pinned authority (stored grant or expected root issuer). |
| State | None. |
| On failure | `{ok: false, reason}`. |
| Established by | Tests: "AUTH_REQUIRED mapping (A2A 7.6)" (5 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-487 Every hop of a delegated A2A task is verified for its own audience, on a chain that extends the last

**Statement.** `verifyA2ADelegation` runs the full verifier at each hop with that hop's own audience and authority, and refuses a hop whose capability chain does not start with the previous hop's chain (attenuation only appends). It stops at the first failure and names the hop. The Agent Card extension declaration is validated closed (one declaration, known parameters, `pca_grant` pointers by the profile).

| | |
|---|---|
| Enforced by | `verifyA2ADelegation`, `readPcaExtension`, `pcaExtensionDeclaration` (`@atlasauth/pca-a2a`). |
| Trusted inputs | Each hop's own `PcaVerifyOptions`. |
| State | None. |
| On failure | `{ok: false, failedHop, reason}`. |
| Established by | Tests: "per-hop delegation" (4 tests), "Agent Card extension" (3 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-488 A push-notification token is bound to the task and the chain that authorized it

**Statement.** `pcaPushToken` hashes the task id, the digest of the authorizing chain and a secret salt of at least 16 characters; `checkPushNotification` accepts a delivered notification only with the recomputed token (compared in constant time) and a payload about that task. A token for another task, chain or salt does not validate. An authentic notification is still only a report.

| | |
|---|---|
| Enforced by | `pcaPushToken`, `checkPushNotification`, `uniformTaskNotFound` (`@atlasauth/pca-a2a`). |
| Trusted inputs | The salt shared by client and agent. |
| State | None. |
| On failure | `{ok: false, reason}`. |
| Established by | Tests: "push notifications (A2A 13.2)" (3 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-489 A blueprint ceiling only tightens, and an unevaluable ceiling denies

**Statement.** For a chain with a hop issued by a registered blueprint key, the effective authority is the chain's caveats AND the blueprint's ceiling. A non-empty ceiling that cannot be evaluated (no evaluator and no action in the TypeScript reference; always, in the native verifiers) denies. A hop issued by the blueprint key that the previous hop did not delegate to that key is `broken_link`; depth, expiry and status are enforced per blueprint.

| | |
|---|---|
| Enforced by | `checkBlueprints`, `BlueprintRegistry` (`@atlasauth/pca-grants`); `check_blueprints` (Python), `CheckBlueprints` (Go). |
| Trusted inputs | The pinned operator keys; the newest accepted record per blueprint key. |
| State | The registry. |
| On failure | Deny with a typed code naming the blueprint. |
| Established by | Tests: "agent blueprints: ceiling and group kill" (12 tests) and the shared vectors `blueprint-vectors.json` (16 scenarios) in TypeScript, Python and Go. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-490 A group kill refuses every instance of a blueprint, seen or never seen, and cannot be undone by an older record

**Statement.** A blueprint record is signed by a pinned operator; a record replaces the stored one only with a strictly higher epoch, the same epoch with different content is a fork and is refused, and the operator of a key cannot change. `groupKill` signs the record `disabled` at the next epoch, accepts it, and revokes the blueprint key as an issuer in the revocation registry. Re-enabling needs a higher epoch signed by the operator.

| | |
|---|---|
| Enforced by | `signBlueprint`, `verifyBlueprint`, `BlueprintRegistry.accept`, `groupKill`. |
| Trusted inputs | The pinned operator keys. |
| State | Per-key newest record; the highest epoch. |
| On failure | `{ok: false, code}` on accept; deny `blueprint_disabled` on check. |
| Established by | Tests: "GROUP KILL", "a disabled blueprint cannot be revived", "refuses records from unknown operators". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-491 Blueprint state is never older than the epoch a caller proved it saw, and an unreachable store denies

**Statement.** With `minEpoch` (the `revocation_epoch` of a `fresh_at` token the caller presented), a registry behind it answers escalate (`stale_blueprint_state`), never allow; `groupKill` advances the verifier's `fresh_at` revocation epoch to the record's epoch. A store that throws is a deny (`store_unreachable`), as is malformed input.

| | |
|---|---|
| Enforced by | `checkBlueprints` (`minEpoch`), `groupKill` (`freshAt`). |
| Trusted inputs | The verifier's `FreshAtIssuer`; the presented token. |
| State | The registry's epochs. |
| On failure | Escalate or deny. |
| Established by | Tests: "staleness", "composes with fresh_at", "fail closed". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-492 A blueprint instance with runtime pins is admitted only on verified, bound hardware evidence matching a pin

**Statement.** For a blueprint record with `runtime_pins`, `checkBlueprints` denies (`admission_required`, `not_admitted`) unless an admission exists for that instance key under the record's current epoch and it has not expired. An admission is made only when an existing attestation verifier returns ok, confirms the evidence is bound to the expected holder, grant and nonce, and returns a measured identity matching a pin on every field the pin names. No evidence, a verifier that throws, an unbound or unmeasured result, or no matching pin is a deny; the document's own claims are never the identity. A new record (group kill, re-enable) voids earlier admissions. The native verifiers refuse a record carrying pins (its signature covers a member they do not read).

| | |
|---|---|
| Enforced by | `admitBlueprintInstance`, `AdmissionRegistry`, `checkBlueprints` (`admitted`) (`@atlasauth/pca-grants`). |
| Trusted inputs | The pinned operator keys; the attestation verifier and its roots. |
| State | Admissions per instance key and epoch. |
| On failure | Deny with a typed code. |
| Established by | Tests: "attestation-gated blueprint admission" (5 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-493 A task-update receipt is signed, chained and bound to the task and the authorizing chain

**Statement.** `verifyTaskReceipt` accepts a receipt only under the pinned signer key, over exactly its content; `checkReceiptChain` requires every receipt to be about the task and the authorizing chain digest, to start at sequence 0, to link to the previous receipt by digest with the next sequence number, and to be followed by nothing after a terminal state. `mayTriggerNext` is true only for such a chain ending in COMPLETED; a push payload, a status update or an unsigned completion is never enough.

| | |
|---|---|
| Enforced by | `signTaskReceipt`, `verifyTaskReceipt`, `checkReceiptChain`, `mayTriggerNext` (`@atlasauth/pca-a2a`). |
| Trusted inputs | The signer key the receiver pinned. |
| State | The caller's receipt list. |
| On failure | `{ok: false, code}` or false. |
| Established by | Tests: "signed task-update receipts" (6 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-494 An extended Agent Card lists only what the analyzer says the caller may attempt

**Statement.** `extendedAgentCard` requires an authenticated caller, reveals a hidden skill only when the `whatMayIDo` envelope for its verb is autonomous or needs-approval, and reveals nothing for a denied verb, a verb with no envelope or an untagged skill (so absence looks the same as non-existence). Envelopes from different policies are refused; the policy digest is recorded in the PCA extension parameters; the derived card drops its now-stale signatures.

| | |
|---|---|
| Enforced by | `extendedAgentCard` (`@atlasauth/pca-a2a`) over `whatMayIDo` (`@atlasauth/pca-analyzer`). |
| Trusted inputs | The analyzer's envelopes for the caller's authenticated chain. |
| State | None. |
| On failure | Throws on unauthenticated callers and mixed policies; hidden skills stay hidden otherwise. |
| Established by | Tests: "extended Agent Card from a residual policy" (5 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-495 Scopes come from the confirmed action and nothing is released for an unconfirmed one

**Statement.** `deriveActionScopes` returns the confirmed action's `upstream.scopes_min` (deduplicated, sorted, valid scope tokens) and nothing else: an unknown, unconfirmed, provider-mismatched, empty, malformed or over-grant action derives no scope. In `admitRequest` a tool listed in `toolActions` takes its required scope from the action and is refused (403 `forbidden`) when none can be derived; `oauthScopeForAction` requests exactly the derived scope.

| | |
|---|---|
| Enforced by | `deriveActionScopes` (`@atlasauth/pca`), `admitRequest` (`toolActions`), `oauthScopeForAction`. |
| Trusted inputs | The operator-pinned action mapping and its confirmation flag (computed from the signed review). |
| State | None. |
| On failure | 403 `forbidden`, or a refusal code and no request. |
| Established by | Tests: "MCP scopes derived from the confirmed action", "OAuth scopes derived from the confirmed action". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-496 SPIFFE and EAT evidence admit a blueprint instance only when verified, fresh and bound to the instance key

**Statement.** `eatAdmissionEvidence` verifies the EAT signature and issuer, the server-issued nonce and age, the appraisal policy (minimum tier `affirming`), and that `cnf.jkt` is the RFC 7638 thumbprint of the instance key; `spiffeAdmissionEvidence` verifies an X.509 or JWT SVID against the trust bundle and binds it to the instance key through `svidToHolder`. The identity handed to `admitWithEvidence` is what the verifier established (measured values, the verified SPIFFE ID), never a field the instance supplies. A bad signature, stale or foreign nonce, evidence minted for another key, an SVID of another trust domain, an expired or unbound SVID, a thrown error or a malformed result is a deny.

| | |
|---|---|
| Enforced by | `eatAdmissionEvidence` (`@atlasauth/pca-attest-eat`), `spiffeAdmissionEvidence` (`@atlasauth/pca-spiffe`), `admitWithEvidence` (`@atlasauth/pca-grants`). |
| Trusted inputs | The EAT verify key and appraisal policy; the SPIFFE trust bundle; the server-issued nonce. |
| State | None (admissions live in `AdmissionRegistry`). |
| On failure | `{ok: false}` evidence, or `admitted: false` with a typed code. |
| Established by | Tests: "EAT evidence for blueprint admission" (5 tests), "SPIFFE evidence for blueprint admission" (2 tests). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-497 Every native verifier decides the A2A binding gates exactly like the reference

**Statement.** The nine native verifiers (Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET, Swift) replay `a2a-vectors.json`: decoding and validating a `pca_need` (strict base64url, UTF-8, strict JSON, closed shape), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption, push-token binding to task, chain and salt (a salt under 16 characters yields no token), and signed task-update receipts (signature under the pinned signer, task, chain, sequence, digest links, nothing after a terminal state, COMPLETED only). The per-hop PCActn itself is verified by the ordinary verifier.

| | |
|---|---|
| Enforced by | `decode_need`, `resume_gate`, `check_chain_extension`, `push_token`/`check_push`, `verify_receipt`/`check_receipt_chain` in each native (`a2a` modules). |
| Trusted inputs | The pinned signer key and the push salt. |
| State | None. |
| On failure | The typed refusal code or false. |
| Established by | Shared vectors `a2a-vectors.json` (89 checks) replayed in all nine natives and in the TypeScript reference. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |
### C-460 The approval commits to the canonical render of the action

**Statement.** An approval is signed over `SHA-256(domain || action_digest || H(R))`, where `R` is the canonical render of the action: a deterministic, locale-free list of EVERY supplied parameter (id, role, value, resolved unit), sorted by id, made only from the action definition and the executed parameters. A model never produces any part of it. A parameter the definition does not declare, a missing required parameter, a value outside the canonical domain (a float, null, a lone surrogate, a wrong type), an unresolved currency and a parameter key containing a dot are refused: nothing partial is ever rendered. A definition without a valid signed confirmation renders with `unreviewed: true`, a different digest, and single-tap approval is not allowed. The approver client re-renders from the pinned definition and refuses to sign a digest it cannot reproduce.

| | |
|---|---|
| Enforced by | `renderApproval`, `approvalRenderDigest`, `approvalChallenge` (`@atlasauth/pca`, `@atlasauth/pca-actions`); `buildApprovalChallenge` (`@atlasauth/pca-webauthn`); the render module of each of the nine native SDKs and the Python SDK. |
| Trusted inputs | The pinned action definition and the executed parameters. |
| State | None. |
| On failure | The render is not made (a typed refusal), no digest is made over a malformed render, and no approval is signed. |
| Established by | Tests: the canonical-render, completeness, unreviewed and challenge tests; the shared `approval_render`, `approval_digest` and `approval_challenge` vectors replayed byte for byte by the TypeScript reference, the Python SDK and the nine native SDKs. |
| Guarantees | G-20. |
| Status | **Enforced.** Wire-affecting: an additive optional member, off unless the verifier recomputes a render. Residual: the render shows raw parameter values; presenting them well (and in the principal's language) is the approver client's job and is shown below the canonical render, never instead of it. |

### C-461 The verifier recomputes the render and refuses a mismatch

**Statement.** An escalation answer may carry `render_digest`, signed with the rest of the answer. When the verifier recomputes `H(R)` from the executed parameters and its own definition (`escalation.render`), the answer must carry exactly that digest; an answer without it, with another one, or carrying a render the verifier did not recompute is refused. **By default (0.5) an answer is admitted only when a render was recomputed and the answer is signed over exactly it**: a guard with no `escalation.render` refuses every answer. The only way back to the pre-render behaviour is the explicit, documented `insecureUnboundApproval: true` (`insecure_unbound_approval`, `InsecureUnboundApproval`) on the guard. `renderDigestForAction` refuses unless the supplied parameters are the ones the PCActn signed (`params_digest`) and the verb is the PCActn's verb.

| | |
|---|---|
| Enforced by | `verifyEscalationAnswer` and the guards (`requirePCA`, `authorize`) with `escalation.render`; the same binding in every native SDK; the TLA+ model `Escalation.tla` (`AnswerRendered`). |
| Trusted inputs | The verifier's own definitions and the executed parameters. |
| State | None beyond the replay counter that already spends an answer. |
| On failure | The answer is not accepted; the decision stays `escalate`. |
| Established by | Tests: guard tests (answer for another render, none, unchecked render, no recomputation by default, the `insecureUnboundApproval` opt-out), the shared `approval_escalation` vectors in all ten SDKs, the TLA+ case `esc_bad_norender` (must fail) next to `esc_good`. |
| Guarantees | G-20. |
| Status | **Enforced.** The TLA+ case runs in the formal job; it was not run in the build that added it. Every native guard (`authorize`) takes the render recomputation and applies the same default. |

### C-462 A payment approval binds the amount and the payee

**Statement.** For a payment verb the render carries exactly one `money.amount` (with a money unit) and one `party.payee`; an unreviewed definition, a missing amount or payee, a negative or non-integer amount is not linkable (PSD2 RTS Art. 5(1)). For Secure Payment Confirmation, `verifyAssertion` with a `payment` expectation requires `clientData.type` `payment.get` and a signed `clientData.payment` whose `total`, payee, `topOrigin` and `rpId` equal the canonical render, and refuses `webauthn.get` in that mode and `payment.get` outside it. A batch commits to the per-currency totals, the payee set (Merkle root) and every item (Merkle root), so changing any amount or payee changes the digest (Art. 5(3)(b)).

| | |
|---|---|
| Enforced by | `psd2Linking`, `approvalBatch`, `spcExpectation` (`@atlasauth/pca-actions`); `verifyAssertion` (`@atlasauth/pca-webauthn`); the profile vectors in Python, Go, Ruby, PHP, Rust, Java, Kotlin, .NET and Swift. |
| Trusted inputs | The pinned definition, the verifier's approval origin and rpId. |
| State | None. |
| On failure | The approval is refused. |
| Established by | Tests: PSD2 linking, batch and SPC tests; shared `approval-profiles` vectors. |
| Guarantees | G-20. |
| Status | **Enforced.** Source text: the UK-retained copy of the regulation was fetched and checked; the EUR-Lex original could not be fetched and is unverified here. |

### C-463 The vault does not hand an agent a bare bearer token

**Statement.** In proxy mode the vault makes the outbound call itself: the pinned extractor maps the outbound request (method, pinned origin and path template, allowed query keys, strict-JSON or form body members, fixed members) back to the action parameters and the call is made only if their digest equals the PCActn's signed `params_digest`; any extra, repeated or mismatched member, header or host is refused before the action is spent. Redirects are not followed, the agent cannot set Authorization, Cookie, Host or override headers, and a response that echoes the token is redacted. A bare bearer token is released only by a vault constructed with `insecureBearerRelease: true`.

| | |
|---|---|
| Enforced by | `TokenVault.proxyCall`, `httpExtractor` (`@atlasauth/pca-connect`). |
| Trusted inputs | The pinned action registry, the connection store, the injected transport. |
| State | The replay store spends the action. |
| On failure | Typed refusal (`request_mismatch`, `bearer_release_disabled`); a refused request does not spend the action. |
| Established by | Tests: proxy-mode, extractor and header tests. |
| Guarantees | G-20. |
| Status | **Enforced.** Breaking: `getConnectionToken` now needs the explicit opt-in; the plain release remains documented as insecure. |

### C-464 Scopes derive from the pinned, confirmed action

**Statement.** With `actions` set the vault resolves the PCActn's verb to a pinned action; an unknown verb is refused, an action whose definition is not confirmed is refused (unconfirmed means maximally dangerous), the provider must match, and the released scopes are the action's `scopes_min`, which must lie inside the grant and inside the stored connection. A bearer release carries no scope beyond `scopes_min` and never outlives the PCActn.

| | |
|---|---|
| Enforced by | `TokenVault` (`@atlasauth/pca-connect`). |
| Trusted inputs | The pinned action registry and the review pins behind `confirmed`. |
| State | None. |
| On failure | Typed refusal (`unknown_action`, `unconfirmed_action`, `scope_exceeded`). |
| Established by | Tests: scope-derivation tests. |
| Guarantees | G-20. |
| Status | **Enforced.** The scope declaration lives in the vault's action registry, not in the `ActionDef` digest (no wire change to definitions). |

### C-465 A release or a proxied call leaves a signed receipt

**Statement.** Every release or proxied call (when `receipts` is configured) yields an Ed25519-signed `pca-release-receipt` over the action digest, provider, connection, mode, scopes the token carried, request digest, HTTP status and outcome. A failed call is receipted as failed. A failing sink never turns a made call into an error.

| | |
|---|---|
| Enforced by | `signReleaseReceipt`, `verifyReleaseReceipt` (`@atlasauth/pca-connect`). |
| Trusted inputs | The vault signing key. |
| State | The sink the operator supplies. |
| On failure | No receipt; the call result is unchanged. |
| Established by | Tests: receipt signing, tamper and failure tests. |
| Guarantees | G-20. |
| Status | **Enforced.** Reconciliation of the receipt against the rail's own record is C-466. |

### C-466 A spend rail never approves what the policy does not

**Statement.** The real-time authorization callback approves only when `authorizeChargeAtomic` returns `auto`; a step-up, a deny, an unknown card or merchant, a missing merchant id, a non-positive or non-integer amount, an exception and a missed latency budget all decline. Instrument limits are an upper-bounded copy of the grant (per-authorization = min(threshold, remaining budget), total = remaining budget, categories = the mandate's allowlist narrowed by `mcc.*` traits), a card without a category control is refused, and the rail unreachable at mint means no card. A settlement with more than approved, another merchant or currency, or a second capture is a tighten-only event: freeze the grant. The Stripe webhook verifies the signature over the raw body and answers 400 on a bad one.

| | |
|---|---|
| Enforced by | `createRailAuthorizer`, `railLimits`, `reconcileSettlement` (`@atlasauth/pca-payments`); `createStripeIssuingWebhook`, `stripeCardParams` (`@atlasauth/pca-payments/stripe-issuing`). |
| Trusted inputs | The mandate, the verified grant, the budget store, the rail signing secret. |
| State | The cumulative budget (compare-and-set). |
| On failure | Decline; for a settlement mismatch, `freeze_grant`. |
| Established by | Tests: limit mirroring, decision, latency, signature and reconciliation tests against documented-shape fixtures. |
| Guarantees | G-20. |
| Status | **Enforced in the reference.** The fixtures follow the documented object shapes and are not captured from a live account. The operator must set the Issuing timeout response to decline and turn Autopilot off. |

### C-280 A network token binds to its grant and holder

**Statement.** A `NetworkTokenBinding` ties an opaque `token_ref` (never a PAN; a Luhn-valid 13 to 19 digit run is refused) to the digest of one grant, the holder key and an issuer nonce, with the holder signature over their canonical digest. Any changed field, wrong holder, wrong nonce or wrong provider fails verification.

| Enforced by | `bindNetworkToken`, `verifyNetworkTokenBinding`, `tokenRefError`. |
| On failure | Refused with a named reason. |
| Established by | Tests: "a binding signed by the holder over token_ref, grant digest and nonce verifies", "every field is bound: token_ref, grant, holder, nonce, provider", "a PAN-shaped or malformed token_ref is refused". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-281 The network enforces no more than the grant

**Statement.** The controls sent to a network-token provider are an exact copy of the rail limits (per-authorization maximum, cumulative maximum, categories, merchants, expiry), so the network is a second enforcement point and PCA never relaxes because the network would block. A provider reply with a malformed or PAN-shaped reference fails the issuance; a failed suspend on revoke propagates. The Visa Intelligent Commerce and Mastercard Agent Pay adapters are generic mappings, mock-tested and labelled as such: both APIs are partner-gated.

| Enforced by | `controlsFromLimits`, `issueBoundNetworkToken`, `suspendOnRevoke`, `visaIntelligentCommerceAdapter`, `mastercardAgentPayAdapter`. |
| On failure | Issuance throws; the caller does not hold a binding. |
| Established by | Tests: the issuance-gate and adapter tests. |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-282 A network settlement joins the ledger only on an exact echo

**Statement.** A charge carries the grant digest, the PCActn digest and the token reference as metadata; a settlement record joins the ledger entry only when all three match exactly.

| Enforced by | `settlementMetadata`, `reconcileNetworkSettlement`. |
| On failure | Not joined; the reasons are named. |
| Established by | Tests: "joins only on an exact echo of grant digest, PCActn digest and token_ref". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-284 Escalation is a deterministic, fail-strict price comparison

**Statement.** A human is asked iff the upper bound of P(bad) times the loss exceeds the principal-signed interruption cost, in integer arithmetic. A bad signature, a currency mismatch, an out-of-range input, a loss above the hard ceiling or an invalid calibration is an ask. The same inputs always give the same decision, and shared vectors pin it.

| Enforced by | `decideEscalation`, `pricingConfigError`. |
| On failure | Ask. |
| Established by | Tests: boundary, fail-strict, determinism and the shared vectors. |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-285 Calibration comes only from the principal's signed answers

**Statement.** Only a validly signed, not-replayed deny of an action the current pricing would have auto-approved changes the calibration, and only by raising a multiplier on P(bad). Approvals, forged answers, replayed nonces and unknown actions change nothing.

| Enforced by | `signAnswer`, `updateCalibration`. |
| On failure | The answer is ignored. |
| Established by | Tests: "a signed deny of an auto-approved action raises the multiplier; approve / replay / forged / unknown change nothing". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-286 No input sequence widens autonomy

**Statement.** For every sequence of answers, the multiplier never decreases and no action that was asked before is auto-approved after. The learner has no code path to the interruption cost.

| Enforced by | `updateCalibration`. |
| On failure | Not applicable: the property holds by construction and by a property test. |
| Established by | Tests: "no sequence of answers ever makes any action go from ask to no-ask" (randomised, with forged and replayed answers), and "a corrupt config makes the learner a no-op". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-287 Asking less needs the principal

**Statement.** Raising the interruption cost needs the principal's signature, a strictly newer epoch and a value no higher than the configured maximum.

| Enforced by | `applyAutonomyRaise`. |
| On failure | Throws. |
| Established by | Tests: "a signed raise within the maximum lowers the ask rate; above the max, wrong key, stale epoch are refused". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-288 A grant maps to an ERC-7715 request with exact units

**Statement.** A grant's cap, period and end map to a periodic permission request with an expiry rule using an explicit integer base-units-per-minor ratio (no price oracle, no fractions). No chain access and no on-chain redemption in the core. Checked against the EIP text at a pinned commit; a wallet increase of an allowance is refused although the EIP lets a wallet attenuate in either direction.

| Enforced by | `grantToPermissionRequest`, `supportsRequest`, `revokeParams`. |
| On failure | Throws. |
| Established by | Tests: the mapping and refusal tests. |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-289 A granted permission is never wider than the grant

**Statement.** A wallet may narrow a permission; any wider amount, other token, chain, recipient, untrusted delegation manager, extended or missing expiry or unknown rule type is refused.

| Enforced by | `verifyGrantedPermission`. |
| On failure | A named refusal reason. |
| Established by | Tests: the table of refusals. |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-290 A permission context belongs to one grant

**Statement.** A context handle already bound to another grant digest is refused.

| Enforced by | `verifyGrantedPermission` with `contextOwner`. |
| On failure | Refused. |
| Established by | Tests: "refuses a context already bound to another grant, and garbage". |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-283 A network charge always carries its PCActn digest

**Statement.** A network-token charge is started by building the signed PCActn and deriving the settlement metadata from its digest; a binding for another grant cannot start a charge. A settlement record without the PCActn digest is refused.

| Enforced by | `chargeWithNetworkToken`, `reconcileNetworkSettlement`. |
| On failure | Throws (wrong grant); the settlement does not join and the reasons are named. |
| Established by | Tests: the "hands its PCActn digest to settlement automatically" tests. |
| Guarantees | G-20. |
| Status | **Reference: enforced** (pending CI). |

### C-300 A step is admitted only as part of the committed workflow

**Statement.** A step the principal's signed workflow does not list, or one whose verb, resource or committed params digest differ, is denied (`unplanned_step`, `step_mismatch`, `params_mismatch`). The workflow must be signed by the principal key the verifier pinned (a key named inside it is never trusted), be inside its validity window, be a DAG (unique ids, known dependencies, no cycle, every edge following a dependency) and have the exact member set (unknown members deny).

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned principal key, the workflow commitment. |
| State | None (pure function). |
| On failure | Deny with a stable code; no partial admission. |
| Established by | Tests: shared vectors `workflow-vectors.json` in the reference and nine natives; Dafny `WorkflowAdmit.dfy` (`AdmittedIsPlanned`, `UnplannedDenied`). |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-301 Reordering and replaying steps is denied

**Statement.** A step whose dependency has no `ok` receipt is denied (`deps_unmet`, `dep_failed`), a step that already has a receipt is denied (`already_done`), and a receipt that precedes a dependency's receipt is accepted only when every edge from that dependency is a declared promise.

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned resource-server key. |
| State | The receipt chain the caller presents. |
| On failure | Deny. |
| Established by | Tests: vectors; Dafny `AdmittedDepsMet`, `ReorderDenied`, `AdmittedNotDone`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-302 Edge constraints bind a step's inputs to earlier steps' signed outputs

**Statement.** For every edge into the step whose source has a receipt, the request's value is proved against that receipt: equal digest (`eq`) or an integer relation (`le`, `ge`, `lt`, `gt`, integers only) with matching units; a missing value, unit mismatch, non-integer or violated relation denies (`edge_missing`, `edge_unit`, `edge_value`, `edge_digest`, `edge_relation`). Values in receipts are the resource server's signed claims, never the agent's.

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned resource-server key. |
| State | The receipt chain. |
| On failure | Deny. |
| Established by | Tests: vectors (boundary at the computed amount, one over, wrong unit, wrong type); Dafny `AdmittedEdgesHold`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-303 The step receipts form a verifiable, signed chain

**Statement.** Each receipt is signed by the pinned resource-server key under its own domain, names this workflow by digest, has `seq` equal to its position and `prev` equal to the digest of its predecessor, repeats no step, names a planned step, and is not from the future. A broken chain denies the admission (`bad_receipt`, with the offending index).

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned resource-server key. |
| State | The receipt chain. |
| On failure | Deny. |
| Established by | Tests: vectors; Dafny `ChainAppend`, `ChainPrefix`, `ChainDistinct`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-304 Labels propagate across the DAG and cannot reach a forbidden step

**Statement.** The labels of every executed ancestor's outputs are inherited. An inherited label in a step's `deny_labels`, or in an edge's `deny_labels` for that edge's source output, denies (`taint_flow`); a label in the step's `escalate_labels` escalates (`taint_escalate`).

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | Receipt labels (the resource server's claim). |
| State | The receipt chain. |
| On failure | Deny or escalate. |
| Established by | Tests: vectors. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** The label values are as trustworthy as the resource server that signed them. |

### C-305 A workflow has budgets that no admission exceeds

**Statement.** The number of steps (`max_steps`) and each named cost cap bound the executed steps plus the one being admitted (`budget_exceeded`). Every cost name must have a cap.

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The workflow commitment. |
| State | The receipt chain. |
| On failure | Deny. |
| Established by | Tests: vectors (exactly met, one over); Dafny `AdmittedWithinBudget` (step count). |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** The cost-cap arithmetic is covered by vectors, not by the Dafny model. |

### C-306 The workflow composes with the goal and the plan root

**Statement.** A request must carry the same goal digest and plan root the workflow commits (`goal_mismatch`, `plan_root_mismatch`). `planRootAuthorized` answers whether a root is authorized by a signed, unexpired, pinned-principal workflow; `verifyPCActnCore` takes `authorizedPlanRoots` and then ENFORCES `plan_root_authorized` (pass, or fail with `the plan root has not been authorized by the principal`).

| | |
|---|---|
| Enforced by | `planRootAuthorized`, `verifyPCActnCore(... authorizedPlanRoots)` (`@atlasauth/pca`); `plan_root_authorized` in the natives' authorize pipeline fed by `plan_root_authorized`. |
| Trusted inputs | The pinned principal key. |
| State | None. |
| On failure | Deny; without `authorizedPlanRoots` the core still reports `not-enforced` and the resource-server layer already requires the check. |
| Established by | Tests: vectors, `e2e.test.ts`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference.** Not turned on by default: a verifier must supply the authorized roots. |

### C-307 A pipelined step is admitted before its input exists only inside a declared domain, and is bound afterwards

**Statement.** A step whose dependency has no receipt yet is admitted (with the unresolved edge indexes in `pending`) only when every edge from that dependency declares a promise domain; otherwise it escalates (`pipeline_unconstrained`), and with no edge at all it denies. `bindPromises` re-checks the step's params against every edge once the receipts exist; a broken promise is a violation (`edge_*`, `params_mismatch`).

| | |
|---|---|
| Enforced by | `admitStep`, `bindPromises`, `signWorkflow`, `signStepReceipt` (`@atlasauth/pca`, `workflow`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned resource-server key. |
| State | The receipt chain. |
| On failure | Escalate, deny, or a post-hoc violation the caller must compensate. |
| Established by | Tests: vectors. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** Compensation itself is the existing contracts module, not part of this gate. |

### C-310 A read is redacted by a signed grant, and a weaker request never loosens it

**Statement.** `redactRead` shows, masks (`last4`, `bucket:N`, `hash`, `token`) or drops each field by its class under the first read scope matching verb, resource prefix and purpose; no scope denies (`no_read_scope`). A caller's `tighten` mode applies only if strictly stricter; a field the schema does not classify is never shown; a mask that cannot apply (short string, non-string, negative) drops.

| | |
|---|---|
| Enforced by | `redactRead`, `checkSink`, `readChainLabels`, `signReadGrant`, `signReadReceipt` (`@atlasauth/pca`, `readside`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned principal key, the action's field-to-class schema. |
| State | The per-window read counters the caller passes. |
| On failure | Deny, or escalate when a required field ends up dropped. |
| Established by | Tests: shared vectors `readside-vectors.json`; Dafny `ReadSide.dfy` (`EffectiveNeverWeaker`, `EffectiveIsOneOf`). |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** Aggregate differential privacy is not implemented (heuristic, out of scope). |

### C-311 Reads leave a signed receipt that audits what was shown without the value

**Statement.** Per field the receipt records its class, whether it was shown, masked (with the kind) or dropped, and a salted value digest. The labels list is exactly the classes of the fields that were not dropped; a receipt that hides a label is rejected.

| | |
|---|---|
| Enforced by | `redactRead`, `checkSink`, `readChainLabels`, `signReadGrant`, `signReadReceipt` (`@atlasauth/pca`, `readside`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned resource-server key. |
| State | The receipt chain. |
| On failure | Deny. |
| Established by | Tests: vectors; Dafny `LabelsSound`, `LabelsExact`, `ChainLabelsUnion`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-312 Data read under a label cannot flow to a sink the grant does not allow

**Statement.** `checkSink` unions the labels of a verified receipt chain and denies any label outside the sink's allow and ask sets (`label_flow`), escalates a label in the ask set (`label_escalate`), denies an unknown sink, and denies on any invalid grant, signature, time or receipt.

| | |
|---|---|
| Enforced by | `redactRead`, `checkSink`, `readChainLabels`, `signReadGrant`, `signReadReceipt` (`@atlasauth/pca`, `readside`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The pinned principal and resource-server keys. |
| State | The read receipt chain. |
| On failure | Deny or escalate. |
| Established by | Tests: vectors; Dafny `SinkAllowIsSubset`, `SinkEscalateNeedsAsk`, `SinkDenyOnForeignLabel`. |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** |

### C-313 Reads are charged per class so data cannot leave a few fields at a time

**Statement.** Each class has an optional cap; the fields not dropped are added to the caller's per-window counter and a count above the cap denies (`read_cap`) with the counters unchanged.

| | |
|---|---|
| Enforced by | `redactRead`, `checkSink`, `readChainLabels`, `signReadGrant`, `signReadReceipt` (`@atlasauth/pca`, `readside`); the same gates in all nine native SDKs and Python. |
| Trusted inputs | The read grant. |
| State | The counters (the caller owns the window). |
| On failure | Deny. |
| Established by | Tests: vectors (at the cap, one over). |
| Guarantees | G-20. |
| Status | **Enforced in the reference; natives pending CI.** Window management and storing the counters are the caller's. |

### C-314 Every native decides the workflow and read-side gates exactly like the reference

**Statement.** One generated vector file per gate, replayed in the reference and all nine natives; the generator cross-checks every hand-written expectation against the reference.

| | |
|---|---|
| Enforced by | the vector replay tests in each SDK. |
| Trusted inputs | The vector files. |
| State | None. |
| On failure | CI failure naming the vector. |
| Established by | Tests: `k5-vectors.test.ts` and the per-language replays. |
| Guarantees | G-20. |
| Status | **Enforced; natives pending CI.** |


### C-308 A step of a committed workflow is checked inside the authorizer and the hosted route

**Statement.** `authorize()` takes a `workflow` option (the pinned principal and resource-server keys). A call carrying a workflow step is decided by `admitStep` BEFORE the guard, so a refusal never spends the PCActn's replay counter; `deny` refuses, `escalate` returns the ternary `escalate`, and `required: true` refuses a call with no workflow. The PCActn's plan root must equal the committed one. The hosted actions route does the same for a presented `workflow` (commitment signed by the grant's principal, receipts by the instance guardian key).

| | |
|---|---|
| Enforced by | `createAuthorizer` (`workflow` option, `AuthorizeInput.workflow`); the hosted `POST /v1/pca/actions` and `/actions/dry-run` (`workflow` body member). |
| Trusted inputs | The pinned principal and resource-server keys. |
| State | The receipts the caller presents. |
| On failure | Deny or escalate; the replay counter is not consumed. |
| Established by | Tests: `authorize-workflow.test.ts` (allow, missing dependency, edge relation, unplanned step, plan root, required). |
| Guarantees | G-20. |
| Status | **Enforced in the TypeScript authorizer, the hosted route and (replaying `authorize-workflow-fixtures.json`) every native authorize pipeline; natives pending CI.** `POST /v1/pca/workflow-receipts` issues guardian-signed step receipts (the caller keeps the chain; a guardian key rotation starts a new chain). |

### C-309 plan_root_authorized fails closed when no authorized plan is configured

**Statement.** `verifyPCActnCore` and `verifyPCActn` FAIL `plan_root_authorized` (reason `default-deny: no authorized plan is configured for this verifier ...`) unless the verifier supplies `authorizedPlanRoots` (core) or a plan with its authorization (`context.plan` + `planAuthorized`). The explicit opt-out `insecureSkipPlanRootCheck` keeps `not-enforced`; `authorize()` rejects it, and `requirePCA` sets it only with `insecureAllowUnenforced`. In every native the authorize pipeline fails the check with the same reason when no plan source is configured and accepts no opt-out.

| | |
|---|---|
| Enforced by | `verifyPCActnCore`, `verifyPCActn`, `createAuthorizer`; `Authorize` in each native SDK. |
| Trusted inputs | The verifier's own plan configuration. |
| State | None. |
| On failure | Deny (`plan_root_authorized`). |
| Established by | Tests: the TypeScript suite, one default-deny test per native. |
| Guarantees | G-20. |
| Status | **Enforced.** Breaking change: see the migration guide. |

### C-315 A token detokenises only for a sink the grant allows its class to reach

**Statement.** `redactReadWithVault` records each minted token with its class, value and grant digest; `detokenize` returns the value only for a signed, unexpired, pinned-principal grant under which the token was minted and whose sink rule lists the token's class in `allow` (`escalate` classes ask). An unknown token, a token of another grant, an unlisted sink and a class outside both lists deny.

| | |
|---|---|
| Enforced by | `redactReadWithVault`, `detokenize`, `memoryVault` (`@atlasauth/pca`). |
| Trusted inputs | The pinned principal key; the vault store. |
| State | The vault store (the resource server's; the in-memory one is a reference). |
| On failure | Deny or escalate; no value is returned. |
| Established by | Tests: `read-vault.test.ts`. |
| Guarantees | G-20. |
| Status | **Enforced; natives pending CI.** The store is the operator's; the in-memory one is a reference. |

### C-316 Aggregates are bounded by a signed group size, a clamp and a query cap

**Statement.** `aggregateRead` refuses an aggregate over fewer than `min_group` rows (`group_too_small`), clamps each value to the rule's bound before summing, and denies once `max_queries` answers were given (`query_cap`).

| | |
|---|---|
| Enforced by | `aggregateRead`, `signAggregateGrant` (`@atlasauth/pca`). |
| Trusted inputs | The pinned principal key. |
| State | The caller-owned `AggregateState`. |
| On failure | Deny; the state is returned unchanged. |
| Established by | Tests: `read-vault.test.ts`. |
| Guarantees | G-20. |
| Status | **Enforced in the TypeScript reference.** |

### C-317 Epsilon is accounted deterministically per grant and an overspend denies

**Statement.** Each differentially private rule charges its `epsilon_micro` (integer micro-epsilon) to the state; a query that would take the total above `epsilon_budget_micro` is denied (`epsilon_exhausted`) and leaves the state untouched. Sequential composition only.

| | |
|---|---|
| Enforced by | `aggregateRead`. |
| Trusted inputs | The grant. |
| State | The caller-owned `AggregateState`. |
| On failure | Deny. |
| Established by | Tests: `read-vault.test.ts` (budget exactly met, then over). |
| Guarantees | G-20. |
| Status | **Enforced; natives pending CI.** This is epsilon accounting under sequential composition, not a proof of privacy for arbitrary data. The noise is an integer-exact discrete Laplace (Canonne-Kamath-Steinke) drawn from SHA-256 blocks: `seeded` mode is deterministic and pinned byte for byte by the shared vectors; `secure` mode (production) seeds the same sampler from the OS CSPRNG. |

### C-318 A repeated aggregate returns the same answer and is not charged again

**Statement.** The query digest (grant, verb, resource, purpose, function, row count, clamped sum) keys the answered map; a repeat returns the stored answer with zero charge, so asking again does not average the noise away. In `seeded` mode the noise is derived from the salt and the digest; in `secure` mode a fresh CSPRNG seed per answered query.

| | |
|---|---|
| Enforced by | `aggregateRead`. |
| Trusted inputs | The salt. |
| State | The answered map. |
| On failure | None. |
| Established by | Tests: `read-vault.test.ts`. |
| Guarantees | G-20. |
| Status | **Enforced; natives pending CI.** In seeded mode the salt must stay with the resource server; production uses `secure`. |

### C-319 The exposure of a committed workflow can be analysed statically, outside the trusted core

**Statement.** `dagExposure` reports the maximum steps, depth, level width, path count, per-cap spend ceiling, never-runnable steps, sinks with their data lineage and whether any label protects them, ordering-only steps and pipelinable edges. Analysis tooling: it enforces nothing.

| | |
|---|---|
| Enforced by | `dagExposure` (`@atlasauth/pca-analyzer`). |
| Trusted inputs | None. |
| State | None. |
| On failure | Throws on a body that is not a DAG. |
| Established by | Tests: `dag-exposure.test.ts`. |
| Guarantees | G-20. |
| Status | **Built (analysis tooling).** |


### C-500 A lease is renewed only to a later expiry, never past its maximum lifetime, and only the newest record is live

**Statement.** `LeaseRegistry.accept` takes an issue (seq 1) or a renewal (seq = current + 1) signed by a pinned authority. A renewal must keep the lease's identity (path, grant, holder, requester, `max_ttl`, first-issue time), strictly extend `expires_at`, arrive before the old expiry, and end no later than `issued_at + max_ttl`; with `freshJustification` (default) it must carry a justification digest different from the previous record's. `checkLease` allows only the newest stored record, inside its window and its cap, and fails closed on a store error, a tampered record, an older record (`superseded`) or an unknown lease. Automatic renewal (`renewLease`) may be vetoed by a caller-supplied signal and is never lengthened by one.

| | |
|---|---|
| Enforced by | `LeaseRegistry`, `checkLease`, `renewLease`, `signLease`, `verifyLease` (`@atlasauth/pca-grants`); `lease-vectors.json` in the nine natives. |
| Trusted inputs | The pinned lease authority keys; the verifier's clock. |
| State | The newest record and the renewal ledger per lease id. |
| On failure | Typed `code` (`bad_seq`, `stale_seq`, `lease_fork`, `renewal_mismatch`, `over_max_ttl`, `not_extending`, `expired_lease`, `stale_justification`, `expired`, `past_max_ttl`, `superseded`, ...); `check` denies. |
| Established by | Tests: "lease vectors" and "lease helpers" (31 scenarios, 81 vectors); the nine native vector replays. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-501 Whoever asks for a lease cannot approve it, and approvals come from distinct, eligible principals

**Statement.** Checked on every issue and every renewal: approvers are distinct, none is the requester or the holder, none appears in the holder's delegation chain, all are in `eligibleApprovers` when that is pinned, and there are at least `minApprovals` (k of n). A policy with a non-positive `minApprovals` refuses everything. The reason text is display-only.

| | |
|---|---|
| Enforced by | `sodError`, `LeaseRegistry.accept` (`@atlasauth/pca-grants`); natives replay the same rule. |
| Trusted inputs | The registry's SoD policy; the chain keys the caller supplies. |
| State | None. |
| On failure | `{ok: false, code: 'sod'}`. |
| Established by | Tests: "sodError returns the exact reason"; vectors `sod-*` (6 scenarios). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-502 A revocation by lease, path prefix or grant kills the matching leases and blocks renewal for good

**Statement.** A signed `LeaseRevocation` by a pinned authority covers every lease with `issued_at` at or before its `revoked_at` whose id (target `lease`), grant (target `grant`) or path (target `prefix`, at a segment boundary: `db/prod` covers `db/prod/ro`, never `db/production`) matches. A covered lease fails `checkLease` (`revoked`) and its renewal is refused (`revoked`). A lease issued after the revocation under the same prefix is a new lease. The store is one document updated atomically, so a revocation cannot be missed by a concurrent renewal.

| | |
|---|---|
| Enforced by | `LeaseRegistry.revoke`, `pathUnder`, hosted `/pca/leases/revoke` (`@atlasauth/pca-grants`). |
| Trusted inputs | The pinned authority keys. |
| State | The revocation list. |
| On failure | `{ok: false, code: 'bad_record' | 'unknown_authority'}`. |
| Established by | Tests: vectors `revoke-*`, "hosted lease routes". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-503 A shadow policy never decides, and its failures and mutations cannot change the enforced answer

**Statement.** `runShadow` computes the enforced decision first and returns it unchanged. A candidate receives a copy of the input; a candidate that throws or returns anything but allow/escalate/deny is recorded as `error`, not as a decision. Every divergence is recorded in the decision record (`shadow: [{digest, decision, diverged}]`) and as a verifier-signed `ShadowDiff`, with the direction (`widening`) derived from the decision order.

| | |
|---|---|
| Enforced by | `runShadow`, `ShadowLog`, `verifyShadowDiff`, the `shadow` member of `PolicyBundleBody` and `DecisionRecord` (`@atlasauth/pca-grants`). |
| Trusted inputs | The enforced decision function. |
| State | Per-candidate counters and diffs. |
| On failure | Candidate failures are counted; the enforced decision is returned regardless. |
| Established by | Tests: "runShadow", "ShadowLog". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-504 A shadow policy is promoted only with zero unexplained widenings, and only by a new signed revision

**Statement.** `promotionGate` passes only when there are enough observations, no candidate failures, every recorded diff verifies under the log signer for this exact (candidate, enforced) pair, and every widening has a principal-signed explanation for that candidate and action. A candidate the analyzer cannot show narrower-or-equal (`wider` or `unknown`) additionally needs a principal-signed approval for the pair (`advisory_wider`). `promoteShadow` refuses without a passing gate or when the candidate is not listed in the enforced revision's `shadow`, and returns the body of revision + 1 chained to the enforced digest; the pinned signers sign it like any bundle.

| | |
|---|---|
| Enforced by | `promotionGate`, `promoteShadow`, `signWideningExplanation`, `signPromotionApproval` (`@atlasauth/pca-grants`). |
| Trusted inputs | The pinned principals and log signer; the analyzer verdict the caller supplies. |
| State | The shadow log. |
| On failure | `{ok: false, code}` or a throw from `promoteShadow`. |
| Established by | Tests: "promotionGate", "bundle shadow member and promotion". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-505 A CEL expression is imported only if it translates exactly

**Statement.** `celToCondition` translates one boolean CEL expression of a closed subset to a PCA `Condition` and rejects, naming the construct, everything else: arithmetic, conditionals, indexing, maps, `size`, `matches`, macros, conversions, doubles, unsigned and hex literals, bytes and raw strings, unsupported escapes, durations, `null`, bare constants, bare boolean variables, comparisons of two literals, chained comparisons, undeclared identifiers, type mismatches, `has()` on a variable not declared optional, and anything over the size limits. For every context the translation is true exactly when CEL evaluates to true (checked by a differential test against a reference CEL evaluator over thousands of contexts, which also found and removed the bare-boolean encoding). One rejection in a batch makes the whole import deny.

| | |
|---|---|
| Enforced by | `celToCondition`, `celToPredicate`, `celConditionsToPca` (`@atlasauth/pca-policy-bridge`). |
| Trusted inputs | The schema mapping CEL names to PCA paths and types. |
| State | None. |
| On failure | `{ok: false, code, message, at}`; a batch with errors fails closed in `decide`. |
| Established by | Tests: "exact translation (differential against a reference CEL evaluator)", "anything it cannot translate exactly is rejected, by name" (60 constructs). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-506 An allow whose obligations the enforcement point cannot perform is a deny

**Statement.** `pepObligationGate` turns an `allow` (or an `escalate` with a verified answer) into a `deny` when any obligation kind is outside the PEP's supported set, when the obligation list is malformed, or when the supported set is malformed. The closed vocabulary (`log`, `notify`, `redact`, `watermark`, `require_receipt`) validates every parameter; unknown kinds and members are malformed. A `deny` and an unanswered `escalate` pass through unchanged. Obligations are carried in the signed decision record and a resource server lists its supported kinds in `/.well-known/pca-configuration` (`obligations_supported`). Merging obligation lists is a union that only adds duties.

| | |
|---|---|
| Enforced by | `pepObligationGate`, `obligationsError`, `mergeObligations`, `collectObligations`, `buildDiscoveryDocument({ obligationsSupported })` (`@atlasauth/pca`); the nine natives. |
| Trusted inputs | The PEP's declared supported kinds. |
| State | None. |
| On failure | `deny` with the unsupported kinds listed. |
| Established by | Tests: "obligations-vectors.json", "obligations (exact outcomes beyond the shared vectors)". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-507 An obligation not reported by its due time tightens and never retroactively allows

**Statement.** `obligationOutcome` lists the obligations that are past `due` and not in the reported-fulfilled set and answers `escalate` with status `obligation_unmet` (the holder is frozen or asked to step up). It never changes a decision already made. Malformed input or a bad clock counts everything as overdue.

| | |
|---|---|
| Enforced by | `obligationOutcome` (`@atlasauth/pca`); the nine natives. |
| Trusted inputs | The PEP's report of fulfilled indexes; the clock. |
| State | None. |
| On failure | `escalate` with the overdue indexes. |
| Established by | Tests: outcome vectors (10). |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-508 Every native verifier agrees with the reference on leases and obligations

**Statement.** `lease-vectors.json` and `obligations-vectors.json` are produced by the TypeScript reference (the generators cross-check the hand-written expectations against it and CI fails on a stale file) and replayed by Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET and Swift; a missing file fails the test.

| | |
|---|---|
| Enforced by | The generators and the native replays. |
| Trusted inputs | The vector files. |
| State | None. |
| On failure | CI failure naming the vector. |
| Established by | Tests: the nine native vector replays; "lease vectors" currentness; "obligations-vectors.json is current". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-509 A break-glass grant is time-boxed, budgeted and loud

**Statement.** A break-glass record is signed by a pinned authority, lasts at most 24 hours (`expires_at - issued_at`), allows 1 to 16 uses and binds its reason as a digest. A use is recorded (numbered, timestamped, bound to the action digest) only inside the window, within the budget, for the named holder, and only when the enforcement point reports that it delivered the notification to `notify_to`; an unreported notification, an expired or not-yet-valid grant, an exhausted budget, an unknown grant and a wrong holder are refusals with typed codes.

| | |
|---|---|
| Enforced by | `signBreakGlass`, `verifyBreakGlass`, `BreakGlassRegistry.use` (`@atlasauth/pca-grants`); the nine natives on `break-glass-vectors.json`. |
| Trusted inputs | The pinned authority keys; the PEP's notification report; the clock. |
| State | Per-holder shard: grants, numbered uses, reviews. |
| On failure | Typed `code` (`not_notified`, `expired`, `budget_exhausted`, ...). |
| Established by | Tests: "break-glass records", "BreakGlassRegistry", the break-glass vectors; the nine native replays. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-510 An unreviewed break-glass use freezes the holder, and a signed review decides the outcome

**Statement.** The first use starts a clock (`review_within`). Once it runs out with no signed review, or after an `unjustified` review, the holder is frozen: no use of any of their break-glass grants, no new grant. The reviewer is a pinned key that is neither the holder nor the issuing authority; the first review of a grant is final; a review needs a use and a time between the first use and now; a late `justified` review lifts an overdue freeze, an `unjustified` one never lifts. A frozen query that cannot be answered is frozen.

| | |
|---|---|
| Enforced by | `BreakGlassRegistry.review`, `BreakGlassRegistry.frozen`, `signBreakGlassReview` (`@atlasauth/pca-grants`); the nine natives. |
| Trusted inputs | The pinned reviewer keys; the clock. |
| State | Per-holder shard. |
| On failure | `holder_frozen`, `revoked`, typed review codes. |
| Established by | Tests: break-glass vectors (freeze, late review, unjustified, SoD, final review); the nine native replays. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-511 Missing context is typed and never a silent allow

**Statement.** `decideWithMissing` answers allow only when the permit conditions are true over the bound context. A condition that cannot be decided because a value is absent yields `escalate` with a reason naming each missing path and who may supply it (`principal`, `discharge_issuer`, `rs_observation`); if any missing path can only be supplied by the agent (`agent_declared_untrusted`) the answer is a deny that names it; an undecidable condition over a present but wrongly typed value is a deny (`ill_typed_context`); a bound context that is not an object with an `action` is a deny (`bad_context`); false conditions deny.

| | |
|---|---|
| Enforced by | `decideWithMissing`, `supplierOf`, `supplierTableError` (`@atlasauth/pca`); the nine natives on `missing-context-vectors.json`. |
| Trusted inputs | The supplier table the host configures. |
| State | None. |
| On failure | Typed deny / escalate reason. |
| Established by | Tests: missing-context vectors; "typed decisions: exact result objects". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-512 Request-supplied context never shadows a value bound in the grant or chain

**Statement.** `bindContext` merges request-supplied context into the bound context: a supplied value never replaces a bound one, a differing value (or a value written beneath a bound leaf) is a conflict that makes the call a deny (`context_shadow: <paths>`), values for agent-only paths are dropped, only `subject`, `env` and `action.params` are mergeable and the verb and resource are never taken from the request side.

| | |
|---|---|
| Enforced by | `bindContext`, `decideWithMissing` (`@atlasauth/pca`); the nine natives. |
| Trusted inputs | The bound context. |
| State | None. |
| On failure | `context_shadow` deny. |
| Established by | Tests: missing-context vectors (bind and shadow cases); "bind never writes into prototypes". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-513 A decision names every policy class consulted, and a refusal names who said no

**Statement.** `decideClasses` is the meet of the answers of the classes consulted (constitution, regulatory, org, blueprint, user), each at most once with its revision and digest, reported in a fixed order with `denied_by` and `escalated_by`. No class consulted, a malformed list, an unknown or repeated class is a deny. `DecisionRecord.policy_classes` carries the list.

| | |
|---|---|
| Enforced by | `decideClasses`, `classVerdictsError` (`@atlasauth/pca`); the nine natives on `policy-classes-vectors.json`. |
| Trusted inputs | The per-class answers the verifier computed. |
| State | None. |
| On failure | Deny with the reason. |
| Established by | Tests: policy-classes vectors; "policy classes". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-514 A template-linked grant can cite the exact parameter object by digest

**Statement.** A `template_ref` carries either its `slots` or a `bind_params_digest` (never both); the resolver must be given a parameter object that hashes to the digest (`hashCanonical` of the slot object) and that passes the template's own slot rules; a missing, edited or substituted object refuses the link. The signature over the grant covers the digest.

| | |
|---|---|
| Enforced by | `createLink({ bindParams })`, `resolveLink` (`registry.params`), `slotsDigest`, `templateRefError` (`@atlasauth/pca`); the nine natives on `policy-link-vectors.json`. |
| Trusted inputs | The registry of signed templates and the parameter store. |
| State | None. |
| On failure | `{ok: false, reason}`. |
| Established by | Tests: policy-link vectors; "bound parameter objects (bind_params_digest)". |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-515 Lease storage is sharded, atomic per shard, and refuses a different shard count

**Statement.** Each lease lives in the shard its id hashes to; an issue, renewal and check touch one shard; a prefix or grant revocation is written to every shard and a lease revocation to its own; a store opened with another shard count is refused instead of appearing empty; with a TTL ceiling, revocations older than the ceiling are pruned from every shard and a longer `max_ttl` is refused. `runLeaseStoreConformance` proves these properties for any key-value store, and is run against the in-memory store and the crash-safe durable state.

| | |
|---|---|
| Enforced by | `LeaseRegistry`, `shardOf`, `runLeaseStoreConformance` (`@atlasauth/pca-grants`). |
| Trusted inputs | The key-value store's atomic update. |
| State | Shard documents. |
| On failure | `store_unreachable`, `ttl_ceiling`. |
| Established by | Tests: "lease storage conformance kit". |
| Guarantees | G-1. |

### C-520 An artifact-class discharge comes only from an artifact-class pin

**Statement.** `needs_discharge.issuer_class` and a discharge pin may be `artifact`. A caveat that asks for `artifact` is discharged only by a key the verifier pinned with that class; a `workload`, `org`, `human` or `model` pin never discharges it, and an `artifact` pin never discharges a caveat that asks for another class. Every native verifier has the class.

| | |
|---|---|
| Enforced by | `ISSUER_CLASSES` and `verifyDischarge` (TypeScript `caveat-lang.ts`; the nine natives' caveat-language modules). |
| Trusted inputs | The verifier's pins. |
| State | None. |
| On failure | The discharge is refused (`not of the class`); the caveat refuses. |
| Established by | K1 corpus `discharge_verify` entries `dv-artifact-*` and `caveat_shape` `shape-nd-artifact` in TypeScript and all nine natives; `provenance-gate.test.ts`. |
| Guarantees | G-3, G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-521 The SLSA level comes only from a pinned signer-builder pair

**Statement.** `provenanceGate` assigns a level only when the OIDC issuer, the signer identity (exact or prefix) and `builder.id` match a root the verifier pinned, and takes the highest such level; nothing in the provenance can raise it. Then the floor, the source repository and ref pins and the build-type allowlist apply, and the provenance's own resolved source must agree with the certificate's.

| | |
|---|---|
| Enforced by | `provenanceGate` (TypeScript and the nine natives). |
| Trusted inputs | The verifier's policy (roots, floor, pins) and clock. |
| State | None. |
| On failure | A refusal code (`no_root`, `level`, `source_repo`, `source_ref`, `source_mismatch`, `build_type`, `stale`, `future`, ...); no discharge. |
| Established by | Shared vectors `provenance-vectors.json` (gate) in TypeScript and nine natives. |
| Guarantees | G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-522 The running image must be the provenance subject

**Statement.** With `require_runtime` (the default of `provenanceCaveat`), a discharge carries `runtime_bound: true` only when the digest of the running image, read from an EAT the verifier accepted (signature, nonce, channel, appraisal), equals one of the statement's subjects under the same algorithm. A missing or ambiguous measurement is no join.

| | |
|---|---|
| Enforced by | `runtimeDigestFromEat`, `issueArtifactDischarge`, `provenanceGate`. |
| Trusted inputs | The accepted EAT; the verifier's policy. |
| State | None. |
| On failure | `runtime_mismatch`, `runtime_required` or `no_runtime`; no discharge, so the caveat refuses. |
| Established by | `sigstore.test.ts` (a swapped image gets no discharge), `provenance-gate.test.ts` (through `requirePCA`). |
| Guarantees | G-10, G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-523 A provenance bundle is verified offline against pinned Sigstore roots

**Statement.** `verifySigstoreBundle` accepts a bundle only if: the signed entry timestamp verifies under a pinned Rekor key valid at that time; the inclusion proof leads to a checkpoint signed by that key with the same size and root; the Fulcio certificate chains to a pinned CA and every certificate is valid at the signing time; an embedded SCT verifies under a pinned CT log; the log entry names this payload, signature and certificate; the DSSE signature over PAE verifies; the statement is in-toto v1 with SLSA v1 provenance. Nothing is fetched.

| | |
|---|---|
| Enforced by | `verifySigstoreBundle`, `parseTrustedRoot` (`@atlasauth/pca-attest-eat`). |
| Trusted inputs | The pinned trusted root. |
| State | None. |
| On failure | A refusal code per stage. |
| Established by | `sigstore.test.ts` on a public bundle and its mutations. |
| Guarantees | G-10, G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-524 Inclusion proofs follow RFC 9162 exactly

**Statement.** `verifyRfc9162Inclusion` implements RFC 9162 section 2.1.3.2 with 64-bit positions; anything malformed is false.

| | |
|---|---|
| Enforced by | `verifyRfc9162Inclusion` (TypeScript and nine natives). |
| Trusted inputs | None. |
| State | None. |
| On failure | False. |
| Established by | `provenance-vectors.json` (merkle_inclusion: a real Rekor proof, its mutations and trees built by the recursive definition). |
| Guarantees | G-12. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-525 Every native decides the provenance gates exactly like the reference

**Statement.** The nine natives replay all `merkle_inclusion`, `gate` and `model_path` entries of `provenance-vectors.json` with exact equality of codes, levels and claims.

| | |
|---|---|
| Enforced by | Each native's provenance module. |
| Trusted inputs | None. |
| State | None. |
| On failure | CI failure naming the vector. |
| Established by | Native vector tests in Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET, Swift. |
| Guarantees | G-1. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-526 A published pack pins the identity that builds it

**Statement.** `pca actions lint` reports `LP-001` for a beta or stable pack whose configuration pins no builder identity; `--strict` fails on it.

| | |
|---|---|
| Enforced by | `k9Findings` (`@atlasauth/pca-cli`). |
| Trusted inputs | The project configuration. |
| State | None. |
| On failure | A warning; a strict run fails. |
| Established by | `actions.test.ts` (LP-001). |
| Guarantees | G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-527 A trace rule is a caveat the verifier evaluates over its own history

**Statement.** `compileTraceRules` lowers `never B after A within W` to K1 `derive` caveats that are false exactly when an A is in the verifier's history within `(now - W, now]` and the action is a B; a missing history or verb is unknown and refuses.

| | |
|---|---|
| Enforced by | `compileTraceRules`; `evaluateDerive` (every verifier). |
| Trusted inputs | The verifier's history. |
| State | The history window. |
| On failure | The caveat refuses. |
| Established by | `trace-rules.test.ts`; K1 corpus `trace-*` entries in all natives. |
| Guarantees | G-3, G-16. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-528 A trace rule that cannot be compiled exactly is an error

**Statement.** Unknown tools, empty selectors, resource selectors on the effect side, windows over 30 days, more than 64 caveats and Invariant conditions outside the subset are errors. The only relaxation, `dropUnsupported`, removes conjuncts from a raise condition, which can only add refusals; removed conditions are reported.

| | |
|---|---|
| Enforced by | `parseTraceRule`, `parseInvariantRule`, `compileTraceRules`. |
| Trusted inputs | The rule text and the verb table. |
| State | None. |
| On failure | `TraceRuleError` (CLI: `LT-000`). |
| Established by | `trace-rules.test.ts`, `actions.test.ts` (LT-000). |
| Guarantees | G-16. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-529 The lethal trifecta is reported until a rule cuts a leg

**Statement.** `lethalTrifecta` reports each send reachable from both an untrusted-content read and a private-data read with no trace rule from every untrusted read, or every private read, to it. It is a lint; it enforces nothing.

| | |
|---|---|
| Enforced by | `lethalTrifecta`; CLI `LT-001`. |
| Trusted inputs | The action set and the compiled edges. |
| State | None. |
| On failure | A warning. |
| Established by | `trace-rules.test.ts`, `actions.test.ts` (LT-001). |
| Guarantees | None (advisory). |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-530 No detector output can widen a decision

**Statement.** `detectorSignal` returns ok, escalate or deny: a valid suspicious receipt lowers to the detector's setting, a valid no_finding is exactly no receipt, an invalid receipt escalates, a malformed policy denies. For every base decision `d` and receipt set `R`, `tighten(d, signal(R)) <= d`, and adding valid no_finding receipts changes neither the signal nor `env.detect` nor any `tighten[]` outcome. There is no option that requires a clean scan.

| | |
|---|---|
| Enforced by | `detectorSignal`, `signDetectorReceipt` (`@atlasauth/pca`). |
| Trusted inputs | The pinned gateway keys, the content digests of the action, the session, the clock. |
| State | None. |
| On failure | escalate or deny. |
| Established by | `detector-receipt.test.ts` (exact outcomes and two fast-check properties). |
| Guarantees | G-22. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-531 A grant cannot read a detector verdict

**Statement.** `env.detect.*` is a model-derived root of rule 21 in TypeScript and every native: a grant `where` that reads it is refused; only `tighten[]` may.

| | |
|---|---|
| Enforced by | `isModelDerivedPath`, `decideTighten` (all verifiers). |
| Trusted inputs | None. |
| State | None. |
| On failure | The grant is refused (`tighten`). |
| Established by | `detector-receipt.test.ts`; `provenance-vectors.json` model_path in nine natives. |
| Guarantees | G-22. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-532 A broken detector integration never looks clean

**Statement.** The Lakera, Prompt Security and generic adapters map a response to `no_finding` only when it is well-formed and reports nothing; malformed or ambiguous responses become `suspicious` with category `detector_error`.

| | |
|---|---|
| Enforced by | `lakeraReceipt`, `promptSecurityReceipt`, `genericReceipt` (`@atlasauth/pca-dataflow`). |
| Trusted inputs | The gateway signing key. |
| State | None. |
| On failure | A suspicious receipt. |
| Established by | `trace-rules.test.ts` (detector adapters are one-sided). |
| Guarantees | G-22. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |

### C-533 The gateway enforces third-party caveats with the verifier's own pins

**Statement.** In full-policy mode a gateway configured with `k1` verifies presented discharges (header `PCA-Discharges`, or body `pca_discharges` when the body is not the signed params) against its own pins and passes them to the full verifier; the configured members win over presented ones; unreadable artifacts are no artifacts; a gateway without `k1` refuses every K1 caveat.

| | |
|---|---|
| Enforced by | `presentedArtifacts`, the `k1` policy member (`@atlasauth/pca-gateway`); `authorizeExecution` `k1`. |
| Trusted inputs | The gateway's pins. |
| State | The `usesStore` for `max_uses`. |
| On failure | `proof-rejected` (403). |
| Established by | `k1-discharges.test.ts`. |
| Guarantees | G-3, G-21. |
| Status | **Implemented, pending CI.** The mutation and CI gates must pass before it is called production. |


### C-540 A capability handle exists only for an operation the verifier allowed

**Statement.** A sandbox handle is minted only from a verifier result that allows exactly the operation named: same verb, same resource, and params that hash to the signed digest. A result the verifier denied, a result for other params, another verb or another resource, and a table below the runtime class the grant requires all end in a thrown error before any handle exists. The handle carries the signed params; the tool cannot change them.

| | |
|---|---|
| Enforced by | `HandleTable.mint` (`@atlasauth/pca-sandbox`), over `isAuthorizedFor` in `@atlasauth/pca`. |
| Trusted inputs | The verifier result (`authorize` / `requireAuthorized`), the operation from the host's own mapping. |
| State | The table: remaining uses, expiry, revocation per slot. |
| On failure | A thrown `not_authorized`, `runtime_class_too_weak` or `bad_uses`; no slot is created. |
| Established by | Tests: "mints only for exactly the operation the verifier allowed", "refuses a result the verifier denied", "refuses a table below the class the grant requires", "validates uses". |
| Status | **Production (pending CI).** Outside the verified core. The table enforces what the verifier decided; it makes no policy of its own. |

### C-541 Derivation only narrows, and revocation follows derivation

**Statement.** A handle derived from another takes its uses from the parent and an expiry no later than the parent's; a request to widen either is refused. Revoking a handle revokes every handle derived from it, at any depth, and revoking twice or revoking an unknown handle changes nothing.

| | |
|---|---|
| Enforced by | `HandleTable.attenuate`, `HandleTable.revoke`. |
| Trusted inputs | The parent slot. |
| State | The derivation tree of one table. |
| On failure | A thrown `attenuate_widens` or `unknown_handle`. |
| Established by | Tests: "a child takes uses from its parent and can never widen", "revoking a parent revokes the whole subtree". |
| Status | **Production (pending CI).** No hardware claim; this is the data-structure property of a capability system, not a kernel. |

### C-542 A sandboxed tool has no authority except its handles

**Statement.** The WebAssembly host runs a tool only if its imports are exactly some of `invoke`, `handle_count` and `handle_verb` from `pca:act`, it declares at most one memory with a maximum inside the cap, it is not shared or 64-bit memory, and it is well formed and under the size cap. Any other import (a WASI interface, `env`, an extra host function) refuses the module before it runs. A guest memory window outside linear memory is refused before a use is spent. A trap is contained and reported. Two sandboxes are separate capability spaces.

| | |
|---|---|
| Enforced by | `createSandbox` (`run`, `runAsync`), `runComponent` with the reference wasmtime host. |
| Trusted inputs | The module bytes (untrusted), the host's executors (trusted). |
| State | The per-sandbox handle table. |
| On failure | `ambient_import:<module>.<name>`, `memory_limits`, `malformed_module`, `module_size`, `no_entry`, `trap:<kind>`, `timeout` (async host). |
| Established by | Tests: the WASM host groups (synchronous and worker), the component tests under wasmtime (canonical ABI, ambient import refused, fuel exhausted, host codes), the scripted-host protocol tests, boundary tests, and the demo agent test. |
| Status | **Production (pending CI).** Two hosts. The Node host runs core modules whose ABI mirrors the package's WIT world (`run` has no time limit; `runAsync` has a wall-clock one). The component host (`runComponent`, wasmtime) runs real components through the canonical ABI with an instruction budget (fuel) as well as a timeout, and refuses any import other than the handle interface before instantiation. Fuel counts WebAssembly instructions, not time spent in the host's executors. |

### C-543 Every handle use is spent first, receipted, and chained

**Statement.** A use is consumed before the executor runs and stays consumed when it throws or returns something that is not bytes. Every use (allowed, refused or failed, an unknown handle included) appends a receipt carrying the authorizing operation id, verb, resource, params digest, the host's runtime class and the outcome; receipts form a hash chain (and can be signed) that detects a bad digest, a broken link, a reorder, a gap and a bad signature.

| | |
|---|---|
| Enforced by | `HandleTable.use` / `useAsync`, `ReceiptLog`, `verifyReceiptChain`. |
| Trusted inputs | The host clock and signing callback. |
| State | The append-only log. |
| On failure | `executor_error`, `spent`, `no_executor`, `unknown_handle` codes to the tool; chain failure at the first bad index. |
| Established by | Tests: "runs the executor on the signed params, once, and receipts it", "a failing executor still spends the use", "refuses when no executor exists", "expires", "receipt chain". |
| Status | **Production (pending CI).** The chain proves internal consistency, not completeness; anchor its head to bound a host that omits receipts. |

### C-544 Egress is default deny and allows only an admitted request

**Statement.** The egress policy allows a request only when it equals a template admitted from a verified operation: exact host, port, scheme and method; the exact path (or a prefix on a segment boundary when asked); the admitted query; and a body only if its hash was admitted. Userinfo, fragments, relative URLs, encoded slashes, dots and backslashes in the path, and a CONNECT that was not admitted as a tunnel are refused. Each admission is spent on use and can expire. A template with a malformed host, port, method, scheme or path is refused when admitted, and so is an operation the verifier did not allow.

| | |
|---|---|
| Enforced by | `EgressPolicy.admit`, `EgressPolicy.claim`, `createEgressProxy`. |
| Trusted inputs | The tool author's mapping from operation to template; the verifier result. |
| State | The admissions and their remaining uses. |
| On failure | 403 with a reason, and a `refused` receipt; a thrown error at admission. |
| Established by | Tests: the policy group and the real-socket proxy group, and the test that runs `curl` under the generated macOS profile. |
| Status | **Production (pending CI).** A tunnel is host-and-port grain. The proxy bounds a tool only if the tool has no other route out (see C-546). |

### C-545 The proxy never reaches a private address unless told to

**Statement.** Unless `allowPrivate` is set, the proxy refuses an upstream that resolves to a private, loopback, link-local, carrier-grade NAT, multicast or unspecified address (IPv4-mapped IPv6 included), and checks IP literals itself. The refusal is a 502 or a failed tunnel with an `error` receipt, and the origin is never contacted.

| | |
|---|---|
| Enforced by | `isPrivateAddress`, `createEgressProxy`. |
| Trusted inputs | The resolver's answer at connect time. |
| State | None. |
| On failure | 502, `upstream:EACCES` receipt. |
| Established by | Tests: "isPrivateAddress", "SSRF guard: with allowPrivate off". |
| Status | **Production (pending CI).** Does not defend against a hostile resolver. |

### C-546 An OS profile grants only what was authorized, and nothing it cannot validate

**Statement.** The policy compiler takes needs only from operations the verifier allowed, refuses any path that is not absolute, normalized and made of a small safe character set (it never escapes), refuses malformed hosts and ports, requires a proxy port for any network need, merges and sorts so the same grant gives the same bytes. The seccomp profile denies by default and includes network system calls only with a proxy and exec only for a named binary; the Landlock ruleset handles every access right and allows only the named paths and the proxy port; the macOS profile denies by default and allows outbound only to the proxy port. On macOS and on Linux the generated profile is applied to real processes in a test: a granted path is readable, others are not, and a tool can reach only the proxy.

| | |
|---|---|
| Enforced by | `compilePolicy`, `policyFromNeeds`, `seccompProfile`, `landlockRuleset`, `macosProfile`. |
| Trusted inputs | The tool author's mapping from operation to needs. |
| State | None. |
| On failure | A thrown `bad_path`, `bad_mode`, `bad_net_need`, `bad_proxy_port`, `net_needs_proxy` or `not_authorized`. |
| Established by | Tests: the shared sandbox vectors, the policy and profile groups, exact-profile tests, and the macOS and Linux enforcement groups. |
| Status | **Production (pending CI).** On Linux the reference helper applies the generated seccomp and Landlock profiles to a child process and the tests check allowed and refused paths and syscalls and that only the proxy port is reachable; in CI a missing prerequisite fails the run instead of skipping it. seccomp is blind to paths and addresses, so it is paired with Landlock; the Landlock port rule does not pin the address, so pair it with a network namespace or firewall rule. |

### C-547 A grant can require a minimum runtime class

**Statement.** The runtime classes are ordered `none`, `os_confined`, `egress_default_deny`, `wasi_no_ambient`. A requirement is satisfied only by a known class at or above it; an unknown name never satisfies. A table below the class a mint requires refuses to mint, and every receipt records the class the host proved. The class comes from a signed runtime-class claim by an attestor the verifier pins, bound by digest to the signed passport, to attestation evidence the verifier checked, and to a validity window, with no member beyond the eight; a claim that is missing, unsigned, unpinned, expired, tampered or for another passport is class `none`, so an operator's statement alone never satisfies a requirement.

| | |
|---|---|
| Enforced by | `satisfiesRuntimeClass`, `verifiedRuntimeClass`, `trustFromAttestation`, `signRuntimeClaim`, `createSandbox` (`runtimeClaim`), `HandleTable.mint` (`requires`). |
| Trusted inputs | The pinned attestor keys and the passport digest. |
| State | None. |
| On failure | `runtime_class_too_weak`. |
| Established by | Tests: "runtime classes", "refuses a table below the class the grant requires". |
| Status | **Production (pending CI).** A claim counts only if its `evidence_digest` is among the digests of attestation evidence the verifier itself checked with an attestation verifier (`trustFromAttestation` admits a digest only for evidence that is both verified and bound). Verified by the TypeScript reference and all nine native verifiers against shared vectors. |

### C-600 Producer outputs are reproducible byte for byte

**Statement.** An agent or issuer built on any native SDK produces the same bytes as the TypeScript reference for every deterministic artifact (Ed25519 signatures, canonical JSON, digests, capability chains, plan roots and proofs, PCActns, escalation answers, discharges, narrow blocks, passports, workflow commitments and receipts, read and aggregate grants, consistency tokens) given the same keys, nonces, counters and timestamps. Randomised post-quantum signatures are not compared byte for byte; they are cross-verified, a signature made by one side verifying on the other.

| | |
|---|---|
| Enforced by | `mintGrant`, `delegate`, `buildPCActn` and the other producers of each SDK (`agent` module). |
| Trusted inputs | None. |
| State | None. |
| On failure | A producer that drifts from the vectors fails its own CI. |
| Established by | Tests: "producer vectors (fixed keys, exact outputs)", "test_vectors", "TestProducerVectors", "producer_vectors". |
| Status | **Production (pending CI).** Replays `producer-vectors.json`, generated independently of the TypeScript producers by `gen-producer.mjs` and checked against them. |

### C-601 A producer never emits a weaker or inconsistent artifact

**Statement.** Every producer refuses, instead of signing, a body the verifier would refuse or a policy that weakens the grant: a grant without a goal or with a malformed risk policy, a hardware-rooted passport without evidence, a passport whose id is not the fingerprint of its identity, a workflow or grant signed by a key that is not its principal, an action whose parameters do not match the plan node, an action outside the committed plan, and a decision other than allow or deny.

| | |
|---|---|
| Enforced by | Each SDK's `mint_grant`, `sign_passport`, `sign_workflow`, `sign_read_grant`, `build_pcactn` and `Agent.act`. |
| Trusted inputs | None. |
| State | None. |
| On failure | An error naming the refused input; nothing is signed. |
| Established by | Tests: "refuses_bad_input", "test_refuses_bad_input", "TestProducerRefusesBadInput", "testRefusesBadInput". |
| Status | **Production (pending CI).** |

### C-602 A producer never signs with a suite it cannot honour

**Statement.** Asking a producer for a signature suite that is registered but that the runtime cannot sign with (fn-dsa-*, less-cat1, and the post-quantum suites in PHP) is an error `unsupported_suite: <alg>`, never a silent fall back to Ed25519; a hybrid or post-quantum suite is signed only with a key pair of the matching family, and the issuing key is bound into the signed body.

| | |
|---|---|
| Enforced by | `sign_with_suite` (and its equivalent) of each SDK. |
| Trusted inputs | None. |
| State | None. |
| On failure | `unsupported_suite: <alg>`. |
| Established by | Tests: "ml_dsa_hybrids_cross_verify", "test_post_quantum_hybrids", "TestPostQuantumSuites", "refuses_bad_input". |
| Status | **Production (pending CI).** |
