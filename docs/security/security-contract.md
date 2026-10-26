---
title: Security contract
order: 32
---

# Security contract

**Audience: security reviewers, auditors and resource-server owners.** This page states the nineteen invariants a resource server can rely on when it authorizes an agent's action with PCA, and for each one: the function that enforces it, the inputs it must trust, the state it needs, what happens when it fails, the tests and conformance vectors that establish it, and its **current status on every verifier surface**. It is deliberately blunt about where an invariant does not hold yet.

Read it with the [Threat model](./threat-model.md) (attacks T-001 to T-057, guarantees G-1 to G-21) and the [Trust model](./trust-model.md) (who is trusted for what). The test files behind each invariant are listed per row, as `C-1` to `C-19`, in [Traceability](./traceability.md), whose checker fails the build when a listed test no longer exists.

## Surfaces

The same invariant can hold on one entry point and not on another. The columns below are:

- **Full TS**: `requirePCA` and the TypeScript HTTP adapters built on it (Express, Fastify, Hono, Next.js, fetch, the site guard), and `authorizeToolCall` for MCP tool calls.
- **`verifyPCActn`**: the full TypeScript verifier called directly, without `requirePCA`.
- **Core**: `verifyPCActnCore` and PCA Core. It checks the proof only.
- **Gateway**: `pca-gateway` (Envoy external authorization, Workers, Lambda).
- **Guards**: the execution guards for Mastra, the Vercel AI SDK and OpenAI Agents.
- **Native**: the Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby and Swift verifiers, their HTTP middleware, and the Python agent-framework guards.
- **Hosted**: the hosted `/v1/pca/actions` endpoint.

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

## How this page is kept honest

- Each invariant's tests are listed by file in [Traceability](./traceability.md) (rows `C-1` to `C-19`); the traceability checker fails when a listed test is renamed or removed, or when an invariant here has no row there.
- A retired-statement check fails the build when a public page or README repeats a statement that is no longer true (for example a stale corpus size, or a feature described as unimplemented that now ships).
- No external security audit has been performed. The tests, vectors and models above are the project's own.

Next: [Trust model](./trust-model.md) and [Traceability](./traceability.md).
