# PCA roadmap to "fully done": ideas backlog

Internal spec. Collects every idea raised for taking PCA from its pre-0.5 state to the reference system for agent authorization. Each item has a status; the detailed designs live in the linked specs. Update this file as items ship.

Status keys: **built** (on a 0.5 branch, awaiting CI), **in progress** (a track is running), **spec** (designed, not started), **idea** (not yet designed).

## 1. Positioning: why this is not "API keys with scopes"

| | API key with scopes | PCA |
|---|---|---|
| What is authorized | A category, held for a long time (`payments:write`) | One concrete action with its arguments ("refund $40 on charge ch_1") |
| Parameters | Not seen | Checked per call against limits (amount, merchant, repo) |
| If stolen | Full access until rotated | Useless: single-use, bound to audience, operation and parameters |
| Delegation | Share the key or mint an equal one | Signed chain person → agent → sub-agent; each hop can only narrow |
| Purpose | None | Must fit the signed goal and plan, compiled to policy with proofs |
| Totals over time | None | Durable totals across sessions, agents, fleet; replay and revocation freshness |
| Outcome | Yes / no | Allow / deny / escalate to a person who answers with a signature |
| Model judgement | n/a | Classifier output can only tighten, never widen |
| Audit | "This key called this endpoint" | Signed record of chain, goal, limits; transparency log |

Neighbours: OAuth RAR (rich authorization requests), Macaroons and Biscuit (attenuating tokens), Cedar and OPA (policy engines). Each does one or two of these; PCA's claim is the combination, verified the same way in 10 languages. Where PCA is overkill: plain service-to-service calls with no agent acting on someone's behalf. Public docs should open with this table.

## 2. Goal to decision (abstract goal → binary decision)

Spec: `goal-to-decision.md`. Status: **built**, CI pending (tracks T1–T6, integrated on 05-g2d).

- Typed Goal IR with formal semantics; deterministic compiler with Dafny proofs (soundness, monotonicity, provenance witness, hole safety, units, render injectivity).
- Ternary decision allow / deny / escalate; escalate never becomes allow; signed escalation answers.
- Rules 20/21: unit checks; model-derived values only in `tighten[]`.
- Principal review: PolicyCard, semantic diff, one signed approval of goal + policy + tests; goal_commit v3.
- Durable principal / org / fleet budgets (TLA+ and Lean).
- Adversarial suite W1–W23 and cross-language goal vectors.

### Intent fidelity (getting as close as possible to what the person meant)

Status: **built** (T6), CI pending; live-model eval needs repo secrets.

1. Active disambiguation: minimal distinguishing questions before signing.
2. Policy-by-example: boundary allow/deny examples confirmed and signed as tests.
3. N-version interpretation: several interpreters; enforce the intersection; disagreement escalates.
4. Round-trip check: independent explanation compared with the goal.
5. Conformal risk control: published per-domain error bounds with stated assumptions (Lean proof).
6. Domain ontologies (payments, email, calendar/travel, code, data access).
7. Progressive authorization: start narrow; widen only by signed approval; precedents.
8. Drift monitors that can only tighten.
9. Hostile / prompt-injection benchmark with widening-rate gates.

Honest boundary: we prove the compiler and enforcement, and measure interpretation; no system can prove a model understood intent.

## 3. Action kit (make actions ~100x richer and trivially definable)

Spec: `action-kit.md` (being written). Status: **spec in progress**.

1. One canonical ActionDef (JSON/YAML + TS builder): verb, resource, typed params with units, effects, reversibility, blast radius, idempotency.
2. Traits that carry auth meaning (money-moving, destructive, irreversible, external-communication, data-export, privilege-change, code-execution, credential-access, bulk...): default risk, required limits, escalation. Traits only add restrictions (proved monotone).
3. Importers: MCP tool schemas, OpenAPI, GraphQL, gRPC/protobuf, AsyncAPI, JSON Schema; trait suggestions never auto-trusted; unconfirmed actions get the most restrictive defaults.
4. Built-in catalog packs, thousands of actions (Stripe, GitHub, GitLab, Slack, Google Workspace, Microsoft 365, AWS, GCP, Azure, Salesforce, HubSpot, Shopify, Jira, Linear, Notion, Zendesk, Twilio, SendGrid, databases, filesystem, shell, browser, HTTP, Kubernetes, Terraform, payments, travel), pinned to spec digests.
5. Linter + CLI: `pca actions init | import | lint | test | diff | sign | publish`.
6. Signed, versioned registries; a definition change that would widen existing grants is blocked without re-approval.
7. Policies against traits and params ("any money-moving action under $200/day on these merchants"), wired into the goal compiler.
8. ActionDef loading and trait expansion in all 9 natives + Python with shared vectors.

## 4. Ideas taken from neighbouring systems

Gap analysis against the code (per-idea reference behaviour with sources, file:line status, design beyond the reference, size, track). Status key: present / partial / absent in the 0.5 tree. Pointers are to the gap analysis item number (G#) plus the code that exists today. Reference claims marked [K] there were not re-fetched.

### From Biscuit and Macaroons
1. Third-party caveats with discharge proofs. **absent.** Closest: signed escalation answer (escalation.ts), label/oracle receipts. Design: `needs_discharge` caveat, verifier-pinned issuers, typed claims, rule-21 polarity, single-use via action digest (G1, track K1).
2. Offline attenuation by any holder. **present** (capability.ts:385-412 `attenuate`/`delegate`, attributable, stronger than anonymous blocks). Missing: explicit `seal`, per-action narrow block in the leaf, chain compaction (G2, K1).
3. Datalog-style checks with derived facts. **partial** (predicate DSL with Kleene Tri and `member_of`, no user-defined derived facts). Design: bounded, stratified, non-recursive derive layer; no general Datalog in the verified core (G3, K1 stretch).

### From Cedar and AWS Zelkova
4. SMT policy analysis. **built, experimental (K2, pending_ci)**: pca-analyzer gains maxExposure (per action, autonomous, windowed; composes rate, cap/rate invariants and, in the dollar model, budget_alloc), escalationSurface, delegationEnvelope, a ternary diffPolicies with a CI gate and exposure delta, and an optional untrusted solver hook (witnesses re-checked, unsat labelled unchecked). C-244..C-246, T-344. Open: no solver ships; history-dependent budgets are not in the static answer.
5. Partial evaluation, residual policies, "what may I do". **built, experimental (K2, pending_ci)**: `residual()` (exact against the real evaluator, property-tested; an unknown never prunes a veto), `whatMayIDo()` (advisory envelope bound to the policy digest) and `toFilter()` (SQL, refuses what it cannot express exactly). C-247..C-249, T-346. Open: the `/pca/can` HTTP route and UCAST output are not built (the envelope is a library result).
6. Policy templates linked per principal. **built, experimental (K2, pending_ci)**: signed templates with typed slots, `template_ref` in the envelope (covered by the grant signature), immutable digest-named versions, signed tighten-only overlays, slot-injection refusal; TypeScript reference plus Python, Go and Ruby replaying shared vectors. C-242, C-243, T-342, T-343. Open: Java, Kotlin, .NET, PHP, Rust and Swift ports; the hosted verifier does not resolve links yet (`verifyLinkedPolicy` is opt-in).
7. Forbid overrides permit, with proofs. **built, experimental (K2, pending_ci)**: `decideClauses` / `certify` / `checkForbidCertificate` / `certificateConsistent` (forbid beats permit whoever signed it, order independent, cross-signer precedence names the winner), `forbid-monotone` invariant in pca-invariants, shared vectors, table check in Python, Go and Ruby. C-240, C-241, T-340, T-341. Open: the other six natives; not yet returned by `requirePCA`.

### From AWS IAM Access Analyzer
8. Least privilege from observed behaviour. **built, experimental (K2, pending_ci)**: `suggestNarrowing()` (proposal proven subsumed by the original, ledger-only input, unused-permission findings ranked by blast radius, access requests, decay, task binding). C-250, C-251, T-345. Open: per-task trace storage and the signed AccessRequest transport belong to the operational plane (K3).

### From Zanzibar and OpenFGA
9. Consistency tokens. **implemented, pending CI** in `@atlasauth/pca-grants` (`fresh_at`: signed monotone high-water mark of revocation epoch, ledger size, budget version, policy revision; stale state escalates, never allows; C-260, C-261). The token is a signed PCActn member (`fresh_at`, 0.5), verified by the TS reference and all nine natives (vectors `fresh-at-vectors.json`); the side-carried header form is read for one release (G9, K3).
10. List-objects at scale. **implemented, pending CI** (`listAuthorized`: capability AND pluggable relation source, signed cursor, signed ListReceipt, read accumulator charged for scanned objects; C-262, C-263). The residual-filter engine of item 5 is not built; the capability is a host-supplied predicate (G10, K3).

### From OPA
11. Signed bundles and decision logs. **implemented, pending CI** (`PolicyBundle` k-of-n, rollback and chain checks, `min_verifier_version`; hash-chained Merkle-committed `DecisionRecord` log with signed heads, inclusion proofs, class-based masking, batch streaming, `semanticDiff` and `auditReplay`; C-264, C-265). Not done: FROST aggregate signing is a 1-of-1 signer by construction; witness co-signing of log heads reuses the existing ledger witnesses, not wired here (G11, K3).
12. Policy coverage. **built, experimental (K2, pending_ci)**: `coverage()` over decision witnesses, boundary coverage and policy mutation survivors with killer actions; `pca-policy-ci coverage`. C-252, T-349.

### From OAuth RAR and Grant Management
13. Grant management API. **implemented, pending CI** (`GrantService` list/inspect/amend narrow|merge|replace/revoke grant|agent|subtree, typed `needs[]` with principal-signed, lower-only approval; framework-neutral HTTP handler, discovery fragment and fetch client; hosted `GET /v1/pca/grants`, `GET /v1/pca/grants/:grantRef`, `DELETE /v1/pca/grants/:grantRef`; C-266, C-267, C-268). Hosted: list/inspect/revoke plus authority enrolment, amend (narrow in place; widening needs principal signature + step-up + a registered successor), needs and step-up challenges; admission enforces the statement (verbs, resources, expiry; limits are recorded only). Natives verify the amend/revoke/need-approval signatures (G13, K3).

### From payments (Stripe Issuing, Visa / Mastercard agent tokens, wallet session keys)
14. Real-time authorization callbacks. **partial** (async escalation up to 24 h, operations pending 5 min, optimistic admission; no deadline contract). Design: pinned Decision Service with `deadline_ms`, signed answers, narrow-only adjustments, and a fallback on timeout signed inside the grant (Stripe: 2 s then account timeout setting or Autopilot) (G14, K4). As built, the real-time callback is `createRailAuthorizer` in `pca-payments`; a signed timeout fallback inside the grant does not exist under any name.
15. Category spend controls. **partial** (pca-payments MCC allowlist, mandate caps; no blocked categories, per-category windows, caller-claimed MCC). Design: SpendPolicy compiled to principal-scope Bounds, MCC from a signed merchant-directory attestation (needs item 1), as traits in the action kit (G15, K4).
16. Agent payment network tokens. **absent** (AP2/ACP/mandate/passport exist around it). Design: `NetworkTokenProvider` interface, issuance gate that pushes mandate limits into the token, authorization hook carries the PCActn digest; Stripe Issuing first, Visa/Mastercard gated on primary docs and partner access (G16, K4).

### From UCAN
17. Workflow / DAG authorization. **built (K5, pending_ci)**: `admitStep`, `bindPromises`, signed workflow commitment and step receipts, edge constraints, taint, budgets, enforced `plan_root_authorized` via `authorizedPlanRoots`; C-300..C-307; Dafny `WorkflowAdmit.dfy`. Earlier state: (plan Merkle set with `plan_root_authorized` then not-enforced, label receipts, pca-dataflow as a library, receipts, operations). Design: plan nodes with edges, verifier-enforced dataflow constraints via FlowRules on edges, `cause`-chained invocation receipts, promise pipelining only with typed domain constraint (G17, K5).

### Our own
18. Counterfactual explanations. **built, experimental (K2, pending_ci)**: `minimalFlip()` (wait, lower, other value or resource, two-edit combinations, obtain a fact, opt-in split; every candidate verified; holder-only, probe budget, redaction). C-254, C-255, T-347. Open: the wire form in `intent_required` bodies is K3.
19. Risk-priced escalation. **partial** (trust budget tiers, objective-risk, wallet fatigue stats, approvals, immune overlay, conformal program). Design: escalate iff P(bad)*L > interruption cost, with conformal upper bound; learned changes tighten automatically, loosening needs a signed AutonomyRaise capped by the hard ceiling (G19, K4).
20. Read-side authorization. **built (K5, pending_ci)**: read grants, `redactRead`, read receipts, `checkSink`, caps; C-310..C-314; Dafny `ReadSide.dfy`; aggregate differential privacy deliberately not built. Earlier state: (Intent v2 read cells and purpose minimisation, `pca-labels` receipts, flow rules, DLP ceilings). Design: redaction receipts, mask transforms with tokenisation, read accumulators, untrusted text never changes mask level (G20, K5).

### New ideas found in the gap analysis
21. Per-action narrow block and `seal` caveat. **absent**. Prompt-injection firewall: an agent narrows itself before touching untrusted content (G2, K1).
22. Schema validation of policies against the action schema/ActionDef. **built, experimental (K2, pending_ci)**: `validatePolicyAgainstSchema()` and the `schema-mismatch` rule of pca-policy-ci (undeclared verbs/params, type, range, enum, unit tags, unbounded money). C-253, T-348. Assumption: ActionDef is read through the structural `ActionDefLike` (verb or id, params with type/values/min/max/unit/semantic/sensitivity), because track A1 has not committed ActionDef types yet.
23. Lifetime `max_uses` caveat for one-shot delegation. **absent** (`rate` exists) (G21-J, K1).
24. ERC-7715 session-key RPC shim (`wallet_requestExecutionPermissions`, get/revoke/supported, `isAdjustmentAllowed`). **absent**. Maps to grant requests and `adjustable` approval (G21-A, K4; on-chain redemption stays out of scope).
25. AuthZEN Search APIs. **implemented, pending CI** (`authzenSearchHandler`, subject/resource/action search per AuthZEN 1.0 section 8; C-271). The provider that backs resource search is the host's (G21-D, K3).
26. SSF stream health plus emitting CAEP risk/assurance changes. **implemented, pending CI** (`StreamHealth`, stream configuration validation, verification event round trip, RFC 8936 poll queue, RFC 8935 push status mapping, `riskLevelChangeSET`, `assuranceLevelChangeSET`; C-269). Stream management endpoints (SSF 8.1: create/read/update/replace/delete/status/subjects/verification) are in `ssfManagementHandler`; hosted persistence of streams is not built (G21-E, K3).
27. SPIFFE workload identity as grant holder and as discharge issuer. **partial** (pca-spiffe bundle verification) (G21-F, K1).
28. GNAP interaction/continuation depth mapped to typed `needs[]`. **implemented, pending CI** (all four start modes, redirect and push finish, interaction hash with the RFC 9635 vector, single-use `interact_ref`, `accessToNeeds`; C-270). ZCAP-LD / VC presentation profile: **partial**, low priority (G21-B, G21-C).
29. Policy-as-code test runner. **built, experimental (K2, pending_ci)**: `generateBoundaryTests`, `runPolicyTests` (digest-pinned), `signPolicyTests`; `pca-policy-ci test`. C-256, T-349.

### 4b. Protocol and identity front doors (second sweep, track K6)

Items 30, 31 (scope derivation), 32, 43 and 44 of the second gap analysis. Specification text: [protocol-front-doors.md](./protocol-front-doors.md).

30. Fleet blueprint identity, ceiling and group kill (Entra Agent ID, AgentCore, Keycard). **built, experimental (K6, pending_ci)**: signed `AgentBlueprint` record with a monotone epoch, tighten-only ceiling, depth and expiry, `groupKill` composed with the revocation registry and `fresh_at`; TypeScript plus Python and Go on shared vectors. C-489..C-491, T-588. Attestation-gated admission (runtime pins, existing attestation verifiers; C-492, T-589) is built; the seven other natives (Rust, Ruby, PHP, Java, Kotlin, .NET, Swift) verify the shared vectors. SPIFFE and EAT adapters built (C-496, T-593).
31. Scope derived from the confirmed action. **built, experimental (K6, pending_ci)** for MCP and OAuth: `deriveActionScopes`, `admitRequest({ toolActions })`, `oauthScopeForAction`; unconfirmed derives nothing. C-495, T-592. The vault side (proxy mode, receipts, token lifetime) is K7's.
32. `pca_grant` authorization-details type (RFC 9396) so any AS can carry a grant. **built, experimental (K6, pending_ci)**: profile, parsing and validation in TypeScript and nine natives, 68 vectors, `@atlasauth/pca-oauth` helpers, Atlas-hosted example. C-481, C-485, T-580, T-586. Open: RAR custom-type support is documented at Auth0 and Atlas only; Entra ID, WorkOS, Stytch and Descope documentation (read 2026-10-26) does not show it.
43. MCP `pca_need` and per-revision conformance. **built, experimental (K6, pending_ci)**: C-480, C-482..C-484, T-581..T-585. Open: re-fetch the draft before relying on its cells; client registration and authorization-server discovery rows.
44. A2A binding. **built, experimental (K6, pending_ci)**: extension declaration, AUTH_REQUIRED mapping, per-hop verification, push tokens. C-486..C-488, T-587. Extended Agent Card from `whatMayIDo` (C-494, T-591) and signed task-update receipts (C-493, T-590) are built. A2A gates ported to all nine natives (C-497, T-594).
### 4b. Second sweep: transaction integrity and money (K7)
31b. Credential brokering bound to the action. **built, experimental (K7, pending_ci)**: scopes derive from the pinned, confirmed action (an unconfirmed definition releases nothing), vault proxy mode (the outbound request must re-derive the signed `params_digest`; the agent never holds the credential), signed release receipts, bearer release only behind `insecureBearerRelease`. C-463..C-465. Open: scope declaration lives in the vault's action registry, not in the `ActionDef` (no definition wire change); no RFC 9396 request upstream; posture discharges (K1) not wired.
33. What-you-see-is-what-you-sign approvals. **built, experimental (K7, pending_ci)**: canonical render, challenge `H(action_digest || H(R))`, `render_digest` on escalation answers, WebAuthn / Secure Payment Confirmation / PSD2 Article 5 / CIBA profiles, batch total plus payee root; vectors in TypeScript, Python and the nine natives. C-460..C-462. Open: completeness is structural (every parameter is a field), so no separate lint rule; the approver UI must show the canonical render (a browser or wallet that ignores it is outside the verifier's control).
34. One-action credentials and spend rails. **built, experimental (K7, pending_ci)**: grant-mirroring instrument limits, MCC controls from the mandate and `mcc.*` traits, real-time authorization callback inside a latency budget, settlement reconciliation, Stripe Issuing adapter on documented-shape fixtures. C-466. Open: no Ramp or Privacy adapter (partner-gated), no live-account fixtures, no `mint(pcactn)` single-use card per action.

### 4b. Lifecycle and policy operations (K8)

Specification text: [lifecycle-and-policy-ops.md](./lifecycle-and-policy-ops.md).

35. Leases, renewal rules and request/approve flow. **built, experimental (K8, pending_ci)**: signed lease records with renewal under a hard `max_ttl`, fresh justification, separation of duties (k of n), revoke by lease, prefix or grant, durable registry, hosted routes; `lease-vectors.json` in TypeScript and the nine natives. Break-glass grants (time-boxed, loud, auto-revoked, signed review, holder freeze) with `reason_digest`; lease storage sharded with a storage conformance kit. C-500..C-502, C-508..C-510, C-515, T-600..T-602, T-608, T-609, T-613.
37. Rollout modes and CEL import. **built, experimental (K8, pending_ci)**: shadow candidates in bundles, enforced-first evaluation, signed divergence diffs, promotion gate with zero unexplained widenings, `promoteShadow`; strict CEL importer (in `pca-policy-bridge`, not `pca-grants`) with exactness differential test. `bind_params_digest` (a grant cites the exact parameter object by digest). C-503..C-505, C-514, T-603, T-604, T-614.
38. Obligations. **built, experimental (K8, pending_ci)**: closed obligation vocabulary, PEP gate (unsupported obligation turns allow into deny), merge, overdue outcome, discovery `obligations_supported`; vectors in TypeScript and the nine natives. Policy classes named in decision records (`policy_classes`, `denied_by`). C-506..C-508, C-513, T-605..T-607, T-612.
36. Typed missing context and the stored-wins rule. **built, experimental (K8, pending_ci)**: `decideWithMissing` (typed escalate / deny reasons, never a silent allow), `bindContext` (bound wins, a differing request value is `context_shadow`); vectors in TypeScript and the nine natives. C-511, C-512, T-610, T-611.

### Ranking (impact for agent adoption x feasibility)
1 item 13 grant management (with 24 shim); 2 item 18 minimal-flip; 3 item 5 residual/discovery; 4 item 4 analyzer extensions + 22 schema validation; 5 item 1 discharges (with 27, 15 attestation); 6 item 14 callbacks; 7 items 7+11+12 certificate, bundles/decision records, coverage; 8 items 15+16 spend policy and network-token adapter; 9 item 9 fresh_at; 10 item 8 least privilege; 11 item 20 read-side; 12 item 17 DAG (biggest differentiator, biggest blast radius); 13 item 6; 14 item 19; 15 items 2/21/23; 16 item 10; 17 item 3. Decline: general Datalog or an SMT solver inside the trusted core, automatic widening from observed denials, on-chain redemption in core.

### Proposed tracks (names distinct from goal-to-decision T1-T6)
- K1 Caveat language: 1, 2/21, 3-lite, 23, 27. Joins goal-to-decision T2 and T5 vectors. Size L.
- K2 Static analysis and authoring: 4, 5, 6, 7 certificate, 8, 12, 18, 22, 29. Sits on pca-analyzer, policy-debug, pca-policy-ci; fold into the action-kit and goal tracks as originally proposed. Size M-L.
- K3 Operational plane: 9, 10, 11, 13, 25, 26, 28. Joins goal-to-decision T4 (durable budgets). Size L.
- K4 Money and approvals: 14, 15, 16, 19, 24 on pca-payments/ap2/acp/wallet (the "payments 14-16 own track" in the original grouping). Size M-L.
- K5 Workflow and read side: 17, 20. Starts after K1 and K2 witnesses; verified-core impact, own wave. Size L-XL.
Order: K2 and K3 now, K1 in parallel (specs first), K4 after the GrantResource and decision-record wire, K5 last.

### 4b. Second sweep (agent identity products, transaction binding, JIT, policy engines, supply chain, capability systems, guardrails, MCP/A2A)

Rule kept: no heuristic or classifier decides authorization; everything learned only tightens; unsupported, unreviewed or unparseable means deny or escalate.

30. Blueprint identity (Entra Agent ID style): signed `AgentBlueprint` with runtime pins, tighten-only ceiling and an epoch for group kill. **absent** (revoke-subtree and SPIFFE exist) (K6).
31. Action-bound credential release: scopes derived from the ActionDef (unreviewed = refuse), proxy mode that re-derives `params_digest` from the outbound request, signed ReleaseReceipt. **partial** (pca-connect TokenVault, one-time per action, fail-closed revocation) (K6/K7).
32. `pca_grant` RFC 9396 authorization-details profile so any OAuth AS (Auth0, Stytch, WorkOS, Descope) carries a grant while the RS still requires a per-action PCActn. **absent** (K6).
33. Display commitment (WYSIWYS): approval challenge = H(action_digest || H(canonical render)), completeness lint, batch total + payee root, SPC `payment` profile, CIBA RAR = the render. **partial** (challenge = action digest exists in pca-webauthn; display is unbound) (K7). PSD2 RTS Art. 5 is the citation.
34. One-action spend instruments (Ramp/Privacy/Stripe style) with limits from the decision, and settlement reconciliation that freezes on mismatch. **absent** (mandate, ledger reserve/commit exist) (K7).
35. Leases (`lease` caveat, `max_ttl`, veto-only auto-renew), separation of duties on approvals, goal-bound access reasons, break-glass with mandatory review. **partial** (timeBox, GrantResource need/approve) (K8).
36. Typed missing context (who may supply each unknown) and a "request context never shadows grant-bound values" vector. **partial** (Tri, residual, fresh_at exist) (K8).
37. Shadow rollout revisions (tighten-only admission, DecisionRecord shows divergence) and a strict CEL importer that rejects unknown constructs. **absent** (K8).
38. Decision obligations (unsupported by the RS = deny; unmet = tighten event) and named policy classes in DecisionRecord. **partial** (K8).
39. Positioning/profile for Permit.io-style MCP gateways ("one URL change", bring-your-PDP as tighten-or-neutral input). **docs** (K9).
40. Identity-pinned provenance (Sigstore/in-toto/SLSA) as a discharge class joined to EAT runtime attestation; pack provenance lint. **partial** (own releases have SLSA v1; SCITT bundles) (K9).
41. No-ambient-authority sandbox profile (WASI component, grant-to-sandbox policy compile). **absent**, outside the TCB (K10).
42. `TraceRule` authoring (never B after A) compiled to dataflow edges plus history predicates, lethal-trifecta lint, tighten-only DetectorReceipt (`no_finding` never widens). **partial** (pca-dataflow, FlowRules, immune) (K9).
43. MCP authorization draft: additive `pca_need` parameter on the 403 `insufficient_scope` challenge for argument-aware step-up; per-spec-revision conformance rows (CIMD, RFC 9207 iss table, resource parameter, scope union). **partial** (pca-mcp-rs has PRM, 8707, 401/403) (K6).
44. A2A: AUTH_REQUIRED mapped to escalate/discharge, extended card computed from `residual`, anti-enumeration via the probe leak budget, PCA proof on push notifications. **partial** (pca-a2a, pca-agentcard) (K6).

Ranking: 33, 31, 43, 32, 30, 40, 44, 35, 37, 34, 42, 38, 36, 41, 39.

Proposed tracks (continue K1-K5):
- K6 Protocol and identity front doors: 30, 31 scope derivation, 32, 43, 44. Size M-L.
- K7 Transaction integrity and money: 33, 34, 31 proxy and receipts. Wire-affecting (challenge change). Size M-L.
- K8 Lifecycle and policy operations: 35, 36, 37, 38. Size M-L.
- K9 Supply chain and guard authoring: 40, 42, 39. Size M-L.
- K10 Runtime containment profile: 41 (optional, parallel). Size M-L.
Order: K7 and K6 first, K8 and K9 next (route `lease` and `ArtifactAttestation` through the K1 caveat-language vectors), K10 last.

Status after K9:
40. Identity-pinned provenance for tools, packs and runtimes. **built, experimental (K9, pending_ci)**: `artifact` discharge class, offline Sigstore verification against a pinned trusted root, `provenanceGate` (signer-builder level, source pins, runtime join) in TypeScript and nine natives, `issueArtifactDischarge` joined to an accepted EAT, pack `LP-001` lint. C-520..C-526, T-620..T-623, T-629. Rekor v2 (hashedrekord over DSSE) and RFC 3161 time are verified; full bundle verification in the natives on shared `sigstore-vectors.json` (sigstore-conformance fixtures); the pack provenance is a sidecar bundle (the signed pack wire is unchanged).
42. Trace rules and detector receipts. **built, experimental (K9, pending_ci)**: `never B after A within W` and an Invariant subset compiled to K1 `derive` caveats, lethal-trifecta lint (`LT-001`), tighten-only `DetectorReceipt` with property tests, Lakera / Prompt Security / generic adapters (the Prompt Security shape is unverified). C-527..C-532, T-624..T-628.
39. Gateway profile and an external PDP. **built (K9)**: `guides/mcp-gateway-profile.md`; `@atlasauth/pca-gateway` full-policy mode takes `k1` and reads `PCA-Discharges` / `PCA-Narrow` (and body members when the body is not the signed params). C-533.

### 4c. Provenance by default (0.5, track prov)

Spec: [provenance-by-default.md](./provenance-by-default.md). Claim: an agent protected by PCA cannot be steered by injected content
(tool output, web page, email, retrieved document) into choosing who, where or how much for a sensitive action. **Built (TypeScript
reference, default-on in `authorize()`)**: mediator-signed `pca-prov` receipt chains per session, verifier re-derivation (an
unverified label is untrusted, a forged chain denies), per-argument labels with action-kit sinks (`provenance_min`, unconfirmed defs
are maximally sensitive), the control-flow rule (the choice must come from the principal, a principal plan or an admitted workflow
step), escalate through the existing WYSIWYS answer path, the signed envelope opt-out `provenance.mode: insecure_off`, the
data-flow model promoted to core (`@atlasauth/pca/dataflow`), automatic labelling in every framework adapter, the gateway and the RAG
filter, and shared vectors `conformance/arg-provenance-vectors.json`. Remaining: native ports (nine verifiers replay the vectors and
gate `authorize`), native authorize fixtures regenerated with bundles.

### 4d. Undo windows (kill approval fatigue)
43. Act now, veto later. **built (05-undo, pending_ci)**: a CONFIRMED-reversible action (signed definition by a pinned reviewer,
effective class reversible for these params, a confirmed compensating action derivable before the effect and authorized under the
same grant) runs at once under a veto window instead of waiting for prior approval; irreversible actions keep the escalation path.
`allow` + the `undo_window` obligation (no fourth decision value: a PEP that cannot run windows denies), a durable undo ledger
(refuses non-durable stores; CAS state machine open -> vetoed -> compensated | compensation_failed, open -> finalized), one-click
signed undo tokens bound to the action, compensation and render digests, hash-chained signed receipts, real rollback through the
Policy VM and an at-most-once operation record, aggregate budgets held until the window closes, revocation policy, and a slashed
optimistic bond rolls its effect back. Spec `undo-windows.md`; hosted ledger and veto routes; vectors `undo-vectors.json`;
natives: pure layer (transitions, token, receipts, obligation kind) per `brief-undo-natives.md`.

## 5. Production readiness

At audit time, 92 units needing work at audit time: 38 code, 31 CI evidence only, 23 outside code.

| Track | Scope | Status |
|---|---|---|
| mB | 12 auth and token bridges | built, CI pending |
| mC | credential, commerce, interop (12 units) | built; x402 v2, Stripe SPT, JPY in progress |
| mE | core feature groups, B15–B17, hosted bonds on Postgres | built, CI pending |
| mF | crypto audit-readiness | built, CI pending |
| mN | native parity gaps (mesh in Python, approved_goal, operation records, plan lifecycle, staleness, assurance labels, Kotlin/Swift middleware) | in progress |
| mD | shared docs: contract entries, Stryker enrolment, version bumps, retire the 291 pre-0.5 maturity mentions | not started (runs last) |
| Native parity (Go, Rust, Python, Ruby, PHP, Java, .NET, Swift, Kotlin) | ternary decision, escalation, rules 20/21, passport, attestation, Track 3 vectors, goal vectors | built, CI pending |

Rule: tiers move to production only when CI (including the mutation run) proves it; units flagged `pending_ci` flip mechanically.

## 6. Outside code (owner actions)

- O-1 independent crypto audit (17 packages/features).
- O-2 trusted-setup ceremony (SNARK backends).
- O-3 real TEE hardware for the attestation canary.
- O-4 hosted hardware-verifier decision.
- O-5 independent ledger witnesses.
- O-6 final standards / draft-pin labels (FN-DSA, BBS, LESS, draft-based bridges).
- O-7 breaking-change sign-off (approved for 0.5).
- O-9 label vocabulary and the STARK privacy decision.
- Goal live-model eval: set ANTHROPIC_API_KEY, OPENAI_API_KEY and PCA_GOAL_MODEL_A/B on the flagship repo.
- FAME generic-group security proof: needs a Mathlib CI loop.

## 7. Known follow-ups

- Prod migration numbering for `0154_pca_bond_store.sql` must be checked against prod before hand-applying.
- Attestation vectors must be generated by CI and committed, then replayed by every native.
- Dafny extraction `pca_goal.js` and the goal-golden digest pin after the first verified-core run.
- One 48-shard mutation run at the end, survivors killed with real tests.

## 8. Human approval of step-ups (track 05-approve)

Spec: [human-approval.md](human-approval.md). **built, CI pending.** A held step-up reaches a human, who approves it with a passkey on a hosted page:

- a non-custodial principal key, wrapped by the passkey's PRF output and stored only as ciphertext (migration 0471, applied by hand);
- the passkey challenge is `H(action_digest || H(R))` over the hosted render, which the server derives and the page re-checks (`vectors/hosted-approval-render.json`);
- single-use links that can deny but cannot approve on their own, sent by push, email (BYOK), SMS, Slack (URL buttons only) and signed webhook, with retries, dedupe, per-member rate limits and delivery status on the step-up;
- quorum with delegates, per-instance CIBA (`notify` / `require`), agent long poll plus decision webhooks (timeout = deny), and the `undo_window` notifier for the undo track;
- the dashboard's raw-key cosign is kept only as a collapsed "Advanced" path, and is refused when a quorum or CIBA `require` applies.
