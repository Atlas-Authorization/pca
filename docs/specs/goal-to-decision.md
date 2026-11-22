# Goal to decision: closing the abstract-to-binary gap

Status: internal design (0.5 line, branch 05-c1). Repo paths are intentional here. Do NOT copy any of this into public docs.
Scope: audit of the existing pipeline, weakness catalogue, and a spec that makes "human goal in, allow/deny/escalate out" a typed, proven, tested path, plus an intent-fidelity program for the part that cannot be proven.

Reading note: I read in full intent.ts, intent-binding.ts, intent-v2.ts, nl.ts, facade.ts (compilePolicy, parseLimit), server/authorize.ts, predicates.ts (head), action-schema.ts (types, conformAction), intent-acc.ts (head), and the doc headers of offer-set, param-provenance, label-receipts, intent-classifier, intent-env, semantic-threshold, objective-risk, progress, contracts, contract-enforcer, session, pca-intent compilers/slots, pca-analyzer, pca-policy-bridge, plus docs/pca/security (security-contract, threat-model, verified-core, trusted-base) and formal/ READMEs. Items marked (unverified) were not read to the line.

## 0. The honest bottom line

Two different claims are being conflated, and the spec separates them.

- Downstream of a signed, typed Goal IR: everything can be a theorem or a tested invariant. A deterministic compiler from IR to policy, a three-valued enforcement decision, tighten-only model signals, aggregates. This is provable (Dafny with extraction, Lean for the quantitative parts) and testable cross-language.
- Upstream of the IR (text or intent to IR): "the model understood the human" is NOT provable. It is reduced by typed templates and ontologies, disambiguation questions, boundary examples the human confirms, N-version least-privilege intersection, and measured with conformal risk control. Each gives a stated guarantee under stated assumptions (section 10), never an absolute one.

The end-to-end statement we can defend: every Allow is inside the semantics of an IR the principal signed after seeing a lossless, deterministic rendering of it and confirming its boundary examples; no model signal can widen; whatever the principal meant beyond that is covered by a measured, published widening rate with a confidence bound.

## 1. Part 1: audit of the existing pipeline

### 1.1 Pipeline (as built today)

```
 human goal (free text, form, ticket, conversation)
        |
        v
 [S1 capture]  IntentStatement{text, slots:unknown, sources[digest]}  signed by principal      intent.ts:49-60,126
        |         (text and slots are NOT linked by any check)                                  intent.ts:108-123
        v
 [S2 compile]  three unrelated paths, none verified against the statement:
        |        (a) nl.ts: LLM -> {permissions, limits} -> grounded to catalog -> facade.compilePolicy
        |        (b) pca-intent compilers.ts / slots.ts: k-compiler + slotsToPolicy (research ext)
        |        (c) hand-written grant
        v
 [S3 review]   nl.ts approveDraft: pinned reviewer signs draftDigest(permissions, limits, catalog)  nl.ts:165-168,234
        v
 [S4 grant]    Root Intent Grant: predicates + caveats + envelope{goal_commit, risk_policy}
        |        goal_commit = H(goal "pca-intent:v1:"||ref||":"||map_digest, salt)               intent-binding.ts:101-107
        |        => binds grant to the statement's IDENTITY, not to its meaning                    intent-binding.ts:156-158
        v
 [S5 plan]     Merkle plan root; plan_inclusion proves the action is a plan node                   pcactn.ts:703; plan_root_authorized 'not-enforced' at :705
        v
 [S6 action]   PCActn{verb, resource, params_digest, intent{ref,map_digest,fidelity_ppm,residual_risk_ppm}, intent_session{...}}
        v
 [S7 verify]   verifyPCActnCore: wire, audience, validity, cap_chain, grant_ref, plan, leaf sig, counter
        |        + intent (decideIntentBinding) + v2: schema -> intent_session -> layers -> accumulators -> map -> facts -> provenance -> classes   intent-v2.ts:540-570
        |        + predicates/caveats (predicates.ts, 3-valued Tri internally) + risk/budget/threshold + hooks (semantic judge, contracts)
        v
 [S8 decision] authorize(): { allow: boolean, status 200|403|401 }; "question" is a deny with reason prefix `intent_required:`   authorize.ts:101-114, intent-v2.ts (wb question)
        v
 [S9 effect]   handler runs; isAuthorizedFor(result, operation) is advisory                        authorize.ts:327
```

### 1.2 Stage table

| Stage | Formally defined | Proven (by what) | Signed assertion / heuristic only | Missing |
|---|---|---|---|---|
| S1 intent capture | Statement wire, content address, suite-agile signature (intent.ts) | Signature/binding: ProVerif/Tamarin/CryptoVerif models of intent delta (formal/cryptoverif/intent_delta.cv), conformance vectors `intent-*` | `text` and `slots` meaning; `sources` are digests only (intent.ts:44) | Any semantics for `slots` (typed `unknown`, intent.ts:54); text-to-slots faithfulness; ontology reference |
| S2 compile | Predicate DSL + caveat algebra (predicates.ts); slot vocabulary (pca-intent slots.ts) | The TARGET semantics: formal/dafny/PolicyVm.dfy (Kleene Tri, 1,812 lines, extracted to packages/pca-verified-core/generated/pca_policyvm.js); attenuation (Chain/Caveats.dfy, Lean Attenuation) | LLM output (nl.ts) grounded to catalog membership only (nl.ts:79); k-compiler disagreement is research (compilers.ts) | A source language with semantics; any theorem relating compiler output to input; units; aggregates in compiled output; ambiguity detection in the signing path |
| S3 review | Approval wire (nl.ts:213-231), pinned reviewers, TTL | Tests + mutation (nl tests, mutation-kill-*), fail-closed table | The reviewer reading the draft | Digest excludes `instruction`, model id, prompt, resource scoping, param constraints (nl.ts:165-168); loader trusts `goal` string (nl.ts:307,319); no human-readable diff; no boundary examples |
| S4 grant | Envelope, goal commitment | Chain attenuation (Dafny ChainAttenuates, Lean, TLA+ Attenuation); goal-commit opening (conformance) | Nothing links grant predicates to the statement's meaning | Compilation relation between statement and grant |
| S5 plan | Merkle inclusion | Merkle in Dafny (Merkle.dfy) and verified-core ext | Plan semantics: `plan_root_authorized` 'not-enforced' in Core (pcactn.ts:705) | Plan-level semantics; plan to goal relation |
| S6/S7 verify | Normative check order, rules 12-19 in conformance README | Dafny verified core (171 verified, 0 errors per trusted-base.md): chain, threshold, replay, verdict fold, FailsClosed; ProVerif/Tamarin protocol; conformance vectors in 9 native languages (conformance-checked, not proved); mutation tests; Kani fragments | `fidelity_ppm` / `residual_risk_ppm` are "SIGNED CLAIMS by the leaf holder" (intent-binding.ts:43-45; gate on them "as claimed" 159-164); classifier labels, oracle facts, labels (signed assertions: T-054); semantic judge (distributional, T-036) | Predicate/caveat evaluator, risk arithmetic, strict JSON, regex are hand-written TS by default (verified-core.md "Not covered"); units unchecked; model-derived env has no polarity restriction |
| aggregates | Accumulators/monitors in session root (intent-acc.ts) | TLA+ Reservation.tla (NoOverspend, 28,132 states), Lean Aggregate/Trajectory (formal/intent) | Pre-state must come from a linearizable store (T-055 residual) | Principal-level and cross-session aggregates; agent-fleet aggregates |
| S8 decision | allow boolean; risk tiers t in {1,2,3}; question as deny reason | Verdict.dfy fold (any fail => deny) | - | First-class ESCALATE; signed escalation answers |
| S9 effect | `isAuthorizedFor` | - | - | C-10 "every success bound to its execution" is a stated gap on every surface (security-contract summary) |
| intent frontier | objective-risk, progress, semantic-threshold, classifier, offer-set, provenance | Lean statistics for the learner (formal/intent: halving, credence, Hoeffding; 174 theorems, axioms audit clean), TLA+ elicitation loops | Everything about quality of judgement (prod-readiness-plan 3.5: "frontier modules stay experimental") | Tighten-only typing; benchmark; measured error rates |

What is genuinely strong today: the verification pipeline (S6/S7), chain attenuation, replay, fail-closed behavior, and a typed action schema (action-schema.ts: closed world, declared params, domains, units, semantic types, sensitivity) that is the right foundation for the IR. The weak point is the join from human goal to signed grant: it is a convention, not a relation.

## 2. Part 2: weakness catalogue

Verdicts: STOPPED (code enforces, evidence cited), PARTIAL (only when configured / only some paths), OPEN (not stopped).

| # | Attack, with example | Today | Evidence |
|---|---|---|---|
| W1 | Goal-to-grant is unconstrained (the root gap). Principal says "refund this duplicate charge"; the minting wallet/server signs a grant with `stripe.*` under that intent ref. The binding opens a hash of (ref, map digest, salt) only. | OPEN | intent-binding.ts:101-107,156-158; intent.ts:53-54 |
| W2 | Agent-claimed fidelity. An active policy `min_fidelity_ppm` is satisfied by an agent that signs `fidelity_ppm: 1000000`; core gates "as claimed"; only a relying party that replays the map catches it. | OPEN in Core | intent-binding.ts:43-45,159-164 |
| W3 | Goal smuggling in NL compile. Instruction "refund duplicate charge ch_9"; model also emits `stripe.transfer` (a valid catalog verb). Grounding checks catalog membership, so it passes; only a human reading the permission list stops it. | PARTIAL (human) | nl.ts:79; no resource/param scoping is even expressible in nl output |
| W4 | Review is not bound to the instruction. `draftDigest` covers permissions, limits, catalog only; approval is over that digest; `goal` is a free string at mint. A reviewer-signed draft can be attached to any goal text, and model/prompt version is not pinned (model-generated policy drift between reviews). | OPEN | nl.ts:165-168,307,319 |
| W5 | Limit semantics mismatch ("$200/day"). It compiles to a per-call `lte 200` ceiling, a grant `expires` at min period, and a lifetime budget bMax = sum of caps; there is no per-day renewal. `month` is a fixed 30 days, `day` 24h not a calendar day. Not a widening here but a fidelity bug, and no per-window cap exists in this path. | OPEN (fidelity) | facade.ts:205-209,221,240; PERIODS facade.ts:~100-103 |
| W6 | Silent unbounded money limit. `$500` on a verb whose catalog entry has no `amountField` produces no ceiling predicate and no error. | OPEN | facade.ts:205 (`lim.unit === 'usd' && s.amountField`) |
| W7 | Non-monotone compile (adding a constraint widens). (a) Two count limits: `rate` caveat is emitted only when exactly one count limit exists, so adding a second REMOVES it. (b) Adding any `$` limit switches the budget model to dollars with theta1 = theta2 = 1 ("within-cap actions auto-approve"), dropping the human co-sign tiers the risk model would have required for irreversible actions. | OPEN (real bug) | facade.ts:224; facade.ts:243-244 |
| W8 | Salami / action splitting. 100 x $19 under a $20 per-call cap. | PARTIAL: stopped inside an intent session with accumulators and durable linearizable store (T-055, intent-acc.ts, TLA+ Reservation); facade/NL grants rely on the budget store (required by authorize) with the W5 caveats | intent-v2.ts accStep; authorize.ts:29-32 |
| W9 | Aggregates across sessions/agents. Same principal opens N sessions (or N sub-agents on separate grants), each with a full cap. Accumulators select events "of this session". Trust budget is per grant. | OPEN | intent-acc.ts:22; threat-model T-055 residual |
| W10 | Confused deputy across delegation. Sub-agent holds parent authority, an injected document steers it. Chain attenuation is proven; but the intent binding checks only the ROOT grant's goal commitment, so a delegate acts under the parent's intent with no goal of its own. | PARTIAL: authority narrowing STOPPED (Dafny ChainAttenuates); intent-level OPEN | intent-binding.ts:156; session.ts (a view only) |
| W11 | Parameter laundering. Agent takes an account number from an injected email, passes it as `payee`. | PARTIAL: provenance classes + `intent_required` question when schema+session+registry are configured; omitted receipts default to `agent` provenance and only a statistical classifier can catch the rest (documented honest gap) | param-provenance.ts; label-receipts.ts:40 |
| W12 | Ambiguous goal resolved permissively. "Triage my inbox" read as read + archive + delete + reply. No ambiguity detection in the signing path; the pca-intent committee/disagreement analysis (compilers.ts) is research and not wired to signing. | OPEN | nl.ts; compilers.ts |
| W13 | Synonym / schema aliasing. `never(verb = delete)` prohibition bypassed by `bulk_remove` doing the same effect. Allow-lists are safe (default deny), prohibitions and contracts match by verb predicate. `effects`/`harm`/`world` schema members are "signed, carried, NOT read". | PARTIAL: allow side STOPPED; deny/prohibition side OPEN | action-schema.ts:99-106; threat-model T-050 residual |
| W14 | TOCTOU. (a) Param swap between check and call: authorize freezes a snapshot and binds params digest (STOPPED). (b) Effect not bound to the decision: `isAuthorizedFor` is advisory; C-10 is a stated gap. (c) World facts go stale: freshness bounds exist. | PARTIAL | authorize.ts:233,327; security-contract C-10 |
| W15 | Plan/semantic-distance gaming. Every step "makes progress" on a gameable potential, or the plan contains a dangerous in-plan node. | OPEN by nature (heuristic) | pcactn.ts:705; progress.ts header (anti-Goodhart bound is budgeted exploration only); T-003 residual |
| W16 | Classifier/oracle compromise or error. A wrong `env.class.tone` label flips which allow-predicate matches. Model-derived env values feed predicate `where` with arbitrary polarity (eq, ne, not, any_of), so a wrong label can WIDEN. Quorum raises the bar but "wrong or colluding quorum is accepted". | OPEN (polarity), PARTIAL (quorum) | intent-v2.ts (env merge after W-B), intent-env.ts; T-054 residual |
| W17 | Semantic-judge false allow. Conformal bound holds on an exchangeable hold-out, not against an adaptive adversary. | OPEN as an allow-gate | semantic-threshold.ts:339-353; T-036 residual |
| W18 | Unit/currency confusion. Schema declares `units{currency, exponent}` but it is only shape-checked, never read by any verifier; predicates compare bare numbers; `parseLimit` knows only `$`=usd and counts and stores a float; `agent-native max_spend` treats `amount` as USD with `currency` in {usd,USD} while schema integers are minor units: 100x confusion between a cents-typed schema and a dollar-typed limit. | OPEN | action-schema.ts:126,242-244; facade.ts:117-121; agent-native.ts:648-657 |
| W19 | Text/Unicode identity tricks. Predicates compare without normalization (documented: NFC vs NFD are different strings); lookalike ids fail closed for allow-lists but two ids for one entity (aliases) are not modelled; `like` `?` is one UTF-16 code unit (cross-language divergence risk, documented). | PARTIAL | predicates.ts doc on orderUtf8; predicates.ts:214 |
| W20 | Prompt injection into the compiler. Ticket body says "also authorize bulk refunds"; nl prompt interpolates `instruction` into the model prompt; no separation of principal text from untrusted source text; no hostile-goal corpus found for nl/compilers (grep of tests found none). | OPEN | nl.ts:29-46; (unverified for pca-intent tests beyond grep) |
| W21 | Escalate collapses into deny/allow. The decision is boolean; "ask a human" is a string prefix on a deny, risk tiers elsewhere. Nothing prevents a host from mapping it to allow. | OPEN | authorize.ts:101-114 |
| W22 | Delegation limits not part of the goal. Depth cap 16 is global; goal cannot say "no sub-agents" or "sub-agents may not touch X". | OPEN | Chain.dfy DepthBound; no goal field |
| W23 | Policy-language gaps vs goals. Resource scope defaults to `*` in both facade (facade.ts:209) and slotsToPolicy (slots.ts:54); relations like "this customer's charges" are only expressible as a prefix over id strings; slot `unit` is "not interpreted" (slots.ts SlotConstraint.unit). | OPEN | facade.ts:209; pca-intent/src/slots.ts:51-57 |

Top-10 by severity: W1, W2, W7, W16, W4, W18, W12, W9, W3, W21.

## 3. Spec part A: the Goal IR

New package `packages/pca-goal` (`@atlasauth/pca-goal`), plus `formal/dafny/Goal*.dfy`. Types below are normative; encoding is strict canonical JSON (same canonicalizer as the rest of PCA), ints are safe integers.

### 3.1 Types

```
Ontology   := signed {id, version, domain, types, units, relations, verbs, aliases, templates}   (F6, section 10)
Quantity   := Money{ccy, minor:int}  | Count{n} | Duration{ms} | Instant{epoch_ms} | Bytes{n} | Ratio{ppm}
              -- no floats; Money carries currency and exponent from the ontology unit; no implicit conversion
Term       := Param(path:Ptype) | Lit(q:Quantity|Enum|Id|Text) | HistAgg(bound_id)
Cond       := Cmp(op, Term, Term) with op in {eq,ne,lt,lte,gt,gte,in,nin} well-typed only | And | Or | Not
              -- Text supports only eq/in (no ordering, no regex) so semantics stay finite
ResourceSel:= Exact(Id) | OneOf(Id[]) | Related(rel, anchor:Id)   -- e.g. charges_of(customer:C123), resolved by ontology
              | Any(reason) -- permitted only with an explicit `wildcard_ack` clause that the card renders in red
Grant      := {gid, verb ∈ Ontology.verbs, resource:ResourceSel, where:Cond}
Prohibit   := {pid, effect_class | verb, resource:ResourceSel, where:Cond}   -- by EFFECT CLASS (ontology), not verb string (W13)
Bound      := {bid, agg: sum|count|max|distinct, over: select(gid[] | effect_class), value: Term, key: Id-param?,
               window: task | sliding(ms) | period(ms,t0) | lifetime,
               scope: session | principal | org | fleet(agent set),
               cap: Quantity, on_exceed: deny|escalate}
Validity   := {not_before, not_after, max_idle}
Delegation := {max_depth: 0..16, narrow_only: true, delegate_may_touch: gid[]}
Hole       := ⟨q: typed question, domain⟩     -- an unresolved ambiguity; allowed only in drafts
Goal       := {v, principal, ontology_digest, nl_digest, sources[digests], grants[], prohibits[], bounds[],
               validity, delegation, escalate_on: Cond[]  , holes[]}
```

A Goal with `holes != []` is a Draft: it is not signable, and its compiled policy is the most restrictive completion (every grant that depends on a hole is dropped).

### 3.2 Semantics

State: an action `a = (verb, resource, params, t)` and a history `H` of previously admitted actions (for the principal, per scope). Define

```
Allow_G(a,H)    iff  t ∈ Validity ∧ ∃g∈grants. match(g,a) ∧ ⟦g.where⟧(a)=true
                     ∧ ∀p∈prohibits. ¬trigger(p,a)  ∧ ∀b∈bounds selected by g. agg_b(H∪{a}) ≤ cap_b
Escalate_G(a,H) iff  ¬Allow ∧ (a escalate-trigger fires: some Cond in escalate_on, a bound with on_exceed=escalate exceeded,
                     or a Cond evaluates Unknown)  ∧ no prohibit triggers
Deny_G(a,H)     otherwise
```

`⟦·⟧` is three-valued Kleene exactly as PolicyVm.dfy `Tri` (Unknown on missing/ill-typed). Order Deny < Escalate < Allow; conjunction is meet, so `Unknown` never yields Allow. Closed world: a verb or param not declared in the ontology/schema is Deny (`conformAction` already does this).

### 3.3 Typing rules (units, currency, locale)

- Money comparisons require equal `ccy`; arithmetic on Money requires equal `ccy`; there is no float and no implicit FX. Conversion is a typed term `Convert(q, rate_artifact)` needing a site/oracle-signed rate with an explicit max age and a slippage bound; a goal that needs FX without it is ill-typed (compile error, not a guess).
- Param types come from the signed action schema; the compiler checks that a `Param` term's unit equals the ontology unit, and the verifier gets a new check `units` (rule 20) that rejects an action whose schema param unit differs from the policy term's unit tag. This closes W18 on the verifier side; today `units` is never read.
- Locale: parsing of human numbers ("1,000.50", "1.000,50") happens ONLY in the interpreter front end; the IR has no locale. An ambiguous literal ("1,000") is a Hole, not a guess.
- Time: `day`/`week` windows are explicit: `sliding(86_400_000)` or `period(ms, t0, tz)`; calendar units require a declared timezone in the Goal (else Hole).

## 4. Spec part B: the deterministic compiler and its theorems

`C : Goal -> Policy ⊎ Escalate(reasons)` is a pure total function: typecheck, normalize (canonical order, dedupe), lower. Target (no verifier redesign): existing artifacts: `predicates[]`, `caveats[]` (expires, rate, reversibility_max), session-root accumulators/monitors/ceilings (`intent_session`, intent-acc.ts), prohibitions/contracts (contracts.ts), plus the new `tighten[]` list (section 7).

Theorems (T-numbers local to this spec; proved against the Dafny `PolicyVm` model as target semantics):

- G-T1 Soundness: `C(G)=P ⇒ ∀a,H. D_P(a,H)=Allow ⇒ Allow_G(a,H)`. The compiled policy never allows more than the goal.
- G-T2 Monotonicity: if `G'` refines `G` (clause-wise: grants of G' ⊆ grants of G up to narrowing, prohibits/bounds ⊇, validity ⊆) then `⟦C(G')⟧ ⊆ ⟦C(G)⟧`. Corollary: adding a clause that is a constraint (prohibit, bound, narrower where) never grows the allow set. (This is exactly what facade W7 violates today.)
- G-T3 Provenance: every Allow carries a witness `(gid, {bid...})` computed by the decision function, and `Allow ⇒ witness.gid ∈ G.grants ∧ ` all conditions of that grant and all selected bounds hold. The decision returns the witness; a checker `verifyWitness(G,a,H,w)` is a separate small function also proved sound. Receipts store witnesses (ledger anchored).
- G-T4 Totality and ternary: `D_P` is total and deterministic; the result type is {Allow, Deny, Escalate}. `combine` is meet on Deny < Escalate < Allow, so `Escalate` is absorbing against Allow and never becomes Allow. PEP lemma: `PEP_allow ⇒ D=Allow ∨ ∃ valid signed EscalationAnswer bound to (policy_digest, action_digest, history_head)`. A PEP that sees Escalate with no answer must refuse; `authorize()` gets `decision: 'allow'|'deny'|'escalate'` (breaking, section 12).
- G-T5 Canonicity: same Goal bytes => byte-identical Policy (digest). Required for the principal-signs-the-artifact flow and for cross-language vectors.
- G-T6 Unit safety: well-typed Goals never mix currencies or units; ill-typed Goals are rejected (no coercion).
- G-T7 Hole safety: `holes != [] ⇒ ⟦C(G)⟧ ⊆ ⟦C(G ∖ clauses depending on holes)⟧`.
- G-T8 Aggregate soundness: for any interleaving of admissions through a linearizable store with durable reservation, `agg_b ≤ cap_b` for every bound. Lean (formal/intent Aggregate, Trajectory) + TLA+ (Reservation.tla extended to principal/fleet scope and crash recovery).

Not provable and stated as such: that `Allow_G` is what the principal meant (section 10), the correctness of the ontology as a model of the site's API, the linearizability of the store (TLA+ models PgStore/RedisStore exist: formal/tla), and cryptographic assumptions.

## 5. Spec part C: mechanization

Existing tools (checked): Dafny 4.11.0 pinned with Z3 4.12.1 and extraction to JS/Go/Java/Python/C# (formal/dafny, TOOLCHAIN.lock, difftargets harness; 171 verified, 0 errors; 0 assume/axiom/extern); Lean 4 v4.34.1 (formal/pca-lean without Mathlib; formal/intent with Mathlib, 174 theorems, axioms audit); TLA+/TLC/Apalache (formal/tla, formal/intent/tla); Tamarin/ProVerif/CryptoVerif; EasyCrypt; Kani/Verus fragments for Rust.

Decision: Dafny is the primary tool for the IR, compiler, decision function and witness checker, because (1) `PolicyVm.dfy` already defines the target semantics, so soundness is a refinement inside one tool and one pinned toolchain; (2) Dafny extracts to JS, and the verified-core already ships extracted code that production runs (no model-to-code gap, `build.sh --check` byte-identity); (3) diverse compilation to Go/Java/Python/C# is already a validation harness. Lean (no Mathlib where possible, per formal/pca-lean convention) is secondary for the quantitative layer: conformal risk control inequality, aggregate arithmetic, halving/query bounds already proved in formal/intent. TLA+ for the escalation protocol and durable aggregate store.

Files (new): `formal/dafny/GoalIr.dfy` (types, typing, semantics), `GoalCompile.dfy` (C and T1-T7), `GoalWitness.dfy` (T3 checker), `GoalTighten.dfy` (T9 below), `formal/tla/Escalation.tla`, `formal/tla/PrincipalAggregate.tla`, `formal/intent/lean/PcaIntent/Crc.lean` (conformal risk bound). Extracted output: `packages/pca-verified-core/generated/pca_goal.js` + typed bridge `src/goal.ts`, committed and `--check`ed byte-identical in CI like pca_core.js.

Link between proof model and implementations:
1. TS compiler is the extracted Dafny code behind a thin typed glue (parse, strict validate, canonicalize, render). Glue is the trusted base, listed in trusted-base.md.
2. Differential: Harness-style entry points for `typecheck`, `normalize`, `lower`, `decide`, `verifyWitness`; the same case file runs through JS, Go, Java, Python, C# builds and the production bridge; transcripts must be byte-identical (existing pattern, formal/dafny/difftargets).
3. Verifier side: the runtime `decide` for a policy lowered from IR already runs `ext-policyvm` (proved); the new `units` and `tighten` checks are added to Dafny Verdict/PolicyVm and to the native verifiers' conformance corpus (Go, Rust, Python first, then the rest).
4. Rust verifier is not proved (conformance only, verified-core.md); we claim conformance for it, not proof.

CI proves, per commit: `dafny verify --verify-included-files` zero errors; zero assume/axiom/extern grep; `build.sh --check` byte-identity; `lake build` plus `#print axioms` audit with no `sorryAx`; TLC cases including expected-fail mutants (an escalation-that-becomes-allow mutant must produce a counterexample); differential transcripts equal. Run on GitHub Actions (box dropped 2026-10-26; no Mac builds).

## 6. Spec part D: principal review (human-readable, signed exactly)

- `render(G)`: a deterministic template renderer (no LLM) producing the PolicyCard: per grant, plain sentences with exact numbers, currency, windows, resource scopes, prohibitions, aggregate caps, delegation limits, escalation triggers, wildcard warnings. Lemma G-T10 (render injective): `parse(render(G)) = G` on well-typed IR, so the card is lossless: anything the policy permits is visible on the card.
- `diffCard(G_old, G_new)`: semantic diff = clause-level plus the witness actions in `⟦G_new⟧ ∖ ⟦G_old⟧` (what newly becomes allowed) shown first; widenings in red.
- Boundary examples (F2) are part of the card.
- `GoalApproval` (extends nl.ts `NLApproval`): signed over `{goal_digest, policy_digest, card_digest, ontology_digest, tests_digest, nl_digest, model_set_digest, expires}`. The nl.ts flaw (digest without instruction/resource constraints, nl.ts:165-168) is fixed by making the signed object the whole IR plus the compiled policy. `loadApprovedGoal` recomputes `C(G)` itself (trust nothing the draft claims, same as loadApprovedPolicy today) and refuses on `holes != []`, digest mismatch, unpinned reviewer, TTL, or analyzer error.
- The principal key signs the exact artifact; the grant's `goal_commit` is redefined to commit to `goal_digest || policy_digest` (not just ref+map), so the intent binding finally pins semantics (closes W1). Old `pca-intent:v1/v2` goals stay verifiable.

## 7. Spec part E: model judgement is tighten-or-escalate only

Principle: a model may change a decision only toward Deny or Escalate. Model outputs never enter an allow path.

- Typed lattice `ModelSignal ∈ {ok, escalate, deny}` with order ok > escalate > deny, carried in a new `tighten[]` policy list evaluated AFTER the allow decision.
- Theorem G-T9 (no widening by any oracle): for every policy P and every model oracle M (any function, including adversarial, compromised, noisy), `D_{P,M}(a,H) ≤ D_P(a,H)` in the order Deny < Escalate < Allow, and `D_{P,M}` with M absent equals `D_P`. Proof in Dafny by construction: the final verdict is `meet(D_P, tighten(M))` and `tighten(M) ≤ Allow`-neutral.
- Typing rule enforced by the compiler AND by a verifier lint/check (rule 21): model-derived env paths (`env.class.*`, `env.prov.*`, `env.world.*` when from a single oracle, `env.judge.*`) are forbidden inside `grants[].where` and allowed only inside `tighten[]`. Today they are merged into the env the grant predicates read (intent-v2.ts, intent-env.ts), the root of W16. Migration: existing grants that read them keep working in a compatibility mode flagged `model_polarity: legacy`, reported in assurance as degraded.
- Consequences: semantic-threshold (conformal gate), classifier, objective-risk, progress and the immune layer can only raise friction. Their error costs availability (extra escalations), never safety, so their quality becomes a measured UX metric. This is the condition under which intent-frontier modules can leave "experimental": they must (a) be tighten-only typed, (b) have a published benchmark (F5/F9), (c) have mutation + fail-closed tables (already largely present).
- Non-model signals that are proved facts (signed oracle facts from a pinned quorum with freshness, deterministic taint) may stay in `where` but are tagged `assertion` in the card ("rests on X's signature").

## 8. Spec part F: adversarial evaluation suite

`packages/pca-goal/adversarial/` plus shared vectors `packages/pca-conformance/vectors/goal/` (exact path to be matched to the existing conformance layout (unverified); one JSON file per case).

Executable tests, one per row of section 2, each asserting the post-spec outcome: W1 (grant minted for another goal text fails `goal_commit` opening), W2 (claimed fidelity ignored without map replay or removed), W3 (extra verb in model output: N-version intersection drops it; deterministic path cannot emit it), W4 (instruction/model change changes digest), W5-W7 (IR windows exact; ill-typed money limit without a param is a compile error; monotonicity property test: for random G and random constraint c, `⟦C(G+c)⟧ ⊆ ⟦C(G)⟧`), W8-W9 (split across N sessions and agents at principal scope), W10 (delegate without the grant's gid is denied), W11-W12 (ambiguity yields a Hole/Escalate, never Allow), W13 (aliased verb with same effect class hits the prohibition), W14, W16 (adversarial oracle: property test over random M: never widens), W18 (cents vs dollars, EUR vs USD, 1,000 vs 1.000), W19 (NFC/NFD, homoglyph, alias ids), W20 (prompt-injection corpus, F9), W21 (Escalate with no answer is refused by every PEP).

Generated corpus: grammar-based generator over the IR (seeded, deterministic) producing goals, actions and boundary probes; for each, an executable reference semantics `⟦G⟧` written in the Dafny model is evaluated against the compiled policy: the oracle is the semantics, so no human labels are needed for the deterministic path. Mutation of the compiler (drop a prohibition, flip a bound, widen a window) must be killed (mutation test, repo convention `mutation-kill-*`).

Cross-language vectors: `(goal.json, policy_digest, probe -> decision, witness)` tuples consumed by TS, Go, Rust, Python (then the other natives), same corpus format as the existing conformance vectors; all four must agree byte for byte on policy digest and decisions. Rust and Python also run the verifier-side checks `units` and `tighten`.

## 9. Spec part G: aggregates and budgets with durable stores

- `Bound.scope` adds `principal`, `org`, `fleet`. State lives in a `BudgetLedger` interface (compare-and-swap reservations, idempotent under retry, crash-safe) with the existing conformance-kit pattern (`pca-store-conformance`, KvLedgerStore/KvBondStore precedent from 0.5 Track 3) and a reference durable KV store; the in-memory store is refused when a bound has `scope != session` (`requireDurable`, as T-055 already advises).
- Reservation two-phase: reserve (counts as admitted) then commit/release on effect result; release is a signed, ledger-anchored event; failure to release only over-restricts.
- Keyed by principal id (not grant id), so N sessions or N delegated agents share one cap (W9). Sequenced holder receipts (intent-acc.ts sequenced holder) are reused for cross-site aggregates.
- TLA+: `PrincipalAggregate.tla` (NoOverspend under concurrent sessions, crash, replay, clock skew) with expected-fail mutants (no CAS, release-without-reserve).
- Windows are explicit (section 3.3); no `day`=24h ambiguity.

## 10. Spec part H: intent fidelity (getting as close as possible to what the human meant)

This is the unprovable half. Each technique states its guarantee and assumptions; "Guarantee" never exceeds what the assumption supports.

F1. Active disambiguation.
- Mechanism: the interpreter fills a typed template/IR; any required slot it cannot fill, any literal it cannot type (locale, timezone, currency), and any disagreement between readings (F3) becomes a `Hole`. The question generator ranks witness actions in the symmetric difference of two readings by risk times mass (reuse pca-intent `analyzeDisagreement`, `omega`, halving learner) and asks the minimal distinguishing question ("Should refunds apply only to charge ch_9, or all of this customer's charges?"). Signing is impossible while `holes != []` (type-level, G-T7).
- Guarantee (proved, existing Lean `halving_card`/`halving_queries`, formal/intent): with a finite realizable hypothesis class and truthful answers, the number of questions to isolate the principal's reading is at most log2 of the class size; the remaining disagreement mass after q answers is bounded. Also proved: no signed goal contains an unresolved Hole.
- Assumptions: the principal's intent is inside the hypothesis class (realizability), answers truthful and consistent, question budget respected (wallet-held question cap, intent-acc.ts).
- Metrics: questions per goal; residual disagreement mass at signing; abandonment.

F2. Policy-by-example confirmation.
- Mechanism: from the compiled policy, generate boundary examples by exhaustive enumeration over the typed IR: for each numeric bound b the points b-1, b, b+1 (minor units); each enum and relation member in/out; one minimal Allow witness per grant; one trigger per prohibition; the sequence that reaches each aggregate cap and the next action; unmentioned-dimension probes (extreme amount, other resource, other customer) to expose over-breadth. Use the analyzer's representative enumeration (packages/pca-analyzer `representatives`, exact on its decided fragment, `approximate` flagged otherwise); SMT only if the fragment outgrows enumeration (Dafny's bundled Z3 is already pinned).
- Principal marks each example would-allow / would-deny / ask-me. Confirmed examples become `GoalTest` records signed with the approval and pinned (`tests_digest`); any recompile (new ontology version, new compiler) must reproduce all of them or the policy is refused. This is regression protection for model-generated policy drift (W4).
- Guarantee (proved): coverage: the example set contains at least one representative of every decision cell of the arrangement induced by the literals of the policy (decided fragment), so any other policy in the fragment that differs on a cell differs on at least one example. Plus the pin property: policy version cannot silently change under a signed test set.
- Assumptions: the principal answers correctly (fatigue is real: cap examples, order by risk); cells are defined by literals present in the policy, so a reading with a literal the policy lacks is caught only by the unmentioned-dimension probes, not by cell coverage.

F3. N-version interpretation.
- Mechanism: k >= 3 interpreters produce IRs independently: different model families and prompts plus one deterministic template/form interpreter. The enforced policy is the semantic intersection (compiler computes the grant cross-product with conjoined conditions, union of prohibitions, minimum of caps); disagreement beyond threshold, or any grant present in only some readings, becomes Holes (F1) or Escalate.
- Guarantee (proved, easy): `⟦merged⟧ ⊆ ⟦C(G_i)⟧` for every i. So if at least ONE interpreter is faithful, the enforced policy is no broader than the faithful reading (k-1 interpreters can be wrong or hostile without widening). Independence is NOT needed for this safety property; it is needed only for the detection rate of disagreement.
- Cost: availability (over-restriction) and escalations; measured.
- Assumptions: at least one faithful interpreter for the goal in question; common-mode failure (all interpreters share the same bias or the same prompt-injection) defeats detection, so at least one deterministic non-LLM interpreter and a different-vendor model are required, and the F9 benchmark measures common-mode widening.

F4. Round-trip check.
- Mechanism: (a) deterministic: the card renderer is injective (G-T10), so `parse(render(G))=G`: provable losslessness. (b) independent LLM explainers see ONLY the compiled policy and write a plain-language account; a separate comparator (different family) judges equivalence with the original goal text; mismatch escalates.
- Guarantee: (a) proved. (b) none by proof: it is a detector whose detection rate is measured by mutation: apply random semantic mutations to compiled policies (widen a cap, drop a prohibition, swap a resource) and report the fraction detected. It can only escalate (tighten-only, G-T9).
- Assumptions for (b): explainer/comparator errors are not correlated with the interpreter's errors.

F5. Statistical guarantees (conformal risk control).
- Mechanism: per domain, a labeled benchmark of (goal text, principal-adjudicated probe set of would-allow/would-deny actions, including adversarial probes from F9). Define the loss for a goal = 1 if the auto-accepted compiled policy permits any probe the labelers reject (a widening event); the loss is monotone in the tunable threshold lambda (e.g. the F3 agreement threshold and the F2 confirmation requirement). Choose lambda by conformal risk control (Angelopoulos et al.) on a calibration split.
- Guarantee: under exchangeability of calibration and deployment goals within the domain, `E[loss] <= alpha` (finite-sample correction B/(n+1) with B=1), i.e. "with probability at least 1-alpha the auto-signed policy permits no probe action the principal would reject" over the probe distribution used. Report with Clopper-Pearson upper bounds (packages/pca-intent/src/clopper.ts exists); rule of three: 0 failures in n gives a 95% upper bound of 3/n, so alpha=1% needs n of a few hundred per domain.
- Assumptions (all stated in the published report): exchangeability (broken by distribution shift, new ontology versions, new models: recalibrate and gate on it), label quality (inter-annotator agreement reported), probe-set coverage (the guarantee is about probes, not every action; the probe generator and its coverage are published), non-adaptive deployment distribution (an adaptive attacker is handled by F9, not by this bound). The Lean file `Crc.lean` proves the inequality given the assumptions; the assumptions themselves are empirical.
- Published rates per domain: widening rate (with CI), escalation rate, mean questions, false-restriction rate, per-model-set.

F6. Domain ontologies and templates.
- Mechanism: signed, versioned, typed vocabularies layered on the existing action schema (action-schema.ts: closed world, semantic types, units, sensitivity). Initial domains: payments (refund, charge, transfer, payout, subscription; Money, Charge, Customer, relations `charges_of`), email (read, label, archive, delete, send, forward; Mailbox, Thread, Recipient, domain allow-lists; effect classes read/reversible/external-send/irreversible), calendar/travel (search, hold, book, cancel; Money, Airport, Date with tz, Traveler), code/repos (read, branch, push, merge, release, delete; Repo, Ref, protected branches), data access (query, export, delete; Dataset, Column class, purpose, row/aggregate limits). Each ontology provides: verbs mapped to effect classes (closes W13), total alias maps (synonym to canonical id, signed, so aliasing is declared not guessed), typed relations, mandatory slots (missing = Hole), safe default bounds, and goal templates ("refund duplicate charge" is `Refund(charge ∈ charges_of(customer), amount ≤ charge.remaining)` with prohibits and a count bound).
- Guarantee (proved): ontology well-formedness checker: typing total, unit systems closed, alias map a function with no cycles, no verb without an effect class, templates type-check and compile to Allow-sets that are non-empty and bounded. Plus: goals expressed through a template have `holes` limited to the template's declared slots.
- Assumptions: the ontology faithfully models the site API (the same trust the action-schema author has today); free-text goals outside any ontology get the lowest autonomy (escalate-heavy).

F7. Progressive authorization.
- Mechanism: start narrow (template minimum, usually read-only or the single named object). Widening is only by an `EscalationRequest` (witness action, risk, reason, policy digest) answered by a principal-signed `EscalationAnswer`; answered escalations become signed `Precedents` (cell, decision, answer, expiry) stored append-only and anchored. Precedents are monotone refinement: a recorded cell decision is never flipped except by principal-signed revocation (existing intent revocation epochs).
- Guarantee (TLA+ `Escalation.tla` plus Dafny G-T4 lemma): the effective allow set grows only by cells with a valid principal signature bound to (policy_digest, action cell); no widening without a signature; no replay of an answer onto another policy or action; escalation never becomes allow implicitly. Reuse: delta grants D_k, `intent_required` questions, LazyElicitation.tla, wallet question caps.
- Assumptions: the principal is not fatigue-manipulated into approving (T-057/N-1 residual): mitigated by question caps, risk-ordered batching, and showing the widening diff.

F8. Runtime drift monitoring (tighten-only).
- Mechanism: monitors compare the observed action stream to the goal's expected profile (verbs, resources, magnitudes, rate, novelty of resources/recipients; reuse immune.ts monotone signed tightening and contracts monitors). Anomalies convert Allow to Escalate or raise the required threshold; never relax.
- Guarantee: tighten-only (G-T9, proved); rates of false escalation and detection of seeded drift scenarios are measured. No guarantee of detecting a given drift.
- Assumptions: baseline profile is representative; the monitor state is durable and not agent-writable.

F9. Adversarial benchmark.
- Corpus: hostile goals and documents with injected widening instructions ("also allow all refunds", "ignore the limit"), homoglyph and Unicode tricks, locale/currency traps, multi-turn drift, synonym attacks, split-across-sessions, role confusion in delegated agents, and tampered precedents. Each case has an executable oracle (reference semantics or labeled probes).
- Two separately reported rates. (1) Compile-widening (IR to policy): MUST be zero, and is zero by G-T1 plus the generated-corpus test; any nonzero is a release blocker. (2) Interpretation-widening (text to IR through models): bounded and published with a Clopper-Pearson upper bound per model set and domain; release gate: upper bound <= alpha chosen per domain (payments strictest). The deterministic template path reports zero for both on its supported grammar by construction (typed form input has no free text to inject).
- Assumption: the corpus is a sample, not the attack space; it is versioned, extended with every incident, and run in CI (corpus tests) plus a scheduled model-path evaluation job on GitHub Actions with pinned model versions and recorded seeds.

## 11. Build tracks

Each is one-agent buildable; all verification runs on GitHub Actions.

| Track | Scope | Main files | DoD | CI must prove | Depends on |
|---|---|---|---|---|---|
| T1 Goal IR + compiler + proofs | IR types, typing (units, currency, holes), normalize, lower to PolicyVm target, witness, ternary decision, G-T1..T7,T10; extraction + bridge | formal/dafny/GoalIr.dfy, GoalCompile.dfy, GoalWitness.dfy; packages/pca-goal (glue, canonical JSON, render/parse); packages/pca-verified-core/generated/pca_goal.js, src/goal.ts; docs/pca/security/trusted-base.md row | Dafny verifies with 0 assume/axiom/extern; extraction `--check` byte-identical; injectivity of render proved; differential transcripts (JS, Go, Java, Python, C#) equal; docs/pca/security/traceability row per theorem | `dafny verify`, build.sh --check, difftargets run, unit + property tests (monotonicity random test), mutation-kill tests of compiler | none (starts first) |
| T2 Enforcement: ternary PEP, units check, tighten-only | `authorize()` returns allow/deny/escalate; EscalationAnswer wire; verifier checks `units` (rule 20) and `tighten[]` typing (rule 21); G-T4, G-T9; legacy model-polarity flag; fix facade W5-W7 bugs behind the new compiler | packages/pca/src/server/authorize.ts, require-pca.ts, intent-v2.ts, intent-env.ts, pcactn.ts wire; formal/dafny/Verdict.dfy, PolicyVm.dfy, GoalTighten.dfy; formal/tla/Escalation.tla; native verifiers Go, Rust, Python (+ conformance vectors rules 20-21) | Escalate never yields allow in any adapter (fail-closed table); G-T9 proved; native verifiers pass new vectors; contract C-numbers added (C-30+) | Dafny, TLC, conformance in TS, Go, Rust, Python, adapter tests | T1 types (can start on the Dafny Verdict/PolicyVm changes in parallel) |
| T3 Principal review + signing flow | PolicyCard renderer, semantic diff, GoalApproval, `loadApprovedGoal` (re-derives), goal_commit redefinition (goal_digest||policy_digest), migration of nl.ts | packages/pca/src/nl.ts, new packages/pca-goal/src/review.ts, console surface, docs/pca/guides/nl-policy-review.md (internal notes only) | Approval covers instruction/IR/policy; tamper tests for every field; v1/v2 goals still verify; reviewer-fatigue limits (card size caps) tested | unit/mutation tests, conformance vectors for the new commit, trace to W1/W4 tests | T1 |
| T4 Aggregates and durable budgets | principal/org/fleet scope, `BudgetLedger` interface + conformance kit + reference KV store, two-phase reserve/commit/release, TLA+ and Lean | packages/pca/src/intent-acc.ts (extend), packages/pca-store-conformance, formal/tla/PrincipalAggregate.tla, formal/intent/lean Aggregate | NoOverspend model-checked incl. crash and mutants; store conformance suite fails the defective stores; refuse non-durable for non-session scope | TLC, store-conformance, cross-session and cross-agent attack tests (W8, W9) | T1 types for Bound (interfaces first), otherwise independent |
| T5 Adversarial suite + cross-language vectors | W1..W23 executable tests, IR-grammar generator, reference semantics oracle, compiler mutation tests, vector format, runners in TS, Go, Rust, Python | packages/pca-goal/adversarial/, shared vectors dir, per-language runners, scripts/ CI workflow | all W cases assert post-spec behavior; generated corpus >= N cases/domain deterministic seeds; mutants killed; four languages agree on digests and decisions | GitHub Actions matrix incl. the four runners | T1 (semantics), T2 (verifier checks) for the verifier-side cases; can pre-build the generator |
| T6 Intent fidelity program | Ontologies (5 domains) + checker, interpreters (LLM adapters + deterministic template), disambiguation, boundary-example generator + signed GoalTest, N-version intersection, explainer/comparator, precedents, drift monitors (tighten-only), labeled benchmarks, conformal risk control with published rates, hostile corpus | packages/pca-goal/{ontology,interpret,disambiguate,examples,nversion,roundtrip,precedent,drift}, packages/pca-intent (reuse compilers/analyzeDisagreement/clopper), formal/intent/lean/PcaIntent/Crc.lean, benchmarks/ per domain, eval workflow | Ontology checker proofs; examples coverage theorem tested; N-version meet proved `⊆` each; CRC report per domain with CI bounds, assumptions section generated into the report; widening-rate gates in CI; model path scheduled job | GitHub Actions: Lean build, unit tests, offline benchmark runs with recorded model outputs (no live model needed in PR CI), scheduled live-model eval | T1 (IR), T3 (signing), T5 corpus; ontologies can start immediately |

Order: T1 first; T2 and T4 parallel once T1 types are merged; T3 after T1; T5 builds generator early, verifier cases after T2; T6 ontologies and benchmarks start in parallel with T1, integrate last. Single integration, single deploy at the end (repo convention).

## 12. Migration from today's APIs (0.5 may break)

- `authorize()` / `requireAuthorized` / adapters: result gains `decision: 'allow'|'deny'|'escalate'`; `allow: boolean` stays as `decision === 'allow'` for one release; `intent_required:` deny-reason prefix becomes `escalate`. BREAKING for hosts that treated the 403 as deny-only.
- `facade.compilePolicy` / `agent()`: deprecated in favor of `compileGoal(G)`; the `{permissions, limits}` input is lifted to a Goal by a total, documented, conservative `liftLegacy` (month, day semantics made explicit; `$` limits without amount field become a compile error, not silent). The W7 behaviors are fixed, not preserved. `facade` stays for the quickstart through a template ontology.
- `nl.ts`: `draftPolicyFromNL` becomes an interpreter front end producing a Goal draft; `approveDraft`/`loadApprovedPolicy` replaced by `GoalApproval`/`loadApprovedGoal`; old approvals still load for one release, flagged `legacy_unbound_instruction`.
- `goal_commit`: v3 commits to `goal_digest || policy_digest`; v1/v2 verification retained.
- `IntentPolicy.min_fidelity_ppm / max_residual_risk_ppm`: documented as untrusted claims; default behavior changed to require a verified map replay or ignore the claim (they never gate Allow); moved to tighten-only.
- Model-derived env in `where`: legacy mode flag, warning in assurance, removal one release later.
- `action-schema` reserved members `effects`, `harm`, `world`, `state`: `effects` becomes normative (effect class), read by the compiler and prohibitions; others stay reserved.
- `slotsToPolicy` (pca-intent): replaced by the ontology-typed slots; `unit` becomes interpreted.
- docs/pca/migration.md and upgrading-to-0.5.md updated (internal first; public docs only after the owner decides what to publish, and nothing from this spec is copied verbatim).

## 13. What this spec will and will not let us claim

Can claim (after T1-T5): the compiled policy is a sound, monotone, traceable, unit-safe refinement of the signed goal (machine-checked, extracted, differentially tested); escalation never becomes allow; models can only tighten; aggregates hold at principal scope under the stated store assumptions; all of the above is checked in CI.
Can claim with published numbers (after T6): the measured rate at which the model-assisted interpretation permits an action the principal would reject, with confidence bounds and stated exchangeability assumptions.
Cannot claim: that any model understands a human, that the principal reads or answers correctly, that an ontology matches a site's real behavior, anything about actions outside the schema, or protection from a principal who approves a harmful widening (N-1).
