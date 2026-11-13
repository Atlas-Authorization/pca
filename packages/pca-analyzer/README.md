# @atlasauth/pca-analyzer

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Static analyzability of authority for Proof-Carrying Authority (PCA). PCA can verify one action and prove a quantitative trust-budget bound, but on its own it cannot answer "what can this whole delegated authority ever do?". This package decides that over PCA's predicate/caveat policy (reachability, vacuity, totality, delegation-safety subsumption, disjointness, equivalence, and conformance to a declared intent) without an SMT dependency.

It is a sound, bounded decision procedure in the spirit of AWS Cedar's symbolic compiler (SymCC, arXiv:2403.04651), which decides policy equivalence, subsumption and always-allow/deny with counterexamples. Instead of discharging to Z3, it exploits a finite-distinguishing-value property of PCA's predicate theory and decides by enumeration against the real `evaluatePredicates` from `@atlasauth/pca`.

## Install

```sh
npm i @atlasauth/pca-analyzer @atlasauth/pca
```

## Usage

```ts
import { compilePolicy } from '@atlasauth/pca';
import { subsumes, intentConformance, reachable } from '@atlasauth/pca-analyzer';

const parent = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500' } });
const child  = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' } });

// Delegation safety: a child must not widen its parent.
subsumes(parent, child).subsumes;   // true
subsumes(child, parent);            // { subsumes: false, counterexample: { verb: 'stripe.refund', params: { amount: 300 }, ... } }

// Can any input complete this action into an ALLOW? Returns a verified witness.
reachable(parent, { verb: 'stripe.refund', resource: 'charge:1', params: { amount: 50 } }); // { reachable: true, witness }

// Intent conformance: does the authority stay inside what was meant?
const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$20000' } });
const r = intentConformance(policy, { verbs: ['stripe.refund'], maxAmount: 10000 });
// r.conforms === false; r.violations[0].kinds includes 'over-amount'
```

## Queries

All take a `CompiledPolicy` (from `compilePolicy` / `agent().policy`) or a bare
`{ predicates, caveats? }`. Every negative/relational verdict carries a concrete counterexample or
witness.

| Function | Decides |
|---|---|
| `reachable(policy, action)` | Can any input complete `(verb, resource, params)` into an ALLOW? Returns a verified `witness`. |
| `alwaysDenies(policy, verb?)` | Is the policy vacuous (denies everything / everything for `verb`)? |
| `alwaysAllows(policy, verb)` | Is the policy total for `verb` (admits every action of it)? |
| `subsumes(a, b)` | Does `a` permit everything `b` does (`admitted(b) ⊆ admitted(a)`)? The delegation-safety check: a child must be subsumed by its parent. |
| `disjoint(a, b)` | Do the two admit no common action? |
| `equivalent(a, b)` | Do the two admit exactly the same actions? |
| `intentConformance(policy, intent)` | Does the policy admit **only** actions inside a declared intent envelope (verbs + resource scopes + amount ceiling)? |

`intentConformance` is a safety check distinct from the runtime trust-budget. It catches the
*"a $14k renewal under a $10k cap on an approved vendor still violates intent"* class: an action that
passes the policy's predicates and stays under budget, yet falls outside what the principal intended,
because the policy's own ceiling is higher than (or absent relative to) the intent cap.


## Analysis and authoring tools (0.5)

On the same engine, outside the trusted core. Every witness is re-checked by the real evaluator; anything not decided exactly is marked `approximate`. The guide "Analyze, author and test a policy" in the PCA docs has the details.

| Function | Answers |
|---|---|
| `maxExposure(policy, { verb, windowSecs, constitution })` | The most that can leave: per action, without a human, and over a window (rate limits, `cap` / `rate` invariants, and the budget allocation in the dollar model). An upper bound. |
| `escalationSurface(policy)` | Verified actions that are admitted only with a human. |
| `delegationEnvelope(chain)` | The meet of a delegation chain, the remaining depth, and any hop wider than its parent. |
| `diffPolicies(a, b)` / `diffGate(d)` | A ternary diff with witnesses (deny, escalate, allow), the change in maximum exposure, and a CI gate. |
| `residual(policy, known)` / `whatMayIDo(policy, verbs, known)` | Partial evaluation: the policy specialised to what is known, exact for every completion; per-verb allowed parameter domains for an agent to plan with. |
| `toFilter(residual, { columns })` | A parameterized SQL filter that never selects more than the evaluator allows, or a refusal. |
| `suggestNarrowing(policy, observed)` | A narrower grant proven subsumed by the original, unused-permission findings ranked by blast radius, and access requests. Never widens. |
| `coverage(policy, traffic)` / `coverageGate` | Clauses that never decided, thresholds not probed, and mutations the traffic cannot detect. |
| `minimalFlip(policy, action, { holderAuthenticated })` | The smallest verified change that gets a denied or escalated action allowed; holder-only, rate-limited, redacted. |
| `validatePolicyAgainstSchema(policy, schema)` | Undeclared verbs and parameters, type, range and enum mismatches, unit tags (rule 20), unbounded money verbs. |
| `generateBoundaryTests`, `runPolicyTests`, `signPolicyTests` | Boundary examples, a digest-pinned runner, signed confirmed examples. |
| `vetoesFromConstitution(c)` | A constitution's stateless invariants as analyzer vetoes (`never`, `never_unless`, `require_approval_over`). |
| `findWithBackend(backend, query)` | An optional external solver, used only to look for a counterexample and never trusted. |

A `PolicyInput` may also carry `vetoes` (prohibitions), `tighten` (model-signal rules) and `meet` (the ancestors of a delegation chain); the ternary decision is `allow`, `escalate` or `deny`.

## How it decides (the engine)

PCA's `where` conditions are a conjunction of threshold tests (`lt/lte/gt/gte/eq` on numbers),
membership tests (`eq/ne/in/nin` over finite values) and string `prefix` tests; predicates match on a
verb allowlist and a resource matcher; the envelope caveats are append-only and conjunctive. The
admitted region of a policy is therefore a **union of cells** of the arrangement defined by the literals
that appear in it. The analyzer builds one representative value per cell — every literal and numeric
threshold, the midpoints between consecutive thresholds, boundary points just outside the range, prefix
probes, a *fresh* verb / resource / value matching none of the literals, and an *absent* probe for each
field — then evaluates both policies at every representative with the real evaluator. Because that set
is distinguishing, agreeing on all representatives implies agreeing on all actions, so the relational
queries are decided exactly, and any mismatch is a real counterexample. Caveat satisfiability is decided
separately (`analyzeCaveats`): the context (time window, blast radius, depth, rate) is taken as
favourably chosen, and the one action-tied caveat, `reversibility_max`, becomes a per-action cap.

## Decided exactly vs. sound-over-approximated

**Decided exactly** (the fragment):

- verb allowlists (`string`, `string[]`, `'*'`);
- resource matchers that are exact, `'*'`, or a trailing-`*` **prefix**;
- numeric `where` over `lt/lte/gt/gte/eq` (the interval engine; merges bounds, detects empty
  conjunctions such as `amount >= 100 AND amount <= 10`);
- finite-domain `eq/ne/in/nin` and string `prefix` (the set engine — the fresh/absent probes make
  unbounded string domains decidable for these operators);
- `exists` (via the absent probe);
- the conjunctive envelope caveats: `expires`, `not_before` (empty-window detection), `rate`,
  `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc`.

**Sound but over-approximated** — the result is reported with `approximate: true` and **fails safe**
(never claims *subsumed / always-deny / disjoint / equivalent / conforms* without proof; falls back to
*not-subsumed / reachable / not-disjoint / not-equivalent / non-conforming*):

- **`re:` regex resource matchers** — a regex relation (containment/overlap) is not decided; the
  resource dimension cannot be soundly enumerated. (A regex is still evaluated *exactly* against a fully
  concrete resource in `reachable`, where there is nothing to enumerate.)
- **cross-field `ref` conditions** — a comparison whose operand is another field (`a != env.b`); the two
  fields co-vary and are not resolved statically.
- **ordering against a non-numeric operand** (`lt`/`lte`/`gt`/`gte` with a string, boolean, array or null): the verifier orders strings, and only finite numeric thresholds partition the value line into the cells the enumeration relies on. Before 0.5 such a policy could be "proved" to always deny; a differential test against the verifier found it.
- **whole-`action.params` conditions** (a condition on the container rather than a `.subfield`).
- **grid overflow** — a representative grid larger than `maxCombinations` (default 200,000); no
  enumeration is performed.

A value that is not a policy is an empty policy (it admits nothing and nothing throws), and a `maxCombinations` that is not a non-negative finite number falls back to the default so the cap cannot be switched off.

The soundness contract: a proven verdict (`approximate` falsy) is correct for the fragment above; an
`approximate` verdict is never a false "safe". 

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A value that is not a policy | treated as an empty policy: it admits nothing and nothing throws |
| `maxCombinations` that is not a non-negative finite number | the default (200,000) is used; the cap cannot be switched off |
| Representative grid larger than `maxCombinations` | `approximate: true`, falling back to the unsafe-looking side (reachable, not subsumed, not disjoint, not equivalent, non-conforming) |
| A feature the engine cannot decide (`re:` resources, cross-field `ref`, non-numeric ordering, whole-`action.params` conditions) | `approximate: true`, never a false "safe" |
| Caveats that cannot be satisfied | `reachable` is `false` with the reason |
| Policy-test document run with `requireDigest` against a changed policy | the run is not `ok`, even if every case passes |
| Signed policy tests with another signer, the wrong kind, or a bad signature | `verifyPolicyTests` returns `false`; it does not throw |

## Checked against the verifier

`differential/verifier.diff.test.ts` generates policies and actions (with the generators of `@atlasauth/pca-invariants`) and compares every answer with `evaluatePredicates` and `evaluateCaveats`: a policy is never called unreachable or always-deny when the verifier admits a concrete action, a `subsumes` or `disjoint` "yes" is never refuted by an action, and every witness or counterexample is real. It runs 1,500 cases per property by default; set `PCA_DIFF_RUNS` and `PCA_DIFF_SEED` for more.

## Limits

- It analyses the fragment listed above. Outside it, a verdict is approximate and says so; it never proves safety there.
- It reasons about policies, not about the world: it cannot tell whether a policy matches what a person meant, except through the intent envelope you declare.
- It performs no cryptography beyond verifying signed test documents, and it is not a replacement for the verifier, which stays the authority.
- Answers are bounded by `maxCombinations`; a larger problem returns an approximate verdict.

## Status

Production. Verdicts without `approximate: true` are exact for the fragment listed above; this package performs no cryptography itself. Regular-expression resource scopes are evaluated only through the verifier's linear-time-safe subset; anything else matches nothing. An external SMT backend for the regex and cross-field fragments is not included.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
