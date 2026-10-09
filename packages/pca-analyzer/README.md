# @atlasauth/pca-analyzer

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
- **whole-`action.params` conditions** (a condition on the container rather than a `.subfield`).
- **grid overflow** — a representative grid larger than `maxCombinations` (default 200,000); no
  enumeration is performed.

The soundness contract: a proven verdict (`approximate` falsy) is correct for the fragment above; an
`approximate` verdict is never a false "safe". 

## Status

Experimental. Verdicts without `approximate: true` are exact for the fragment listed above; the cryptography in `@atlasauth/pca` is unaudited, though this package performs no cryptography itself. An external SMT backend for the regex and cross-field fragments is not included.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
