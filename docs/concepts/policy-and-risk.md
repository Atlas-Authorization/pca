---
title: Policy and risk
order: 4
---

# Policy and risk

PCA treats authorization as a **control system**. The setpoint is "operate within sanctioned intent". The sensor is the **risk functional** `r(A)`. The actuator is **friction**: the signing threshold `t` an action needs. The integral state is a depleting **trust budget** `B`. All of this is pure, deterministic code in `@atlasauth/pca`, so a verifier can recompute it.

## The Policy VM

`decide(input)` is the deterministic evaluator that decides whether the **guardian share may be released** for an action and what threshold the resulting signature must meet. It is total and never throws: every failure is a denial with a reason (fail closed).

```ts
const d = decide({ grant, chain, action, plan, risk, budget, now, nodeId, caveatContext });
// PolicyDecision:
// { releaseGuardianShare, requiredThreshold, r, admit, needStepUp, reasons, budget }
```

In order, `decide`:

1. reads the grant envelope (none: deny);
2. evaluates **predicates** (default deny);
3. evaluates **envelope caveats**, plus caveats added by delegation hops when a `chain` is given;
4. computes `r`, with missing risk inputs assumed worst case;
5. maps `r` to a required threshold and checks **budget admission**;
6. releases the guardian share only if predicates and caveats and the chain are all satisfied. If policy passes but risk or budget requires more, the step-up path remains available.

`deriveDecideInput(pcactn, ctx)` builds a `DecideInput` from a PCActn so caller and verifier derive the action, node and chain identically.

## Predicates

Predicates are **pure data**. There is no `eval`, no user code path. An action is allowed iff it matches **at least one** predicate (verb AND resource AND all `where` conditions). An empty list allows nothing.

```ts
interface Predicate {
  verb: string | string[];     // exact, list, or '*'
  resource?: string;           // exact; '*'; trailing '*' = prefix; 're:<pattern>' = full-match regex (<= 200 chars)
  where?: Condition[];         // ALL must hold
}
interface Condition {
  field: string;               // dotted path rooted at action | subject | env
  op: 'eq' | 'ne' | 'in' | 'nin' | 'lt' | 'lte' | 'gt' | 'gte' | 'prefix' | 'exists';
  value?: unknown;
  ref?: string;                // compare against another path instead of a literal
}
```

Example: revoke only sessions on devices other than the current one.

```ts
{ verb: 'revoke_session', resource: 'session:*',
  where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }] }
```

**Ordering operators.** `lt`, `lte`, `gt` and `gte` compare two finite numbers numerically, or two strings by the **byte-wise order of their UTF-8 encoding** (Unicode code point order): `"\uFFFF"` sorts before `"\u{10000}"`, unlike JavaScript's `<`, which compares UTF-16 code units. There is no Unicode normalisation (`é` as `U+00E9` and as `U+0065 U+0301` are different strings), no case folding and no locale. A string with a lone surrogate (not valid UTF-8) is unordered, so the condition is false. Any other operand pair is unordered and false.

Everything fails closed: a missing field, missing operand, unknown operator, forbidden path segment (`__proto__`, `constructor`, `prototype`) or malformed predicate makes the condition false. `exists` with `value: false` means "must be absent". The pattern for `re:` is authored by the principal and signed into the grant, so it is trusted input.

## Caveats

Built-in caveat types (all conjunctive; an unknown type is unsatisfied):

| Type | Fields | Satisfied when |
|---|---|---|
| `expires` | `at` (ms) | `now < at` |
| `not_before` | `at` (ms) | `now >= at` |
| `rate` | `max`, `per_secs` | admitted actions in `(now - per_secs, now]` is below `max` |
| `max_blast_radius` | `max` in [0,1] | blast radius is at most `max` |
| `reversibility_max` | `class` | class is no more severe than `class` (`reversible` < `rate_limited` < `irreversible`) |
| `delegation_depth` | `max` | hops below the root is at most `max` |

`evaluateCaveats(caveats, ctx)` returns `{ ok, failed }`. Missing context data (for example no `recentActionTimes` for a `rate` caveat) fails closed.

## The risk functional

```
r(A) = clamp( α·d_sem + β·(1 − rev) + γ·bl + δ·taint + ε·(1 − conf) + ζ·age , 0, 1 )
```

| Input | Meaning |
|---|---|
| `semanticDistance` (`d_sem`) | Distance of the action from the committed intent: the normalized geodesic in the plan DAG (`planGeodesic`), deterministic and verifier-checkable. Embedding distance is advisory only and never gates. |
| `reversibility` (`rev`) | 1 = fully reversible, 0 = irreversible |
| `blastRadius` (`bl`) | Normalized extent of effect |
| `taint` | Untrusted-lineage fraction (L4) |
| `confidence` (`conf`) | Agent uncertainty |
| `age` | Normalized time since the last human touch (`ageSinceTouch`, default horizon 1 hour) |

Weights live in the grant's `risk_policy`. `riskScore` clamps weights to be non-negative, which makes `r` monotone non-decreasing in distance, blast radius, taint and age, and non-increasing in reversibility and confidence, for any policy. Non-finite inputs are treated as worst case.

Default policy (`DEFAULT_RISK_POLICY`):

| Parameter | Value |
|---|---|
| weights α, β, γ, δ, ε, ζ | 0.25, 0.2, 0.2, 0.2, 0.1, 0.05 |
| θ₁, θ₂ | 0.25, 0.6 |
| κ (cost scale) | 1 |
| λ (leak per second) | 0.0005 |
| ρ (recharge per human co-sign) | 0.5 |
| bMax | 1 |

### Taint

Agent inputs are labeled trusted (principal utterance, first-party data) or untrusted (tool output, retrieved content, other agents). The causal lineage is carried in the PCActn (`provenance`) and its taint level feeds `r`, so untrusted content cannot be laundered into a high-authority action without raising the required threshold. In this release the taint level is an input to `r` (the agent's claimed value is used only as a default; a resource-server-supplied `risk.taint` wins). The separate `taint_gate` check reports `not-enforced`.

## Threshold map

`requiredThreshold(r, policy, { irreversible })`:

| Risk | `t` | Proof | Meaning |
|---|---|---|---|
| `r <= θ₁` | 1 | `claim` | Agent plus auto-guardian. Optimistic path allowed unless irreversible. |
| `θ₁ < r <= θ₂` | 2 | `standard` | A second factor: the guardian co-signature. |
| `r > θ₂` | 3 | `strong` | Requires the principal-device share: a human. |

`escalateThreshold` only ever raises a threshold and keeps it coherent (optimistic is never allowed at `t > 1`). How `t` is satisfied is in [Threshold and step-up](./threshold-and-step-up.md).

## The trust budget

State per `(principal, agent, grant)`: a budget `B` in `[0, bMax]` and the last human-touch time `τ`.

| Operation | Function | Effect |
|---|---|---|
| Passive leak | `leak(b, now, lambda)` | `B ← max(0, B − λ·Δt)`; idempotent at the same `now` |
| Per-action debit | `debit(b, cost(r, kappa))` | `B ← B − κ·r` |
| Recharge | `recharge(b, rho, bMax, now)` | `B ← min(bMax, B + ρ)`, `τ ← now`. **The only way budget increases.** |
| Full re-confirmation | `rechargeFull(b, bMax, now)` | `B ← bMax` |

Admission: `admit(r, budget, policy)` auto-admits iff `t == 1` **and** `B >= κ·r`. A depleted budget on a low-risk action forces `t = 3`: the agent must check in with the human. Recharge is human-sourced only; the battery has no self-charge. On the hosted surface a principal co-signature triggers `recharge`.

### Safety bound

`safetyBound(policy)` returns `bMax / κ`.

> Between two consecutive human recharges, the total risk of auto-admitted actions satisfies **Σ rᵢ ≤ bMax / κ**, regardless of what the agent does, even if fully compromised.

Proof sketch. Let `B₀ ≤ bMax` be the budget right after a recharge. Auto-admitting action `i` requires `Bᵢ ≥ cᵢ = κ·rᵢ` and sets `Bᵢ₊₁ = Bᵢ − cᵢ ≥ 0`. Leak only lowers `B` further and nothing but a human recharge raises it. Telescoping, `Σ cᵢ ≤ B₀ − B_last ≤ bMax`, so `κ·Σ rᵢ ≤ bMax`.

You can therefore choose `bMax/κ` to bound blast radius per human checkpoint a priori. This holds only while the verifier computes `r` itself or from inputs it vouches for; an agent that can understate its own risk claim defeats it, which is why the hosted surface derives risk server-side and lets the agent's claim only make things worse (see [Trust model](../security/trust-model.md)).

### Multi-agent budget algebra

`subBudget(parent, alloc)` allocates `B_sub ≤ parent.B`. `debitConsolidated(parent, sub, c)` debits both, so a swarm of sub-agents cannot collectively exceed the parent's remaining budget: the capability chain is the budget tree. It fails without state change if either side cannot cover the cost.

## How the hosted surface derives risk

The agent's own `risk_claim` is untrusted. The hosted `/v1/pca/actions` starts from a server-side baseline and lets the claim only raise risk:

| Input | Baseline | Claim may |
|---|---|---|
| `semanticDistance` | 0 (the action is in the committed plan) | raise |
| `reversibility` | from the node class: `irreversible` 0, `costly` 0.4, otherwise 1 | lower |
| `blastRadius` | 0.5 | raise |
| `confidence` | 1 | lower |
| `age` | 0 | raise |

With default weights, an ordinary reversible in-plan action scores `r = 0.1` (`t = 1`); an irreversible one scores `0.3` (`t = 2`). A deployment tunes this through the grant's `risk_policy`.

Next: [Threshold and step-up](./threshold-and-step-up.md).
