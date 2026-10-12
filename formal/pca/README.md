# PCA formal models — trust-budget safety & capability attenuation

Machine-checkable TLA+ specifications of two PCA safety properties, with TLC
model-checking configs and **verified results**.

> Note: `PCA.tla`, `PCA.cfg`, `PCA_fix.cfg`, `PCA_race.cfg` in this directory
> pre-date this work and are unrelated to the two models documented here.
> The models added here are `TrustBudget.*` and `Attenuation.*` (+ their `MC_*`).

## What is modelled

### 1. `TrustBudget.tla` — the decaying trust-budget as an admission controller
Formalises **Deep Dive III** of
`docs/specs/agentic-auth-proof-carrying-authority.md` (~lines 520–592) and the
**shipped** `packages/pca/src/risk.ts`. A state machine over discrete actions:
a budget `B`, the cost scale `κ`, a per-tick passive leak `λ`, thresholds
`θ1/θ2`, per-action debit, human-only (rate-limited) recharge, and the `t(r)`
threshold map. The adversary is maximally free: it picks **any** risk level and
the timing of every action and leak, trying to maximise admitted risk between
two human touchpoints.

**Discretisation.** Everything lives on an integer grid of size `GRID`: an
actual risk `r ∈ [0,1]` is the integer `R ∈ 0..GRID` with `r = R/GRID`; budget
`b ∈ [0,bMax]` is `B ∈ 0..Bmax`. Then `c(A) = κ·r(A)` is the integer `Kappa·R`
and the spec's bound `Σ r ≤ bMax/κ` becomes `Kappa · sumRisk ≤ Bmax`.

Invariants checked:

| Invariant | Meaning | Spec / `risk.ts` origin |
|---|---|---|
| `SafetyInvariant` = `Kappa*sumRisk ≤ Bmax` | **The crown.** Between two consecutive human recharges the risk-weighted autonomous blast radius is bounded a priori by `bMax/κ`, even adversarially. | Safety invariant `Σc(Aᵢ) ≤ B_available ≤ Bmax ⇒ Σr(Aᵢ) ≤ Bmax/κ` (spec lines 561–567); `safetyBound()` |
| `BudgetBounds` = `0 ≤ B ≤ Bmax` | Budget never goes negative on the auto path; a recharge never exceeds `Bmax`. | `debit` floor at 0; `recharge` = `min(Bmax, B+ρ)`; anti-windup cap |
| `MeteredImpliesCovered` | A metered (debited) machine action was admitted only with `B ≥ c(A)`. | `admit()` gate `t<3 ∧ B≥c` |
| `DepletionForcesHuman` | A depleted budget forces a human touch **even for a low-risk action**. | spec lines 558–559; `admit()` `B<c ⇒ {admit:false, t:3}` |

Construct → source mapping: `ReqT` ↔ `requiredThreshold`; `Cost` ↔ `cost`;
`Tick` ↔ `leak`; `MachineAction` metered branch ↔ `admit`+`debit`;
`RechargeHuman` ↔ `recharge`; `RechargeFull` ↔ `rechargeFull`; `cooldown` ↔ the
anti-windup "rate-limit recharges" note.

### 2. `Attenuation.tla` — monotone capability attenuation over a caveat lattice
Formalises spec §5.2 and the **shipped** `verifyChain` in
`packages/pca/src/capability.ts` (with caveat families from
`packages/pca/src/predicates.ts`). `verifyChain` enforces *structural*
attenuation: a child's caveat list must contain the parent's as an **exact
prefix** and may only **append** conjunctive caveats. The model builds chains by
exactly that append-only construction and derives each hop's **effective
authority** `Eff` as the set of concrete actions satisfying every caveat
(verb-set, resource-set, max-blast/budget cap).

| Invariant | Meaning | Origin |
|---|---|---|
| `Monotone` = `∀ hops: Eff(child) ⊆ Eff(parent)` | **The monotonicity invariant.** Adding caveats only narrows; no hop can widen scope / verb / budget. | §5.2; `verifyChain` prefix-equality + append-only; `attenuate`/`delegate` |
| `WithinRoot` | Every hop stays within the root's authority (transitive form). | §5.2 "the capability chain is the budget tree" |
| `PrefixPreserved` | Every hop keeps its parent's caveats as an exact prefix. | `verifyChain` lines 186–193 (drop/alter/reorder rejected) |

The `max_blast` caveat (`cap` can only decrease across hops) is the formal image
of the multi-agent budget algebra `B_sub ≤ B_parent_remaining` (`subBudget`).

**Negative control.** `MC_Attenuation_widen.cfg` sets `AllowWiden = TRUE`, which
enables an *illegal* `Widen` hop that drops a parent caveat (what `verifyChain`
rejects). TLC then **finds a counterexample**, proving the invariant is
non-vacuous: without the prefix rule a child can out-scope its parent.

## How to run

Requires a JVM (11+) and `tla2tools.jar` (TLC). This box has no `tlc` on PATH;
fetch the jar once:

```sh
curl -L -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
```

From `formal/pca/` (use a real JDK, e.g. `/opt/homebrew/opt/openjdk@17`):

```sh
JAR=./tla2tools.jar
# trust-budget safety (should HOLD)
java -cp $JAR tlc2.TLC -config MC_TrustBudget.cfg    -workers auto MC_TrustBudget
java -cp $JAR tlc2.TLC -config MC_TrustBudget_k2.cfg -workers auto MC_TrustBudget   # κ=2 variant
# attenuation monotonicity (should HOLD)
java -cp $JAR tlc2.TLC -config MC_Attenuation.cfg       -workers auto MC_Attenuation
# negative control (MUST fail with a counterexample)
java -cp $JAR tlc2.TLC -config MC_Attenuation_widen.cfg -workers 1    MC_Attenuation
```

## Verified results (TLC 2026.10.06, JDK 17, this box, 2026-10-07)

| Config | Bounds | Result | State space |
|---|---|---|---|
| `MC_TrustBudget.cfg` | GRID=6, Bmax=6, κ=1, θ1=2, θ2=4, λ=1, ρ=3 | **No error — all invariants HOLD** | 533 distinct states, 4723 generated, diameter 9 |
| `MC_TrustBudget_k2.cfg` | GRID=4, Bmax=8, κ=2, θ1=1, θ2=3, λ=1, ρ=4 | **No error — all invariants HOLD** | 352 distinct states, 2425 generated, diameter 10 |
| `MC_Attenuation.cfg` | 2 verbs, 2 resources, blast 0..2, depth ≤4, AllowWiden=FALSE | **No error — Monotone / WithinRoot / PrefixPreserved HOLD** | 820 distinct states, 1640 generated, diameter 4 |
| `MC_Attenuation_widen.cfg` | same, AllowWiden=TRUE | **Invariant VIOLATED (expected)** — counterexample below | violation at depth 3 |

Negative-control counterexample (exactly as intended):

```
State 1:  chain = <<  <<>>  >>                                        (root, no caveats)
State 2:  chain = <<  <<>>, <<[type|->"verb_in", set|->{v1}]>>  >>    (legal attenuate: verb ⊆ {v1})
State 3:  chain = <<  <<>>, <<[type|->"verb_in", set|->{v1}]>>, <<>>  >>  (ILLEGAL widen: caveat dropped)
```

`Eff(State3 hop3)` = all actions ⊋ `Eff(hop2)` = verb-`v1` actions only — the
child out-scoped its parent, violating `Monotone`/`PrefixPreserved`. This is the
widening that `verifyChain`'s prefix-equality check (capability.ts:186–193)
rejects, so it cannot occur on the shipped path (confirmed by the positive run).

## Interpretation

Both PCA safety properties **hold** on the shipped model, model-checked
exhaustively over the stated finite bounds against a maximally adversarial agent:

- The trust-budget gives a provable a-priori bound on risk-weighted autonomous
  blast radius per human checkpoint (`Σr ≤ bMax/κ`) — confirmed for κ=1 and κ=2.
- Capability attenuation is monotone — a child's authority is always a subset of
  its parent's — and the negative control confirms this is a genuine consequence
  of the append-only/prefix rule, not a modelling artefact.
