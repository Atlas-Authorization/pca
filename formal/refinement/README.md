# PCA refinement — linking the spec-level proofs to the shipped decision/verify logic

This directory documents the **refinement layer** added on top of the two existing
mechanized PCA results:

- the TLA+ models in `formal/pca/*.tla` (TLC model-checked, finite bounds), and
- the Lean 4 proofs in `formal/pca-lean/` (deductive, all states/levels/lengths).

It explains exactly **what is now proven**, **how it links to the shipped TypeScript
decision/verify logic**, and — rigorously and without overclaiming — **the one gap that
Lean cannot close** and how the differential-conformance suite bridges it.

---

## 1. The audit finding this addresses

> Today it is "convergence-by-fuzzing" across implementations plus two **isolated**
> invariants (trust-budget safety, attenuation monotonicity). There is **no mechanized
> link** between the proofs and the semantics of the code that actually makes the
> decision (`risk.ts` / `policy-vm.ts`) and verifies the action (`pcactn.ts`).

Before this work the Lean proofs modelled two *properties* (`PcaProof.TrustBudget`,
`PcaProof.Attenuation`) as standalone state machines. Nothing connected them to the
*shape of the decision the code computes*: the 8-check verifier pipeline, the risk
functional, and the admission controller.

## 2. What is now mechanized (Lean, `lake build`-verified, 0 `sorry`)

Two new self-contained Lean modules formalize the shipped decision/verify logic **as an
operational semantics** and prove the safety properties as theorems **of that
semantics** — including that it **refines** the two already-proven theorems.

- `formal/pca-lean/PcaProof/PolicyVM.lean` — Theorem 3: the risk functional
  (`risk.ts riskScore`) + the admission controller (`risk.ts admit` /
  `requiredThreshold` / `escalateThreshold`, as driven by `policy-vm.ts decide`),
  **refined to** `PcaProof.TrustBudget` (Theorem 1) and linked to
  `PcaProof.Attenuation` (Theorem 2).
- `formal/pca-lean/PcaProof/Verifier.lean` — Theorem 4: a small-step operational
  semantics of the verifier's check pipeline (`pcactn.ts verifyPCActnCore`) and its
  decision function `allow = !values.includes('fail')`, with the soundness /
  fail-closed / monotonicity theorems.

### 2.1 Theorem 3 — Policy-VM semantics and admission refinement (`PolicyVM.lean`)

Risk, threshold, and admission are modelled on the same integer grid the TLA+ model
uses. Every statement below is proved; the verbatim Lean signatures:

```lean
-- Risk functional: monotone in every raise-only input (for any well-formed policy).
theorem clamp_mono (lo hi : Int) {x y : Int} (h : x ≤ y) : clamp lo hi x ≤ clamp lo hi y
theorem riskRaw_mono (w : Weights) (hw : w.wf) {a b : RiskInputs} (hab : a.le b) :
    riskRaw w a ≤ riskRaw w b
theorem riskScore_mono (G : Int) (w : Weights) (hw : w.wf) {a b : RiskInputs} (hab : a.le b) :
    riskScore G w a ≤ riskScore G w b

-- The signed caution / rFloor can only RAISE risk, and does so monotonically.
theorem applyFloor_raises (serverR floor : Int) : serverR ≤ applyFloor serverR floor
theorem applyFloor_mono_floor (serverR : Int) {f f' : Int} (h : f ≤ f') :
    applyFloor serverR f ≤ applyFloor serverR f'

-- The required threshold is monotone in risk; escalation never lowers it.
theorem tOf_mono (θ1 θ2 : Int) (h12 : θ1 ≤ θ2) {R R' : Int} (h : R ≤ R') :
    tOf θ1 θ2 R ≤ tOf θ1 θ2 R'
theorem escalate_ge (t minT : Int) : t ≤ escalateT t minT
theorem escalate_mono_minT (t : Int) {m m' : Int} (h : m ≤ m') : escalateT t m ≤ escalateT t m'

-- The admission gate is DISCHARGED by the decision (metering ⇒ budget covers cost).
theorem admit_metered_gate (κ θ1 θ2 R B : Int) (h : (admit κ θ1 θ2 R B).metered = true) :
    cost κ R ≤ B
theorem admit_depleted_forces_human (κ θ1 θ2 R B : Int)
    (hlow : tOf θ1 θ2 R < 3) (hbroke : ¬ (cost κ R ≤ B)) :
    (admit κ θ1 θ2 R B).t = 3 ∧ (admit κ θ1 θ2 R B).metered = false

-- THE REFINEMENT: every Policy-VM trajectory is a trust-budget trajectory…
theorem vmreach_to_reach {κ θ1 θ2 : Int} {init s : St}
    (h : VMReach κ θ1 θ2 init s) : Reach κ init s

-- …so the admission DECISION inherits Theorem 1's crown and non-negativity.
theorem vm_trust_budget_safety {κ bMax θ1 θ2 : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : VMReach κ θ1 θ2 init s) : κ * s.sumRisk ≤ bMax
theorem vm_trust_budget_safety_div {κ bMax θ1 θ2 : Int} {init s : St}
    (hκ : 0 < κ)
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : VMReach κ θ1 θ2 init s) : s.sumRisk ≤ bMax / κ
theorem vm_budget_nonneg {κ θ1 θ2 : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitS : 0 ≤ init.sumRisk)
    (h : VMReach κ θ1 θ2 init s) : 0 ≤ s.B

-- LINK TO THEOREM 2: the VM's leaf-caveat evaluation (grant ++ delegated) narrows authority.
theorem vm_leaf_within_grant (grant extra : List Caveat) : EffSub (grant ++ extra) grant
```

The crux is `vmreach_to_reach`: the VM's metered machine step (the only budget-debiting
path, `policy-vm.ts`: `release && adm.metered ? debit(leaked, cost(r,κ)) : leaked`) is
*exactly* `TrustBudget.stepMachine κ R`, and the admission gate `cost κ R ≤ B` that
`Reach.machine` requires is **not assumed** — it is produced by the VM's own `admit`
decision via `admit_metered_gate`. Therefore the decision is proven safe, not merely a
separate abstract machine that happens to be safe.

### 2.2 Theorem 4 — verifier pipeline semantics (`Verifier.lean`)

The verifier runs an ordered pipeline of named checks, each reporting
`pass | fail | not-enforced`, then decides `allow = !values.includes('fail')`. Both the
**denotational** decision (`Allows` / `allowsB`) and a **small-step** semantics (`Step` /
`Steps`, with `wire` terminal on failure) are modelled, and proven to agree.

```lean
-- Decision function; Bool/Prop forms agree.
def Allows (cs : List Check) : Prop := ∀ c ∈ cs, c.status ≠ CheckStatus.fail
theorem allowsB_true_iff (cs : List Check) : allowsB cs = true ↔ Allows cs

-- SOUNDNESS OF THE CHECK ORDER: allow ⇒ every required (always-evaluated) check PASSED.
theorem allow_no_fail {cs : List Check} (h : Allows cs) :
    ∀ c ∈ cs, c.status = CheckStatus.pass ∨ c.status = CheckStatus.notEnforced
theorem allow_required_pass {cs : List Check} (h : Allows cs)
    {c : Check} (hc : c ∈ cs) (hreq : c.status ≠ CheckStatus.notEnforced) :
    c.status = CheckStatus.pass

-- MONOTONE / FAIL-CLOSED: adding checks anywhere can never turn a DENY into an ALLOW.
theorem fail_denies {cs : List Check} {c : Check}
    (hc : c ∈ cs) (hf : c.status = CheckStatus.fail) : ¬ Allows cs
theorem deny_stable_append {cs extra : List Check} (h : ¬ Allows cs) : ¬ Allows (cs ++ extra)
theorem deny_stable_insert {pre cs post : List Check} (h : ¬ Allows cs) :
    ¬ Allows (pre ++ cs ++ post)
theorem append_fail_denies (cs : List Check) (n : String) :
    ¬ Allows (cs ++ [⟨n, CheckStatus.fail⟩])
theorem allow_antitone_worsen {pre post : List Check} {c c' : Check}
    (hworse : c'.status = CheckStatus.fail)
    (h : Allows (pre ++ c' :: post)) : Allows (pre ++ c :: post)

-- OPERATIONAL ⇔ DENOTATIONAL: the small-step run's verdict equals the decision function.
theorem steps_advance_all (done cs : List Check)
    (hno : ∀ c ∈ cs, ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail)) :
    Steps ⟨done, cs⟩ ⟨done ++ cs, []⟩
theorem steps_wire_fail (done rest : List Check) {c : Check}
    (hw : c.name = "wire") (hf : c.status = CheckStatus.fail) :
    Steps ⟨done, c :: rest⟩ ⟨done ++ [c], []⟩
theorem run_no_wirefail (cs : List Check)
    (hno : ∀ c ∈ cs, ¬ (c.name = "wire" ∧ c.status = CheckStatus.fail)) :
    ∃ done, Steps ⟨[], cs⟩ ⟨done, []⟩ ∧ allowsB done = allowsB cs
theorem run_wirefail_head (rest : List Check) {c : Check}
    (hw : c.name = "wire") (hf : c.status = CheckStatus.fail) :
    ∃ done, Steps ⟨[], c :: rest⟩ ⟨done, []⟩
      ∧ allowsB done = false ∧ allowsB (c :: rest) = false
```

`allow_required_pass` is the formal reading of the NORMATIVE CHECK ORDER's intent: a
reported allow can never have skipped a mandatory check. The `deny_stable_*` family is
fail-closure as a lattice-monotonicity statement: worsening any check (toward `fail`), or
adding failing checks anywhere, can only move the verdict allow → deny.

### 2.3 Model ↔ code correspondence

| Lean symbol | Shipped code (file · function) |
|---|---|
| `PolicyVM.riskScore` / `riskRaw` / `clamp` | `packages/pca/src/risk.ts` · `riskScore` (clamped weighted sum) |
| `PolicyVM.Weights.wf` | `risk.ts` · `wt(x) = (x>0 ? x : 0)` (weights ≥ 0) |
| `PolicyVM.applyFloor` | `policy-vm.ts` · `r = Math.max(riskScore, rFloor)` + signed `caution` |
| `PolicyVM.tOf` / `tOf_mono` | `risk.ts` · `requiredThreshold` piecewise `t(r)` |
| `PolicyVM.escalateT` / `escalate_ge` | `risk.ts` · `escalateThreshold` (`t = max(minT, rt.t)`) |
| `PolicyVM.admit` | `risk.ts` · `admit` (metered band `t<3 ∧ B≥c`, then `debit`) |
| `PolicyVM.VMReach.admitStep` = `stepMachine` | `policy-vm.ts` · `adm.metered ? debit(leaked, cost(r,κ)) : leaked` |
| `PolicyVM.vm_leaf_within_grant` | `policy-vm.ts` · `extra = chain[last].caveats.slice(grant.caveats.length)`; `capability.ts verifyChain` prefix rule |
| `Verifier.CheckStatus` | `pcactn.ts` · `type CheckStatus = 'pass'|'fail'|'not-enforced'` |
| `Verifier.checkOrder` | `pcactn.ts` · the NORMATIVE CHECK ORDER comment block |
| `Verifier.requiredChecks` | `pcactn.ts` · the always-evaluated M0 core (vs. `not-enforced` hooks) |
| `Verifier.Allows` / `allowsB` | `pcactn.ts` · `allow = !Object.values(checks).includes('fail')` |
| `Verifier.Step.wireFail` | `pcactn.ts` · "A wire failure is terminal: nothing else is evaluated" |

## 3. The gap Lean does **not** close (read this part carefully)

> **Lean proves the MODEL is sound. It does not prove that the shipped TypeScript bytes
> implement the model.**

This is a hard, honest boundary, and it must not be overstated:

1. **The Lean functions are hand-written transcriptions, not a mechanical extraction.**
   `PolicyVM.admit`, `PolicyVM.riskScore`, `Verifier.Allows`, the small-step `Step`
   relation, etc. were written by a human to *mirror* `risk.ts` / `policy-vm.ts` /
   `pcactn.ts`. Lean checks that **those Lean definitions** have the stated properties.
   It cannot see the TypeScript. If a transcription is subtly wrong (e.g. a `<` where the
   code has `≤`, a check omitted from `checkOrder`, a branch mis-ordered), Lean will still
   happily prove theorems — about the wrong model.

2. **The integer grid is an abstraction of the code's domain.** `risk.ts` computes over
   IEEE-754 floats in `[0,1]` with `clamp01` and NaN-fails-closed handling; the Lean
   model (like the TLA+ model) works on an integer grid `0..G`. The monotonicity and
   budget-telescoping arguments are faithful on that grid, but the float↔grid gap (and
   float-specific behaviour such as rounding, `-0`, NaN propagation) is **not** modelled.
   The code's NaN/non-finite fail-closed paths are argued informally, not in Lean.

3. **The verifier model abstracts the per-check *verdicts*, not their computation.**
   `Verifier` proves the *decision logic over a list of statuses* is sound and
   fail-closed. It does **not** model how each individual check computes its status
   (signature verification, Merkle inclusion, canonical-JSON parsing, the capability-chain
   prefix check). Those are assumed to deliver a correct `pass`/`fail`/`not-enforced`;
   Lean reasons only about how the pipeline combines them.

Closing that last mile genuinely would require one of:

- **verified extraction / a verified compiler** — compile the Lean (or a shared spec)
  down to the executable, or extract the executable *from* the proof, so the running
  bytes are the proved object (e.g. extraction to a verified runtime). Not done here, and
  a large undertaking for a TypeScript/multi-SDK codebase; **or**
- **a translation validation / equivalence proof** between the TypeScript AST and the
  Lean function. Not done here; **or**
- **the differential-conformance suite as the empirical bridge** — which is what PCA
  actually ships, described next.

## 4. How the conformance suite bridges model ↔ code

`packages/pca/conformance/vectors.json` is a frozen set of **108 golden vectors**
(wire-format v2). Each vector fixes a concrete `grant`, `context (now, aud)`, and a
`pcactn` (or raw JSON), and pins the **expected verdict**: `allow` **and the per-check
`pass`/`fail` map**. The *same file* is executed by the TypeScript reference
(`packages/pca/src/conformance.test.ts`) **and** by every language verifier —
`sdks/{go,rust,python,java,php,ruby,dotnet,swift}-pca` — plus a canonicalization fuzz
corpus (`tools/pca-canon-fuzz/`). CI (`.github/workflows/pca-conformance.yml`) runs all of
them.

This is the bridge, and it is the *complement* of the Lean proof — each covers what the
other cannot:

- **The conformance suite anchors the real code at concrete points.** On 108 fixed
  inputs it observes the *actual* bytes of `verifyPCActnCore` (and 8 independent
  re-implementations) producing an actual `allow` + per-check status map. The Lean
  `Verifier.Allows` / `allowsB` computes its verdict from exactly that per-check status
  map, by exactly the `allow = !values.includes('fail')` rule. So on every vector, the
  decision the code emits is the decision the Lean model scores — the two are checked to
  coincide at 108 points, across 9 implementations ("convergence", but now *pinned to a
  spec'd expectation*, not just to each other).
- **The Lean proof generalizes the decision logic to all inputs.** Where the vectors are
  a finite sample, `allow_required_pass`, `deny_stable_*`, `vm_trust_budget_safety`, and
  `riskScore_mono` hold for *every* status list, risk level, budget, and trajectory — the
  properties a finite vector set can never establish.

**What the bridge still does not give you.** The vectors are finite samples; they do not
prove the code computes the Lean function on *all* inputs, and they test per-check
*outcomes*, not that each check's internal computation matches a spec. A regression that
only manifests outside the 108 vectors, or a float-domain edge the grid does not model,
can still slip through. The honest composite claim is therefore:

> The **decision/verification logic** (how per-check verdicts combine into allow, the
> admission-gate/budget telescoping, risk monotonicity, attenuation) is **proved sound
> for all inputs** on a faithful integer-grid model; the **shipped bytes** are tied to
> that model **empirically**, at 108 pinned points, across 9 implementations. The
> remaining, un-mechanized link between the TypeScript AST and the Lean model is the
> transcription itself — reviewed by hand, not machine-checked.

## 5. How to verify (reproduce everything in this document)

```sh
cd formal/pca-lean
elan toolchain install "$(cat lean-toolchain)"   # once; pins leanprover/lean4:v4.34.1
lake build                                        # builds + checks ALL proofs (Theorems 1–4)
```

A successful `lake build` *is* the proof check — Lean refuses to compile a file with an
unproved goal. To confirm no theorem rests on `sorry`, print the axiom dependencies with
a small checker file (this Lean toolchain's `lean` takes a file, not inline `-e` code):

```sh
cat > /tmp/pca-axioms.lean <<'EOF'
import PcaProof
open PcaProof
#print axioms PolicyVM.vm_trust_budget_safety
#print axioms PolicyVM.admit_metered_gate
#print axioms Verifier.allow_required_pass
#print axioms Verifier.deny_stable_append
#print axioms Verifier.run_no_wirefail
EOF
lake env lean /tmp/pca-axioms.lean
```

All new theorems depend only on Lean's standard trusted axioms — `propext`,
`Quot.sound`, and (for the classical case splits) `Classical.choice` — and **never on
`sorryAx`**. Verified on this box with Lean 4.34.1 (2026-10-07): `lake build` completes
all 7 jobs with **no errors and no warnings**, and the axiom audit for all 27 new
theorems reports only the three standard axioms (several depend on none at all); `grep -r
sorry` over the module sources is empty.

The conformance bridge is reproduced from the repo root:

```sh
scripts/pca-conformance.sh         # runs the TS reference + all 8 SDK verifiers on vectors.json
```
