/-
  Theorem 3 — PCA Policy-VM operational semantics + refinement to the trust-budget
  admission controller (Theorem 1).

  This module closes part of the audit gap flagged in `formal/refinement/README.md`:
  the two shipped-code artefacts that make the admission DECISION —

    * the risk functional        `packages/pca/src/risk.ts  riskScore`
    * the admission controller    `packages/pca/src/risk.ts  admit` / `requiredThreshold`
      as driven by               `packages/pca/src/policy-vm.ts  decide`

  are modelled here as Lean functions with the SAME control flow, and the decision is
  PROVED to refine the trust-budget state machine already proven safe in
  `PcaProof.TrustBudget` (Theorem 1). Concretely: whenever the VM meters an action
  (the only path that debits the budget, policy-vm.ts `adm.metered ? debit(...)`), the
  resulting `(B, sumRisk)` transition is exactly `TrustBudget.stepMachine`, AND the
  admission gate `cost κ R ≤ B` that `TrustBudget.Reach.machine` demands is DISCHARGED
  by the VM's own `admit` decision — not assumed. Hence a run of VM decisions is a
  `TrustBudget.Reach` trajectory and inherits `trust_budget_safety`.

  As in `TrustBudget.lean` / the TLA grid, every quantity is an integer on a grid of
  size `G`; a risk `r ∈ [0,1]` is `R ∈ 0..G`, weights are integers clamped to ≥ 0
  (risk.ts `wt`), and `cost = κ·R` (reusing `TrustBudget.cost`). No mathlib.

  Source correspondence (risk.ts / policy-vm.ts  ↔  Lean here):
    * risk.ts `riskScore` (clamped weighted sum)         ↔ `riskScore` / `riskRaw`
    * risk.ts `wt(w) = max(0, w)` (weights ≥ 0)           ↔ `Weights.wf`
    * risk.ts monotone-in-raise-only-inputs comment       ↔ `riskScore_mono`
    * policy-vm.ts `r = max(riskScore, rFloor)` + caution  ↔ `applyFloor` (+ its raise/mono lemmas)
    * risk.ts `requiredThreshold` piecewise t(r)           ↔ `tOf` + `tOf_mono`
    * risk.ts `escalateThreshold` (never lowers t)         ↔ `escalateT` + `escalate_ge`
    * risk.ts `admit` (metered machine band t<3, B≥c)      ↔ `admit`
    * policy-vm.ts `adm.metered ? debit(leaked, cost) : …` ↔ `VMReach.admitStep` = `stepMachine`
    * the admission gate `B ≥ c`                           ↔ `admit_metered_gate`
    * capability.ts leaf caveats = grant ++ delegated      ↔ `vm_leaf_within_grant` (links Theorem 2)
-/
import PcaProof.TrustBudget
import PcaProof.Attenuation

namespace PcaProof.PolicyVM

open PcaProof.TrustBudget (St cost stepMachine stepLeak Reach trust_budget_safety
  trust_budget_safety_div reach_budget_nonneg)

/- ------------------------------------------------------------------------- -/
/-  The risk functional (risk.ts `riskScore`) and its monotonicity            -/
/- ------------------------------------------------------------------------- -/

/-- Risk inputs on the integer grid, each ALREADY in its RISK-INCREASING orientation:
    reversibility and confidence enter as their complements (`oneMinusRev`,
    `oneMinusConf`), exactly as risk.ts uses `(1 − rev)` and `(1 − conf)`. So EVERY
    component is a "raise-only" input: larger ⇒ not-less risk. -/
structure RiskInputs where
  semanticDistance : Int
  oneMinusRev : Int
  blastRadius : Int
  taint : Int
  oneMinusConf : Int
  age : Int
deriving Repr

/-- Policy weights (risk.ts `RiskWeights`). -/
structure Weights where
  alpha : Int
  beta : Int
  gamma : Int
  delta : Int
  epsilon : Int
  zeta : Int
deriving Repr

/-- Well-formed weights: each ≥ 0. This is exactly risk.ts `wt(x) = (x > 0 ? x : 0)`,
    the clamp that MAKES risk monotone for any policy. -/
def Weights.wf (w : Weights) : Prop :=
  0 ≤ w.alpha ∧ 0 ≤ w.beta ∧ 0 ≤ w.gamma ∧ 0 ≤ w.delta ∧ 0 ≤ w.epsilon ∧ 0 ≤ w.zeta

/-- Clamp to `[lo, hi]` (risk.ts `clamp01`, here on the grid `[0, G]`). -/
def clamp (lo hi x : Int) : Int := max lo (min hi x)

/-- The raw weighted sum, risk.ts `riskScore` before the final clamp. -/
def riskRaw (w : Weights) (i : RiskInputs) : Int :=
  w.alpha * i.semanticDistance + w.beta * i.oneMinusRev + w.gamma * i.blastRadius
    + w.delta * i.taint + w.epsilon * i.oneMinusConf + w.zeta * i.age

/-- risk.ts `riskScore`: the weighted sum clamped to the grid `[0, G]`. -/
def riskScore (G : Int) (w : Weights) (i : RiskInputs) : Int :=
  clamp 0 G (riskRaw w i)

/-- Componentwise "no input decreased" ordering on risk inputs. -/
def RiskInputs.le (a b : RiskInputs) : Prop :=
  a.semanticDistance ≤ b.semanticDistance ∧ a.oneMinusRev ≤ b.oneMinusRev ∧
  a.blastRadius ≤ b.blastRadius ∧ a.taint ≤ b.taint ∧ a.oneMinusConf ≤ b.oneMinusConf ∧
  a.age ≤ b.age

/-- Clamp is monotone. -/
theorem clamp_mono (lo hi : Int) {x y : Int} (h : x ≤ y) : clamp lo hi x ≤ clamp lo hi y := by
  simp only [clamp]; omega

/-- The raw weighted sum is monotone in every raise-only input (weights ≥ 0). -/
theorem riskRaw_mono (w : Weights) (hw : w.wf) {a b : RiskInputs} (hab : a.le b) :
    riskRaw w a ≤ riskRaw w b := by
  obtain ⟨ha, hb, hc, hd, he, hf⟩ := hw
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := hab
  have e1 := Int.mul_le_mul_of_nonneg_left h1 ha
  have e2 := Int.mul_le_mul_of_nonneg_left h2 hb
  have e3 := Int.mul_le_mul_of_nonneg_left h3 hc
  have e4 := Int.mul_le_mul_of_nonneg_left h4 hd
  have e5 := Int.mul_le_mul_of_nonneg_left h5 he
  have e6 := Int.mul_le_mul_of_nonneg_left h6 hf
  simp only [riskRaw]
  omega

/-- **Theorem 3a — RISK IS MONOTONE in the raise-only inputs.** Increasing semantic
    distance / blast radius / taint / age, or decreasing reversibility / confidence
    (which raise `oneMinusRev` / `oneMinusConf`), can only RAISE the server risk — for
    ANY well-formed policy. This is the risk.ts invariant the whole admission ladder
    rests on. -/
theorem riskScore_mono (G : Int) (w : Weights) (hw : w.wf) {a b : RiskInputs} (hab : a.le b) :
    riskScore G w a ≤ riskScore G w b :=
  clamp_mono 0 G (riskRaw_mono w hw hab)

/- ------------------------------------------------------------------------- -/
/-  The monotone raise-only "caution / rFloor" (policy-vm.ts `r = max(r, rFloor)`) -/
/- ------------------------------------------------------------------------- -/

/-- policy-vm.ts `r = Math.max(riskScore, rFloor)` and the signed `caution` slot: a
    signed floor can only RAISE the risk, never lower it. -/
def applyFloor (serverR floor : Int) : Int := max serverR floor

/-- The floor can only RAISE risk: `serverR ≤ max(serverR, floor)`. -/
theorem applyFloor_raises (serverR floor : Int) : serverR ≤ applyFloor serverR floor := by
  simp only [applyFloor]; omega

/-- A higher floor yields not-lower risk (monotone in the raise-only `caution`/`rFloor`). -/
theorem applyFloor_mono_floor (serverR : Int) {f f' : Int} (h : f ≤ f') :
    applyFloor serverR f ≤ applyFloor serverR f' := by
  simp only [applyFloor]; omega

/- ------------------------------------------------------------------------- -/
/-  The threshold ladder (risk.ts `requiredThreshold`, `escalateThreshold`)    -/
/- ------------------------------------------------------------------------- -/

/-- risk.ts `requiredThreshold`: the piecewise `t(r)` map. `r ≤ θ1 → 1`, `r ≤ θ2 → 2`,
    else `3`. -/
def tOf (θ1 θ2 R : Int) : Int := if R ≤ θ1 then 1 else if R ≤ θ2 then 2 else 3

/-- **Theorem 3b — the required threshold is MONOTONE in risk.** Higher risk can only
    demand an equal-or-stronger threshold (risk.ts `requiredThreshold` is non-decreasing
    in `r`), so raising risk never WEAKENS the proof obligation. -/
theorem tOf_mono (θ1 θ2 : Int) (h12 : θ1 ≤ θ2) {R R' : Int} (h : R ≤ R') :
    tOf θ1 θ2 R ≤ tOf θ1 θ2 R' := by
  simp only [tOf]
  by_cases hR1 : R ≤ θ1 <;> by_cases hR2 : R ≤ θ2 <;>
    by_cases hR1' : R' ≤ θ1 <;> by_cases hR2' : R' ≤ θ2 <;>
    simp_all <;> omega

/-- risk.ts `escalateThreshold`: raise a required threshold to at least `minT`
    (`t = max(minT, rt.t)`). -/
def escalateT (t minT : Int) : Int := max t minT

/-- **Theorem 3b' — escalation never LOWERS the threshold.** -/
theorem escalate_ge (t minT : Int) : t ≤ escalateT t minT := by
  simp only [escalateT]; omega

/-- Escalation is monotone in the budget-driven floor `minT`. -/
theorem escalate_mono_minT (t : Int) {m m' : Int} (h : m ≤ m') :
    escalateT t m ≤ escalateT t m' := by
  simp only [escalateT]; omega

/- ------------------------------------------------------------------------- -/
/-  The admission controller (risk.ts `admit`) and its refinement to Theorem 1 -/
/- ------------------------------------------------------------------------- -/

/-- The decision `admit` returns (risk.ts `Admission`). `metered` is the ONLY flag that
    causes a budget debit (policy-vm.ts `adm.metered ? debit : leaked`). -/
structure AdmOut where
  admit : Bool
  needStepUp : Bool
  metered : Bool
  t : Int
deriving Repr, DecidableEq

/-- risk.ts `admit`, verbatim control flow:
      * `t<3 ∧ ¬(B ≥ c)`  → budget cannot cover ⇒ human step-up, t=3, NOT metered
      * `t=1`             → auto-admit, metered
      * `t=2`             → guardian auto-cosign, NOT auto-admit but metered
      * else (`t=3`)      → human step-up, NOT metered
    `c = cost κ R = κ·R`. -/
def admit (κ θ1 θ2 R B : Int) : AdmOut :=
  if tOf θ1 θ2 R < 3 ∧ ¬ (cost κ R ≤ B) then
    { admit := false, needStepUp := true, metered := false, t := 3 }
  else if tOf θ1 θ2 R = 1 then
    { admit := true, needStepUp := false, metered := true, t := 1 }
  else if tOf θ1 θ2 R = 2 then
    { admit := false, needStepUp := true, metered := true, t := 2 }
  else
    { admit := false, needStepUp := true, metered := false, t := 3 }

/-- **Theorem 3c — the admission gate is DISCHARGED by the decision.** Whenever the VM
    meters an action (the only budget-debiting path), the admission gate `cost κ R ≤ B`
    holds — because the metered band is exactly `t ∈ {1,2}` reached only when the budget
    covers the cost. This is the premise `TrustBudget.Reach.machine` demands, now a
    THEOREM about the decision rather than an assumption. -/
theorem admit_metered_gate (κ θ1 θ2 R B : Int) (h : (admit κ θ1 θ2 R B).metered = true) :
    cost κ R ≤ B := by
  unfold admit at h
  split at h
  next h1 => simp at h
  next h1 =>
    split at h
    next h2 => omega
    next h2 =>
      split at h
      next h3 => omega
      next h3 => simp at h

/-- The VM only step-ups to a HUMAN (`t=3`, not metered) when the budget cannot cover
    a would-be machine action — i.e. a depleted budget forces a human touch even for a
    low-risk action (risk.ts `admit`: `t<3 ∧ B<c ⇒ {admit:false, t:3}`). -/
theorem admit_depleted_forces_human (κ θ1 θ2 R B : Int)
    (hlow : tOf θ1 θ2 R < 3) (hbroke : ¬ (cost κ R ≤ B)) :
    (admit κ θ1 θ2 R B).t = 3 ∧ (admit κ θ1 θ2 R B).metered = false := by
  unfold admit
  split
  · exact ⟨rfl, rfl⟩
  · next h => exact absurd ⟨hlow, hbroke⟩ h

/-- One-checkpoint reachability UNDER THE POLICY-VM DECISION. Identical shape to
    `TrustBudget.Reach`, except the machine step's admission gate is NOT assumed: it is
    produced by the VM's own `admit` decision metering the action. Leaks as in Theorem 1.
    `admitStep` folds in the budget effect policy-vm.ts applies: a metered action debits
    `cost κ R` and accrues `R`, i.e. `TrustBudget.stepMachine`. -/
inductive VMReach (κ θ1 θ2 : Int) (init : St) : St → Prop where
  | refl : VMReach κ θ1 θ2 init init
  | admitStep {u : St} (R : Int) (hR : 0 ≤ R)
      (hmet : (admit κ θ1 θ2 R u.B).metered = true) :
      VMReach κ θ1 θ2 init u → VMReach κ θ1 θ2 init (stepMachine κ R u)
  | leak {u : St} (L : Int) (hL : 0 ≤ L) :
      VMReach κ θ1 θ2 init u → VMReach κ θ1 θ2 init (stepLeak L u)

/-- **Theorem 3 — THE REFINEMENT.** Every Policy-VM trajectory is a trust-budget
    trajectory: `VMReach ⊆ Reach`. The metered machine step refines `stepMachine` and
    its gate is discharged by `admit_metered_gate`; the leak step is identical. -/
theorem vmreach_to_reach {κ θ1 θ2 : Int} {init s : St}
    (h : VMReach κ θ1 θ2 init s) : Reach κ init s := by
  induction h with
  | refl => exact Reach.refl
  | admitStep R hR hmet _ ih =>
      exact Reach.machine R hR (admit_metered_gate κ θ1 θ2 R _ hmet) ih
  | leak L hL _ ih => exact Reach.leak L hL ih

/-- **Theorem 3 — the crown, inherited.** The trust-budget bound `κ·sumRisk ≤ bMax`
    holds for the admission controller AS THE POLICY VM DECIDES IT — the DECISION is
    proven safe, not merely a separate abstract machine. (Composes `vmreach_to_reach`
    with Theorem 1 `trust_budget_safety`.) -/
theorem vm_trust_budget_safety {κ bMax θ1 θ2 : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : VMReach κ θ1 θ2 init s) : κ * s.sumRisk ≤ bMax :=
  trust_budget_safety hInitB hInitBmax hInitS (vmreach_to_reach h)

/-- **Theorem 3 — risk-sum form, inherited.** `sumRisk ≤ bMax / κ` for the VM decision. -/
theorem vm_trust_budget_safety_div {κ bMax θ1 θ2 : Int} {init s : St}
    (hκ : 0 < κ)
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : VMReach κ θ1 θ2 init s) : s.sumRisk ≤ bMax / κ :=
  trust_budget_safety_div hκ hInitB hInitBmax hInitS (vmreach_to_reach h)

/-- **Theorem 3 — budget never negative under the VM decision**, inherited from Theorem 1. -/
theorem vm_budget_nonneg {κ θ1 θ2 : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitS : 0 ≤ init.sumRisk)
    (h : VMReach κ θ1 θ2 init s) : 0 ≤ s.B :=
  reach_budget_nonneg hInitB hInitS (vmreach_to_reach h)

/- ------------------------------------------------------------------------- -/
/-  Link to Theorem 2: the VM's delegated-caveat evaluation refines attenuation -/
/- ------------------------------------------------------------------------- -/

open PcaProof.Attenuation (Caveat Eff EffSub eff_antitone_append)

/-- **Theorem 3 ↔ Theorem 2 link.** The Policy VM evaluates the leaf hop as the grant's
    caveats with the delegated extension APPENDED (policy-vm.ts:
    `extra = chain[last].caveats.slice(grant.caveats.length)`, then BOTH the grant's
    caveats and `extra` are conjoined — decide's `cv.ok ∧ dcv.ok`). So the authority the
    VM actually enforces at the leaf is a SUBSET of the grant's: the decision refines the
    attenuation monotonicity of Theorem 2. -/
theorem vm_leaf_within_grant (grant extra : List Caveat) :
    EffSub (grant ++ extra) grant :=
  eff_antitone_append grant extra

end PcaProof.PolicyVM
