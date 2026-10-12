/-
  Theorem 1 — PCA trust-budget safety.

  The machine-checked (Lean) image of `formal/pca/TrustBudget.tla`, which TLC has
  already model-checked (see formal/pca/README.md). Where TLC checks the invariant
  `Kappa * sumRisk <= Bmax` over a finite grid against a maximally adversarial
  agent, this file PROVES it for all reachable states, all risk levels, and all
  timings — as a deductive theorem over the integers.

  Source correspondence (TLA+  ↔  risk.ts  ↔  Lean here):
    * TLA `Cost(R) == Kappa * R`                  ↔ risk.ts `cost`        ↔ `cost`
    * TLA `MachineAction` metered branch          ↔ risk.ts `admit`+`debit` ↔ `stepMachine` + the `cost κ R ≤ u.B` gate on `Reach.machine`
    * TLA `Tick` (leak, floors at 0)              ↔ risk.ts `leak`        ↔ `stepLeak`
    * TLA `RechargeHuman` / `RechargeFull`        ↔ risk.ts `recharge`/`rechargeFull` ↔ `recharge` / `rechargeFull`
    * TLA `SafetyInvariant == Kappa*sumRisk ≤ Bmax` ↔ risk.ts `safetyBound` ↔ `trust_budget_safety`
    * TLA `BudgetBounds` (0 ≤ B)                  ↔ debit floor / admit gate ↔ `reach_budget_nonneg`

  Discretisation matches the TLA module: every quantity lives on the integer grid,
  so an action's risk level `R` and the budget `B` are integers and
  `cost = κ·R`. We model budget over `Int` (not `Nat`) so that "budget never goes
  negative" is a genuine theorem rather than a typing artefact.
-/
namespace PcaProof.TrustBudget

/-- Admission-controller state between human touchpoints.
    `B` is the current budget (grid units); `sumRisk` is the risk accrued by
    metered machine actions since the last human recharge. (TLA `VARIABLES B, sumRisk`.) -/
structure St where
  B : Int
  sumRisk : Int
deriving Repr

/-- `c(A) = κ · r(A)`  (risk.ts `cost`, TLA `Cost`). -/
def cost (κ R : Int) : Int := κ * R

/-- The Lyapunov potential `Φ = κ·sumRisk + B`.
    A metered machine action conserves it exactly (debit = κ·R = accrued cost);
    passive leak only lowers it; nothing but a human recharge raises it. This is the
    integer embodiment of the telescoping argument in `risk.ts safetyBound`. -/
def phi (κ : Int) (s : St) : Int := κ * s.sumRisk + s.B

/-- A metered machine action on the admit path (TLA `MachineAction` metered branch,
    risk.ts `admit` with `t<3 ∧ B≥c` then `debit`): debit EXACTLY `κ·R`, accrue `R`.
    The admission gate `cost κ R ≤ u.B` lives on the `Reach.machine` constructor. -/
def stepMachine (κ R : Int) (s : St) : St :=
  { B := s.B - cost κ R, sumRisk := s.sumRisk + R }

/-- Passive leak of `L` grid-units, floored at 0 (TLA `Tick`, risk.ts `leak`:
    `B ← max(0, B − λ·dt)`). Leak is not a human touch, so `sumRisk` is unchanged. -/
def stepLeak (L : Int) (s : St) : St :=
  { s with B := max 0 (s.B - L) }

/-- Human co-sign recharge `B ← min(bMax, B+ρ)`, and `sumRisk ← 0` — the event that
    closes a checkpoint (TLA `RechargeHuman`, risk.ts `recharge`). The ONLY increase of B. -/
def recharge (bMax rho : Int) (s : St) : St :=
  { B := min bMax (s.B + rho), sumRisk := 0 }

/-- Full goal re-confirmation `B ← bMax`, `sumRisk ← 0` (TLA `RechargeFull`, risk.ts `rechargeFull`). -/
def rechargeFull (bMax : Int) (_ : St) : St :=
  { B := bMax, sumRisk := 0 }

/-- One-checkpoint reachability: the states reachable from `init` using ONLY metered
    machine actions (each respecting the admission gate) and passive leaks — i.e. the
    trajectory strictly BETWEEN two consecutive human recharges. `t=3` / forced-human
    actions leave `(B, sumRisk)` unchanged (TLA `MachineAction` OTHER / forced_human
    branches) and so are omitted. The adversary is maximally free: `Reach.machine`
    quantifies over EVERY risk level `R ≥ 0` and the timing of every action and leak. -/
inductive Reach (κ : Int) (init : St) : St → Prop where
  | refl : Reach κ init init
  | machine {u : St} (R : Int) (hR : 0 ≤ R) (hgate : cost κ R ≤ u.B) :
      Reach κ init u → Reach κ init (stepMachine κ R u)
  | leak {u : St} (L : Int) (hL : 0 ≤ L) :
      Reach κ init u → Reach κ init (stepLeak L u)

/-- A metered machine action conserves the potential EXACTLY: `Φ(stepMachine) = Φ`.
    This is the per-step telescoping identity `κ·(s+R) + (B−κ·R) = κ·s + B`. -/
theorem phi_machine_eq (κ R : Int) (s : St) :
    phi κ (stepMachine κ R s) = phi κ s := by
  simp only [phi, stepMachine, cost, Int.mul_add]
  omega

/-- A passive leak never raises the potential: `Φ(stepLeak) ≤ Φ` (given `0 ≤ B`, `0 ≤ L`). -/
theorem phi_leak_le (κ L : Int) (s : St) (hB : 0 ≤ s.B) (hL : 0 ≤ L) :
    phi κ (stepLeak L s) ≤ phi κ s := by
  simp only [phi, stepLeak]
  omega

/-- The core inductive invariant carried along any one-checkpoint trajectory:
      (1) the budget stays non-negative,
      (2) the accrued risk stays non-negative,
      (3) the potential never exceeds its starting value.
    Proved by induction over `Reach`. -/
theorem reach_inv {κ : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitS : 0 ≤ init.sumRisk)
    (h : Reach κ init s) :
    0 ≤ s.B ∧ 0 ≤ s.sumRisk ∧ phi κ s ≤ phi κ init := by
  induction h with
  | refl => exact ⟨hInitB, hInitS, Int.le_refl _⟩
  | @machine u R hR hgate _ ih =>
      obtain ⟨hB, hS, hphi⟩ := ih
      refine ⟨?_, ?_, ?_⟩
      · simp only [stepMachine]; omega        -- 0 ≤ u.B − cost κ R   (gate: cost κ R ≤ u.B)
      · simp only [stepMachine]; omega         -- 0 ≤ u.sumRisk + R
      · rw [phi_machine_eq]; exact hphi         -- Φ conserved
  | @leak u L hL _ ih =>
      obtain ⟨hB, hS, hphi⟩ := ih
      refine ⟨?_, ?_, ?_⟩
      · simp only [stepLeak]; omega             -- 0 ≤ max 0 (u.B − L)
      · simp only [stepLeak]; exact hS          -- sumRisk unchanged
      · exact Int.le_trans (phi_leak_le κ L u hB hL) hphi

/-- **Budget never goes negative on the admit path** (TLA `BudgetBounds`, `0 ≤ B`).
    The admission gate on every metered action (`cost κ R ≤ u.B`) is exactly what
    guarantees the debit `B − κ·R` cannot underflow. -/
theorem reach_budget_nonneg {κ : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitS : 0 ≤ init.sumRisk)
    (h : Reach κ init s) : 0 ≤ s.B :=
  (reach_inv hInitB hInitS h).1

/-- **Theorem 1 — THE CROWN (integer form).** Between two consecutive human recharges,
    for a budget starting at `init.B ≤ bMax` with `sumRisk = 0`, EVERY reachable state
    satisfies `κ · sumRisk ≤ bMax` — whatever risk levels and timing the (possibly
    fully compromised) agent chooses. This is TLA `SafetyInvariant` / risk.ts `safetyBound`. -/
theorem trust_budget_safety {κ bMax : Int} {init s : St}
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : Reach κ init s) :
    κ * s.sumRisk ≤ bMax := by
  have hS0 : 0 ≤ init.sumRisk := by omega
  obtain ⟨hB, _, hphi⟩ := reach_inv hInitB hS0 h
  simp only [phi] at hphi
  rw [hInitS, Int.mul_zero] at hphi
  omega

/-- **Theorem 1 — the crown, risk-sum form `Σ rᵢ ≤ bMax / κ`.** The exact statement of
    the spec bound (and the TLA header comment): the risk-weighted autonomous blast
    radius per human checkpoint is bounded a priori by `bMax/κ`. Here `/` is integer
    (floor) division, so `s.sumRisk ≤ bMax/κ` is the integer-grid reading of `Σr ≤ bMax/κ`. -/
theorem trust_budget_safety_div {κ bMax : Int} {init s : St}
    (hκ : 0 < κ)
    (hInitB : 0 ≤ init.B) (hInitBmax : init.B ≤ bMax) (hInitS : init.sumRisk = 0)
    (h : Reach κ init s) :
    s.sumRisk ≤ bMax / κ := by
  have hcrown : κ * s.sumRisk ≤ bMax := trust_budget_safety hInitB hInitBmax hInitS h
  have hdiv := Int.ediv_le_ediv hκ hcrown
  rwa [Int.mul_ediv_cancel_left s.sumRisk (by omega : κ ≠ 0)] at hdiv

/-- A human recharge CLOSES a checkpoint and re-establishes the precondition of the crown
    (`sumRisk = 0`, `0 ≤ B ≤ bMax`), so the bound holds afresh over the next trajectory.
    This is what makes `trust_budget_safety` a true per-checkpoint invariant of the whole
    system (TLA `RechargeHuman` resets `sumRisk ← 0`; `min` keeps `B ≤ bMax`). -/
theorem recharge_resets {bMax rho : Int} {s : St}
    (hbMax : 0 ≤ bMax) (hrho : 0 ≤ rho) (hB : 0 ≤ s.B) :
    (recharge bMax rho s).sumRisk = 0
      ∧ 0 ≤ (recharge bMax rho s).B
      ∧ (recharge bMax rho s).B ≤ bMax := by
  refine ⟨?_, ?_, ?_⟩
  · simp [recharge]
  · simp only [recharge]; omega
  · simp only [recharge]; omega

end PcaProof.TrustBudget
