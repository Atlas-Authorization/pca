import PcaIntent.VersionSpace

/-!
# P9 (R1, R2, CUSUM): trust ramp

* R1 (ratchet): vetoes only accumulate, and the grant served at step `t` (`base t ∖ vetoed t`) never contains a
  vetoed outcome, whatever the base grants are.
* R2 (freeze): with η = 0 and τ = 1, dropping any runtime observations (in particular positive ones) never
  enlarges `G_1`: `G_1` is anti-monotone in the version space (T2).
* CUSUM: the statistic `S_{t+1} = max(0, S_t + x_t)` is non-negative and the alarm is sticky. (Its average run
  length, Page 1954 / Lorden 1971, is not a formalisation target.)
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω] [DecidableEq Ω]

/-- Vetoes accumulated after `t` steps, `new t` being the outcomes vetoed at step `t`. -/
def vetoedAt (new : ℕ → Finset Ω) : ℕ → Finset Ω
  | 0 => ∅
  | t + 1 => vetoedAt new t ∪ new t

/-- The grant served at step `t`. -/
def grantAt (base new : ℕ → Finset Ω) (t : ℕ) : Finset Ω := base t \ vetoedAt new t

/-- **R1 (ratchet: monotone).** -/
theorem R1_mono (new : ℕ → Finset Ω) : Monotone (vetoedAt new) :=
  monotone_nat_of_le_succ fun t => Finset.subset_union_left

/-- **R1 (ratchet: disjoint).** -/
theorem R1_disjoint (base new : ℕ → Finset Ω) (t : ℕ) : Disjoint (grantAt base new t) (vetoedAt new t) :=
  Finset.sdiff_disjoint

/-- Once vetoed, never granted again. -/
theorem R1_sticky (base new : ℕ → Finset Ω) {s t : ℕ} (hst : s ≤ t) {ω : Ω} (hω : ω ∈ vetoedAt new s) :
    ω ∉ grantAt base new t := by
  intro hg
  have hv : ω ∈ vetoedAt new t := R1_mono new hst hω
  exact (Finset.mem_sdiff.1 hg).2 hv

/-- **R2 (freeze).** Keeping only some of the observations (dropping any runtime observations) never enlarges
the conservative grant. -/
theorem R2_freeze {acc : Θ → Ω → Bool} {H : Finset Θ} {kept obs : List (Ω × Bool)}
    (hsub : ∀ o ∈ kept, o ∈ obs) : G1 acc (VS acc H kept) ⊆ G1 acc (VS acc H obs) :=
  G1_grows hsub

/-- CUSUM statistic. -/
noncomputable def cusum (x : ℕ → ℝ) : ℕ → ℝ
  | 0 => 0
  | t + 1 => max 0 (cusum x t + x t)

/-- Sticky alarm at level `hth`. -/
noncomputable def alarm (x : ℕ → ℝ) (hth : ℝ) : ℕ → Prop
  | 0 => False
  | t + 1 => alarm x hth t ∨ hth ≤ cusum x (t + 1)

theorem cusum_nonneg (x : ℕ → ℝ) : ∀ t, 0 ≤ cusum x t
  | 0 => le_rfl
  | t + 1 => le_max_left _ _

theorem alarm_sticky (x : ℕ → ℝ) (hth : ℝ) {s t : ℕ} (hst : s ≤ t) (h : alarm x hth s) :
    alarm x hth t := by
  induction t with
  | zero =>
      have : s = 0 := Nat.le_zero.1 hst
      subst this; exact h
  | succ t ih =>
      rcases Nat.lt_or_ge s (t + 1) with hlt | hge
      · exact Or.inl (ih (Nat.lt_succ_iff.1 hlt))
      · have : s = t + 1 := le_antisymm hst hge
        subst this; exact h

end PcaIntent
