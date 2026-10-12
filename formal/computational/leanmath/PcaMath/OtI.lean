import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtB
import PcaMath.OtC
import PcaMath.OtD
import PcaMath.OtE
import PcaMath.OtF
import PcaMath.OtG
import PcaMath.OtH
import PcaMath.OtHC

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

theorem fb_zero_closed (r : ℕ) : 2 * fb r 0 = (r : ℝ) * (r + 1) := by
  induction r with
  | zero => simp [fb]
  | succ r ih =>
    unfold fb at ih ⊢
    rw [Finset.sum_range_succ, mul_add, ih]
    push_cast; ring

open Classical in
theorem tcr_one_sided (h2 : ∀ x : D, x + x = 0) (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh) :
    prY A - prX A ≤ (((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) / Fintype.card D
      + fb kh 0 / Fintype.card D := by
  have hN : (0 : ℝ) < Fintype.card D := by exact_mod_cast Fintype.card_pos
  have := OtHC.hcoef (Ω1 := Equiv.Perm D × (V → D)) (Ω2 := Equiv.Perm D × (V × D × D → D))
    (T := List (Qry V D × D) × Bool)
    (fun ω => A.play (oX ω.1 ω.2)) (fun ω => A.play (oY ω.1 ω.2)) BadT
    ((((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) / Fintype.card D) (fb kh 0 / Fintype.card D)
    (by positivity) (hbad_bound A kp kh hA)
    (fun τ hτ hnb => hgood_bound h2 A kp kh hA τ hτ hnb) (fun τ => τ.2 = true)
  unfold prY prX
  linarith

/-- flip the output bit -/
def Adv.neg : Adv V D → Adv V D
  | .done b => .done (!b)
  | .ask q k => .ask q (fun d => (k d).neg)

theorem play_neg (A : Adv V D) (O : Qry V D → D) :
    A.neg.play O = ((A.play O).1, !(A.play O).2) := by
  induction A with
  | done b => simp [Adv.neg, Adv.play]
  | ask q k ih => simp [Adv.neg, Adv.play, ih]

theorem Bdd_neg : ∀ (A : Adv V D) (kp kh : ℕ), A.Bdd kp kh → A.neg.Bdd kp kh := by
  intro A
  induction A with
  | done b => intro _ _ _; simp [Adv.neg, Adv.Bdd]
  | ask q k ih =>
    intro kp kh h
    cases q with
    | P z => exact ⟨h.1, fun d => ih d _ _ (h.2 d)⟩
    | Pi w => exact ⟨h.1, fun d => ih d _ _ (h.2 d)⟩
    | H v x t => exact ⟨h.1, fun d => ih d _ _ (h.2 d)⟩

open Classical in
theorem prX_neg (A : Adv V D) : prX A.neg = 1 - prX A := by
  unfold prX
  have hpos : (0 : ℝ) < Fintype.card (Equiv.Perm D × (V → D)) := by exact_mod_cast Fintype.card_pos
  have := Finset.card_filter_add_card_filter_not (s := (Finset.univ : Finset (Equiv.Perm D × (V → D))))
    (fun ω => (A.play (oX ω.1 ω.2)).2 = true)
  have e : (Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => (A.neg.play (oX ω.1 ω.2)).2 = true)) =
      Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => ¬ (A.play (oX ω.1 ω.2)).2 = true) := by
    apply Finset.filter_congr; intro ω _
    rw [play_neg]; simp
  rw [e]
  rw [Finset.card_univ] at this
  have : ((Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => (A.play (oX ω.1 ω.2)).2 = true)).card : ℝ) +
      ((Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => ¬ (A.play (oX ω.1 ω.2)).2 = true)).card : ℝ) =
      Fintype.card (Equiv.Perm D × (V → D)) := by exact_mod_cast this
  field_simp
  linarith

open Classical in
theorem prY_neg (A : Adv V D) : prY A.neg = 1 - prY A := by
  unfold prY
  have hpos : (0 : ℝ) < Fintype.card (Equiv.Perm D × (V × D × D → D)) := by exact_mod_cast Fintype.card_pos
  have := Finset.card_filter_add_card_filter_not (s := (Finset.univ : Finset (Equiv.Perm D × (V × D × D → D))))
    (fun ω => (A.play (oY ω.1 ω.2)).2 = true)
  have e : (Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => (A.neg.play (oY ω.1 ω.2)).2 = true)) =
      Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => ¬ (A.play (oY ω.1 ω.2)).2 = true) := by
    apply Finset.filter_congr; intro ω _
    rw [play_neg]; simp
  rw [e]
  rw [Finset.card_univ] at this
  have : ((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => (A.play (oY ω.1 ω.2)).2 = true)).card : ℝ) +
      ((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => ¬ (A.play (oY ω.1 ω.2)).2 = true)).card : ℝ) =
      Fintype.card (Equiv.Perm D × (V × D × D → D)) := by exact_mod_cast this
  field_simp
  linarith

/-- THE ICM THEOREM.  Real TMMO (full 128-bit output) with `Delta_v`-shifted inputs versus a uniformly random
function, against any adaptive adversary with at most `kp` permutation/inverse queries and `kh` hash queries:
`|Pr_real - Pr_ideal| <= ( L (L-1) + kh (kh+1)/2 ) / N`, `L = kp + 2 kh`, `N = |D|` (`2^128`). -/
theorem tcr_icm (h2 : ∀ x : D, x + x = 0) (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh) :
    |prX A - prY A| ≤
      ((((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) + (kh : ℝ) * (kh + 1) / 2) / Fintype.card D := by
  have h1 := tcr_one_sided h2 A kp kh hA
  have h2' := tcr_one_sided h2 A.neg kp kh (Bdd_neg A kp kh hA)
  rw [prX_neg, prY_neg] at h2'
  have e : fb kh 0 = (kh : ℝ) * (kh + 1) / 2 := by
    have := fb_zero_closed kh; linarith
  rw [e] at h1 h2'
  rw [abs_le]
  constructor <;> [skip; skip]
  · rw [add_div] ; linarith
  · rw [add_div]; linarith

end PcaMath.OtDefs
