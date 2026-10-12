import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtB
import PcaMath.OtC
import PcaMath.OtD
import PcaMath.OtE
import PcaMath.OtHC
import PcaMath.OtPerm
import PcaMath.OtLin

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

noncomputable def prX (A : Adv V D) : ℝ :=
  ((Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => (A.play (oX ω.1 ω.2)).2 = true)).card : ℝ)
    / Fintype.card (Equiv.Perm D × (V → D))

noncomputable def prY (A : Adv V D) : ℝ :=
  ((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => (A.play (oY ω.1 ω.2)).2 = true)).card : ℝ)
    / Fintype.card (Equiv.Perm D × (V × D × D → D))

theorem card_ΩX : Fintype.card (Equiv.Perm D × (V → D)) = (Fintype.card D).factorial * Fintype.card D ^ Fintype.card V := by
  simp [Fintype.card_prod, Fintype.card_perm, Fintype.card_fun]

theorem card_ΩY : Fintype.card (Equiv.Perm D × (V × D × D → D)) =
    (Fintype.card D).factorial * Fintype.card D ^ Fintype.card (V × D × D) := by
  simp [Fintype.card_prod, Fintype.card_perm, Fintype.card_fun]

open Classical in
noncomputable def BadT (τ : List (Qry V D × D) × Bool) : Prop := BadH (hSet τ.1)

open Classical in
theorem hbad_bound [Nonempty D] (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh) :
    ((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => BadT (A.play (oY ω.1 ω.2)))).card : ℝ)
      / Fintype.card (Equiv.Perm D × (V × D × D → D)) ≤ fb kh 0 / Fintype.card D := by
  have hN : (0 : ℝ) < Fintype.card D := by exact_mod_cast Fintype.card_pos
  have hfac : (0 : ℝ) < (Fintype.card D).factorial := by exact_mod_cast Nat.factorial_pos _
  rw [card_ΩY]
  have key : ∀ π : Equiv.Perm D,
      ((Finset.univ.filter (fun R : V × D × D → D => BadT (A.play (oY π R)))).card : ℝ) * Fintype.card D
        ≤ fb kh 0 * (Fintype.card D : ℝ) ^ Fintype.card (V × D × D) := by
    intro π
    have := delta_count π A kp kh hA ∅ (by intro p hp; simp at hp) (by
      rintro (⟨h, hh, _⟩ | ⟨h, hh, _⟩) <;> simp at hh)
    simp only [Finset.card_empty, Nat.sub_zero, Finset.empty_union] at this
    have e : (Finset.univ.filter (fun R : V × D × D → D => BadT (A.play (oY π R)))) =
        (Finset.univ.filter (fun R : V × D × D → D =>
          (∀ h ∈ (∅ : Finset ((V × D × D) × D)), R h.1 = h.2) ∧ BadH (hSet (A.play (oY π R)).1))) := by
      apply Finset.filter_congr; intro R _
      simp [BadT]
    rw [e]
    simpa using this
  have hsum : (Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => BadT (A.play (oY ω.1 ω.2)))).card =
      ∑ π : Equiv.Perm D, (Finset.univ.filter (fun R : V × D × D → D => BadT (A.play (oY π R)))).card := by
    rw [Finset.card_filter, Fintype.sum_prod_type]
    apply Finset.sum_congr rfl; intro π _
    rw [Finset.card_filter]
  rw [hsum]
  push_cast
  rw [div_le_div_iff₀ (by positivity) hN]
  calc (∑ π : Equiv.Perm D, (((Finset.univ.filter (fun R : V × D × D → D => BadT (A.play (oY π R)))).card : ℕ) : ℝ)) * Fintype.card D
      = ∑ π : Equiv.Perm D, (((Finset.univ.filter (fun R : V × D × D → D => BadT (A.play (oY π R)))).card : ℕ) : ℝ) * Fintype.card D := by
        rw [Finset.sum_mul]
    _ ≤ ∑ π : Equiv.Perm D, fb kh 0 * (Fintype.card D : ℝ) ^ Fintype.card (V × D × D) :=
        Finset.sum_le_sum (fun π _ => key π)
    _ = (Fintype.card D).factorial * (fb kh 0 * (Fintype.card D : ℝ) ^ Fintype.card (V × D × D)) := by
        rw [Finset.sum_const, Finset.card_univ, Fintype.card_perm, nsmul_eq_mul]
    _ = fb kh 0 * ((Fintype.card D).factorial * (Fintype.card D : ℝ) ^ Fintype.card (V × D × D)) := by ring

end PcaMath.OtDefs
