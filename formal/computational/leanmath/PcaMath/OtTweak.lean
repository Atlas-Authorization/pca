import Mathlib
import PcaMath.OtRows
import PcaMath.OtCounter
import PcaMath.OtCompose

/-!
# R4-12: the OT-extension hash layer, assembled

* `rows_prob`      : probability that two of the `2Q` sender inputs coincide is `<= (2Q)^2 / N` (`N = 2^128`).
* `OtCounter.*`    : global row index injective, lockstep, no wrap below `2^64` rows, 64-bit add is exact.
* `OtDefs.tcr_icm_post`, `tcr_icm_simple` : tweakable correlation robustness of `H(x,t) = pi(pi(x)+t)+pi(x)`
  (and of any post-processing of it, e.g. `low64`) in the ideal-cipher model: advantage `<= 2 (kp+2kh)^2 / N`.
-/

namespace PcaMath.OtTweak

open PcaMath.OtRows

variable {D : Type} [AddCommGroup D] [Fintype D] [DecidableEq D] {ι : Type} [Fintype ι] [DecidableEq ι]

/-- sender-input distinctness, probability form (idealised PRG rows; any receiver choice function). -/
theorem rows_prob (h2 : ∀ x : D, x + x = 0) (r : (ι → D) → ι → Bool) :
    ((Finset.univ.filter (fun ω : (ι → D) × D => ∃ a b : ι × Bool, a ≠ b ∧ zin r ω a = zin r ω b)).card : ℝ)
      / Fintype.card ((ι → D) × D) ≤ ((2 * Fintype.card ι : ℕ) : ℝ) ^ 2 / Fintype.card D := by
  have hN : (0 : ℝ) < Fintype.card D := by exact_mod_cast Fintype.card_pos
  have h := rows_distinct h2 r
  have hc : Fintype.card ((ι → D) × D) = Fintype.card D ^ Fintype.card ι * Fintype.card D := by
    simp [Fintype.card_prod, Fintype.card_fun]
  rw [hc]
  have hq : (Fintype.card ι * (Fintype.card ι - 1) + 1) ≤ (2 * Fintype.card ι) ^ 2 ∨ Fintype.card ι = 0 := by
    rcases Nat.eq_zero_or_pos (Fintype.card ι) with h0 | h0
    · right; exact h0
    · left; nlinarith [Nat.sub_le (Fintype.card ι) 1]
  rcases hq with hq | h0
  · have hr : ((Finset.univ.filter (fun ω : (ι → D) × D => ∃ a b : ι × Bool, a ≠ b ∧ zin r ω a = zin r ω b)).card : ℝ)
        ≤ (((2 * Fintype.card ι) ^ 2 : ℕ) : ℝ) * (Fintype.card D : ℝ) ^ Fintype.card ι := by
      calc _ ≤ (((Fintype.card ι * (Fintype.card ι - 1) + 1) * Fintype.card D ^ Fintype.card ι : ℕ) : ℝ) := by exact_mod_cast h
        _ ≤ _ := by
          push_cast
          have : ((Fintype.card ι * (Fintype.card ι - 1) + 1 : ℕ) : ℝ) ≤ (((2 * Fintype.card ι) ^ 2 : ℕ) : ℝ) := by exact_mod_cast hq
          have hp : (0:ℝ) ≤ (Fintype.card D : ℝ) ^ Fintype.card ι := by positivity
          push_cast at this ⊢
          nlinarith
    rw [div_le_div_iff₀ (by positivity) hN]
    push_cast at hr ⊢
    nlinarith
  · -- no rows: the event is empty
    have : (Finset.univ.filter (fun ω : (ι → D) × D => ∃ a b : ι × Bool, a ≠ b ∧ zin r ω a = zin r ω b)) = ∅ := by
      apply Finset.filter_eq_empty_iff.mpr
      rintro ω _ ⟨a, b, -, -⟩
      have : IsEmpty ι := Fintype.card_eq_zero_iff.mp h0
      exact this.false a.1
    rw [this]; simp; positivity

end PcaMath.OtTweak
