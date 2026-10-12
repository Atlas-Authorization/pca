import Mathlib

/-!
# The forking lemma (Pointcheval-Stern 2000 / Bellare-Neven 2006), as a finite counting theorem

Everything is over finite types and uniform sampling, so every probability is a ratio of
cardinalities and no measure theory is needed.

*Abstract form.*  `Ω` is the finite sample space of one run (coins and the whole random-oracle
table).  For every query index `i` there is
* a partition of `Ω` into "classes" (`cls i`) = runs that agree up to the `i`-th query,
  all of the same size `N i`,
* the value `a i ω` of the oracle answer at the fork point, each value taking the same share
  `N i / |H|` of every class,
* the set `A i` of runs that accept with fork point `i`.

The forking experiment samples `ω` uniformly; if `ω ∈ A i` it re-samples `ω'` uniformly from the
class of `ω` (same coins, same answers before query `i`, fresh answers from `i` on), and
succeeds when `ω' ∈ A i` as well and the two answers at the fork point differ.

`fork_bound` proves   `Pr[success] ≥ acc · (acc / q − 1/|H|)`   with `acc = Σ_i |A i| / |Ω|`,
`q` the number of indices and `|H|` the size of the answer space (Cauchy-Schwarz twice).
-/

open Finset

namespace PcaMath.Fork

/-! ## Cauchy-Schwarz over equal-size classes -/

section Count
variable {Ω L : Type*} [Fintype Ω] [DecidableEq L] [DecidableEq Ω]

lemma class_cs (c : Ω → L) (N : ℕ)
    (hN : ∀ ω, (univ.filter (fun ω' => c ω' = c ω)).card = N) (A : Finset Ω) :
    (N : ℝ) * (A.card : ℝ) ^ 2 ≤
      (Fintype.card Ω : ℝ) * ∑ ω ∈ A, ((A.filter (fun ω' => c ω' = c ω)).card : ℝ) := by
  classical
  set m : L → ℝ := fun l => ((A.filter (fun ω' => c ω' = l)).card : ℝ) with hm
  have h1 : ∑ ω ∈ A, ((A.filter (fun ω' => c ω' = c ω)).card : ℝ) = ∑ l ∈ A.image c, m l * m l := by
    have := Finset.sum_comp (s := A) (fun l => m l) c
    simp only [smul_eq_mul, nsmul_eq_mul] at this
    simpa [hm] using this
  have h2 : ∑ l ∈ A.image c, m l = (A.card : ℝ) := by
    have := Finset.card_eq_sum_card_image c A
    simp only [hm]
    exact_mod_cast this.symm
  have h3 : (Fintype.card Ω : ℝ) = (N : ℝ) * ((univ.image c).card : ℝ) := by
    have := Finset.card_eq_sum_card_image c (univ : Finset Ω)
    have h4 : ∑ l ∈ univ.image c, (univ.filter (fun x => c x = l)).card = ∑ _l ∈ univ.image c, N := by
      apply Finset.sum_congr rfl
      intro l hl
      obtain ⟨ω, _, rfl⟩ := Finset.mem_image.mp hl
      exact hN ω
    rw [h4] at this
    simp only [Finset.sum_const, smul_eq_mul, Finset.card_univ] at this
    rw [this]; push_cast; ring
  have hsub : (A.image c).card ≤ (univ.image c).card :=
    Finset.card_le_card (Finset.image_subset_image (Finset.subset_univ _))
  have hcs := _root_.sq_sum_le_card_mul_sum_sq (s := A.image c) (f := m)
  rw [h2] at hcs
  rw [h1, h3]
  have hsq : ∀ l, m l ^ 2 = m l * m l := fun l => by ring
  simp only [hsq] at hcs
  have hS : ∑ l ∈ A.image c, m l * m l ≥ 0 := Finset.sum_nonneg (fun l _ => mul_self_nonneg _)
  have hsub' : ((A.image c).card : ℝ) ≤ ((univ.image c).card : ℝ) := by exact_mod_cast hsub
  have hN0 : (0 : ℝ) ≤ N := Nat.cast_nonneg _
  calc (N : ℝ) * (A.card : ℝ) ^ 2 ≤ (N : ℝ) * (((A.image c).card : ℝ) * ∑ l ∈ A.image c, m l * m l) :=
        mul_le_mul_of_nonneg_left hcs hN0
    _ ≤ (N : ℝ) * (((univ.image c).card : ℝ) * ∑ l ∈ A.image c, m l * m l) := by
        apply mul_le_mul_of_nonneg_left _ hN0
        exact mul_le_mul_of_nonneg_right hsub' hS
    _ = (N : ℝ) * ((univ.image c).card : ℝ) * ∑ l ∈ A.image c, m l * m l := by ring

end Count

/-! ## The abstract forking lemma -/

section Fork
variable {Ω L ι H : Type*} [Fintype Ω] [DecidableEq L] [DecidableEq Ω] [Fintype ι] [Fintype H]
  [DecidableEq H]

/-- `|Ω| ·` the success probability of the forking experiment. -/
noncomputable def forkMass (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : ι → Finset Ω) : ℝ :=
  ∑ i, ∑ ω ∈ A i,
    ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card : ℝ) / (N i : ℝ)

/-- `|Ω| ·` the accepting probability (the `A i` are the accepting runs, one set per fork point). -/
def accMass (A : ι → Finset Ω) : ℝ := ∑ i, ((A i).card : ℝ)

theorem fork_mass_ge (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : ι → Finset Ω)
    (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i)
    (hU : ∀ i ω (c : H),
      (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = c)).card * Fintype.card H = N i)
    (hH : 0 < Fintype.card H) (hΩ : 0 < Fintype.card Ω) :
    forkMass cls a N A ≥
      (accMass A) ^ 2 / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ))
        - accMass A / (Fintype.card H : ℝ) := by
  classical
  have hHr : (0 : ℝ) < Fintype.card H := by exact_mod_cast hH
  have hΩr : (0 : ℝ) < Fintype.card Ω := by exact_mod_cast hΩ
  -- per-index bound
  have key : ∀ i, ∑ ω ∈ A i,
      ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card : ℝ) / (N i : ℝ)
      ≥ ((A i).card : ℝ) ^ 2 / (Fintype.card Ω : ℝ) - ((A i).card : ℝ) / (Fintype.card H : ℝ) := by
    intro i
    by_cases hAe : A i = ∅
    · simp [hAe]
    obtain ⟨ω0, hω0⟩ := Finset.nonempty_iff_ne_empty.mpr hAe
    have hNpos : 0 < N i := by
      rw [← hN i ω0]
      exact Finset.card_pos.mpr ⟨ω0, by simp⟩
    have hNr : (0 : ℝ) < N i := by exact_mod_cast hNpos
    set n : Ω → ℝ := fun ω => ((( A i).filter (fun ω' => cls i ω' = cls i ω)).card : ℝ) with hn
    -- every ω: count ≥ n ω - N i / |H|
    have hcnt : ∀ ω, ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card : ℝ)
        ≥ n ω - (N i : ℝ) / (Fintype.card H : ℝ) := by
      intro ω
      have hsplit : ((A i).filter (fun ω' => cls i ω' = cls i ω)).card ≤
          (univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card
          + (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card := by
        calc ((A i).filter (fun ω' => cls i ω' = cls i ω)).card
            ≤ ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)) ∪
                (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω))).card := by
              apply Finset.card_le_card
              intro x hx
              simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at hx ⊢
              by_cases hax : a i x = a i ω
              · right; exact ⟨hx.2, hax⟩
              · left; exact ⟨hx.1, hx.2, hax⟩
          _ ≤ _ := Finset.card_union_le _ _
      have hU' := hU i ω (a i ω)
      have hUr : ((univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card : ℝ)
          = (N i : ℝ) / (Fintype.card H : ℝ) := by
        rw [eq_div_iff hHr.ne']
        exact_mod_cast hU'
      have : n ω ≤ ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card : ℝ)
          + ((univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card : ℝ) := by
        simp only [hn]; exact_mod_cast hsplit
      linarith
    have hsum : ∑ ω ∈ A i,
        ((univ.filter (fun ω' => ω' ∈ A i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card : ℝ) / (N i : ℝ)
        ≥ ∑ ω ∈ A i, (n ω / (N i : ℝ) - 1 / (Fintype.card H : ℝ)) := by
      apply Finset.sum_le_sum
      intro ω _
      have := hcnt ω
      have e : (n ω - (N i : ℝ) / (Fintype.card H : ℝ)) / (N i : ℝ) = n ω / (N i : ℝ) - 1 / (Fintype.card H : ℝ) := by
        field_simp
      rw [← e]
      exact div_le_div_of_nonneg_right this hNr.le
    have hcs := class_cs (cls i) (N i) (hN i) (A i)
    have hsn : ∑ ω ∈ A i, n ω = ∑ ω ∈ A i, ((A i).filter (fun ω' => cls i ω' = cls i ω)).card := by
      simp [hn]
    rw [Finset.sum_sub_distrib, ← Finset.sum_div (A i) n (N i : ℝ)] at hsum
    simp only [Finset.sum_const, nsmul_eq_mul, mul_one_div] at hsum
    have hq : ((A i).card : ℝ) ^ 2 / (Fintype.card Ω : ℝ) ≤ (∑ ω ∈ A i, n ω) / (N i : ℝ) := by
      rw [div_le_div_iff₀ hΩr hNr]
      have : ∑ ω ∈ A i, n ω = ∑ ω ∈ A i, ((A i).filter (fun ω' => cls i ω' = cls i ω)).card := by
        simp [hn]
      rw [this]
      nlinarith [hcs]
    have e2 : ((A i).card : ℝ) / (Fintype.card H : ℝ) = ((A i).card : ℝ) * (1 / (Fintype.card H : ℝ)) := by ring
    rw [e2]
    linarith
  have hsumi : forkMass cls a N A ≥ ∑ i, (((A i).card : ℝ) ^ 2 / (Fintype.card Ω : ℝ)
      - ((A i).card : ℝ) / (Fintype.card H : ℝ)) := by
    unfold forkMass
    exact Finset.sum_le_sum (fun i _ => key i)
  rw [Finset.sum_sub_distrib, ← Finset.sum_div, ← Finset.sum_div] at hsumi
  have hcs2 := _root_.sq_sum_le_card_mul_sum_sq (s := (univ : Finset ι)) (f := fun i => ((A i).card : ℝ))
  simp only [Finset.card_univ] at hcs2
  have : accMass A ^ 2 / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) ≤
      (∑ i, ((A i).card : ℝ) ^ 2) / (Fintype.card Ω : ℝ) := by
    by_cases hι : Fintype.card ι = 0
    · have h0 : accMass A = 0 := by
        haveI : IsEmpty ι := Fintype.card_eq_zero_iff.mp hι
        unfold accMass
        rw [Finset.univ_eq_empty, Finset.sum_empty]
      have h1 : (0 : ℝ) ≤ (∑ i, ((A i).card : ℝ) ^ 2) / (Fintype.card Ω : ℝ) :=
        div_nonneg (Finset.sum_nonneg (fun i _ => sq_nonneg _)) hΩr.le
      rw [h0]
      have h2 : ((0 : ℝ) ^ 2) / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) = 0 := by
        rw [zero_pow two_ne_zero, zero_div]
      rw [h2]; exact h1
    have hιr : (0 : ℝ) < Fintype.card ι := by exact_mod_cast Nat.pos_of_ne_zero hι
    rw [div_le_div_iff₀ (mul_pos hιr hΩr) hΩr]
    unfold accMass
    nlinarith [hcs2, hΩr]
  unfold accMass at *
  linarith

end Fork

end PcaMath.Fork
