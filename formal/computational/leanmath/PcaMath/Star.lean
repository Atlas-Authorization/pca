import Mathlib

/-!
# The k-fork ("star") forking lemma

`Fork.fork_mass_ge` rewinds a run once, at one fork point.  A composite Fiat-Shamir proof (the range
proof of `packages/pca-ratchet` has 33 independent challenges: 32 bit OR-proofs and one aggregation
Schnorr proof, each a separate random-oracle query) needs a special-soundness pair for EVERY component.

The extractor: sample a run `ω`; if it accepts, then for EVERY component `r` independently re-sample the
run from the fork point `idx r ω` of that component (same coins, same answers before the fork point,
fresh answers from there on).  `starMass` is `|Ω|` times the probability that, for every `r`, the `r`-th
re-sampled run also accepts with the same index and a different answer at the fork point.

`star_mass_ge`:   `starMass / |Ω|  >=  p * ((p / |ι|)^k - k / |H|)`   with `p = |A|/|Ω|` the accepting
probability, `|ι|` the number of fork indices (`q`), `k` the number of components and `|H|` the challenge
space.  For `k = 1` this is exactly `fork_mass_ge`.

Proof (no measure theory).  For each component let `g_r(ω)` be the accepted share of the class of `ω`.
(1) `sum_{ω in A} log(g_r(ω)/σ) >= 0` for `σ = p/|ι|`: use `log x >= 1 - 1/x`; then
    `sum_{ω in A} 1/g_r(ω)` counts the non-empty classes (times class size), at most `|ι||Ω|`.
(2) `∏ g_r >= σ^k (1 + sum_r log(g_r/σ))` since `exp y >= 1 + y`.   Summing over `A` gives
    `sum_{ω in A} ∏ g_r >= σ^k |A|`.
(3) the "different answer" requirement costs at most `1/|H|` per component, so at most `k/|H|` overall.
-/

open Finset

namespace PcaMath.Star

variable {Ω L ι H κ : Type*} [Fintype Ω] [DecidableEq L] [DecidableEq Ω] [Fintype ι] [DecidableEq ι]
  [Fintype H] [DecidableEq H] [Fintype κ]

section Defs
variable (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : Finset Ω) (idx : κ → Ω → ι)

/-- accepted runs in the class of `ω` at component `r`'s fork point. -/
noncomputable def cnt (r : κ) (ω : Ω) : ℝ :=
  ((A.filter (fun ω' => idx r ω' = idx r ω ∧ cls (idx r ω) ω' = cls (idx r ω) ω)).card : ℝ)

/-- ... that moreover have a different answer at the fork point. -/
noncomputable def dcnt (r : κ) (ω : Ω) : ℝ :=
  ((A.filter (fun ω' => idx r ω' = idx r ω ∧ cls (idx r ω) ω' = cls (idx r ω) ω ∧
      a (idx r ω) ω' ≠ a (idx r ω) ω)).card : ℝ)

/-- `|Ω|` times the success probability of the star experiment. -/
noncomputable def starMass : ℝ := ∑ ω ∈ A, ∏ r, dcnt cls a A idx r ω / (N (idx r ω) : ℝ)

end Defs

section Lemmas
variable (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : Finset Ω) (idx : κ → Ω → ι)

lemma cnt_ge_one (r : κ) {ω : Ω} (hω : ω ∈ A) : 1 ≤ cnt cls A idx r ω := by
  unfold cnt
  have : 0 < (A.filter (fun ω' => idx r ω' = idx r ω ∧ cls (idx r ω) ω' = cls (idx r ω) ω)).card :=
    Finset.card_pos.mpr ⟨ω, by simp [hω]⟩
  exact_mod_cast this

lemma cnt_le (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i) (r : κ) (ω : Ω) :
    cnt cls A idx r ω ≤ (N (idx r ω) : ℝ) := by
  unfold cnt
  rw [← hN (idx r ω) ω]
  exact_mod_cast Finset.card_le_card (fun x hx => by simp at hx ⊢; exact hx.2.2)

lemma dcnt_ge (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i)
    (hU : ∀ i ω (c : H),
      (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = c)).card * Fintype.card H = N i)
    (hH : 0 < Fintype.card H) (r : κ) (ω : Ω) :
    dcnt cls a A idx r ω ≥ cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ) := by
  classical
  set i := idx r ω
  have hHr : (0 : ℝ) < Fintype.card H := by exact_mod_cast hH
  have hsplit : (A.filter (fun ω' => idx r ω' = i ∧ cls i ω' = cls i ω)).card ≤
      (A.filter (fun ω' => idx r ω' = i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)).card
      + (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card := by
    calc (A.filter (fun ω' => idx r ω' = i ∧ cls i ω' = cls i ω)).card
        ≤ ((A.filter (fun ω' => idx r ω' = i ∧ cls i ω' = cls i ω ∧ a i ω' ≠ a i ω)) ∪
            (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω))).card := by
          apply Finset.card_le_card
          intro x hx
          simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at hx ⊢
          by_cases hax : a i x = a i ω
          · right; exact ⟨hx.2.2, hax⟩
          · left; exact ⟨hx.1, hx.2.1, hx.2.2, hax⟩
      _ ≤ _ := Finset.card_union_le _ _
  have hUr : ((univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card : ℝ)
      = (N i : ℝ) / (Fintype.card H : ℝ) := by
    rw [eq_div_iff hHr.ne']
    exact_mod_cast hU i ω (a i ω)
  have : cnt cls A idx r ω ≤ dcnt cls a A idx r ω +
      ((univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = a i ω)).card : ℝ) := by
    unfold cnt dcnt; exact_mod_cast hsplit
  linarith

/-- `sum_{ω in S} 1 / |fibre of ω|` is the number of fibres. -/
lemma sum_inv_fibre {β : Type*} [DecidableEq β] (S : Finset Ω) (c : Ω → β) :
    ∑ ω ∈ S, (1 : ℝ) / ((S.filter (fun ω' => c ω' = c ω)).card : ℝ) = ((S.image c).card : ℝ) := by
  have := Finset.sum_comp (s := S) (fun l : β => (1 : ℝ) / ((S.filter (fun ω' => c ω' = l)).card : ℝ)) c
  rw [this]
  rw [Finset.card_eq_sum_ones, Nat.cast_sum]
  apply Finset.sum_congr rfl
  intro l hl
  obtain ⟨ω, hω, rfl⟩ := Finset.mem_image.mp hl
  have : 0 < (S.filter (fun ω' => c ω' = c ω)).card := Finset.card_pos.mpr ⟨ω, by simp [hω]⟩
  have h0 : ((S.filter (fun ω' => c ω' = c ω)).card : ℝ) ≠ 0 := by exact_mod_cast this.ne'
  simp [h0]

lemma inv_sum_le (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i) (r : κ) :
    ∑ ω ∈ A, (N (idx r ω) : ℝ) / cnt cls A idx r ω ≤ (Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ) := by
  classical
  rw [← Finset.sum_fiberwise A (idx r)]
  have hper : ∀ i : ι, ∑ ω ∈ A.filter (fun ω' => idx r ω' = i), (N (idx r ω) : ℝ) / cnt cls A idx r ω
      ≤ (Fintype.card Ω : ℝ) := by
    intro i
    set S := A.filter (fun ω' => idx r ω' = i) with hS
    have h1 : ∀ ω ∈ S, (N (idx r ω) : ℝ) / cnt cls A idx r ω
        = (N i : ℝ) * ((1 : ℝ) / ((S.filter (fun ω' => cls i ω' = cls i ω)).card : ℝ)) := by
      intro ω hω
      have hi : idx r ω = i := (Finset.mem_filter.mp hω).2
      have hcnt : cnt cls A idx r ω = ((S.filter (fun ω' => cls i ω' = cls i ω)).card : ℝ) := by
        unfold cnt
        rw [hi]
        have hset : A.filter (fun ω' => idx r ω' = i ∧ cls i ω' = cls i ω)
            = S.filter (fun ω' => cls i ω' = cls i ω) := by
          ext x
          simp only [hS, Finset.mem_filter]
          tauto
        rw [hset]
      rw [hi, hcnt]; ring
    rw [Finset.sum_congr rfl h1, ← Finset.mul_sum, sum_inv_fibre S (cls i)]
    -- |Ω| = N i * |image of cls i on univ|
    have h3 : (Fintype.card Ω : ℝ) = (N i : ℝ) * ((univ.image (cls i)).card : ℝ) := by
      have := Finset.card_eq_sum_card_image (cls i) (univ : Finset Ω)
      have h4 : ∑ l ∈ univ.image (cls i), (univ.filter (fun x => cls i x = l)).card
          = ∑ _l ∈ univ.image (cls i), N i := by
        apply Finset.sum_congr rfl
        intro l hl
        obtain ⟨ω, _, rfl⟩ := Finset.mem_image.mp hl
        exact hN i ω
      rw [h4] at this
      simp only [Finset.sum_const, smul_eq_mul, Finset.card_univ] at this
      rw [this]; push_cast; ring
    rw [h3]
    have hsub : ((S.image (cls i)).card : ℝ) ≤ ((univ.image (cls i)).card : ℝ) := by
      exact_mod_cast Finset.card_le_card (Finset.image_subset_image (Finset.subset_univ _))
    exact mul_le_mul_of_nonneg_left hsub (Nat.cast_nonneg _)
  calc _ ≤ ∑ _i : ι, (Fintype.card Ω : ℝ) := Finset.sum_le_sum (fun i _ => hper i)
    _ = _ := by simp

/-- Step (1): the log-sum is non-negative. -/
lemma log_sum_nonneg (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i) (r : κ)
    (hA : A.Nonempty) :
    0 ≤ ∑ ω ∈ A, Real.log (cnt cls A idx r ω / (N (idx r ω) : ℝ) /
      ((A.card : ℝ) / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)))) := by
  classical
  obtain ⟨ω0, hω0⟩ := hA
  have hιpos : (0 : ℝ) < Fintype.card ι := by
    have : 0 < Fintype.card ι := Fintype.card_pos_iff.mpr ⟨idx r ω0⟩
    exact_mod_cast this
  have hΩpos : (0 : ℝ) < Fintype.card Ω := by
    have : 0 < Fintype.card Ω := Fintype.card_pos_iff.mpr ⟨ω0⟩
    exact_mod_cast this
  have hApos : (0 : ℝ) < A.card := by exact_mod_cast Finset.card_pos.mpr ⟨ω0, hω0⟩
  set σ : ℝ := (A.card : ℝ) / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) with hσ
  have hσpos : 0 < σ := div_pos hApos (mul_pos hιpos hΩpos)
  have hNpos : ∀ ω ∈ A, (0 : ℝ) < N (idx r ω) := by
    intro ω hω
    have h1 := cnt_ge_one cls A idx r hω
    have h2 := cnt_le cls N A idx hN r ω
    linarith
  have hterm : ∀ ω ∈ A, 1 - σ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω) ≤
      Real.log (cnt cls A idx r ω / (N (idx r ω) : ℝ) / σ) := by
    intro ω hω
    have hc := cnt_ge_one cls A idx r hω
    have hcpos : (0 : ℝ) < cnt cls A idx r ω := by linarith
    have hNp := hNpos ω hω
    have hx : 0 < cnt cls A idx r ω / (N (idx r ω) : ℝ) / σ := by positivity
    have := Real.one_sub_inv_le_log_of_pos hx
    have e : (cnt cls A idx r ω / (N (idx r ω) : ℝ) / σ)⁻¹ = σ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω) := by
      field_simp
    rw [e] at this; exact this
  calc (0 : ℝ) = (A.card : ℝ) - σ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) := by
        rw [hσ]; field_simp; ring
    _ ≤ (A.card : ℝ) - σ * ∑ ω ∈ A, (N (idx r ω) : ℝ) / cnt cls A idx r ω := by
        have := inv_sum_le cls N A idx hN r
        nlinarith
    _ = ∑ ω ∈ A, (1 - σ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω)) := by
        rw [Finset.sum_sub_distrib, ← Finset.mul_sum]; simp
    _ ≤ _ := Finset.sum_le_sum hterm

lemma prod_div_const (f : κ → ℝ) (σ : ℝ) :
    ∏ r, (f r / σ) = (∏ r, f r) / σ ^ (Fintype.card κ) := by
  rw [Finset.prod_div_distrib, Finset.prod_const, Finset.card_univ]

lemma prod_sub_prod_le {s : Finset κ} (x y : κ → ℝ) (h0 : ∀ r, 0 ≤ y r) (hxy : ∀ r, y r ≤ x r)
    (h1 : ∀ r, x r ≤ 1) : ∏ r ∈ s, x r - ∏ r ∈ s, y r ≤ ∑ r ∈ s, (x r - y r) := by
  classical
  induction s using Finset.induction_on with
  | empty => simp
  | insert b s hb ih =>
    rw [Finset.prod_insert hb, Finset.prod_insert hb, Finset.sum_insert hb]
    have hPx : ∏ r ∈ s, x r ≤ 1 :=
      Finset.prod_le_one₀ (fun r _ => (h0 r).trans (hxy r)) (fun r _ => h1 r)
    have hPy : 0 ≤ ∏ r ∈ s, y r := Finset.prod_nonneg (fun r _ => h0 r)
    have hPxy : ∏ r ∈ s, y r ≤ ∏ r ∈ s, x r := Finset.prod_le_prod₀ (fun r _ => h0 r) (fun r _ => hxy r)
    have hPx0 : 0 ≤ ∏ r ∈ s, x r := hPy.trans hPxy
    nlinarith [h0 b, hxy b, h1 b, mul_nonneg (h0 b) (sub_nonneg.2 hPxy),
      mul_nonneg (sub_nonneg.2 (hxy b)) (sub_nonneg.2 hPx)]

end Lemmas

/-- **The k-fork lemma (star form).** -/
theorem star_mass_ge (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : Finset Ω) (idx : κ → Ω → ι)
    (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i)
    (hU : ∀ i ω (c : H),
      (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = c)).card * Fintype.card H = N i)
    (hH : 0 < Fintype.card H) :
    starMass cls a N A idx ≥
      (A.card : ℝ) * (((A.card : ℝ) / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ))) ^ (Fintype.card κ)
        - (Fintype.card κ : ℝ) / (Fintype.card H : ℝ)) := by
  classical
  by_cases hAe : A = ∅
  · subst hAe; simp [starMass]
  have hA : A.Nonempty := Finset.nonempty_iff_ne_empty.mpr hAe
  by_cases hκ : IsEmpty κ
  · haveI := hκ
    simp [starMass]
  obtain ⟨r0⟩ := not_isEmpty_iff.mp hκ
  obtain ⟨ω0, hω0⟩ := hA
  have hHr : (0 : ℝ) < Fintype.card H := by exact_mod_cast hH
  have hιpos : (0 : ℝ) < Fintype.card ι := by
    have : 0 < Fintype.card ι := Fintype.card_pos_iff.mpr ⟨idx r0 ω0⟩
    exact_mod_cast this
  have hΩpos : (0 : ℝ) < Fintype.card Ω := by
    have : 0 < Fintype.card Ω := Fintype.card_pos_iff.mpr ⟨ω0⟩
    exact_mod_cast this
  have hApos : (0 : ℝ) < A.card := by exact_mod_cast Finset.card_pos.mpr ⟨ω0, hω0⟩
  set σ : ℝ := (A.card : ℝ) / ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) with hσ
  have hσpos : 0 < σ := div_pos hApos (mul_pos hιpos hΩpos)
  set ε : ℝ := 1 / (Fintype.card H : ℝ) with hε
  have hε0 : 0 ≤ ε := by positivity
  set g : κ → Ω → ℝ := fun r ω => cnt cls A idx r ω / (N (idx r ω) : ℝ) with hg
  have hNpos : ∀ r, ∀ ω ∈ A, (0 : ℝ) < N (idx r ω) := by
    intro r ω hω
    have h1 := cnt_ge_one cls A idx r hω
    have h2 := cnt_le cls N A idx hN r ω
    linarith
  have hg0 : ∀ r, ∀ ω ∈ A, 0 < g r ω := by
    intro r ω hω
    have := cnt_ge_one cls A idx r hω
    have := hNpos r ω hω
    simp only [hg]; positivity
  have hg1 : ∀ r, ∀ ω ∈ A, g r ω ≤ 1 := by
    intro r ω hω
    simp only [hg]
    rw [div_le_one (hNpos r ω hω)]; exact cnt_le cls N A idx hN r ω
  have hpt : ∀ ω ∈ A, (∏ r, dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) ≥
      σ ^ (Fintype.card κ) * (1 + ∑ r, Real.log (g r ω / σ)) - (Fintype.card κ : ℝ) * ε := by
    intro ω hω
    -- AM-GM / exp step
    have hprod : ∏ r, g r ω ≥ σ ^ (Fintype.card κ) * (1 + ∑ r, Real.log (g r ω / σ)) := by
      have h1 : ∏ r, g r ω = σ ^ (Fintype.card κ) * ∏ r, (g r ω / σ) := by
        rw [prod_div_const (fun r => g r ω) σ]
        field_simp
      have h2 : ∏ r, (g r ω / σ) = Real.exp (∑ r, Real.log (g r ω / σ)) := by
        rw [Real.exp_sum]
        apply Finset.prod_congr rfl
        intro r _
        rw [Real.exp_log (div_pos (hg0 r ω hω) hσpos)]
      rw [h1, h2]
      have := Real.add_one_le_exp (∑ r, Real.log (g r ω / σ))
      have hσk : 0 < σ ^ (Fintype.card κ) := pow_pos hσpos _
      nlinarith
    -- the distinct-answer step
    set y : κ → ℝ := fun r => max (g r ω - ε) 0 with hy
    have hd : ∀ r, y r ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := by
      intro r
      have hNp := hNpos r ω hω
      have hdc := dcnt_ge cls a N A idx hN hU hH r ω
      have hd0 : 0 ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := by
        unfold dcnt; positivity
      apply max_le _ hd0
      have : (cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ)) / (N (idx r ω) : ℝ)
          ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := div_le_div_of_nonneg_right hdc hNp.le
      have e : (cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ)) / (N (idx r ω) : ℝ)
          = g r ω - ε := by
        simp only [hg, hε]; field_simp
      linarith
    have hprod2 : ∏ r, y r ≤ ∏ r, dcnt cls a A idx r ω / (N (idx r ω) : ℝ) :=
      Finset.prod_le_prod₀ (fun r _ => (le_max_right _ _ : (0:ℝ) ≤ y r)) (fun r _ => hd r)
    have hsub := prod_sub_prod_le (s := Finset.univ) (g · ω) y (fun r => le_max_right _ _)
      (fun r => max_le (by linarith [hg0 r ω hω]) (hg0 r ω hω).le) (fun r => hg1 r ω hω)
    have hsum : ∑ r, (g r ω - y r) ≤ (Fintype.card κ : ℝ) * ε := by
      have : ∀ r ∈ (Finset.univ : Finset κ), g r ω - y r ≤ ε := by
        intro r _
        simp only [hy]
        rcases le_total (g r ω - ε) 0 with h | h
        · rw [max_eq_right h]; linarith [hg0 r ω hω]
        · rw [max_eq_left h]; linarith
      calc ∑ r, (g r ω - y r) ≤ ∑ _r : κ, ε := Finset.sum_le_sum this
        _ = _ := by simp
    linarith
  have hlog : ∀ r, 0 ≤ ∑ ω ∈ A, Real.log (g r ω / σ) := fun r =>
    log_sum_nonneg cls N A idx hN r ⟨ω0, hω0⟩
  calc starMass cls a N A idx = ∑ ω ∈ A, ∏ r, dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := rfl
    _ ≥ ∑ ω ∈ A, (σ ^ (Fintype.card κ) * (1 + ∑ r, Real.log (g r ω / σ)) - (Fintype.card κ : ℝ) * ε) :=
        Finset.sum_le_sum hpt
    _ = σ ^ (Fintype.card κ) * ((A.card : ℝ) + ∑ r, ∑ ω ∈ A, Real.log (g r ω / σ))
          - (A.card : ℝ) * ((Fintype.card κ : ℝ) * ε) := by
        rw [Finset.sum_sub_distrib, ← Finset.mul_sum, Finset.sum_add_distrib, Finset.sum_comm]
        simp
    _ ≥ σ ^ (Fintype.card κ) * (A.card : ℝ) - (A.card : ℝ) * ((Fintype.card κ : ℝ) * ε) := by
        have : 0 ≤ ∑ r, ∑ ω ∈ A, Real.log (g r ω / σ) := Finset.sum_nonneg (fun r _ => hlog r)
        have hσk : 0 < σ ^ (Fintype.card κ) := pow_pos hσpos _
        nlinarith
    _ = (A.card : ℝ) * (σ ^ (Fintype.card κ) - (Fintype.card κ : ℝ) / (Fintype.card H : ℝ)) := by
        simp only [hε]; ring

/-! ## The retry extractor: linear (not `q^k`) dependence on the accepting probability -/

section Retry
variable (cls : ι → Ω → L) (a : ι → Ω → H) (N : ι → ℕ) (A : Finset Ω) (idx : κ → Ω → ι)

lemma dcnt_le_cnt (r : κ) (ω : Ω) : dcnt cls a A idx r ω ≤ cnt cls A idx r ω := by
  unfold dcnt cnt
  exact_mod_cast Finset.card_le_card (fun x hx => by simp at hx ⊢; exact ⟨hx.1, hx.2.1, hx.2.2.1⟩)

/-- `|Ω|` times the success probability of an extractor that, for each component, applies the
post-processing `Ψ` to the probability that one fresh re-sample of the class is good. -/
noncomputable def genMass (Ψ : ℝ → ℝ) : ℝ :=
  ∑ ω ∈ A, ∏ r, Ψ (dcnt cls a A idx r ω / (N (idx r ω) : ℝ))

/-- `1 - (1 - x)^T`: probability that at least one of `T` independent re-samples is good, when one
re-sample is good with probability `x`. -/
noncomputable def retryΨ (T : ℕ) (x : ℝ) : ℝ := 1 - (1 - x) ^ T

lemma light_card (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i) (r : κ)
    (δ : ℝ) (hδ : 0 < δ) :
    ((A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ))).card : ℝ) ≤
      δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) := by
  classical
  have hterm : ∀ ω ∈ A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ)),
      (1 : ℝ) ≤ δ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω) := by
    intro ω hω
    rw [Finset.mem_filter] at hω
    have hc := cnt_ge_one cls A idx r hω.1
    have hcpos : (0 : ℝ) < cnt cls A idx r ω := by linarith
    rw [← mul_div_assoc, le_div_iff₀ hcpos]
    linarith [hω.2]
  calc ((A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ))).card : ℝ)
      = ∑ _ω ∈ A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ)), (1 : ℝ) := by simp
    _ ≤ ∑ ω ∈ A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ)),
          δ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω) := Finset.sum_le_sum hterm
    _ ≤ ∑ ω ∈ A, δ * ((N (idx r ω) : ℝ) / cnt cls A idx r ω) := by
        apply Finset.sum_le_sum_of_subset_of_nonneg (Finset.filter_subset _ _)
        intro ω hω _
        have hc := cnt_ge_one cls A idx r hω
        have hN0 : (0 : ℝ) ≤ N (idx r ω) := Nat.cast_nonneg _
        have : (0 : ℝ) < cnt cls A idx r ω := by linarith
        positivity
    _ = δ * ∑ ω ∈ A, (N (idx r ω) : ℝ) / cnt cls A idx r ω := by rw [Finset.mul_sum]
    _ ≤ δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) :=
        mul_le_mul_of_nonneg_left (inv_sum_le cls N A idx hN r) hδ.le

/-- **Retry form of the k-fork lemma.**  With `T` independent re-samples per component and any threshold
`δ > 1/|H|`:   success mass `>= (|A| - k δ q |Ω|) * (1 - (1 - (δ - 1/|H|))^T)^k`.
Choosing `δ = p/(2kq)` and `T ~ (4kq/p) ln(2k)` gives success `>= p/4` (linear in `p`). -/
theorem retry_mass_ge (hN : ∀ i ω, (univ.filter (fun ω' => cls i ω' = cls i ω)).card = N i)
    (hU : ∀ i ω (c : H),
      (univ.filter (fun ω' => cls i ω' = cls i ω ∧ a i ω' = c)).card * Fintype.card H = N i)
    (hH : 0 < Fintype.card H) (T : ℕ) (δ : ℝ) (hδ : 1 / (Fintype.card H : ℝ) < δ)
    (hδ1 : δ - 1 / (Fintype.card H : ℝ) ≤ 1) :
    genMass cls a N A idx (retryΨ T) ≥
      ((A.card : ℝ) - (Fintype.card κ : ℝ) * (δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)))) *
        (1 - (1 - (δ - 1 / (Fintype.card H : ℝ))) ^ T) ^ (Fintype.card κ) := by
  classical
  have hHr : (0 : ℝ) < Fintype.card H := by exact_mod_cast hH
  set ε : ℝ := 1 / (Fintype.card H : ℝ) with hε
  have hε0 : 0 ≤ ε := by positivity
  have hδ0 : 0 < δ := lt_of_le_of_lt hε0 hδ
  set y : ℝ := δ - ε with hy
  have hy0 : 0 < y := by linarith
  set c : ℝ := 1 - (1 - y) ^ T with hc
  have hc0 : 0 ≤ c := by
    have : (1 - y) ^ T ≤ 1 := pow_le_one₀ (by linarith) (by linarith)
    linarith
  set heavy := A.filter (fun ω => ∀ r, δ * (N (idx r ω) : ℝ) ≤ cnt cls A idx r ω) with hheavy
  -- heavy is almost everything
  have hcard : (A.card : ℝ) - (Fintype.card κ : ℝ) * (δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)))
      ≤ heavy.card := by
    have h1 : A.card = heavy.card + (A.filter (fun ω => ¬ ∀ r, δ * (N (idx r ω) : ℝ) ≤ cnt cls A idx r ω)).card :=
      (Finset.card_filter_add_card_filter_not (s := A) _).symm
    have h2 : (A.filter (fun ω => ¬ ∀ r, δ * (N (idx r ω) : ℝ) ≤ cnt cls A idx r ω)) ⊆
        Finset.univ.biUnion (fun r => A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ))) := by
      intro ω hω
      simp only [Finset.mem_filter, Finset.mem_biUnion, Finset.mem_univ, true_and, not_forall, not_le] at hω ⊢
      obtain ⟨hA, r, hr⟩ := hω
      exact ⟨r, hA, hr⟩
    have h3 := (Finset.card_le_card h2).trans Finset.card_biUnion_le
    have h4 : ((A.filter (fun ω => ¬ ∀ r, δ * (N (idx r ω) : ℝ) ≤ cnt cls A idx r ω)).card : ℝ) ≤
        (Fintype.card κ : ℝ) * (δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ))) := by
      calc _ ≤ ((∑ r : κ, (A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ))).card : ℕ) : ℝ) := by
            exact_mod_cast h3
        _ = ∑ r : κ, ((A.filter (fun ω => cnt cls A idx r ω < δ * (N (idx r ω) : ℝ))).card : ℝ) := by
            push_cast; rfl
        _ ≤ ∑ _r : κ, δ * ((Fintype.card ι : ℝ) * (Fintype.card Ω : ℝ)) :=
            Finset.sum_le_sum (fun r _ => light_card cls N A idx hN r δ hδ0)
        _ = _ := by simp
    have : (A.card : ℝ) = heavy.card + ((A.filter (fun ω => ¬ ∀ r, δ * (N (idx r ω) : ℝ) ≤ cnt cls A idx r ω)).card : ℝ) := by
      exact_mod_cast h1
    linarith
  -- pointwise
  have hNpos : ∀ r, ∀ ω ∈ A, (0 : ℝ) < N (idx r ω) := by
    intro r ω hω
    have h1 := cnt_ge_one cls A idx r hω
    have h2 := cnt_le cls N A idx hN r ω
    linarith
  have hfac : ∀ ω ∈ heavy, ∀ r, c ≤ retryΨ T (dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) := by
    intro ω hω r
    rw [Finset.mem_filter] at hω
    have hNp := hNpos r ω hω.1
    have hdc := dcnt_ge cls a N A idx hN hU hH r ω
    have hx : y ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := by
      have h1 : (cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ)) / (N (idx r ω) : ℝ)
          ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := div_le_div_of_nonneg_right hdc hNp.le
      have h2 : y ≤ (cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ)) / (N (idx r ω) : ℝ) := by
        have e : (cnt cls A idx r ω - (N (idx r ω) : ℝ) / (Fintype.card H : ℝ)) / (N (idx r ω) : ℝ)
            = cnt cls A idx r ω / (N (idx r ω) : ℝ) - ε := by
          simp only [hε]; field_simp
        rw [e, hy]
        have := hω.2 r
        have h3 : δ ≤ cnt cls A idx r ω / (N (idx r ω) : ℝ) := by
          rw [le_div_iff₀ hNp]; exact this
        linarith
      linarith
    have hx1 : dcnt cls a A idx r ω / (N (idx r ω) : ℝ) ≤ 1 := by
      rw [div_le_one hNp]
      exact (dcnt_le_cnt cls a A idx r ω).trans (cnt_le cls N A idx hN r ω)
    unfold retryΨ
    have : (1 - dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) ^ T ≤ (1 - y) ^ T :=
      pow_le_pow_left₀ (by linarith) (by linarith) T
    linarith
  have hnn : ∀ ω ∈ A, 0 ≤ ∏ r, retryΨ T (dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) := by
    intro ω hω
    apply Finset.prod_nonneg; intro r _
    have hNp := hNpos r ω hω
    have hx0 : 0 ≤ dcnt cls a A idx r ω / (N (idx r ω) : ℝ) := by unfold dcnt; positivity
    have hx1 : dcnt cls a A idx r ω / (N (idx r ω) : ℝ) ≤ 1 := by
      rw [div_le_one hNp]
      exact (dcnt_le_cnt cls a A idx r ω).trans (cnt_le cls N A idx hN r ω)
    unfold retryΨ
    have : (1 - dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) ^ T ≤ 1 := pow_le_one₀ (by linarith) (by linarith)
    linarith
  calc genMass cls a N A idx (retryΨ T)
      = ∑ ω ∈ A, ∏ r, retryΨ T (dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) := rfl
    _ ≥ ∑ ω ∈ heavy, ∏ r, retryΨ T (dcnt cls a A idx r ω / (N (idx r ω) : ℝ)) :=
        Finset.sum_le_sum_of_subset_of_nonneg (Finset.filter_subset _ _) (fun ω hω _ => hnn ω hω)
    _ ≥ ∑ _ω ∈ heavy, c ^ (Fintype.card κ) := by
        apply Finset.sum_le_sum; intro ω hω
        calc c ^ (Fintype.card κ) = ∏ _r : κ, c := by simp
          _ ≤ _ := Finset.prod_le_prod₀ (fun _ _ => hc0) (fun r _ => hfac ω hω r)
    _ = (heavy.card : ℝ) * c ^ (Fintype.card κ) := by simp
    _ ≥ _ := mul_le_mul_of_nonneg_right hcard (pow_nonneg hc0 _)

end Retry

end PcaMath.Star
