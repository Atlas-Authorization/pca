import Mathlib
open Finset

namespace PcaMath.OtHC

lemma sumfib {Ω T : Type*} [Fintype Ω] [DecidableEq T] (f : Ω → T) (U : Finset T) :
    ∑ τ ∈ U, ((Finset.univ.filter (fun ω => f ω = τ)).card : ℝ)
      = ((Finset.univ.filter (fun ω => f ω ∈ U)).card : ℝ) := by
  have h := Finset.card_eq_sum_card_fiberwise (f := f)
    (s := Finset.univ.filter (fun ω => f ω ∈ U)) (t := U) (by intro x hx; simpa using hx)
  have h2 : ∑ b ∈ U, ((Finset.univ.filter (fun ω => f ω ∈ U)).filter (fun a => f a = b)).card
      = ∑ τ ∈ U, (Finset.univ.filter (fun ω => f ω = τ)).card := by
    apply Finset.sum_congr rfl
    intro b hb
    congr 1
    ext ω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    constructor
    · exact fun h => h.2
    · intro h; exact ⟨h ▸ hb, h⟩
  have : (Finset.univ.filter (fun ω => f ω ∈ U)).card
      = ∑ τ ∈ U, (Finset.univ.filter (fun ω => f ω = τ)).card := h.trans h2
  exact_mod_cast this.symm

theorem hcoef {Ω1 Ω2 T : Type*} [Fintype Ω1] [Fintype Ω2] [Nonempty Ω1] [Nonempty Ω2] [DecidableEq T]
    (f1 : Ω1 → T) (f2 : Ω2 → T) (Bad : T → Prop) [DecidablePred Bad] (ε δ : ℝ) (hε : 0 ≤ ε)
    (hbad : ((Finset.univ.filter (fun ω => Bad (f2 ω))).card : ℝ) / Fintype.card Ω2 ≤ δ)
    (hgood : ∀ τ ∈ Finset.univ.image f2, ¬ Bad τ →
      (1 - ε) * (((Finset.univ.filter (fun ω => f2 ω = τ)).card : ℝ) / Fintype.card Ω2)
        ≤ ((Finset.univ.filter (fun ω => f1 ω = τ)).card : ℝ) / Fintype.card Ω1)
    (S : T → Prop) [DecidablePred S] :
    ((Finset.univ.filter (fun ω => S (f2 ω))).card : ℝ) / Fintype.card Ω2
      - ((Finset.univ.filter (fun ω => S (f1 ω))).card : ℝ) / Fintype.card Ω1 ≤ δ + ε := by
  classical
  have hn1 : (0 : ℝ) < Fintype.card Ω1 := by exact_mod_cast Fintype.card_pos
  have hn2 : (0 : ℝ) < Fintype.card Ω2 := by exact_mod_cast Fintype.card_pos
  set n1 : ℝ := (Fintype.card Ω1 : ℝ)
  set n2 : ℝ := (Fintype.card Ω2 : ℝ)
  set A := Finset.univ.image f2 with hA
  set U := A.filter S with hU
  set p1 : T → ℝ := fun τ => ((Finset.univ.filter (fun ω => f1 ω = τ)).card : ℝ) / n1 with hp1
  set p2 : T → ℝ := fun τ => ((Finset.univ.filter (fun ω => f2 ω = τ)).card : ℝ) / n2 with hp2
  have p1nn : ∀ τ, 0 ≤ p1 τ := fun τ => by positivity
  have p2nn : ∀ τ, 0 ≤ p2 τ := fun τ => by positivity
  -- Pr2 = Σ_U p2
  have e2 : ((Finset.univ.filter (fun ω => S (f2 ω))).card : ℝ) / n2 = ∑ τ ∈ U, p2 τ := by
    rw [hp2, ← Finset.sum_div, sumfib]
    congr 3
    ext ω
    simp [hU, hA]
  -- Pr1 ≥ Σ_U p1
  have e1 : ∑ τ ∈ U, p1 τ ≤ ((Finset.univ.filter (fun ω => S (f1 ω))).card : ℝ) / n1 := by
    rw [hp1, ← Finset.sum_div, sumfib]
    apply div_le_div_of_nonneg_right _ hn1.le
    exact_mod_cast Finset.card_le_card (by
      intro ω hω
      simp only [Finset.mem_filter, Finset.mem_univ, true_and, hU] at hω ⊢
      exact hω.2)
  have split : ∑ τ ∈ U, (p2 τ - p1 τ)
      = ∑ τ ∈ U.filter Bad, (p2 τ - p1 τ) + ∑ τ ∈ U.filter (fun τ => ¬ Bad τ), (p2 τ - p1 τ) :=
    (Finset.sum_filter_add_sum_filter_not U Bad _).symm
  have bad_part : ∑ τ ∈ U.filter Bad, (p2 τ - p1 τ) ≤ δ := by
    calc ∑ τ ∈ U.filter Bad, (p2 τ - p1 τ) ≤ ∑ τ ∈ U.filter Bad, p2 τ :=
          Finset.sum_le_sum (fun τ _ => by linarith [p1nn τ])
      _ = ((Finset.univ.filter (fun ω => f2 ω ∈ U.filter Bad)).card : ℝ) / n2 := by
          rw [hp2, ← Finset.sum_div, sumfib]
      _ ≤ ((Finset.univ.filter (fun ω => Bad (f2 ω))).card : ℝ) / n2 := by
          apply div_le_div_of_nonneg_right _ hn2.le
          exact_mod_cast Finset.card_le_card (by
            intro ω hω
            simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
            exact hω.2)
      _ ≤ δ := hbad
  have good_part : ∑ τ ∈ U.filter (fun τ => ¬ Bad τ), (p2 τ - p1 τ) ≤ ε := by
    calc ∑ τ ∈ U.filter (fun τ => ¬ Bad τ), (p2 τ - p1 τ)
        ≤ ∑ τ ∈ U.filter (fun τ => ¬ Bad τ), ε * p2 τ := by
          apply Finset.sum_le_sum
          intro τ hτ
          rw [Finset.mem_filter, hU, Finset.mem_filter] at hτ
          have := hgood τ hτ.1.1 hτ.2
          simp only [hp1, hp2] at this ⊢
          linarith
      _ = ε * (((Finset.univ.filter (fun ω => f2 ω ∈ U.filter (fun τ => ¬ Bad τ))).card : ℝ) / n2) := by
          rw [← Finset.mul_sum, hp2, ← Finset.sum_div, sumfib]
      _ ≤ ε * 1 := by
          apply mul_le_mul_of_nonneg_left _ hε
          rw [div_le_one hn2]
          have h := Finset.card_le_univ (Finset.univ.filter (fun ω => f2 ω ∈ U.filter (fun τ => ¬ Bad τ)))
          have h' : (((Finset.univ.filter (fun ω => f2 ω ∈ U.filter (fun τ => ¬ Bad τ))).card : ℕ) : ℝ) ≤ (Fintype.card Ω2 : ℝ) := by exact_mod_cast h
          exact h'
      _ = ε := mul_one ε
  have : ∑ τ ∈ U, (p2 τ - p1 τ) = ∑ τ ∈ U, p2 τ - ∑ τ ∈ U, p1 τ := Finset.sum_sub_distrib _ _
  linarith

theorem card_fun_extend {α β : Type*} [Fintype α] [DecidableEq α] [Fintype β] [DecidableEq β]
    (ctx : Finset (α × β)) (hf : ∀ p ∈ ctx, ∀ q ∈ ctx, p.1 = q.1 → p.2 = q.2) :
    (Finset.univ.filter (fun f : α → β => ∀ p ∈ ctx, f p.1 = p.2)).card
      = Fintype.card β ^ (Fintype.card α - ctx.card) := by
  set D := ctx.image Prod.fst with hD
  let t : α → Finset β := fun a =>
    if a ∈ D then (ctx.filter (fun p => p.1 = a)).image Prod.snd else Finset.univ
  have hset : Finset.univ.filter (fun f : α → β => ∀ p ∈ ctx, f p.1 = p.2)
      = Fintype.piFinset t := by
    ext f
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Fintype.mem_piFinset]
    constructor
    · intro h a
      by_cases ha : a ∈ D
      · simp only [t, if_pos ha]
        obtain ⟨p, hp, rfl⟩ := Finset.mem_image.mp ha
        exact Finset.mem_image.mpr ⟨p, Finset.mem_filter.mpr ⟨hp, rfl⟩, (h p hp).symm⟩
      · simp [t, ha]
    · intro h p hp
      have hpD : p.1 ∈ D := Finset.mem_image.mpr ⟨p, hp, rfl⟩
      have := h p.1
      simp only [t, if_pos hpD] at this
      obtain ⟨q, hq, hq2⟩ := Finset.mem_image.mp this
      rw [Finset.mem_filter] at hq
      rw [← hq2]
      exact (hf p hp q hq.1 hq.2.symm).symm
  have hcard : ∀ a, (t a).card = if a ∈ D then 1 else Fintype.card β := by
    intro a
    by_cases ha : a ∈ D
    · simp only [t, if_pos ha]
      obtain ⟨p, hp, rfl⟩ := Finset.mem_image.mp ha
      rw [Finset.card_eq_one]
      refine ⟨p.2, ?_⟩
      ext b
      simp only [Finset.mem_image, Finset.mem_filter, Finset.mem_singleton]
      constructor
      · rintro ⟨q, ⟨hq, hq1⟩, rfl⟩
        exact (hf p hp q hq hq1.symm).symm
      · rintro rfl
        exact ⟨p, ⟨hp, rfl⟩, rfl⟩
    · simp [t, ha]
  have hDc : D.card = ctx.card := by
    apply Finset.card_image_of_injOn
    intro p hp q hq h
    exact Prod.ext h (hf p hp q hq h)
  rw [hset, Fintype.card_piFinset]
  simp only [hcard]
  rw [Finset.prod_ite, Finset.prod_const_one, one_mul, Finset.prod_const]
  congr 1
  have : (Finset.univ.filter (fun a => ¬ a ∈ D)).card = Fintype.card α - D.card := by
    rw [Finset.filter_not, Finset.card_sdiff_of_subset (Finset.subset_univ _), Finset.card_univ]
    simp
  rw [this, hDc]

end PcaMath.OtHC
