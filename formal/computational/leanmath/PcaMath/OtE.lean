import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtB
import PcaMath.OtC
import PcaMath.OtD
import PcaMath.OtHC
import PcaMath.OtPerm
import PcaMath.OtLin

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]
variable {E : Finset (D × D)} {Hs : Finset ((V × D × D) × D)}

open Classical in
theorem good_count (hEd : ∀ p ∈ E, ∀ q ∈ E, p.1 = q.1 → p = q)
    (hEr : ∀ p ∈ E, ∀ q ∈ E, p.2 = q.2 → p = q) (hHf : Func Hs) (hnb : ¬ BadH Hs) :
    ((Finset.univ.filter (fun σ : VarT Hs → D => ¬ GoodS E Hs σ)).card : ℝ) * Fintype.card D
      ≤ ((Fintype.card (PosT E Hs) * (Fintype.card (PosT E Hs) - 1) : ℕ) : ℝ) *
        (Fintype.card D : ℝ) ^ (Fintype.card (VarT Hs)) := by
  have hA := OtLin.card_bad_le_real (domT E Hs) (hsame_dom hEd hHf)
  have hB := OtLin.card_bad_le_real (rngT E Hs) (hsame_rng hEr hnb)
  have hsub : (Finset.univ.filter (fun σ : VarT Hs → D => ¬ GoodS E Hs σ)) ⊆
      (Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (domT E Hs p).eval σ = (domT E Hs p').eval σ)) ∪
      (Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (rngT E Hs p).eval σ = (rngT E Hs p').eval σ)) := by
    intro σ hσ
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, GoodS, not_and_or, not_forall,
      Finset.mem_union] at hσ ⊢
    rcases hσ with ⟨p, p', hne, h⟩ | ⟨p, p', hne, h⟩
    · left; exact ⟨p, p', hne, not_not.mp h⟩
    · right; exact ⟨p, p', hne, not_not.mp h⟩
  have h1 := Finset.card_le_card hsub
  have h2 := Finset.card_union_le (Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (domT E Hs p).eval σ = (domT E Hs p').eval σ))
      (Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (rngT E Hs p).eval σ = (rngT E Hs p').eval σ))
  have h3 : ((Finset.univ.filter (fun σ : VarT Hs → D => ¬ GoodS E Hs σ)).card : ℝ) ≤
      ((Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (domT E Hs p).eval σ = (domT E Hs p').eval σ)).card : ℝ) +
      ((Finset.univ.filter (fun σ : VarT Hs → D =>
        ∃ p p', p ≠ p' ∧ (rngT E Hs p).eval σ = (rngT E Hs p').eval σ)).card : ℝ) := by
    exact_mod_cast le_trans h1 h2
  have hN : (0 : ℝ) ≤ Fintype.card D := by positivity
  have hc : ((Fintype.card (PosT E Hs) * (Fintype.card (PosT E Hs) - 1) : ℕ) : ℝ) =
      2 * ((Fintype.card (PosT E Hs)).choose 2 : ℝ) := by
    rw [← two_mul_choose_two]; push_cast; ring
  rw [hc]
  calc _ ≤ (_ + _) * (Fintype.card D : ℝ) := mul_le_mul_of_nonneg_right h3 hN
    _ = _ + _ := add_mul _ _ _
    _ ≤ _ := add_le_add hA hB
    _ = _ := by ring

open Classical in
theorem cardX_ge (h2 : ∀ x : D, x + x = 0) :
    (Finset.univ.filter (GoodS E Hs)).card * (Fintype.card D - Fintype.card (PosT E Hs)).factorial ≤
    (Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) =>
      (∀ p ∈ E, ω.1 p.1 = p.2) ∧
      ∀ h ∈ Hs, ω.1 (ω.1 (h.1.2.1 + ω.2 h.1.1) + h.1.2.2) + ω.1 (h.1.2.1 + ω.2 h.1.1) = h.2)).card := by
  classical
  let ext : (VarT Hs → D) → Finset (Equiv.Perm D) := fun σ =>
    Finset.univ.filter (fun π : Equiv.Perm D => ∀ p : PosT E Hs,
      π ((domT E Hs p).eval σ) = (rngT E Hs p).eval σ)
  have hext : ∀ σ, GoodS E Hs σ → (ext σ).card = (Fintype.card D - Fintype.card (PosT E Hs)).factorial := by
    intro σ hσ
    have hd : Function.Injective (fun p : PosT E Hs => (domT E Hs p).eval σ) := by
      intro p p' h
      by_contra hne
      exact hσ.1 p p' hne h
    have hr : Function.Injective (fun p : PosT E Hs => (rngT E Hs p).eval σ) := by
      intro p p' h
      by_contra hne
      exact hσ.2 p p' hne h
    exact OtPerm.card_perm_extend _ _ hd hr
  let Sg := (Finset.univ.filter (GoodS E Hs)).sigma ext
  have hSg : Sg.card = (Finset.univ.filter (GoodS E Hs)).card *
      (Fintype.card D - Fintype.card (PosT E Hs)).factorial := by
    rw [Finset.card_sigma]
    rw [Finset.sum_congr rfl (fun σ hσ => hext σ (Finset.mem_filter.mp hσ).2)]
    simp
  rw [← hSg]
  apply Finset.card_le_card_of_injOn (fun x : (Σ _ : VarT Hs → D, Equiv.Perm D) => (x.2, fun v => x.1 (Sum.inl v)))
  · rintro ⟨σ, π⟩ hx
    simp only [Sg, Finset.mem_coe, Finset.mem_sigma, Finset.mem_filter, Finset.mem_univ, true_and, ext] at hx
    obtain ⟨hg, hrel⟩ := hx
    simp only [Finset.coe_filter, Finset.mem_univ, true_and, Set.mem_setOf_eq]
    refine ⟨fun p hp => ?_, fun h hh => ?_⟩
    · have := hrel (Sum.inl ⟨p, hp⟩)
      simpa [domT, rngT, OtLin.Term.eval] using this
    · set g : ↥(GrS Hs) := grpOf Hs ⟨h, hh⟩ with hgdef
      have e1 := hrel (Sum.inr (Sum.inl g))
      have e2 := hrel (Sum.inr (Sum.inr ⟨h, hh⟩))
      simp only [domT, rngT, OtLin.Term.eval, add_zero] at e1 e2
      have e1' : π (σ (Sum.inl h.1.1) + h.1.2.1) = σ (Sum.inr g) := e1
      have e2' : π (σ (Sum.inr g) + h.1.2.2) = σ (Sum.inr g) + h.2 := e2
      show π (π (h.1.2.1 + σ (Sum.inl h.1.1)) + h.1.2.2) + π (h.1.2.1 + σ (Sum.inl h.1.1)) = h.2
      rw [add_comm h.1.2.1 (σ (Sum.inl h.1.1)), e1', e2']
      calc (σ (Sum.inr g) + h.2) + σ (Sum.inr g)
          = h.2 + (σ (Sum.inr g) + σ (Sum.inr g)) := by abel
        _ = h.2 := by rw [h2, add_zero]
  · rintro ⟨σ, π⟩ hx ⟨σ', π'⟩ hx' heq
    simp only [Sg, Finset.mem_coe, Finset.mem_sigma, Finset.mem_filter, Finset.mem_univ, true_and, ext] at hx hx'
    simp only [Prod.mk.injEq] at heq
    obtain ⟨hπ, hΔ⟩ := heq
    subst hπ
    have hσ : σ = σ' := by
      funext i
      rcases i with v | g
      · exact congrFun hΔ v
      · have e1 := hx.2 (Sum.inr (Sum.inl g))
        have e2 := hx'.2 (Sum.inr (Sum.inl g))
        simp only [domT, rngT, OtLin.Term.eval, add_zero] at e1 e2
        rw [← e1, ← e2]
        have this : σ (Sum.inl g.1.1) = σ' (Sum.inl g.1.1) := congrFun hΔ g.1.1
        rw [this]
    subst hσ
    rfl

end PcaMath.OtDefs
