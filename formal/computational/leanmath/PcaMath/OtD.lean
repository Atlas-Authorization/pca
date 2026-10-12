import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtB
import PcaMath.OtC
import PcaMath.OtHC
import PcaMath.OtPerm
import PcaMath.OtLin

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

theorem Func_card_le {α β : Type} [Fintype α] [DecidableEq α] {ctx : Finset (α × β)} (hf : Func ctx) :
    ctx.card ≤ Fintype.card α := by
  have hinj : Set.InjOn Prod.fst (ctx : Set (α × β)) := by
    intro p hp q hq h
    exact Prod.ext h (hf p hp q hq h)
  have h1 : (ctx.image Prod.fst).card = ctx.card := Finset.card_image_of_injOn hinj
  rw [← h1]
  exact le_trans (Finset.card_le_univ _) le_rfl

/-- number of ideal-world randomnesses producing a given (realisable) transcript -/
theorem cardY (ents : List (Qry V D × D))
    (hex : ∃ (π : Equiv.Perm D) (R : V × D × D → D), ∀ e ∈ ents, oY π R e.1 = e.2) :
    (Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) =>
        ∀ e ∈ ents, oY ω.1 ω.2 e.1 = e.2)).card
      = (Fintype.card D - (eSet ents).card).factorial *
        Fintype.card D ^ (Fintype.card (V × D × D) - (hSet ents).card) := by
  obtain ⟨π0, R0, h0⟩ := hex
  obtain ⟨hE0, hH0⟩ := (consY_iff π0 R0 ents).mp h0
  have hprod : (Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) =>
        ∀ e ∈ ents, oY ω.1 ω.2 e.1 = e.2))
      = (Finset.univ.filter (fun π : Equiv.Perm D => ∀ p ∈ eSet ents, π p.1 = p.2)) ×ˢ
        (Finset.univ.filter (fun R : V × D × D → D => ∀ h ∈ hSet ents, R h.1 = h.2)) := by
    ext ⟨π, R⟩
    simp only [mem_filter, mem_univ, true_and, mem_product]
    exact consY_iff π R ents
  rw [hprod, Finset.card_product]
  congr 1
  · have hd : Function.Injective (fun p : ↥(eSet ents) => p.1.1) := by
      intro p q h
      apply Subtype.ext
      have h1 := hE0 p.1 p.2
      have h2 := hE0 q.1 q.2
      exact Prod.ext h (by rw [← h1, ← h2]; exact congrArg π0 h)
    have hr : Function.Injective (fun p : ↥(eSet ents) => p.1.2) := by
      intro p q h
      apply Subtype.ext
      have h1 := hE0 p.1 p.2
      have h2 := hE0 q.1 q.2
      have : π0 p.1.1 = π0 q.1.1 := by rw [h1, h2]; exact h
      exact Prod.ext (π0.injective this) h
    have := OtPerm.card_perm_extend (fun p : ↥(eSet ents) => p.1.1) (fun p => p.1.2) hd hr
    rw [Fintype.card_coe] at this
    rw [← this]
    congr 1
    ext π
    simp only [mem_filter, mem_univ, true_and, Subtype.forall]
  · exact OtHC.card_fun_extend (hSet ents) (fun p hp q hq h => by
      have h1 := hH0 p hp
      have h2 := hH0 q hq
      rw [← h1, ← h2, h])

theorem two_mul_choose_two (n : ℕ) : 2 * n.choose 2 = n * (n - 1) := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [Nat.choose_succ_succ, Nat.choose_one_right, mul_add, ih]
    cases n <;> simp <;> ring_nf <;> omega

section Struct

variable (E : Finset (D × D)) (Hs : Finset ((V × D × D) × D))

abbrev GrS : Finset (V × D) := Hs.image (fun h => (h.1.1, h.1.2.1))
abbrev VarT := V ⊕ ↥(GrS Hs)
abbrev PosT := ↥E ⊕ ↥(GrS Hs) ⊕ ↥Hs

def grpOf (h : ↥Hs) : ↥(GrS Hs) := ⟨(h.1.1.1, h.1.1.2.1), Finset.mem_image_of_mem _ h.2⟩

def domT : PosT E Hs → OtLin.Term (VarT Hs) D
  | Sum.inl e => (none, e.1.1)
  | Sum.inr (Sum.inl g) => (some (Sum.inl g.1.1), g.1.2)
  | Sum.inr (Sum.inr h) => (some (Sum.inr (grpOf Hs h)), h.1.1.2.2)

def rngT : PosT E Hs → OtLin.Term (VarT Hs) D
  | Sum.inl e => (none, e.1.2)
  | Sum.inr (Sum.inl g) => (some (Sum.inr g), 0)
  | Sum.inr (Sum.inr h) => (some (Sum.inr (grpOf Hs h)), h.1.2)

variable {E Hs}

theorem hsame_dom (hEd : ∀ p ∈ E, ∀ q ∈ E, p.1 = q.1 → p = q) (hHf : Func Hs) :
    ∀ p p' : PosT E Hs, p ≠ p' → (domT E Hs p).1 = (domT E Hs p').1 →
      (domT E Hs p).2 ≠ (domT E Hs p').2 := by
  intro p p' hne hvar
  rcases p with e | g | h <;> rcases p' with e' | g' | h' <;> simp only [domT] at hvar ⊢
  all_goals try (exfalso; simp at hvar; done)
  · intro hh
    exact hne (congrArg Sum.inl (Subtype.ext (hEd _ e.2 _ e'.2 hh)))
  · simp only [Option.some.injEq, Sum.inl.injEq] at hvar
    intro hh
    apply hne
    congr 2
    exact Subtype.ext (Prod.ext hvar hh)
  · simp only [Option.some.injEq, Sum.inr.injEq] at hvar
    intro ht
    apply hne
    have hg : grpOf Hs h = grpOf Hs h' := hvar
    have hv : h.1.1.1 = h'.1.1.1 := congrArg (fun z => z.1.1) hg
    have hx : h.1.1.2.1 = h'.1.1.2.1 := congrArg (fun z => z.1.2) hg
    have h11 : h.1.1 = h'.1.1 := Prod.ext hv (Prod.ext hx ht)
    have h1 : h.1 = h'.1 := Prod.ext h11 (hHf h.1 h.2 h'.1 h'.2 h11)
    exact congrArg (fun z => Sum.inr (Sum.inr z)) (Subtype.ext h1)

theorem hsame_rng (hEr : ∀ p ∈ E, ∀ q ∈ E, p.2 = q.2 → p = q) (hnb : ¬ BadH Hs) :
    ∀ p p' : PosT E Hs, p ≠ p' → (rngT E Hs p).1 = (rngT E Hs p').1 →
      (rngT E Hs p).2 ≠ (rngT E Hs p').2 := by
  have hz : ∀ h ∈ Hs, h.2 ≠ 0 := fun h hh h0 => hnb (Or.inl ⟨h, hh, h0⟩)
  intro p p' hne hvar
  rcases p with e | g | h <;> rcases p' with e' | g' | h' <;> simp only [rngT] at hvar ⊢
  all_goals try (exfalso; simp at hvar; done)
  · intro hh
    exact hne (congrArg Sum.inl (Subtype.ext (hEr _ e.2 _ e'.2 hh)))
  · simp only [Option.some.injEq, Sum.inr.injEq] at hvar
    exact absurd (congrArg (fun z => Sum.inr (Sum.inl z)) hvar) hne
  · intro h0
    exact hz h'.1 h'.2 h0.symm
  · intro h0
    exact hz h.1 h.2 h0
  · simp only [Option.some.injEq, Sum.inr.injEq] at hvar
    intro ho
    apply hnb
    have hg : grpOf Hs h = grpOf Hs h' := hvar
    have hv : h.1.1.1 = h'.1.1.1 := congrArg (fun z => z.1.1) hg
    have hx : h.1.1.2.1 = h'.1.1.2.1 := congrArg (fun z => z.1.2) hg
    refine Or.inr ⟨h.1, h.2, h'.1, h'.2, hv, hx, ?_, ho⟩
    intro h1
    exact hne (congrArg (fun z => Sum.inr (Sum.inr z)) (Subtype.ext h1))

/-- an assignment `σ` is good when all new domain points and all new range points are pairwise distinct -/
def GoodS (E : Finset (D × D)) (Hs : Finset ((V × D × D) × D)) (σ : VarT Hs → D) : Prop :=
  (∀ p p' : PosT E Hs, p ≠ p' → (domT E Hs p).eval σ ≠ (domT E Hs p').eval σ) ∧
  (∀ p p' : PosT E Hs, p ≠ p' → (rngT E Hs p).eval σ ≠ (rngT E Hs p').eval σ)

end Struct

end PcaMath.OtDefs
