import Mathlib
import PcaMath.OtDefs

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [DecidableEq V] [DecidableEq D]

theorem eSet_cons_H (v : V) (x t d : D) (τ : List (Qry V D × D)) :
    eSet ((Qry.H v x t, d) :: τ) = eSet τ := by
  simp [eSet]

theorem eSet_cons_P (z d : D) (τ : List (Qry V D × D)) :
    eSet ((Qry.P z, d) :: τ) = insert (z, d) (eSet τ) := by
  ext p; simp [eSet, List.mem_filterMap]

theorem eSet_cons_Pi (w d : D) (τ : List (Qry V D × D)) :
    eSet ((Qry.Pi w, d) :: τ) = insert (d, w) (eSet τ) := by
  ext p; simp [eSet, List.mem_filterMap]

theorem hSet_cons_P (z d : D) (τ : List (Qry V D × D)) :
    hSet ((Qry.P z, d) :: τ) = hSet τ := by
  simp [hSet]

theorem hSet_cons_Pi (w d : D) (τ : List (Qry V D × D)) :
    hSet ((Qry.Pi w, d) :: τ) = hSet τ := by
  simp [hSet]

theorem hSet_cons_H (v : V) (x t d : D) (τ : List (Qry V D × D)) :
    hSet ((Qry.H v x t, d) :: τ) = insert ((v, x, t), d) (hSet τ) := by
  ext p; simp [hSet, List.mem_filterMap]

theorem mem_hSet {ents : List (Qry V D × D)} {h : (V × D × D) × D} :
    h ∈ hSet ents ↔ (Qry.H h.1.1 h.1.2.1 h.1.2.2, h.2) ∈ ents := by
  induction ents with
  | nil => simp [hSet]
  | cons e τ ih =>
    obtain ⟨q, d⟩ := e
    cases q with
    | P z => rw [hSet_cons_P, ih]; simp
    | Pi w => rw [hSet_cons_Pi, ih]; simp
    | H v x t =>
      rw [hSet_cons_H, Finset.mem_insert, ih]
      simp only [List.mem_cons, Prod.mk.injEq, Qry.H.injEq]
      constructor
      · rintro (rfl | h); · simp
        · exact Or.inr h
      · rintro (⟨⟨h1, h2, h3⟩, h4⟩ | h)
        · left; ext <;> simp [h1, h2, h3, h4]
        · exact Or.inr h

theorem mem_eSet {ents : List (Qry V D × D)} {p : D × D} :
    p ∈ eSet ents ↔ (Qry.P p.1, p.2) ∈ ents ∨ (Qry.Pi p.2, p.1) ∈ ents := by
  induction ents with
  | nil => simp [eSet]
  | cons e τ ih =>
    obtain ⟨q, d⟩ := e
    cases q with
    | H v x t => rw [eSet_cons_H, ih]; simp
    | P z =>
      rw [eSet_cons_P, Finset.mem_insert, ih]
      simp [Prod.ext_iff]
      tauto
    | Pi w =>
      rw [eSet_cons_Pi, Finset.mem_insert, ih]
      simp [Prod.ext_iff]
      tauto

theorem card_sets_le : ∀ {A : Adv V D} {τ : List (Qry V D × D)} {b : Bool} {kp kh : ℕ},
    IsPath A τ b → A.Bdd kp kh → (eSet τ).card ≤ kp ∧ (hSet τ).card ≤ kh := by
  intro A τ b kp kh hp
  induction hp generalizing kp kh with
  | done b => intro _; simp [eSet, hSet]
  | ask q k d τ b hk ih =>
    intro hb
    cases q with
    | P z =>
      obtain ⟨hpos, hall⟩ := hb
      obtain ⟨h1, h2⟩ := ih (hall d)
      rw [eSet_cons_P, hSet_cons_P]
      exact ⟨le_trans (Finset.card_insert_le _ _) (by omega), h2⟩
    | Pi w =>
      obtain ⟨hpos, hall⟩ := hb
      obtain ⟨h1, h2⟩ := ih (hall d)
      rw [eSet_cons_Pi, hSet_cons_Pi]
      exact ⟨le_trans (Finset.card_insert_le _ _) (by omega), h2⟩
    | H v x t =>
      obtain ⟨hpos, hall⟩ := hb
      obtain ⟨h1, h2⟩ := ih (hall d)
      rw [eSet_cons_H, hSet_cons_H]
      exact ⟨h1, le_trans (Finset.card_insert_le _ _) (by omega)⟩

theorem consY_iff (π : Equiv.Perm D) (R : V × D × D → D) (ents : List (Qry V D × D)) :
    (∀ e ∈ ents, oY π R e.1 = e.2) ↔
      (∀ p ∈ eSet ents, π p.1 = p.2) ∧ (∀ h ∈ hSet ents, R h.1 = h.2) := by
  constructor
  · intro H
    refine ⟨fun p hp => ?_, fun h hh => ?_⟩
    · rcases mem_eSet.mp hp with h | h
      · exact H _ h
      · have := H _ h
        simp only [oY] at this
        exact (π.apply_eq_iff_eq_symm_apply).mpr this.symm
    · have := H _ (mem_hSet.mp hh); simpa [oY] using this
  · rintro ⟨H1, H2⟩ ⟨q, d⟩ he
    cases q with
    | P z => exact H1 (z, d) (mem_eSet.mpr (Or.inl he))
    | Pi w =>
      have := H1 (d, w) (mem_eSet.mpr (Or.inr he))
      simp only [oY]; rw [Equiv.symm_apply_eq]; exact this.symm
    | H v x t => exact H2 ((v, x, t), d) (mem_hSet.mpr he)

variable [AddCommGroup D]

theorem consX_iff (π : Equiv.Perm D) (Δ : V → D) (ents : List (Qry V D × D)) :
    (∀ e ∈ ents, oX π Δ e.1 = e.2) ↔
      (∀ p ∈ eSet ents, π p.1 = p.2) ∧
      (∀ h ∈ hSet ents, π (π (h.1.2.1 + Δ h.1.1) + h.1.2.2) + π (h.1.2.1 + Δ h.1.1) = h.2) := by
  constructor
  · intro H
    refine ⟨fun p hp => ?_, fun h hh => ?_⟩
    · rcases mem_eSet.mp hp with h | h
      · exact H _ h
      · have := H _ h
        simp only [oX] at this
        exact (π.apply_eq_iff_eq_symm_apply).mpr this.symm
    · have := H _ (mem_hSet.mp hh); simpa [oX] using this
  · rintro ⟨H1, H2⟩ ⟨q, d⟩ he
    cases q with
    | P z => exact H1 (z, d) (mem_eSet.mpr (Or.inl he))
    | Pi w =>
      have := H1 (d, w) (mem_eSet.mpr (Or.inr he))
      simp only [oX]; rw [Equiv.symm_apply_eq]; exact this.symm
    | H v x t => exact H2 ((v, x, t), d) (mem_hSet.mpr he)

end PcaMath.OtDefs
