import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtB
import PcaMath.OtC
import PcaMath.OtD
import PcaMath.OtE
import PcaMath.OtF
import PcaMath.OtG
import PcaMath.OtHC
import PcaMath.OtPerm
import PcaMath.OtLin

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

open Classical in
theorem hgood_bound (h2 : ∀ x : D, x + x = 0) (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh)
    (τ : List (Qry V D × D) × Bool)
    (hτ : τ ∈ Finset.univ.image (fun ω : Equiv.Perm D × (V × D × D → D) => A.play (oY ω.1 ω.2)))
    (hnb : ¬ BadT τ) :
    (1 - ((((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) / Fintype.card D)) *
      (((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => A.play (oY ω.1 ω.2) = τ)).card : ℝ)
        / Fintype.card (Equiv.Perm D × (V × D × D → D)))
    ≤ ((Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => A.play (oX ω.1 ω.2) = τ)).card : ℝ)
        / Fintype.card (Equiv.Perm D × (V → D)) := by
  obtain ⟨ω0, -, hτeq⟩ := Finset.mem_image.mp hτ
  have hpe := (play_eq_iff A (oY ω0.1 ω0.2) τ.1 τ.2).mp (by rw [hτeq])
  obtain ⟨hpath, hcons0⟩ := hpe
  have hnb' : ¬ BadH (hSet τ.1) := hnb
  obtain ⟨hE0, hH0⟩ := (consY_iff ω0.1 ω0.2 τ.1).mp hcons0
  have hEd : ∀ p ∈ eSet τ.1, ∀ q ∈ eSet τ.1, p.1 = q.1 → p = q := by
    intro p hp q hq h
    exact Prod.ext h (by rw [← hE0 p hp, ← hE0 q hq, h])
  have hEr : ∀ p ∈ eSet τ.1, ∀ q ∈ eSet τ.1, p.2 = q.2 → p = q := by
    intro p hp q hq h
    have : ω0.1 p.1 = ω0.1 q.1 := by rw [hE0 p hp, hE0 q hq, h]
    exact Prod.ext (ω0.1.injective this) h
  have hHf : Func (hSet τ.1) := by
    intro p hp q hq h
    rw [← hH0 p hp, ← hH0 q hq, h]
  have hY : (Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => A.play (oY ω.1 ω.2) = τ))
      = Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) => ∀ e ∈ τ.1, oY ω.1 ω.2 e.1 = e.2) := by
    apply Finset.filter_congr; intro ω _
    constructor
    · intro h
      exact ((play_eq_iff A (oY ω.1 ω.2) τ.1 τ.2).mp (by rw [h])).2
    · intro h
      exact (play_eq_iff A (oY ω.1 ω.2) τ.1 τ.2).mpr ⟨hpath, h⟩
  have hX : (Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => A.play (oX ω.1 ω.2) = τ))
      = Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) =>
          (∀ p ∈ eSet τ.1, ω.1 p.1 = p.2) ∧
          ∀ h ∈ hSet τ.1, ω.1 (ω.1 (h.1.2.1 + ω.2 h.1.1) + h.1.2.2) + ω.1 (h.1.2.1 + ω.2 h.1.1) = h.2) := by
    apply Finset.filter_congr; intro ω _
    rw [← consX_iff]
    constructor
    · intro h
      exact ((play_eq_iff A (oX ω.1 ω.2) τ.1 τ.2).mp (by rw [h])).2
    · intro h
      exact (play_eq_iff A (oX ω.1 ω.2) τ.1 τ.2).mpr ⟨hpath, h⟩
  have hcY := cardY τ.1 ⟨ω0.1, ω0.2, hcons0⟩
  have hcX := cardX_ge (E := eSet τ.1) (Hs := hSet τ.1) h2
  have hgc := good_count hEd hEr hHf hnb'
  have hsz := card_sets_le hpath hA
  have hHM : (hSet τ.1).card ≤ Fintype.card (V × D × D) := Func_card_le hHf
  have hgh : (GrS (hSet τ.1)).card ≤ (hSet τ.1).card := Finset.card_image_le
  have hPos : Fintype.card (PosT (eSet τ.1) (hSet τ.1)) =
      (eSet τ.1).card + (GrS (hSet τ.1)).card + (hSet τ.1).card := by
    simp only [PosT, Fintype.card_sum, Fintype.card_coe]; omega
  have hVar : Fintype.card (VarT (hSet τ.1)) = Fintype.card V + (GrS (hSet τ.1)).card := by
    simp only [VarT, Fintype.card_sum, Fintype.card_coe]
  have hsplit := Finset.card_filter_add_card_filter_not (s := (Finset.univ : Finset (VarT (hSet τ.1) → D)))
    (GoodS (eSet τ.1) (hSet τ.1))
  have hcardfun : Fintype.card (VarT (hSet τ.1) → D) = Fintype.card D ^ (Fintype.card V + (GrS (hSet τ.1)).card) := by
    rw [Fintype.card_fun, hVar]
  rw [Finset.card_univ, hcardfun] at hsplit
  rw [hPos, hVar] at hgc
  have hG : (Fintype.card D : ℝ) ^ (Fintype.card V + (GrS (hSet τ.1)).card) * Fintype.card D ≤
      ((Finset.univ.filter (GoodS (eSet τ.1) (hSet τ.1))).card : ℝ) * Fintype.card D +
      ((((eSet τ.1).card + (GrS (hSet τ.1)).card + (hSet τ.1).card) *
        ((eSet τ.1).card + (GrS (hSet τ.1)).card + (hSet τ.1).card - 1) : ℕ) : ℝ) *
        (Fintype.card D : ℝ) ^ (Fintype.card V + (GrS (hSet τ.1)).card) := by
    have hs : ((Finset.univ.filter (GoodS (eSet τ.1) (hSet τ.1))).card : ℝ) +
        ((Finset.univ.filter (fun σ => ¬ GoodS (eSet τ.1) (hSet τ.1) σ)).card : ℝ) =
        (Fintype.card D : ℝ) ^ (Fintype.card V + (GrS (hSet τ.1)).card) := by exact_mod_cast hsplit
    nlinarith [hs, hgc]
  have hcX' : (Finset.univ.filter (GoodS (eSet τ.1) (hSet τ.1))).card *
      (Fintype.card D - ((eSet τ.1).card + (GrS (hSet τ.1)).card + (hSet τ.1).card)).factorial ≤
      (Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) => A.play (oX ω.1 ω.2) = τ)).card := by
    rw [hX, ← hPos]; exact hcX
  rw [hY, hcY, card_ΩY, card_ΩX]
  exact ratio_arith (Fintype.card D) (Fintype.card (V × D × D)) (Fintype.card V) (eSet τ.1).card
    (GrS (hSet τ.1)).card (hSet τ.1).card kp kh _ _ Fintype.card_pos hsz.1 hsz.2 hgh hHM hG hcX'

end PcaMath.OtDefs
