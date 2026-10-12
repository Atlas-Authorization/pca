import Mathlib
open Finset

namespace PcaMath.OtPerm

/-- The number of permutations of a finite type `α` that send `d i` to `r i` for all `i`, for injective
families `d r : ι → α`, is `(|α| - |ι|)!`. -/
theorem card_perm_extend {α ι : Type*} [Fintype α] [DecidableEq α] [Fintype ι] [DecidableEq ι]
    (d r : ι → α) (hd : Function.Injective d) (hr : Function.Injective r) :
    (Finset.univ.filter (fun π : Equiv.Perm α => ∀ i, π (d i) = r i)).card
      = (Fintype.card α - Fintype.card ι).factorial := by
  classical
  let e : {x // x ∈ Set.range d} ≃ {x // x ∈ Set.range r} :=
    (Equiv.ofInjective d hd).symm.trans (Equiv.ofInjective r hr)
  let π0 : Equiv.Perm α := e.extendSubtype
  have hπ0 : ∀ i, π0 (d i) = r i := by
    intro i
    have h1 : (Equiv.ofInjective d hd).symm ⟨d i, ⟨i, rfl⟩⟩ = i := by
      rw [Equiv.symm_apply_eq]; rfl
    have := Equiv.extendSubtype_apply_of_mem e (d i) ⟨i, rfl⟩
    rw [show π0 (d i) = e.extendSubtype (d i) from rfl, this]
    simp only [e, Equiv.trans_apply, h1]
    rfl
  have hcard : Fintype.card {x // x ∉ Set.range d} = Fintype.card α - Fintype.card ι := by
    rw [Fintype.card_subtype_compl, Fintype.card_congr (Equiv.ofInjective d hd).symm]
  calc (Finset.univ.filter (fun π : Equiv.Perm α => ∀ i, π (d i) = r i)).card
      = Fintype.card {π : Equiv.Perm α // ∀ i, π (d i) = r i} :=
        (Fintype.card_subtype _).symm
    _ = Fintype.card {f : Equiv.Perm α // ∀ a, ¬ (a ∉ Set.range d) → f a = a} := by
        refine Fintype.card_congr
          { toFun := fun π => ⟨π0⁻¹ * π, ?_⟩
            invFun := fun f => ⟨π0 * f.1, ?_⟩
            left_inv := ?_
            right_inv := ?_ }
        · intro a ha
          obtain ⟨i, rfl⟩ : a ∈ Set.range d := by simpa using ha
          have := π.2 i
          simp only [Equiv.Perm.mul_apply, this, ← hπ0 i]
          simp
        · intro i
          obtain ⟨f, hf⟩ := f
          simp only [Equiv.Perm.mul_apply]
          rw [hf (d i) (by simp)]
          exact hπ0 i
        · intro π; ext; simp
        · intro f; ext; simp
    _ = Fintype.card (Equiv.Perm {x // x ∉ Set.range d}) :=
        (Fintype.card_congr (Equiv.Perm.subtypeEquivSubtypePerm (fun x => x ∉ Set.range d))).symm
    _ = _ := by rw [Fintype.card_perm, hcard]

/-- falling factorial bound. -/
theorem factorial_le_sub_mul_pow (n c : ℕ) (hc : c ≤ n) :
    n.factorial ≤ (n - c).factorial * n ^ c := by
  obtain ⟨m, rfl⟩ := Nat.exists_eq_add_of_le hc
  rw [Nat.add_sub_cancel_left]
  calc (c + m).factorial ≤ m.factorial * (c + m) ^ c := by
        clear hc
        induction c with
        | zero => simp
        | succ k ih =>
          have h1 : (k + 1 + m).factorial = (k + m + 1) * (k + m).factorial := by
            rw [show k + 1 + m = (k + m) + 1 by omega, Nat.factorial_succ]
          have ih' := ih
          have h2 : (k + m + 1) ^ k ≥ (k + m) ^ k := Nat.pow_le_pow_left (by omega) k
          have h3 : (k + m).factorial ≤ m.factorial * (k + m + 1) ^ k := by
            calc (k + m).factorial ≤ m.factorial * (k + m) ^ k := ih
              _ ≤ _ := Nat.mul_le_mul_left _ h2
          rw [h1, pow_succ', show k + 1 + m = k + m + 1 by omega]
          calc (k + m + 1) * (k + m).factorial ≤ (k + m + 1) * (m.factorial * (k + m + 1) ^ k) :=
                Nat.mul_le_mul_left _ h3
            _ = _ := by ring
    _ = _ := rfl


end PcaMath.OtPerm
