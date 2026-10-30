import Mathlib
import PcaMath.FameDefs

/-!
# FAME in the generic bilinear group: independence (the formal core of CPA security)

If every key slot's attribute set is unauthorised (there is a vector `v` with `v j0 = 1` and `M_y . v = 0` on the held rows),
then the KEM target `e(g,h)^((d1 a1 + d3) s1 + (d2 a2 + d3) s2)` is not in the span of the adversary's pairing products
plus the public GT elements.  Only the `t = 0` half of the scheme is needed: three partial derivatives (in `d1`, `g_{j,0,0}`,
`h_{y,0,0}`) followed by the coefficient of one multilinear monomial each give
  sum_k beta_k = 1,   u_k(y) + beta'_k(y) = 0,   sum_y M_{y,j} u_k(y) + [j = j0] beta_k = 0,
and `v` forces `beta_k = 0`.
-/

open MvPolynomial Finset

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false
set_option maxHeartbeats 800000

namespace PcaMath.FameGgm

noncomputable section Indep

variable {F : Type} [Field F] {Y J : Type} {Q : ℕ}
  [Fintype Y] [Fintype J] [DecidableEq Y] [DecidableEq J]

local notation "AA" => (X (Var.a 0) * X (Var.a 1))

variable (M : Y → J → F) (j0 : J)

theorem sumQ {N : Type} [AddCommMonoid N] (y0 : Y) (g : Y → Fin 3 → N) :
    ∑ x, ∑ l, (if x = y0 ∧ l = 0 then g x l else 0) = g y0 0 := by
  simp only [ite_and]
  rw [Finset.sum_eq_single y0 (fun b _ hb => by simp [hb]) (fun h => absurd (Finset.mem_univ _) h)]
  simp

theorem sumJ0 {N : Type} [AddCommMonoid N] (j : J) (g : J → Fin 3 → N) :
    ∑ x, ∑ l, (if x = j ∧ l = 0 then g x l else 0) = g j 0 := by
  simp only [ite_and]
  rw [Finset.sum_eq_single j (fun b _ hb => by simp [hb]) (fun h => absurd (Finset.mem_univ _) h)]
  simp

theorem sumJ (j : J) (l : Fin 3) (a : J → F) :
    (∑ x, if x = j ∧ l = 0 then a x else 0) = if l = 0 then a j else 0 := by
  by_cases hl : l = 0 <;> simp [hl]

theorem AA_ne_zero : (AA : P F Y J Q) ≠ 0 := mul_ne_zero (X_ne_zero _) (X_ne_zero _)

theorem pd_ev2s_h (y : Y) (l : Fin 3) (t : Fin 2) (x : B2 Q → F) :
    pderiv (Var.h y l t) (ev2s x : P F Y J Q) = 0 := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_ev2s_g (j : J) (l : Fin 3) (t : Fin 2) (x : B2 Q → F) :
    pderiv (Var.g j l t) (ev2s x : P F Y J Q) = 0 := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_ev2s_d (t : Fin 3) (x : B2 Q → F) :
    pderiv (Var.d t) (ev2s x : P F Y J Q) = 0 := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_s0_ev2s (x : B2 Q → F) :
    pderiv (Var.s 0) (ev2s x : P F Y J Q) = C (x b2c0) * X (Var.a 0) + C (x b2c2) := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_b0_ev2s (x : B2 Q → F) :
    pderiv (Var.b 0) (ev2s x : P F Y J Q) = ∑ k, C (x (b2p0 k)) * X (Var.r k 0) := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem S_d (f : B1 Y J Q → P F Y J Q) :
    ∑ b1, pderiv (Var.d 0) (ev1 M j0 b1) * f b1 = ∑ k, AA * f (b1P0 k) := by
  rw [sum_B1]
  simp [fC, fK0, fK1, fK2, fP0, fP1, fP2, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem S_h (y0 : Y) (f : B1 Y J Q → P F Y J Q) :
    ∑ b1, pderiv (Var.h y0 0 0) (ev1 M j0 b1) * f b1 =
      AA * f (b1rawH (y0, 0, 0)) + AA * X (Var.s 0) * f (b1C (y0, 0)) +
        ∑ k, X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0)) * f (b1K0 (k, y0)) := by
  rw [sum_B1]
  simp [fC, fK0, fK1, fK2, fP0, fP1, fP2, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum,
    Fintype.sum_prod_type]
  simp only [sumQ]

theorem pd_g_fC (j : J) (y : Y) (l : Fin 3) :
    pderiv (Var.g j 0 0) (fC M y l : P F Y J Q) = if l = 0 then AA * X (Var.s 0) * C (M y j) else 0 := by
  by_cases hl : l = 0
  · subst hl
    simp [fC, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum, -mul_eq_mul_left_iff,
      -mul_eq_mul_right_iff]
    try ring
  · have hl' : (0 : Fin 3) ≠ l := fun h => hl h.symm
    simp [fC, hl, hl', Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_g_fP0 (j : J) (k : Fin Q) :
    pderiv (Var.g j 0 0) (fP0 j0 k : P F Y J Q) =
      if j = j0 then X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0)) else 0 := by
  by_cases hj : j = j0
  · subst hj
    simp [fP0, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, -mul_eq_mul_left_iff, -mul_eq_mul_right_iff]
    try ring
  · have hj' : j0 ≠ j := fun h => hj h.symm
    simp [fP0, hj, hj', Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]

theorem S_g (j : J) (f : B1 Y J Q → P F Y J Q) :
    ∑ b1, pderiv (Var.g j 0 0) (ev1 M j0 b1) * f b1 =
      AA * f (b1rawG (j, 0, 0)) + ∑ y, AA * X (Var.s 0) * C (M y j) * f (b1C (y, 0)) +
        (if j = j0 then ∑ k, X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0)) * f (b1P0 k) else 0) := by
  rw [sum_B1]
  by_cases hj : j = j0
  · subst hj
    simp [pd_g_fC, pd_g_fP0, ite_mul, fK0, fK1, fK2, fP1, fP2, Derivation.leibniz, pderiv_X, pderiv_C,
      Pi.single_apply, map_sum, Fintype.sum_prod_type, -mul_eq_mul_left_iff, -mul_eq_mul_right_iff]
    try simp only [sumJ0]
    try ring
  · simp [hj, pd_g_fC, pd_g_fP0, ite_mul, fK0, fK1, fK2, fP1, fP2, Derivation.leibniz, pderiv_X, pderiv_C,
      Pi.single_apply, map_sum, Fintype.sum_prod_type, -mul_eq_mul_left_iff, -mul_eq_mul_right_iff]
    try simp only [sumJ0]
    try ring

theorem pd_WW_d (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) :
    pderiv (Var.d 0) (WW M j0 c κ0 κ1 κ2 : P F Y J Q) =
      ∑ k, AA * ev2s (c (b1P0 k)) + C κ1 * (AA * X (Var.a 0)) := by
  unfold WW
  rw [map_add, map_add, map_add, pd_G M j0 (Var.d 0) (pd_ev2s_d 0), S_d M j0 (fun b1 => ev2s (c b1))]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]

theorem pd_WW_h (y0 : Y) (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) :
    pderiv (Var.h y0 0 0) (WW M j0 c κ0 κ1 κ2 : P F Y J Q) =
      AA * ev2s (c (b1rawH (y0, 0, 0))) + AA * X (Var.s 0) * ev2s (c (b1C (y0, 0))) +
        ∑ k, X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0)) * ev2s (c (b1K0 (k, y0))) := by
  unfold WW
  rw [map_add, map_add, map_add, pd_G M j0 _ (pd_ev2s_h y0 0 0), S_h M j0 y0 (fun b1 => ev2s (c b1))]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]

theorem pd_WW_g (j : J) (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) :
    pderiv (Var.g j 0 0) (WW M j0 c κ0 κ1 κ2 : P F Y J Q) =
      AA * ev2s (c (b1rawG (j, 0, 0))) + ∑ y, AA * X (Var.s 0) * C (M y j) * ev2s (c (b1C (y, 0))) +
        (if j = j0 then ∑ k, X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0)) * ev2s (c (b1P0 k)) else 0) := by
  unfold WW
  rw [map_add, map_add, map_add, pd_G M j0 _ (pd_ev2s_g j 0 0), S_g M j0 j (fun b1 => ev2s (c b1))]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]

/-- evaluation point `a2 = 1`, everything else `0` -/
def ε1 : Var Y J Q → F := fun v => if v = Var.a 1 then 1 else 0

theorem claim_d (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) (H : (TA : P F Y J Q) = WW M j0 c κ0 κ1 κ2) :
    ∑ k, c (b1P0 k) b2c0 = 1 := by
  have e1 := congrArg (pderiv (Var.d 0)) H
  rw [pd_WW_d] at e1
  have e1' : pderiv (Var.d 0) (TA : P F Y J Q) = AA * (X (Var.a 0) * X (Var.s 0)) := by
    simp [TA, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]
    try ring
  rw [e1'] at e1
  have e2 : (X (Var.a 0) * X (Var.s 0) : P F Y J Q) = ∑ k, ev2s (c (b1P0 k)) + C κ1 * X (Var.a 0) := by
    apply mul_left_cancel₀ (AA_ne_zero (F := F) (Y := Y) (J := J) (Q := Q))
    rw [mul_add, Finset.mul_sum]
    linear_combination e1
  have e3 := congrArg (pderiv (Var.s 0)) e2
  simp [pd_s0_ev2s, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e3
  have e4 := congrArg (pderiv (Var.a 0)) e3
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e4
  have e5 := congrArg (eval ε1) e4
  simp [map_sum] at e5
  simpa using e5.symm

theorem claim_h (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) (H : (TA : P F Y J Q) = WW M j0 c κ0 κ1 κ2)
    (y : Y) (k : Fin Q) : c (b1C (y, 0)) (b2p0 k) + c (b1K0 (k, y)) b2c0 = 0 := by
  have e0 := congrArg (pderiv (Var.h y 0 0)) H
  rw [pd_WW_h] at e0
  simp only [ev2s_eq] at e0
  have e1 := congrArg (pderiv (Var.s 0)) e0
  simp [TA, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e1
  have e2 := congrArg (pderiv (Var.b 0)) e1
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e2
  have e3 := congrArg (pderiv (Var.r k 0)) e2
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e3
  have e4 := congrArg (pderiv (Var.a 0)) e3
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e4
  have e5 := congrArg (eval ε1) e4
  simp [map_sum, ε1] at e5
  linear_combination -e5

theorem claim_g (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) (H : (TA : P F Y J Q) = WW M j0 c κ0 κ1 κ2)
    (j : J) (k : Fin Q) :
    ∑ y, M y j * c (b1C (y, 0)) (b2p0 k) + (if j = j0 then c (b1P0 k) b2c0 else 0) = 0 := by
  have e0 := congrArg (pderiv (Var.g j 0 0)) H
  rw [pd_WW_g] at e0
  by_cases hj : j = j0
  · rw [if_pos hj] at e0
    rw [if_pos hj]
    simp only [ev2s_eq] at e0
    have e1 := congrArg (pderiv (Var.s 0)) e0
    simp [TA, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e1
    have e2 := congrArg (pderiv (Var.b 0)) e1
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e2
    have e3 := congrArg (pderiv (Var.r k 0)) e2
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e3
    have e4 := congrArg (pderiv (Var.a 0)) e3
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e4
    have e5 := congrArg (eval ε1) e4
    simp [map_sum, ε1] at e5
    simp only [mul_comm (M _ j)]
    linear_combination -e5
  · rw [if_neg hj] at e0
    rw [if_neg hj]
    simp only [ev2s_eq] at e0
    have e1 := congrArg (pderiv (Var.s 0)) e0
    simp [TA, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e1
    have e2 := congrArg (pderiv (Var.b 0)) e1
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e2
    have e3 := congrArg (pderiv (Var.r k 0)) e2
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e3
    have e4 := congrArg (pderiv (Var.a 0)) e3
    simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum] at e4
    have e5 := congrArg (eval ε1) e4
    simp [map_sum, ε1] at e5
    simp only [mul_comm (M _ j)]
    linear_combination -e5

open Classical in
/-- **Independence.**  If every key slot's held attribute set admits a sharing vector, the target is not in the span. -/
theorem fameB (held : Fin Q → Y → Prop) (hsh : Priv M j0 held) : Indep M j0 held := by
  intro c κ0 κ1 κ2 hc H
  have hd := claim_d M j0 c κ0 κ1 κ2 H
  obtain ⟨k, -, hk⟩ := Finset.exists_ne_zero_of_sum_ne_zero (s := Finset.univ)
    (f := fun k => c (b1P0 k) b2c0) (by rw [hd]; exact one_ne_zero)
  obtain ⟨v, hv0, hv⟩ := hsh k
  have hu : ∀ y, ¬ held k y → c (b1C (y, 0)) (b2p0 k) = 0 := by
    intro y hy
    have h1 := claim_h M j0 c κ0 κ1 κ2 H y k
    have := (hc k y hy b2c0).1
    rw [this] at h1
    linear_combination h1
  have hg : ∀ j, ∑ y, M y j * c (b1C (y, 0)) (b2p0 k) + (if j = j0 then c (b1P0 k) b2c0 else 0) = 0 :=
    fun j => claim_g M j0 c κ0 κ1 κ2 H j k
  have hsum : ∑ j, v j * (∑ y, M y j * c (b1C (y, 0)) (b2p0 k) + (if j = j0 then c (b1P0 k) b2c0 else 0)) = 0 :=
    Finset.sum_eq_zero fun j _ => by rw [hg j, mul_zero]
  have hA : ∑ j, v j * (∑ y, M y j * c (b1C (y, 0)) (b2p0 k)) =
      ∑ y, c (b1C (y, 0)) (b2p0 k) * ∑ j, M y j * v j := by
    simp only [Finset.mul_sum]
    rw [Finset.sum_comm]
    refine Finset.sum_congr rfl fun y _ => Finset.sum_congr rfl fun j _ => by ring
  have hB : ∑ y, c (b1C (y, 0)) (b2p0 k) * ∑ j, M y j * v j = 0 := by
    refine Finset.sum_eq_zero fun y _ => ?_
    by_cases hy : held k y
    · rw [hv y hy, mul_zero]
    · rw [hu y hy, zero_mul]
  have hC : ∑ j, v j * (if j = j0 then c (b1P0 k) b2c0 else 0) = c (b1P0 k) b2c0 := by
    simp [hv0]
  simp only [mul_add, Finset.sum_add_distrib, hA, hB, hC, zero_add] at hsum
  exact hk hsum

end Indep
end PcaMath.FameGgm
