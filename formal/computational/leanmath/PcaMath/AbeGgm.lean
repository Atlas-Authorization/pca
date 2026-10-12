import Mathlib
import PcaMath.Abe

/-!
# ABE-B (independence in the generic bilinear group) for the BSW07 type-3 adaptation of `packages/pca-abe`

Formal-polynomial model.  All adversary-visible group elements are polynomials in the randomness variables
`alpha, beta, ct k (s and the Shamir coefficients), r i, rr i a, h a` over a field `F`.  Elements of `G1` are stored
multiplied by `beta` (so `f = beta^-1` is the polynomial `1`); this is an injective `F`-linear rescaling that
commutes with every generic operation, hence preserves every equality pattern.
-/

open MvPolynomial Finset

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false

namespace PcaMath.AbeGgm

inductive Var (I A CV : Type) : Type
  | alpha | beta | z | ct (k : CV) | r (i : I) | rr (i : I) (a : A) | h (a : A)
  deriving DecidableEq

def Var.equivSum (I A CV : Type) : Var I A CV ≃ Unit ⊕ Unit ⊕ Unit ⊕ CV ⊕ I ⊕ (I × A) ⊕ A where
  toFun
    | .alpha => .inl ()
    | .beta => .inr (.inl ())
    | .z => .inr (.inr (.inl ()))
    | .ct k => .inr (.inr (.inr (.inl k)))
    | .r i => .inr (.inr (.inr (.inr (.inl i))))
    | .rr i a => .inr (.inr (.inr (.inr (.inr (.inl (i, a))))))
    | .h a => .inr (.inr (.inr (.inr (.inr (.inr a)))))
  invFun
    | .inl _ => .alpha
    | .inr (.inl _) => .beta
    | .inr (.inr (.inl _)) => .z
    | .inr (.inr (.inr (.inl k))) => .ct k
    | .inr (.inr (.inr (.inr (.inl i)))) => .r i
    | .inr (.inr (.inr (.inr (.inr (.inl (i, a)))))) => .rr i a
    | .inr (.inr (.inr (.inr (.inr (.inr a))))) => .h a
  left_inv := by intro v; cases v <;> rfl
  right_inv := by
    intro v
    rcases v with _ | _ | _ | k | i | ⟨i, a⟩ | a <;> rfl

instance {I A CV : Type} [Fintype I] [Fintype A] [Fintype CV] : Fintype (Var I A CV) :=
  Fintype.ofEquiv _ (Var.equivSum I A CV).symm

noncomputable section Model

variable {F : Type} [Field F] {I A CV L : Type}
  [Fintype I] [Fintype A] [Fintype CV] [Fintype L] [DecidableEq I] [DecidableEq A] [DecidableEq CV] [DecidableEq L]

abbrev P (F : Type) [CommSemiring F] (I A CV : Type) := MvPolynomial (Var I A CV) F

/-- basis of the `G1` list (scaled by `beta`): `1, f, H(a), D_i, D_{i,a}, C'_x` -/
abbrev B1 (I A L : Type) := Unit ⊕ Unit ⊕ A ⊕ I ⊕ (I × A) ⊕ L
/-- basis of the `G2` list: `1, h, D'_{i,a}, C_0, C_x` -/
abbrev B2 (I A L : Type) := Unit ⊕ Unit ⊕ (I × A) ⊕ Unit ⊕ L

def b1D (i : I) : B1 I A L := .inr (.inr (.inr (.inl i)))
def b1Dk (i : I) (a : A) : B1 I A L := .inr (.inr (.inr (.inr (.inl (i, a)))))
def b2Dp (i : I) (a : A) : B2 I A L := .inr (.inr (.inl (i, a)))
def b2C0 : B2 I A L := .inr (.inr (.inr (.inl ())))
def b2hh : B2 I A L := .inr (.inl ())

def ev1 (att : L → A) (lam : L → P F I A CV) : B1 I A L → P F I A CV
  | .inl _ => X .beta
  | .inr (.inl _) => 1
  | .inr (.inr (.inl a)) => X .beta * X (.h a)
  | .inr (.inr (.inr (.inl i))) => X .alpha + X (.r i)
  | .inr (.inr (.inr (.inr (.inl (i, a))))) => X .beta * (X (.r i) + X (.rr i a) * X (.h a))
  | .inr (.inr (.inr (.inr (.inr x)))) => X .beta * lam x * X (.h (att x))

def ev2 (s0 : CV) (lam : L → P F I A CV) : B2 I A L → P F I A CV
  | .inl _ => 1
  | .inr (.inl _) => X .beta
  | .inr (.inr (.inl (i, a))) => X (.rr i a)
  | .inr (.inr (.inr (.inl _))) => X (.ct s0) * X .beta
  | .inr (.inr (.inr (.inr x))) => lam x

variable (att : L → A) (lam : L → P F I A CV) (s0 : CV)

/-- the `G2` element paired with the `G1` basis element `b1` -/
def Pb (c : B1 I A L → B2 I A L → F) (b1 : B1 I A L) : P F I A CV :=
  ∑ b2, C (c b1 b2) * ev2 s0 lam b2

/-- the `G1` element paired with the `G2` basis element `b2` -/
def Rb (c : B1 I A L → B2 I A L → F) (b2 : B2 I A L) : P F I A CV :=
  ∑ b1, C (c b1 b2) * ev1 att lam b1

/-- the span of pairing products, as a polynomial -/
def G (c : B1 I A L → B2 I A L → F) : P F I A CV :=
  ∑ b1, ∑ b2, C (c b1 b2) * ev1 att lam b1 * ev2 s0 lam b2

theorem pderiv_G (v : Var I A CV) (c : B1 I A L → B2 I A L → F) :
    pderiv v (G att lam s0 c) =
      ∑ b1, pderiv v (ev1 att lam b1) * Pb lam s0 c b1 + ∑ b2, pderiv v (ev2 s0 lam b2) * Rb att lam c b2 := by
  unfold G Pb Rb
  simp only [map_sum, Derivation.leibniz, smul_eq_mul, pderiv_C, mul_zero, zero_add, Finset.mul_sum]
  rw [Finset.sum_comm (f := fun b2 b1 => pderiv v (ev2 s0 lam b2) * (C (c b1 b2) * ev1 att lam b1))]
  rw [← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl fun b1 _ => ?_
  rw [← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl fun b2 _ => ?_
  ring


def b1one : B1 I A L := .inl ()
def b1f : B1 I A L := .inr (.inl ())
def b1h (a : A) : B1 I A L := .inr (.inr (.inl a))
def b1Cp (x : L) : B1 I A L := .inr (.inr (.inr (.inr (.inr x))))
def b2one : B2 I A L := .inl ()
def b2Cx (x : L) : B2 I A L := .inr (.inr (.inr (.inr x)))

theorem sum_B1 {M : Type} [AddCommMonoid M] (g : B1 I A L → M) :
    ∑ b, g b = g b1one + g b1f + ∑ a, g (b1h a) + ∑ i, g (b1D i) + ∑ i, ∑ a, g (b1Dk i a) + ∑ x, g (b1Cp x) := by
  simp only [Fintype.sum_sum_type, Fintype.sum_prod_type, b1one, b1f, b1h, b1D, b1Dk, b1Cp, Finset.univ_unique,
    Finset.sum_singleton, Unique.default_eq]
  abel

theorem sum_B2 {M : Type} [AddCommMonoid M] (g : B2 I A L → M) :
    ∑ b, g b = g b2one + g b2hh + ∑ i, ∑ a, g (b2Dp i a) + g b2C0 + ∑ x, g (b2Cx x) := by
  simp only [Fintype.sum_sum_type, Fintype.sum_prod_type, b2one, b2hh, b2Dp, b2C0, b2Cx, Finset.univ_unique,
    Finset.sum_singleton, Unique.default_eq]
  abel

/-- the shares are polynomials in the ciphertext variables only -/
def Pure (lam : L → P F I A CV) : Prop := ∀ x v, (∀ k, v ≠ Var.ct k) → pderiv v (lam x) = 0

theorem pd_ev2_r (hp : Pure lam) (i : I) (b2 : B2 I A L) : pderiv (Var.r i) (ev2 s0 lam b2) = 0 := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, a⟩ | ⟨⟩ | x
  · simp [ev2]
  · simp [ev2, pderiv_X, Pi.single_apply]
  · simp [ev2, pderiv_X, Pi.single_apply]
  · simp [ev2, pderiv_X, Pi.single_apply, Derivation.leibniz]
  · exact hp x (Var.r i) (fun k => by simp)


theorem pd_ev2_alpha (hp : Pure lam) (b2 : B2 I A L) : pderiv Var.alpha (ev2 s0 lam b2) = 0 := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, a⟩ | ⟨⟩ | x
  · simp [ev2]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X, Derivation.leibniz]
  · exact hp x (Var.alpha) (fun k => by simp)

theorem pd_ev2_h (hp : Pure lam) (a : A) (b2 : B2 I A L) : pderiv (Var.h a) (ev2 s0 lam b2) = 0 := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, b⟩ | ⟨⟩ | x
  · simp [ev2]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X, Derivation.leibniz]
  · exact hp x (Var.h a) (fun k => by simp)

theorem pd_ev2_rr (hp : Pure lam) (i : I) (a : A) (b2 : B2 I A L) :
    pderiv (Var.rr i a) (ev2 s0 lam b2) = if b2 = b2Dp i a then (1 : P F I A CV) else 0 := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, b⟩ | ⟨⟩ | x
  · simp [ev2, b2Dp]
  · simp [ev2, pderiv_X, b2Dp]
  · simp [ev2, pderiv_X, b2Dp, Pi.single_apply, and_comm]
  · simp [ev2, pderiv_X, Derivation.leibniz, b2Dp]
  · simp only [ev2]; rw [hp x (Var.rr i a) (fun k => by simp)]; simp [b2Dp]

theorem pd_ev2_beta (hp : Pure lam) (b2 : B2 I A L) :
    pderiv Var.beta (ev2 s0 lam b2) = (if b2 = b2hh then (1 : P F I A CV) else 0) + (if b2 = b2C0 then (X (Var.ct s0) : P F I A CV) else 0) := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, b⟩ | ⟨⟩ | x
  · simp [ev2, b2hh, b2C0]
  · simp [ev2, pderiv_X, b2hh, b2C0]
  · simp [ev2, pderiv_X, b2hh, b2C0]
  · simp [ev2, pderiv_X, Derivation.leibniz, b2hh, b2C0, Pi.single_apply]
  · simp only [ev2]; rw [hp x (Var.beta) (fun k => by simp)]; simp [b2hh, b2C0]

theorem S_r (hp : Pure lam) (i : I) (f : B1 I A L → P F I A CV) :
    ∑ b1, pderiv (Var.r i) (ev1 att lam b1) * f b1 = f (b1D i) + X Var.beta * ∑ a, f (b1Dk i a) := by
  rw [sum_B1]
  have hCp : ∀ x, pderiv (Var.r i) (ev1 att lam (b1Cp x)) = 0 := by
    intro x
    have := hp x (Var.r i) (fun k => by simp)
    simp [ev1, b1Cp, Derivation.leibniz, pderiv_X, this]
  simp only [hCp, zero_mul, Finset.sum_const_zero, add_zero]
  simp [ev1, b1one, b1f, b1h, b1D, b1Dk, pderiv_X, Derivation.leibniz, Pi.single_apply, Finset.mul_sum]


theorem S_rr (hp : Pure lam) (i : I) (a : A) (f : B1 I A L → P F I A CV) :
    ∑ b1, pderiv (Var.rr i a) (ev1 att lam b1) * f b1 = X Var.beta * X (Var.h a) * f (b1Dk i a) := by
  rw [sum_B1]
  have hCp : ∀ x, pderiv (Var.rr i a) (ev1 att lam (b1Cp x)) = 0 := by
    intro x
    have := hp x (Var.rr i a) (fun k => by simp)
    simp [ev1, b1Cp, Derivation.leibniz, pderiv_X, this]
  simp only [hCp, zero_mul, Finset.sum_const_zero, add_zero]
  simp [ev1, b1one, b1f, b1h, b1D, b1Dk, pderiv_X, Derivation.leibniz, Pi.single_apply, ite_and, Finset.sum_ite_eq']

theorem S_h (hp : Pure lam) (a : A) (f : B1 I A L → P F I A CV) :
    ∑ b1, pderiv (Var.h a) (ev1 att lam b1) * f b1 =
      X Var.beta * (f (b1h a) + ∑ j, X (Var.rr j a) * f (b1Dk j a)
        + ∑ x, if att x = a then lam x * f (b1Cp x) else 0) := by
  rw [sum_B1]
  have hCp : ∀ x, pderiv (Var.h a) (ev1 att lam (b1Cp x)) = if att x = a then X Var.beta * lam x else 0 := by
    intro x
    have := hp x (Var.h a) (fun k => by simp)
    simp [ev1, b1Cp, Derivation.leibniz, pderiv_X, this, Pi.single_apply]
  simp only [hCp]
  simp [ev1, b1one, b1f, b1h, b1D, b1Dk, pderiv_X, Derivation.leibniz, Pi.single_apply, mul_add, Finset.mul_sum,
    mul_assoc, ite_mul, mul_ite]

theorem S_alpha (hp : Pure lam) (f : B1 I A L → P F I A CV) :
    ∑ b1, pderiv Var.alpha (ev1 att lam b1) * f b1 = ∑ i, f (b1D i) := by
  rw [sum_B1]
  have hCp : ∀ x, pderiv Var.alpha (ev1 att lam (b1Cp x)) = 0 := by
    intro x
    have := hp x Var.alpha (fun k => by simp)
    simp [ev1, b1Cp, Derivation.leibniz, pderiv_X, this]
  simp only [hCp, zero_mul, Finset.sum_const_zero, add_zero]
  simp [ev1, b1one, b1f, b1h, b1D, b1Dk, pderiv_X, Derivation.leibniz, Pi.single_apply]

theorem pd_Pb_beta (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (b1 : B1 I A L) :
    pderiv Var.beta (Pb lam s0 c b1) = C (c b1 b2hh) + C (c b1 b2C0) * X (Var.ct s0) := by
  have h1 : ∀ b2, pderiv Var.beta (C (c b1 b2) * ev2 s0 lam b2) =
      C (c b1 b2) * ((if b2 = b2hh then (1 : P F I A CV) else 0) + (if b2 = b2C0 then (X (Var.ct s0) : P F I A CV) else 0)) := by
    intro b2
    rw [Derivation.leibniz, pd_ev2_beta (lam := lam) (s0 := s0) hp]
    simp [pderiv_C]
  unfold Pb
  simp only [map_sum, h1, mul_add, Finset.sum_add_distrib, mul_ite, mul_one, mul_zero, Finset.sum_ite_eq',
    Finset.mem_univ, if_true]


/-- assignment: ciphertext variables from `w`, everything else `0` -/
def ext (w : CV → F) : Var I A CV → F
  | .ct k => w k
  | _ => 0

theorem E3 (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (κ0 κ1 : F)
    (H : X Var.beta * X Var.alpha * X (Var.ct s0) =
      G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha)) :
    ∑ i : I, c (b1D i) b2C0 = 1 := by
  have e3a := congrArg (pderiv Var.alpha) H
  rw [map_add, map_add, pderiv_G, S_alpha att lam hp] at e3a
  simp only [pd_ev2_alpha lam s0 hp, zero_mul, Finset.sum_const_zero, add_zero] at e3a
  simp [Derivation.leibniz, pderiv_X, pderiv_C] at e3a
  have e3b := congrArg (pderiv Var.beta) e3a
  simp [Derivation.leibniz, pderiv_X, pderiv_C, pd_Pb_beta lam s0 hp] at e3b
  have e3c := congrArg (pderiv (Var.ct s0)) e3b
  simp [Derivation.leibniz, pderiv_X, pderiv_C] at e3c
  have : (C (∑ i, c (b1D i) b2C0) : P F I A CV) = C 1 := by
    rw [map_sum, map_one]; exact e3c.symm
  exact C_injective _ _ this


theorem pd_Pb_h (hp : Pure lam) (a : A) (c : B1 I A L → B2 I A L → F) (b1 : B1 I A L) :
    pderiv (Var.h a) (Pb lam s0 c b1) = 0 := by
  unfold Pb
  simp [map_sum, Derivation.leibniz, pderiv_C, pd_ev2_h lam s0 hp]

/-- the (negated) `G2` partner of `D_{i,a}` forced by the `h_a`-derivative -/
def M (c : B1 I A L → B2 I A L → F) (i : I) (a : A) : P F I A CV :=
  C (c (b1h a) (b2Dp i a)) + ∑ j, X (Var.rr j a) * C (c (b1Dk j a) (b2Dp i a))
    + ∑ x, if att x = a then lam x * C (c (b1Cp x) (b2Dp i a)) else 0

theorem E1 (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (κ0 κ1 : F) (i : I)
    (H : X Var.beta * X Var.alpha * X (Var.ct s0) =
      G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha)) :
    Pb lam s0 c (b1D i) + X Var.beta * ∑ a, Pb lam s0 c (b1Dk i a) = 0 := by
  have e := congrArg (pderiv (Var.r i)) H
  rw [map_add, map_add, pderiv_G, S_r att lam hp] at e
  simp only [pd_ev2_r lam s0 hp, zero_mul, Finset.sum_const_zero, add_zero] at e
  simp [Derivation.leibniz, pderiv_X, pderiv_C] at e
  exact e.symm

theorem E2 (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (κ0 κ1 : F) (i : I) (a : A)
    (H : X Var.beta * X Var.alpha * X (Var.ct s0) =
      G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha)) :
    Pb lam s0 c (b1Dk i a) = - M att lam c i a := by
  have e := congrArg (pderiv (Var.rr i a)) H
  rw [map_add, map_add, pderiv_G, S_rr att lam hp] at e
  simp only [pd_ev2_rr lam s0 hp, ite_mul, one_mul, zero_mul, Finset.sum_ite_eq', Finset.mem_univ, ite_true] at e
  simp [Derivation.leibniz, pderiv_X, pderiv_C] at e
  have e2 := congrArg (pderiv (Var.h a)) e
  have hR : pderiv (Var.h a) (Rb att lam c (b2Dp i a)) = X Var.beta * M att lam c i a := by
    have : pderiv (Var.h a) (Rb att lam c (b2Dp i a)) =
        ∑ b1, pderiv (Var.h a) (ev1 att lam b1) * C (c b1 (b2Dp i a)) := by
      unfold Rb
      simp only [map_sum, Derivation.leibniz, smul_eq_mul, pderiv_C, mul_zero, zero_add]
      refine Finset.sum_congr rfl fun b1 _ => by ring
    rw [this, S_h att lam hp a (fun b1 => C (c b1 (b2Dp i a)))]
    rfl
  rw [map_add, hR, Derivation.leibniz, Derivation.leibniz, smul_eq_mul, smul_eq_mul, pd_Pb_h lam s0 hp] at e2
  simp [pderiv_X] at e2
  have h3 : X Var.beta * (Pb lam s0 c (b1Dk i a) + M att lam c i a) = 0 := by linear_combination -e2
  rcases mul_eq_zero.mp h3 with h4 | h4
  · exact absurd h4 (X_ne_zero _)
  · linear_combination h4


theorem pd_M_beta (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (i : I) (a : A) :
    pderiv Var.beta (M att lam c i a) = 0 := by
  have h : ∀ x, pderiv Var.beta (lam x) = 0 := fun x => hp x Var.beta (fun k => by simp)
  have h2 : ∀ x, pderiv Var.beta (if att x = a then lam x * C (c (b1Cp x) (b2Dp i a)) else 0) = 0 := by
    intro x; split_ifs <;> simp [Derivation.leibniz, h, pderiv_C]
  simp only [M, map_add, map_sum, h2, Finset.sum_const_zero, pderiv_C, add_zero]
  simp [Derivation.leibniz, pderiv_X, pderiv_C]

theorem E4 (hp : Pure lam) (c : B1 I A L → B2 I A L → F) (κ0 κ1 : F) (i : I)
    (H : X Var.beta * X Var.alpha * X (Var.ct s0) =
      G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha)) :
    C (c (b1D i) b2hh) + C (c (b1D i) b2C0) * X (Var.ct s0) = ∑ a, M att lam c i a := by
  have e1 := E1 att lam s0 hp c κ0 κ1 i H
  have e2 : ∀ a, Pb lam s0 c (b1Dk i a) = - M att lam c i a := fun a => E2 att lam s0 hp c κ0 κ1 i a H
  simp only [e2, Finset.sum_neg_distrib, mul_neg] at e1
  have e3 : Pb lam s0 c (b1D i) = X Var.beta * ∑ a, M att lam c i a := by linear_combination e1
  have e4 := congrArg (pderiv Var.beta) e3
  rw [pd_Pb_beta lam s0 hp, Derivation.leibniz] at e4
  simp only [smul_eq_mul, map_sum, pd_M_beta att lam hp, Finset.sum_const_zero, mul_zero, add_zero, pderiv_X,
    Pi.single_apply, if_true, mul_one] at e4
  simpa using e4

/-- **ABE-B** (independence).  If the shares of the attribute positions of every key admit two assignments of the
ciphertext randomness with different `s` and equal shares, `alpha*s` (times `beta`) is not in the span of the
pairing products of the adversary's `G1` and `G2` elements plus `{1, alpha}`. -/
theorem abeB (hp : Pure lam) (S : I → Finset A)
    (hsh : ∀ i, ∃ w1 w0 : CV → F, w1 s0 = 1 ∧ w0 s0 = 0 ∧
      ∀ x, att x ∈ S i → eval (ext w1) (lam x) = eval (ext w0) (lam x))
    (c : B1 I A L → B2 I A L → F) (hc : ∀ i a, a ∉ S i → ∀ b1, c b1 (b2Dp i a) = 0) (κ0 κ1 : F) :
    X Var.beta * X Var.alpha * X (Var.ct s0) ≠
      G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha) := by
  intro H
  have hsum := E3 att lam s0 hp c κ0 κ1 H
  have hzero : ∀ i, c (b1D i) b2C0 = 0 := by
    intro i
    obtain ⟨w1, w0, h1, h0, hx⟩ := hsh i
    have e4 := E4 att lam s0 hp c κ0 κ1 i H
    have hMe : ∀ (w : CV → F) (a : A), eval (ext w) (M att lam c i a) =
        c (b1h a) (b2Dp i a) + ∑ x, if att x = a then eval (ext w) (lam x) * c (b1Cp x) (b2Dp i a) else 0 := by
      intro w a
      simp only [M, map_add, map_sum, eval_C, eval_mul, eval_X, ext, zero_mul, Finset.sum_const_zero, add_zero,
        apply_ite (eval (ext w)), map_zero]
    have hM : ∀ a, eval (ext w1) (M att lam c i a) = eval (ext w0) (M att lam c i a) := by
      intro a
      rw [hMe, hMe]
      by_cases ha : a ∈ S i
      · congr 1
        refine Finset.sum_congr rfl fun x _ => ?_
        split_ifs with hxa
        · rw [hx x (hxa ▸ ha)]
        · rfl
      · simp [hc i a ha]
    have ev1 := congrArg (eval (ext w1)) e4
    have ev0 := congrArg (eval (ext w0)) e4
    simp only [map_add, map_mul, eval_C, eval_X, ext, map_sum, h1, h0] at ev1 ev0
    simp only [hM] at ev1
    have := ev1.trans ev0.symm
    simpa using this
  simp [hzero] at hsum


theorem pd_ev1_z (hp : Pure lam) (b1 : B1 I A L) : pderiv Var.z (ev1 att lam b1) = 0 := by
  rcases b1 with ⟨⟩ | ⟨⟩ | a | i | ⟨i, a⟩ | x
  · simp [ev1]
  · simp [ev1]
  · simp [ev1, pderiv_X]
  · simp [ev1, pderiv_X]
  · simp [ev1, pderiv_X]
  · have := hp x Var.z (fun k => by simp)
    simp [ev1, Derivation.leibniz, pderiv_X, this]

theorem pd_ev2_z (hp : Pure lam) (b2 : B2 I A L) : pderiv Var.z (ev2 s0 lam b2) = 0 := by
  rcases b2 with ⟨⟩ | ⟨⟩ | ⟨j, a⟩ | ⟨⟩ | x
  · simp [ev2]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X]
  · simp [ev2, pderiv_X, Derivation.leibniz]
  · simp only [ev2]; exact hp x Var.z (fun k => by simp)

theorem pderiv_z_G (hp : Pure lam) (c : B1 I A L → B2 I A L → F) : pderiv Var.z (G att lam s0 c) = 0 := by
  rw [pderiv_G]
  simp [pd_ev1_z att lam hp, pd_ev2_z lam s0 hp]

theorem G_lin (c c' : B1 I A L → B2 I A L → F) (a b : F) :
    G att lam s0 (fun b1 b2 => a * c b1 b2 + b * c' b1 b2) = C a * G att lam s0 c + C b * G att lam s0 c' := by
  unfold G
  simp only [Finset.mul_sum, ← Finset.sum_add_distrib, map_add, map_mul]
  refine Finset.sum_congr rfl fun b1 _ => Finset.sum_congr rfl fun b2 _ => by ring

end Model
end PcaMath.AbeGgm
