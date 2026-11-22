import Mathlib

/-!
# FAME (Agrawal-Chase, CCS 2017) in the type-3 generic bilinear group model: definitions

Formal-polynomial model of `packages/pca-abe` (`fame.ts`).  Every group element the adversary can hold is a polynomial in the
scheme's randomness.  Elements of `G1` are stored multiplied by `a1*a2` (an injective rescaling that commutes with every generic
operation and removes the inverses `1/a_t` of the key components).  Rows of the span program are indexed by the attribute itself
(the row labelling is injective); `M y` is the row of attribute `y` (zero outside the policy), `j0` the secret column.
The adversary is additionally given the ciphertext row components for EVERY attribute (more than the real ciphertext), and the key
material of every one of the `Q` key slots from the start (an unissued slot behaves like a key for the empty attribute set).
-/

open MvPolynomial Finset

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false
set_option maxHeartbeats 800000

namespace PcaMath.FameGgm

inductive Var (Y J : Type) (Q : ℕ) : Type
  | a (t : Fin 2)
  | b (t : Fin 2)
  | s (t : Fin 2)
  | d (t : Fin 3)
  | z
  | h (y : Y) (l : Fin 3) (t : Fin 2)
  | g (j : J) (l : Fin 3) (t : Fin 2)
  | r (k : Fin Q) (t : Fin 2)
  | sg (k : Fin Q) (y : Y)
  | sp (k : Fin Q)
  deriving DecidableEq

def Var.equivSum (Y J : Type) (Q : ℕ) : Var Y J Q ≃
    Fin 2 ⊕ Fin 2 ⊕ Fin 2 ⊕ Fin 3 ⊕ Unit ⊕ (Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2) ⊕ (Fin Q × Fin 2) ⊕
      (Fin Q × Y) ⊕ Fin Q where
  toFun
    | .a t => .inl t
    | .b t => .inr (.inl t)
    | .s t => .inr (.inr (.inl t))
    | .d t => .inr (.inr (.inr (.inl t)))
    | .z => .inr (.inr (.inr (.inr (.inl ()))))
    | .h y l t => .inr (.inr (.inr (.inr (.inr (.inl (y, l, t))))))
    | .g j l t => .inr (.inr (.inr (.inr (.inr (.inr (.inl (j, l, t)))))))
    | .r k t => .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inl (k, t))))))))
    | .sg k y => .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr (.inl (k, y)))))))))
    | .sp k => .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr k))))))))
  invFun
    | .inl t => .a t
    | .inr (.inl t) => .b t
    | .inr (.inr (.inl t)) => .s t
    | .inr (.inr (.inr (.inl t))) => .d t
    | .inr (.inr (.inr (.inr (.inl _)))) => .z
    | .inr (.inr (.inr (.inr (.inr (.inl (y, l, t)))))) => .h y l t
    | .inr (.inr (.inr (.inr (.inr (.inr (.inl (j, l, t))))))) => .g j l t
    | .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inl (k, t)))))))) => .r k t
    | .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr (.inl (k, y))))))))) => .sg k y
    | .inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr (.inr k)))))))) => .sp k
  left_inv := by intro v; cases v <;> rfl
  right_inv := by
    intro v
    rcases v with t | t | t | t | ⟨⟩ | ⟨y, l, t⟩ | ⟨j, l, t⟩ | ⟨k, t⟩ | ⟨k, y⟩ | k <;> rfl

instance {Y J : Type} {Q : ℕ} [Fintype Y] [Fintype J] : Fintype (Var Y J Q) :=
  Fintype.ofEquiv _ (Var.equivSum Y J Q).symm

noncomputable section Model

variable {F : Type} [Field F] {Y J : Type} {Q : ℕ}
  [Fintype Y] [Fintype J] [DecidableEq Y] [DecidableEq J]

abbrev P (F : Type) [CommSemiring F] (Y J : Type) (Q : ℕ) := MvPolynomial (Var Y J Q) F

local notation "AA" => (X (Var.a 0) * X (Var.a 1))

/-- basis of the `G1` span: generator | raw `H(y,l,t)` | raw `H0(j,l,t)` | ciphertext rows | `K_{y,0}` | `K_{y,1}` | `K_{y,2}`
| `K'_0` | `K'_1` | `K'_2` -/
abbrev B1 (Y J : Type) (Q : ℕ) :=
  Unit ⊕ (Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2) ⊕ (Y × Fin 3) ⊕ (Fin Q × Y) ⊕ (Fin Q × Y) ⊕ (Fin Q × Y) ⊕
    Fin Q ⊕ Fin Q ⊕ Fin Q

/-- basis of the `G2` span: `h`, `h^a1`, `h^a2`, `C0_0`, `C0_1`, `C0_2`, `K0_{k,0}`, `K0_{k,1}`, `K0_{k,2}` -/
abbrev B2 (Q : ℕ) := Unit ⊕ Unit ⊕ Unit ⊕ Unit ⊕ Unit ⊕ Unit ⊕ Fin Q ⊕ Fin Q ⊕ Fin Q

def b1gen : B1 Y J Q := Sum.inl ()
def b1rawH (q : Y × Fin 3 × Fin 2) : B1 Y J Q := Sum.inr (Sum.inl q)
def b1rawG (q : J × Fin 3 × Fin 2) : B1 Y J Q := Sum.inr (Sum.inr (Sum.inl q))
def b1C (q : Y × Fin 3) : B1 Y J Q := Sum.inr (Sum.inr (Sum.inr (Sum.inl q)))
def b1K0 (q : Fin Q × Y) : B1 Y J Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl q))))
def b1K1 (q : Fin Q × Y) : B1 Y J Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl q)))))
def b1K2 (q : Fin Q × Y) : B1 Y J Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl q))))))
def b1P0 (k : Fin Q) : B1 Y J Q :=
  Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl k)))))))
def b1P1 (k : Fin Q) : B1 Y J Q :=
  Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl k))))))))
def b1P2 (k : Fin Q) : B1 Y J Q :=
  Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr k))))))))

def b2one : B2 Q := Sum.inl ()
def b2a0 : B2 Q := Sum.inr (Sum.inl ())
def b2a1 : B2 Q := Sum.inr (Sum.inr (Sum.inl ()))
def b2c0 : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inl ())))
def b2c1 : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl ()))))
def b2c2 : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl ())))))
def b2p0 (k : Fin Q) : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl k))))))
def b2p1 (k : Fin Q) : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inl k)))))))
def b2p2 (k : Fin Q) : B2 Q := Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr (Sum.inr k)))))))

variable (M : Y → J → F) (j0 : J)

/-- ciphertext row component `C_{y,l}` (scaled) -/
def fC (y : Y) (l : Fin 3) : P F Y J Q :=
  AA * (X (Var.s 0) * (X (Var.h y l 0) + ∑ j, C (M y j) * X (Var.g j l 0)) +
    X (Var.s 1) * (X (Var.h y l 1) + ∑ j, C (M y j) * X (Var.g j l 1)))

def fK0 (k : Fin Q) (y : Y) : P F Y J Q :=
  X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0) * X (Var.h y 0 0) + X (Var.b 1) * X (Var.r k 1) * X (Var.h y 1 0) +
    (X (Var.r k 0) + X (Var.r k 1)) * X (Var.h y 2 0) + X (Var.sg k y))

def fK1 (k : Fin Q) (y : Y) : P F Y J Q :=
  X (Var.a 0) * (X (Var.b 0) * X (Var.r k 0) * X (Var.h y 0 1) + X (Var.b 1) * X (Var.r k 1) * X (Var.h y 1 1) +
    (X (Var.r k 0) + X (Var.r k 1)) * X (Var.h y 2 1) + X (Var.sg k y))

def fK2 (k : Fin Q) (y : Y) : P F Y J Q := -(AA * X (Var.sg k y))

def fP0 (j0 : J) (k : Fin Q) : P F Y J Q :=
  X (Var.a 1) * (X (Var.b 0) * X (Var.r k 0) * X (Var.g j0 0 0) + X (Var.b 1) * X (Var.r k 1) * X (Var.g j0 1 0) +
    (X (Var.r k 0) + X (Var.r k 1)) * X (Var.g j0 2 0) + X (Var.sp k)) + AA * X (Var.d 0)

def fP1 (j0 : J) (k : Fin Q) : P F Y J Q :=
  X (Var.a 0) * (X (Var.b 0) * X (Var.r k 0) * X (Var.g j0 0 1) + X (Var.b 1) * X (Var.r k 1) * X (Var.g j0 1 1) +
    (X (Var.r k 0) + X (Var.r k 1)) * X (Var.g j0 2 1) + X (Var.sp k)) + AA * X (Var.d 1)

def fP2 (k : Fin Q) : P F Y J Q := -(AA * X (Var.sp k)) + AA * X (Var.d 2)

def ev1 : B1 Y J Q → P F Y J Q :=
  Sum.elim (fun _ : Unit => AA) <|
  Sum.elim (fun q : Y × Fin 3 × Fin 2 => AA * X (Var.h q.1 q.2.1 q.2.2)) <|
  Sum.elim (fun q : J × Fin 3 × Fin 2 => AA * X (Var.g q.1 q.2.1 q.2.2)) <|
  Sum.elim (fun q : Y × Fin 3 => fC M q.1 q.2) <|
  Sum.elim (fun q : Fin Q × Y => fK0 q.1 q.2) <|
  Sum.elim (fun q : Fin Q × Y => fK1 q.1 q.2) <|
  Sum.elim (fun q : Fin Q × Y => fK2 q.1 q.2) <|
  Sum.elim (fun k : Fin Q => fP0 j0 k) <|
  Sum.elim (fun k : Fin Q => fP1 j0 k) <|
  (fun k : Fin Q => fP2 k)

def ev2 : B2 Q → P F Y J Q :=
  Sum.elim (fun _ : Unit => 1) <|
  Sum.elim (fun _ : Unit => X (Var.a 0)) <|
  Sum.elim (fun _ : Unit => X (Var.a 1)) <|
  Sum.elim (fun _ : Unit => X (Var.a 0) * X (Var.s 0)) <|
  Sum.elim (fun _ : Unit => X (Var.a 1) * X (Var.s 1)) <|
  Sum.elim (fun _ : Unit => X (Var.s 0) + X (Var.s 1)) <|
  Sum.elim (fun k : Fin Q => X (Var.b 0) * X (Var.r k 0)) <|
  Sum.elim (fun k : Fin Q => X (Var.b 1) * X (Var.r k 1)) <|
  (fun k : Fin Q => X (Var.r k 0) + X (Var.r k 1))

@[simp] theorem ev1_gen : ev1 M j0 (b1gen : B1 Y J Q) = (AA : P F Y J Q) := rfl
@[simp] theorem ev1_rawH (q : Y × Fin 3 × Fin 2) :
    ev1 M j0 (b1rawH q : B1 Y J Q) = (AA * X (Var.h q.1 q.2.1 q.2.2) : P F Y J Q) := rfl
@[simp] theorem ev1_rawG (q : J × Fin 3 × Fin 2) :
    ev1 M j0 (b1rawG q : B1 Y J Q) = (AA * X (Var.g q.1 q.2.1 q.2.2) : P F Y J Q) := rfl
@[simp] theorem ev1_C (q : Y × Fin 3) : ev1 M j0 (b1C q : B1 Y J Q) = (fC M q.1 q.2 : P F Y J Q) := rfl
@[simp] theorem ev1_K0 (q : Fin Q × Y) : ev1 M j0 (b1K0 q : B1 Y J Q) = (fK0 q.1 q.2 : P F Y J Q) := rfl
@[simp] theorem ev1_K1 (q : Fin Q × Y) : ev1 M j0 (b1K1 q : B1 Y J Q) = (fK1 q.1 q.2 : P F Y J Q) := rfl
@[simp] theorem ev1_K2 (q : Fin Q × Y) : ev1 M j0 (b1K2 q : B1 Y J Q) = (fK2 q.1 q.2 : P F Y J Q) := rfl
@[simp] theorem ev1_P0 (k : Fin Q) : ev1 M j0 (b1P0 k : B1 Y J Q) = (fP0 j0 k : P F Y J Q) := rfl
@[simp] theorem ev1_P1 (k : Fin Q) : ev1 M j0 (b1P1 k : B1 Y J Q) = (fP1 j0 k : P F Y J Q) := rfl
@[simp] theorem ev1_P2 (k : Fin Q) : ev1 M j0 (b1P2 k : B1 Y J Q) = (fP2 k : P F Y J Q) := rfl

@[simp] theorem ev2_one : (ev2 (b2one : B2 Q) : P F Y J Q) = 1 := rfl
@[simp] theorem ev2_a0 : (ev2 (b2a0 : B2 Q) : P F Y J Q) = X (Var.a 0) := rfl
@[simp] theorem ev2_a1 : (ev2 (b2a1 : B2 Q) : P F Y J Q) = X (Var.a 1) := rfl
@[simp] theorem ev2_c0 : (ev2 (b2c0 : B2 Q) : P F Y J Q) = X (Var.a 0) * X (Var.s 0) := rfl
@[simp] theorem ev2_c1 : (ev2 (b2c1 : B2 Q) : P F Y J Q) = X (Var.a 1) * X (Var.s 1) := rfl
@[simp] theorem ev2_c2 : (ev2 (b2c2 : B2 Q) : P F Y J Q) = X (Var.s 0) + X (Var.s 1) := rfl
@[simp] theorem ev2_p0 (k : Fin Q) : (ev2 (b2p0 k : B2 Q) : P F Y J Q) = X (Var.b 0) * X (Var.r k 0) := rfl
@[simp] theorem ev2_p1 (k : Fin Q) : (ev2 (b2p1 k : B2 Q) : P F Y J Q) = X (Var.b 1) * X (Var.r k 1) := rfl
@[simp] theorem ev2_p2 (k : Fin Q) : (ev2 (b2p2 k : B2 Q) : P F Y J Q) = X (Var.r k 0) + X (Var.r k 1) := rfl

theorem sum_B1 {N : Type} [AddCommMonoid N] (g : B1 Y J Q → N) :
    ∑ b, g b = g b1gen + ∑ q, g (b1rawH q) + ∑ q, g (b1rawG q) + ∑ q, g (b1C q) + ∑ q, g (b1K0 q) +
      ∑ q, g (b1K1 q) + ∑ q, g (b1K2 q) + ∑ k, g (b1P0 k) + ∑ k, g (b1P1 k) + ∑ k, g (b1P2 k) := by
  simp only [Fintype.sum_sum_type, b1gen, b1rawH, b1rawG, b1C, b1K0, b1K1, b1K2, b1P0, b1P1, b1P2,
    Finset.univ_unique, Finset.sum_singleton, Unique.default_eq]
  abel

theorem sum_B2 {N : Type} [AddCommMonoid N] (g : B2 Q → N) :
    ∑ b, g b = g b2one + g b2a0 + g b2a1 + g b2c0 + g b2c1 + g b2c2 + ∑ k, g (b2p0 k) + ∑ k, g (b2p1 k) +
      ∑ k, g (b2p2 k) := by
  simp only [Fintype.sum_sum_type, b2one, b2a0, b2a1, b2c0, b2c1, b2c2, b2p0, b2p1, b2p2,
    Finset.univ_unique, Finset.sum_singleton, Unique.default_eq]
  abel

/-- the `G2` element with coordinate vector `x` -/
def ev2s (x : B2 Q → F) : P F Y J Q := ∑ b, C (x b) * ev2 b

/-- the span of the pairing products with coefficient matrix `c` -/
def G (c : B1 Y J Q → B2 Q → F) : P F Y J Q := ∑ b1, ev1 M j0 b1 * ev2s (c b1)

def TA : P F Y J Q :=
  AA * ((X (Var.d 0) * X (Var.a 0) + X (Var.d 2)) * X (Var.s 0) + (X (Var.d 1) * X (Var.a 1) + X (Var.d 2)) * X (Var.s 1))

def TB : P F Y J Q := AA * X Var.z

def WW (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) : P F Y J Q :=
  G M j0 c + C κ0 * AA + C κ1 * (AA * (X (Var.d 0) * X (Var.a 0) + X (Var.d 2))) +
    C κ2 * (AA * (X (Var.d 1) * X (Var.a 1) + X (Var.d 2)))

/-- a key slot may only be paired through the attributes it holds -/
def HCg (held : Fin Q → Y → Prop) (c : B1 Y J Q → B2 Q → F) : Prop :=
  ∀ k y, ¬ held k y → ∀ q, c (b1K0 (k, y)) q = 0 ∧ c (b1K1 (k, y)) q = 0 ∧ c (b1K2 (k, y)) q = 0

/-- the independence statement: the target is not in the span (+ public GT elements) -/
def Indep (held : Fin Q → Y → Prop) : Prop :=
  ∀ (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F), HCg held c → (TA : P F Y J Q) ≠ WW M j0 c κ0 κ1 κ2

/-- the secret-sharing witness: the held attribute set admits a vector with secret `1` and zero shares on held rows -/
def Priv (held : Fin Q → Y → Prop) : Prop :=
  ∀ k, ∃ v : J → F, v j0 = 1 ∧ ∀ y, held k y → ∑ j, M y j * v j = 0

theorem ev2s_eq (x : B2 Q → F) : (ev2s x : P F Y J Q) =
    C (x b2one) + C (x b2a0) * X (Var.a 0) + C (x b2a1) * X (Var.a 1) +
    C (x b2c0) * (X (Var.a 0) * X (Var.s 0)) + C (x b2c1) * (X (Var.a 1) * X (Var.s 1)) +
    C (x b2c2) * (X (Var.s 0) + X (Var.s 1)) +
    ∑ k, C (x (b2p0 k)) * (X (Var.b 0) * X (Var.r k 0)) + ∑ k, C (x (b2p1 k)) * (X (Var.b 1) * X (Var.r k 1)) +
    ∑ k, C (x (b2p2 k)) * (X (Var.r k 0) + X (Var.r k 1)) := by
  unfold ev2s
  rw [sum_B2]
  simp only [ev2_one, ev2_a0, ev2_a1, ev2_c0, ev2_c1, ev2_c2, ev2_p0, ev2_p1, ev2_p2, mul_one]

theorem ev2s_lin (x y : B2 Q → F) (a b : F) :
    (ev2s (fun q => a * x q + b * y q) : P F Y J Q) = C a * ev2s x + C b * ev2s y := by
  unfold ev2s
  simp only [Finset.mul_sum, ← Finset.sum_add_distrib, map_add, map_mul]
  exact Finset.sum_congr rfl fun _ _ => by ring

theorem ev2s_smul (x : B2 Q → F) (a : F) :
    (ev2s (fun q => a * x q) : P F Y J Q) = C a * ev2s x := by
  unfold ev2s
  simp only [Finset.mul_sum, map_mul]
  exact Finset.sum_congr rfl fun _ _ => by ring

theorem G_lin (c c' : B1 Y J Q → B2 Q → F) (a b : F) :
    G M j0 (fun b1 b2 => a * c b1 b2 + b * c' b1 b2) = C a * G M j0 c + C b * G M j0 c' := by
  unfold G
  simp only [ev2s_lin, Finset.mul_sum, ← Finset.sum_add_distrib]
  exact Finset.sum_congr rfl fun _ _ => by ring

theorem WW_lin (c c' : B1 Y J Q → B2 Q → F) (a b k0 k1 k2 k0' k1' k2' : F) :
    WW M j0 (fun b1 b2 => a * c b1 b2 + b * c' b1 b2) (a * k0 + b * k0') (a * k1 + b * k1') (a * k2 + b * k2')
      = C a * WW M j0 c k0 k1 k2 + C b * WW M j0 c' k0' k1' k2' := by
  unfold WW
  rw [G_lin]
  simp only [map_add, map_mul]
  ring


theorem pd_ev2s_z (x : B2 Q → F) : pderiv Var.z (ev2s x : P F Y J Q) = 0 := by
  rw [ev2s_eq]
  simp [Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_G (u : Var Y J Q) (hu : ∀ x : B2 Q → F, pderiv u (ev2s x : P F Y J Q) = 0) (c : B1 Y J Q → B2 Q → F) :
    pderiv u (G M j0 c) = ∑ b1, pderiv u (ev1 M j0 b1) * ev2s (c b1) := by
  unfold G
  simp only [map_sum, Derivation.leibniz, smul_eq_mul, hu, mul_zero, add_zero]
  exact Finset.sum_congr rfl fun b1 _ => by ring

theorem pd_z_ev1 (b : B1 Y J Q) : pderiv Var.z (ev1 M j0 b : P F Y J Q) = 0 := by
  rcases b with _ | q | q | q | q | q | q | k | k | k <;>
  simp [ev1, fC, fK0, fK1, fK2, fP0, fP1, fP2, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply, map_sum]

theorem pd_WW_z (c : B1 Y J Q → B2 Q → F) (κ0 κ1 κ2 : F) :
    pderiv Var.z (WW M j0 c κ0 κ1 κ2 : P F Y J Q) = 0 := by
  unfold WW
  rw [map_add, map_add, map_add, pd_G M j0 Var.z pd_ev2s_z]
  simp [pd_z_ev1, Derivation.leibniz, pderiv_X, pderiv_C, Pi.single_apply]

end Model
end PcaMath.FameGgm
