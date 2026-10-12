import Mathlib
import PcaMath.Abe
import PcaMath.AbeGgm
import PcaMath.GgmTransfer

/-!
# Security of the BSW07 type-3 adaptation in the generic bilinear group model (formal-polynomial / equality-pattern form)

The game: the adversary starts from the public key, the challenge ciphertext header and the target `T`
(`e(g1,g2)^(alpha s)`, world A) or an independent element `beta*z` (world B, the uniform `K`), may query the random
oracle `H`, requests keys (each with an independent `r`, `r_a`) for adaptively chosen attribute sets that do not satisfy the
policy, and applies group operations / the pairing.  `abe_ggm_cpa` bounds its advantage by `30 m^2 / |F|`.
G1 is stored multiplied by `beta` (see `AbeGgm.lean`).
-/

open MvPolynomial Finset PcaMath.AbeGgm PcaMath.GgmTransfer

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false
set_option maxHeartbeats 800000
set_option synthInstance.maxSize 1024
set_option synthInstance.maxHeartbeats 100000

namespace PcaMath.AbeSec

noncomputable section

variable {F : Type} [Field F] [Fintype F] {A CV L : Type} [Fintype A] [Fintype CV] [Fintype L]
  [DecidableEq A] [DecidableEq CV] [DecidableEq L] {Q : ℕ}

abbrev V (F : Type) [Field F] (Q : ℕ) (A CV : Type) := Var (Fin Q) A CV

variable (att : L → A) (lam : L → P F (Fin Q) A CV) (s0 : CV)

def held (aux : List (Finset A)) (i : Fin Q) (a : A) : Prop := a ∈ aux.getD (i : ℕ) ∅

def TA : P F (Fin Q) A CV := X Var.beta * X Var.alpha * X (Var.ct s0)
def TB : P F (Fin Q) A CV := X Var.beta * X Var.z

def WW (c : B1 (Fin Q) A L → B2 (Fin Q) A L → F) (κ0 κ1 : F) : P F (Fin Q) A CV :=
  G att lam s0 c + C κ0 * X Var.beta + C κ1 * (X Var.beta * X Var.alpha)

def HC (aux : List (Finset A)) (c : B1 (Fin Q) A L → B2 (Fin Q) A L → F) : Prop :=
  ∀ i a, ¬ held aux i a → ∀ b1, c b1 (b2Dp i a) = 0

theorem sum_single {ι : Type} [Fintype ι] [DecidableEq ι] (f : ι → P F (Fin Q) A CV) (b : ι) :
    ∑ b', C (if b' = b then (1 : F) else 0) * f b' = f b := by
  rw [Finset.sum_eq_single b]
  · simp
  · intro b' _ hb'; simp [hb']
  · intro h; exact absurd (Finset.mem_univ b) h

def Rep1 (p : P F (Fin Q) A CV) : Prop := ∃ c : B1 (Fin Q) A L → F, p = ∑ b, C (c b) * ev1 att lam b

def Rep2 (aux : List (Finset A)) (p : P F (Fin Q) A CV) : Prop :=
  ∃ c : B2 (Fin Q) A L → F, (∀ i a, ¬ held aux i a → c (b2Dp i a) = 0) ∧ p = ∑ b, C (c b) * ev2 s0 lam b

def RepT (aux : List (Finset A)) (pa pb : P F (Fin Q) A CV) : Prop :=
  ∃ (u κ0 κ1 : F) (c : B1 (Fin Q) A L → B2 (Fin Q) A L → F), HC aux c ∧
    pa = C u * TA s0 + WW att lam s0 c κ0 κ1 ∧ pb = C u * TB + WW att lam s0 c κ0 κ1

/-! ### closure of the representations -/

theorem rep1_zero : Rep1 att lam (0 : P F (Fin Q) A CV) := ⟨fun _ => 0, by simp⟩

theorem rep1_lin {p q : P F (Fin Q) A CV} (hp : Rep1 att lam p) (hq : Rep1 att lam q) (a b : F) :
    Rep1 att lam (C a * p + C b * q) := by
  obtain ⟨c, rfl⟩ := hp
  obtain ⟨c', rfl⟩ := hq
  refine ⟨fun b1 => a * c b1 + b * c' b1, ?_⟩
  simp only [Finset.mul_sum, ← Finset.sum_add_distrib, map_add, map_mul]
  exact Finset.sum_congr rfl fun _ _ => by ring

theorem rep1_basis (b : B1 (Fin Q) A L) : Rep1 att lam (ev1 att lam b) := by
  exact ⟨fun b' => if b' = b then 1 else 0, (sum_single (ev1 att lam) b).symm⟩

theorem rep1_gp {l : List (P F (Fin Q) A CV)} (h : ∀ p ∈ l, Rep1 att lam p) (i : ℕ) :
    Rep1 att lam (gp l i) := by
  by_cases hi : i < l.length
  · exact h _ (gp_mem l i hi)
  · unfold gp; rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact rep1_zero att lam

theorem rep2_zero (aux : List (Finset A)) : Rep2 lam s0 aux (0 : P F (Fin Q) A CV) :=
  ⟨fun _ => 0, fun _ _ _ => rfl, by simp⟩

theorem rep2_lin {aux : List (Finset A)} {p q : P F (Fin Q) A CV} (hp : Rep2 lam s0 aux p)
    (hq : Rep2 lam s0 aux q) (a b : F) : Rep2 lam s0 aux (C a * p + C b * q) := by
  obtain ⟨c, hc, rfl⟩ := hp
  obtain ⟨c', hc', rfl⟩ := hq
  refine ⟨fun b1 => a * c b1 + b * c' b1, fun i a' h => by simp [hc i a' h, hc' i a' h], ?_⟩
  simp only [Finset.mul_sum, ← Finset.sum_add_distrib, map_add, map_mul]
  exact Finset.sum_congr rfl fun _ _ => by ring

theorem rep2_basis (aux : List (Finset A)) (b : B2 (Fin Q) A L)
    (hb : ∀ i a, b = b2Dp i a → held aux i a) : Rep2 lam s0 aux (ev2 s0 lam b) := by
  refine ⟨fun b' => if b' = b then 1 else 0, fun i a h => ?_, (sum_single _ b).symm⟩
  by_cases e : b2Dp i a = b
  · exact absurd (hb i a e.symm) h
  · simp [e]

theorem rep2_gp {aux : List (Finset A)} {l : List (P F (Fin Q) A CV)} (h : ∀ p ∈ l, Rep2 lam s0 aux p) (i : ℕ) :
    Rep2 lam s0 aux (gp l i) := by
  by_cases hi : i < l.length
  · exact h _ (gp_mem l i hi)
  · unfold gp; rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact rep2_zero lam s0 aux

theorem repT_zero (aux : List (Finset A)) : RepT att lam s0 aux (0 : P F (Fin Q) A CV) 0 := by
  refine ⟨0, 0, 0, fun _ _ => 0, fun _ _ _ _ => rfl, ?_, ?_⟩ <;>
  simp [WW, G]

theorem G_zero' : G att lam s0 (fun (_ : B1 (Fin Q) A L) (_ : B2 (Fin Q) A L) => (0 : F)) = (0 : P F (Fin Q) A CV) := by
  simp [G]

theorem repT_lin {aux : List (Finset A)} {pa pb qa qb : P F (Fin Q) A CV}
    (hp : RepT att lam s0 aux pa pb) (hq : RepT att lam s0 aux qa qb) (a b : F) :
    RepT att lam s0 aux (C a * pa + C b * qa) (C a * pb + C b * qb) := by
  obtain ⟨u, k0, k1, c, hc, rfl, rfl⟩ := hp
  obtain ⟨u', k0', k1', c', hc', rfl, rfl⟩ := hq
  refine ⟨a * u + b * u', a * k0 + b * k0', a * k1 + b * k1', fun b1 b2 => a * c b1 b2 + b * c' b1 b2,
    fun i a' h b1 => by simp [hc i a' h, hc' i a' h], ?_, ?_⟩ <;>
  · simp only [WW, G_lin att lam s0, map_add, map_mul]; ring

theorem repT_gp {aux : List (Finset A)} {la lb : List (P F (Fin Q) A CV)} (hl : la.length = lb.length)
    (h : ∀ j (hj : j < la.length), RepT att lam s0 aux (la[j]) (lb[j]'(hl ▸ hj))) (i : ℕ) :
    RepT att lam s0 aux (gp la i) (gp lb i) := by
  by_cases hi : i < la.length
  · have hi' : i < lb.length := hl ▸ hi
    unfold gp
    rw [List.getD_eq_getElem _ _ hi, List.getD_eq_getElem _ _ hi']
    exact h i hi
  · have hi' : ¬ i < lb.length := hl ▸ hi
    unfold gp
    rw [List.getD_eq_default _ _ (not_lt.mp hi), List.getD_eq_default _ _ (not_lt.mp hi')]
    exact repT_zero att lam s0 aux

theorem repT_pair {aux : List (Finset A)} {p q : P F (Fin Q) A CV} (hp : Rep1 att lam p)
    (hq : Rep2 lam s0 aux q) : RepT att lam s0 aux (p * q) (p * q) := by
  obtain ⟨c1, rfl⟩ := hp
  obtain ⟨c2, hc2, rfl⟩ := hq
  refine ⟨0, 0, 0, fun b1 b2 => c1 b1 * c2 b2, fun i a h b1 => by simp [hc2 i a h], ?_, ?_⟩ <;>
  · simp only [WW, G, Finset.sum_mul_sum, map_zero, zero_mul, zero_add, add_zero, map_mul]
    refine Finset.sum_congr rfl fun b1 _ => Finset.sum_congr rfl fun b2 _ => by ring


/-- the key attribute set admits two sharings with different secrets agreeing on its leaves -/
def Sh (k : Finset A) : Prop :=
  ∃ w1 w0 : CV → F, w1 s0 = 1 ∧ w0 s0 = 0 ∧ ∀ x, att x ∈ k → eval (ext w1 : Var (Fin Q) A CV → F) (lam x) = eval (ext w0) (lam x)

theorem pat (hp : Pure lam) (aux : List (Finset A)) (hsh : ∀ i : Fin Q, Sh att lam s0 (aux.getD (i : ℕ) ∅))
    {pa pb qa qb : P F (Fin Q) A CV} (h1 : RepT att lam s0 aux pa pb) (h2 : RepT att lam s0 aux qa qb) :
    pa = qa ↔ pb = qb := by
  obtain ⟨u, k0, k1, c, hc, rfl, rfl⟩ := h1
  obtain ⟨u', k0', k1', c', hc', rfl, rfl⟩ := h2
  have hz : ∀ (c : B1 (Fin Q) A L → B2 (Fin Q) A L → F) κ0 κ1,
      pderiv Var.z (WW att lam s0 c κ0 κ1) = 0 := by
    intro c κ0 κ1
    simp [WW, pderiv_z_G att lam s0 hp, pderiv_X, Derivation.leibniz, pderiv_C]
  constructor
  · intro h
    have hu : u = u' := by
      by_contra hne
      have hd : u - u' ≠ 0 := sub_ne_zero.mpr hne
      have hinv : (C (u - u')⁻¹ : P F (Fin Q) A CV) * (C u - C u') = 1 := by
        rw [← map_sub, ← map_mul, inv_mul_cancel₀ hd, map_one]
      refine abeB att lam s0 hp (fun i => aux.getD (i : ℕ) ∅) hsh
        (fun b1 b2 => -(u - u')⁻¹ * c b1 b2 + (u - u')⁻¹ * c' b1 b2)
        (fun i a ha b1 => by simp [hc i a ha b1, hc' i a ha b1])
        (-(u - u')⁻¹ * k0 + (u - u')⁻¹ * k0') (-(u - u')⁻¹ * k1 + (u - u')⁻¹ * k1') ?_
      rw [G_lin]
      simp only [TA, WW] at h
      simp only [map_add, map_mul, map_neg]
      linear_combination (C (u - u')⁻¹ : P F (Fin Q) A CV) * h - (X Var.beta * X Var.alpha * X (Var.ct s0)) * hinv
    subst hu
    have : WW att lam s0 c k0 k1 = WW att lam s0 c' k0' k1' := add_left_cancel h
    rw [this]
  · intro h
    have hu : u = u' := by
      have := congrArg (pderiv Var.z) h
      simp only [map_add, TB, Derivation.leibniz, smul_eq_mul, hz, pderiv_C, pderiv_X] at this
      simpa using this
    subst hu
    have : WW att lam s0 c k0 k1 = WW att lam s0 c' k0' k1' := add_left_cancel h
    rw [this]


/-! ### the game -/

def prm : Params F (Var (Fin Q) A CV) A (Finset A) where
  ro1 a := ev1 att lam (b1h a)
  kq1 t k := if h : t < Q then ev1 att lam (b1D ⟨t, h⟩) :: k.toList.map (fun a => ev1 att lam (b1Dk ⟨t, h⟩ a)) else []
  kq2 t k := if h : t < Q then k.toList.map (fun a => ev2 s0 lam (b2Dp ⟨t, h⟩ a)) else []

def L0 (T : P F (Fin Q) A CV) : Lists F (Var (Fin Q) A CV) (Finset A) where
  g1 := [ev1 att lam b1one, ev1 att lam b1f] ++ (Finset.univ.toList.map fun x : L => ev1 att lam (b1Cp x))
  g2 := [ev2 s0 lam b2one, ev2 s0 lam b2hh, ev2 s0 lam b2C0] ++ (Finset.univ.toList.map fun x : L => ev2 s0 lam (b2Cx x))
  gt := [X Var.beta, X Var.beta * X Var.alpha, T]
  aux := []

structure Inv (La Lb : Lists F (Var (Fin Q) A CV) (Finset A)) : Prop where
  g1 : La.g1 = Lb.g1
  g2 : La.g2 = Lb.g2
  aux : La.aux = Lb.aux
  r1 : ∀ p ∈ La.g1, Rep1 att lam p
  r2 : ∀ p ∈ La.g2, Rep2 lam s0 La.aux p
  gtl : La.gt.length = Lb.gt.length
  rt : ∀ i, RepT att lam s0 La.aux (gp La.gt i) (gp Lb.gt i)
  sh : ∀ k ∈ La.aux, Sh att lam s0 k

theorem gp_append_single (l : List (P F (Fin Q) A CV)) (x : P F (Fin Q) A CV) (i : ℕ) :
    gp (l ++ [x]) i = if i < l.length then gp l i else if i = l.length then x else 0 := by
  unfold gp
  by_cases hi : i < l.length
  · rw [if_pos hi, List.getD_append _ _ _ _ hi]
  · rw [if_neg hi]
    by_cases he : i = l.length
    · subst he; simp
    · rw [if_neg he, List.getD_append_right _ _ _ _ (not_lt.mp hi)]
      have h1 : i - l.length ≥ 1 := by omega
      obtain ⟨m, hm⟩ : ∃ m, i - l.length = m + 1 := ⟨i - l.length - 1, by omega⟩
      rw [hm]
      simp

theorem held_mono (aux : List (Finset A)) (k : Finset A) {i : Fin Q} {a : A} (h : held aux i a) :
    held (aux ++ [k]) i a := by
  unfold held at *
  by_cases hi : (i : ℕ) < aux.length
  · rwa [List.getD_append _ _ _ _ hi]
  · rw [List.getD_eq_default _ _ (not_lt.mp hi)] at h; simp at h

theorem rep2_mono {aux : List (Finset A)} (k : Finset A) {p : P F (Fin Q) A CV}
    (h : Rep2 lam s0 aux p) : Rep2 lam s0 (aux ++ [k]) p := by
  obtain ⟨c, hc, e⟩ := h
  exact ⟨c, fun i a hh => hc i a (fun h' => hh (held_mono aux k h')), e⟩

theorem repT_mono {aux : List (Finset A)} (k : Finset A) {pa pb : P F (Fin Q) A CV}
    (h : RepT att lam s0 aux pa pb) : RepT att lam s0 (aux ++ [k]) pa pb := by
  obtain ⟨u, k0, k1, c, hc, e1, e2⟩ := h
  exact ⟨u, k0, k1, c, fun i a hh b1 => hc i a (fun h' => hh (held_mono aux k h')) b1, e1, e2⟩

theorem held_new (aux : List (Finset A)) (k : Finset A) {i : Fin Q} (hi : (i : ℕ) = aux.length) {a : A}
    (ha : a ∈ k) : held (aux ++ [k]) i a := by
  unfold held; rw [hi]; simpa using ha


theorem repT_basic (aux : List (Finset A)) :
    RepT att lam s0 aux (X Var.beta) (X Var.beta) ∧ RepT att lam s0 aux (X Var.beta * X Var.alpha) (X Var.beta * X Var.alpha)
    ∧ RepT att lam s0 aux (TA s0) (TB : P F (Fin Q) A CV) := by
  refine ⟨⟨0, 1, 0, fun _ _ => 0, fun _ _ _ _ => rfl, ?_, ?_⟩, ⟨0, 0, 1, fun _ _ => 0, fun _ _ _ _ => rfl, ?_, ?_⟩,
    ⟨1, 0, 0, fun _ _ => 0, fun _ _ _ _ => rfl, ?_, ?_⟩⟩ <;>
  simp [WW, G_zero' att lam s0]

theorem inv_init : Inv att lam s0 (L0 att lam s0 (TA s0)) (L0 att lam s0 (TB : P F (Fin Q) A CV)) := by
  refine ⟨rfl, rfl, rfl, ?_, ?_, rfl, ?_, ?_⟩
  · intro p hp
    simp only [L0, List.mem_append, List.mem_cons, List.not_mem_nil, or_false, List.mem_map] at hp
    rcases hp with (rfl | rfl) | ⟨x, _, rfl⟩ <;> exact rep1_basis att lam _
  · intro p hp
    simp only [L0, List.mem_append, List.mem_cons, List.not_mem_nil, or_false, List.mem_map] at hp
    rcases hp with (rfl | rfl | rfl) | ⟨x, _, rfl⟩ <;>
    exact rep2_basis lam s0 _ _ (fun i a h => by cases h)
  · intro i
    obtain ⟨h1, h2, h3⟩ := repT_basic att lam s0 ([] : List (Finset A))
    simp only [L0]
    match i with
    | 0 => simpa [gp] using h1
    | 1 => simpa [gp] using h2
    | 2 => simpa [gp] using h3
    | n + 3 => simpa [gp] using repT_zero att lam s0 ([] : List (Finset A))
  · intro k hk; simp [L0] at hk


theorem inv_step (op : Op F A (Finset A)) (hk : ∀ k, op = Op.kq k → Sh att lam s0 k)
    {La Lb : Lists F (Var (Fin Q) A CV) (Finset A)} (h : Inv att lam s0 La Lb) :
    Inv att lam s0 (apply (prm att lam s0) op La) (apply (prm att lam s0) op Lb) := by
  obtain ⟨hg1, hg2, haux, r1, r2, gtl, rt, sh⟩ := h
  rcases La with ⟨a1, a2, a3, a4⟩
  rcases Lb with ⟨b1, b2, b3, b4⟩
  simp only at hg1 hg2 haux r1 r2 gtl rt sh
  subst hg1 hg2 haux
  cases op with
  | lin1 i j a b =>
    refine ⟨rfl, rfl, rfl, ?_, r2, gtl, rt, sh⟩
    intro p hp
    simp only [apply, List.mem_append, List.mem_singleton] at hp
    rcases hp with hp | rfl
    · exact r1 p hp
    · exact rep1_lin att lam (rep1_gp att lam r1 i) (rep1_gp att lam r1 j) a b
  | lin2 i j a b =>
    refine ⟨rfl, rfl, rfl, r1, ?_, gtl, rt, sh⟩
    intro p hp
    simp only [apply, List.mem_append, List.mem_singleton] at hp
    rcases hp with hp | rfl
    · exact r2 p hp
    · exact rep2_lin lam s0 (rep2_gp lam s0 r2 i) (rep2_gp lam s0 r2 j) a b
  | linT i j a b =>
    refine ⟨rfl, rfl, rfl, r1, r2, ?_, ?_, sh⟩
    · simp [apply, gtl]
    · intro n
      simp only [apply, gp_append_single, ← gtl]
      split_ifs
      · exact rt n
      · exact repT_lin att lam s0 (rt i) (rt j) a b
      · exact repT_zero att lam s0 a4
  | pair i j =>
    refine ⟨rfl, rfl, rfl, r1, r2, ?_, ?_, sh⟩
    · simp [apply, gtl]
    · intro n
      simp only [apply, gp_append_single, ← gtl]
      split_ifs
      · exact rt n
      · exact repT_pair att lam s0 (rep1_gp att lam r1 i) (rep2_gp lam s0 r2 j)
      · exact repT_zero att lam s0 a4
  | roq a =>
    refine ⟨rfl, rfl, rfl, ?_, r2, gtl, rt, sh⟩
    intro p hp
    simp only [apply, List.mem_append, List.mem_singleton] at hp
    rcases hp with hp | rfl
    · exact r1 p hp
    · exact rep1_basis att lam (b1h a)
  | kq k =>
    have hkk := hk k rfl
    by_cases hQ : a4.length < Q
    · refine ⟨rfl, rfl, rfl, ?_, ?_, gtl, fun n => repT_mono att lam s0 k (rt n), ?_⟩
      · intro p hp
        simp only [apply, prm, hQ, dif_pos, List.mem_append, List.mem_cons, List.mem_map] at hp
        rcases hp with hp | rfl | ⟨a, _, rfl⟩
        · exact r1 p hp
        · exact rep1_basis att lam _
        · exact rep1_basis att lam _
      · intro p hp
        simp only [apply, prm, hQ, dif_pos, List.mem_append, List.mem_map, Finset.mem_toList] at hp
        rcases hp with hp | ⟨a, ha, rfl⟩
        · exact rep2_mono lam s0 k (r2 p hp)
        · refine rep2_basis lam s0 _ _ (fun i a' hh => ?_)
          have hh' : (⟨a4.length, hQ⟩ : Fin Q) = i ∧ a = a' := by simpa [b2Dp] using hh
          obtain ⟨hi, ha'⟩ := hh'
          subst hi; subst ha'
          exact held_new a4 k rfl ha
      · intro k' hk'
        simp only [apply, List.mem_append, List.mem_singleton] at hk'
        rcases hk' with hk' | rfl
        · exact sh k' hk'
        · exact hkk
    · refine ⟨rfl, rfl, rfl, ?_, ?_, gtl, fun n => repT_mono att lam s0 k (rt n), ?_⟩
      · intro p hp
        simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.append_nil] at hp
        exact r1 p hp
      · intro p hp
        simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.append_nil] at hp
        exact rep2_mono lam s0 k (r2 p hp)
      · intro k' hk'
        simp only [apply, List.mem_append, List.mem_singleton] at hk'
        rcases hk' with hk' | rfl
        · exact sh k' hk'
        · exact hkk
  | nop => exact ⟨rfl, rfl, rfl, r1, r2, gtl, rt, sh⟩


theorem obs_of_inv (hp : Pure lam) (hemp : Sh att lam s0 (∅ : Finset A))
    {La Lb : Lists F (Var (Fin Q) A CV) (Finset A)} (h : Inv att lam s0 La Lb) :
    obs eqoF La = obs eqoF Lb := by
  have hsh : ∀ i : Fin Q, Sh att lam s0 (La.aux.getD (i : ℕ) ∅) := by
    intro i
    by_cases hi : (i : ℕ) < La.aux.length
    · rw [List.getD_eq_getElem _ _ hi]; exact h.sh _ (List.getElem_mem hi)
    · rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact hemp
  unfold obs
  have e1 : patL (eqoF : MvPolynomial (Var (Fin Q) A CV) F → _) La.g1 = patL eqoF Lb.g1 := by rw [h.g1]
  have e2 : patL (eqoF : MvPolynomial (Var (Fin Q) A CV) F → _) La.g2 = patL eqoF Lb.g2 := by rw [h.g2]
  have e3 : patL (eqoF : MvPolynomial (Var (Fin Q) A CV) F → _) La.gt = patL eqoF Lb.gt := by
    unfold patL
    rw [← h.gtl]
    refine List.flatMap_congr fun i _ => List.map_congr_left fun j _ => ?_
    simp only [eqoF]
    exact decide_eq_decide.mpr (pat att lam s0 hp La.aux hsh (h.rt i) (h.rt j))
  rw [e1, e2, e3]

theorem run_inv (adv : Adv F A (Finset A)) (hp : Pure lam)
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh att lam s0 k) (hemp : Sh att lam s0 (∅ : Finset A)) :
    ∀ n, (run (prm att lam s0) eqoF adv (L0 att lam s0 (TA s0)) n).2 =
          (run (prm att lam s0) eqoF adv (L0 att lam s0 (TB : P F (Fin Q) A CV)) n).2 ∧
        Inv att lam s0 (run (prm att lam s0) eqoF adv (L0 att lam s0 (TA s0)) n).1
          (run (prm att lam s0) eqoF adv (L0 att lam s0 (TB : P F (Fin Q) A CV)) n).1
  | 0 => by
    refine ⟨?_, inv_init att lam s0⟩
    simp only [run]
    rw [obs_of_inv att lam s0 hp hemp (inv_init att lam s0)]
  | n + 1 => by
    obtain ⟨hh, hI⟩ := run_inv adv hp hkeys hemp n
    have hI' := inv_step att lam s0 (adv.next (run (prm att lam s0) eqoF adv (L0 att lam s0 (TA s0)) n).2)
      (fun k hk => hkeys _ k hk) hI
    refine ⟨?_, ?_⟩
    · simp only [run]
      rw [← hh, obs_of_inv att lam s0 hp hemp hI']
    · simp only [run]
      rw [← hh]
      exact hI'


/-! ### degrees and sizes -/

theorem tD_mul_le {p q : P F (Fin Q) A CV} {m n : ℕ} (hp : p.totalDegree ≤ m) (hq : q.totalDegree ≤ n) :
    (p * q).totalDegree ≤ m + n := (totalDegree_mul p q).trans (add_le_add hp hq)

theorem tD_add_le {p q : P F (Fin Q) A CV} {m : ℕ} (hp : p.totalDegree ≤ m) (hq : q.totalDegree ≤ m) :
    (p + q).totalDegree ≤ m := (totalDegree_add p q).trans (max_le hp hq)

theorem tD_X (v : Var (Fin Q) A CV) : (X v : P F (Fin Q) A CV).totalDegree ≤ 1 := by
  simp [totalDegree_X]

theorem tD_C (a : F) : (C a : P F (Fin Q) A CV).totalDegree ≤ 0 := by simp

theorem tD_sum {ι : Type} (s : Finset ι) (f : ι → P F (Fin Q) A CV) {m : ℕ} (h : ∀ i ∈ s, (f i).totalDegree ≤ m) :
    (∑ i ∈ s, f i).totalDegree ≤ m :=
  (totalDegree_finset_sum s f).trans (Finset.sup_le h)

theorem deg_ev1 (hlin : ∀ x, (lam x).totalDegree ≤ 1) (b : B1 (Fin Q) A L) : (ev1 att lam b).totalDegree ≤ 3 := by
  rcases b with ⟨⟩ | ⟨⟩ | a | i | ⟨i, a⟩ | x
  · simpa [ev1] using (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta).trans (by norm_num)
  · simp [ev1]
  · have := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) (tD_X (Var.h a))
    simpa [ev1] using this.trans (by norm_num)
  · have := tD_add_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.alpha) (tD_X (Var.r i))
    simpa [ev1] using this.trans (by norm_num)
  · have h1 := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) (Var.rr i a)) (tD_X (Var.h a))
    have h2 := tD_add_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) (Var.r i) |>.trans (by norm_num : 1 ≤ 2)) h1
    have h3 := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) h2
    simpa [ev1] using h3
  · have h1 := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) (hlin x)
    have h2 := tD_mul_le h1 (tD_X (Var.h (att x)))
    simpa [ev1] using h2

theorem deg_ev2 (hlin : ∀ x, (lam x).totalDegree ≤ 1) (b : B2 (Fin Q) A L) : (ev2 s0 lam b).totalDegree ≤ 2 := by
  rcases b with ⟨⟩ | ⟨⟩ | ⟨i, a⟩ | ⟨⟩ | x
  · simp [ev2]
  · simpa [ev2] using (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta).trans (by norm_num)
  · simpa [ev2] using (tD_X (F := F) (Q := Q) (A := A) (CV := CV) (Var.rr i a)).trans (by norm_num)
  · have := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) (Var.ct s0)) (tD_X Var.beta)
    simpa [ev2] using this
  · simpa [ev2] using (hlin x).trans (by norm_num)

theorem deg_rep1 (hlin : ∀ x, (lam x).totalDegree ≤ 1) {p : P F (Fin Q) A CV} (h : Rep1 att lam p) : p.totalDegree ≤ 3 := by
  obtain ⟨c, rfl⟩ := h
  refine tD_sum _ _ fun b _ => ?_
  simpa using tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) (c b)) (deg_ev1 att lam hlin b)

theorem deg_rep2 (hlin : ∀ x, (lam x).totalDegree ≤ 1) {aux} {p : P F (Fin Q) A CV} (h : Rep2 lam s0 aux p) : p.totalDegree ≤ 2 := by
  obtain ⟨c, _, rfl⟩ := h
  refine tD_sum _ _ fun b _ => ?_
  simpa using tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) (c b)) (deg_ev2 lam s0 hlin b)

theorem deg_WW (hlin : ∀ x, (lam x).totalDegree ≤ 1) (c : B1 (Fin Q) A L → B2 (Fin Q) A L → F) (k0 k1 : F) :
    (WW att lam s0 c k0 k1).totalDegree ≤ 5 := by
  have hG : (G att lam s0 c).totalDegree ≤ 5 := by
    refine tD_sum _ _ fun b1 _ => tD_sum _ _ fun b2 _ => ?_
    have := tD_mul_le (tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) (c b1 b2)) (deg_ev1 att lam hlin b1))
      (deg_ev2 lam s0 hlin b2)
    simpa using this
  have hb := tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) k0) (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta)
  have hb2 := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.alpha)
  have hb3 := tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) k1) hb2
  unfold WW
  exact tD_add_le (tD_add_le hG (by simpa using hb.trans (by norm_num))) (by simpa using hb3.trans (by norm_num))

theorem deg_TA : (TA s0 : P F (Fin Q) A CV).totalDegree ≤ 3 := by
  have := tD_mul_le (tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) (tD_X Var.alpha)) (tD_X (Var.ct s0))
  simpa [TA] using this

theorem deg_TB : (TB : P F (Fin Q) A CV).totalDegree ≤ 2 := by
  have := tD_mul_le (tD_X (F := F) (Q := Q) (A := A) (CV := CV) Var.beta) (tD_X Var.z)
  simpa [TB] using this

theorem deg_repT (hlin : ∀ x, (lam x).totalDegree ≤ 1) {aux} {pa pb : P F (Fin Q) A CV}
    (h : RepT att lam s0 aux pa pb) : pa.totalDegree ≤ 5 ∧ pb.totalDegree ≤ 5 := by
  obtain ⟨u, k0, k1, c, _, rfl, rfl⟩ := h
  have hw := deg_WW att lam s0 hlin c k0 k1
  have h1 := tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) u) (deg_TA s0 (F := F) (Q := Q) (A := A) (CV := CV))
  have h2 := tD_mul_le (tD_C (F := F) (Q := Q) (A := A) (CV := CV) u) (deg_TB (F := F) (Q := Q) (A := A) (CV := CV))
  exact ⟨tD_add_le (by simpa using h1.trans (by norm_num)) hw, tD_add_le (by simpa using h2.trans (by norm_num)) hw⟩


theorem len_step (op : Op F A (Finset A)) (Lx : Lists F (Var (Fin Q) A CV) (Finset A)) :
    (apply (prm att lam s0) op Lx).g1.length ≤ Lx.g1.length + (1 + Fintype.card A) ∧
    (apply (prm att lam s0) op Lx).g2.length ≤ Lx.g2.length + (1 + Fintype.card A) ∧
    (apply (prm att lam s0) op Lx).gt.length ≤ Lx.gt.length + (1 + Fintype.card A) := by
  have hk : ∀ k : Finset A, k.toList.length ≤ Fintype.card A := fun k => by
    rw [Finset.length_toList]; exact Finset.card_le_univ k
  cases op with
  | kq k =>
    have := hk k
    by_cases hQ : Lx.aux.length < Q
    · simp only [apply, prm, hQ, dif_pos, List.length_append, List.length_cons, List.length_map]
      omega
    · simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.length_append, List.length_nil]
      omega
  | _ => simp [apply]

theorem len_run (adv : Adv F A (Finset A)) (L0' : Lists F (Var (Fin Q) A CV) (Finset A)) (c0 : ℕ)
    (h1 : L0'.g1.length ≤ c0) (h2 : L0'.g2.length ≤ c0) (h3 : L0'.gt.length ≤ c0) :
    ∀ n, (run (prm att lam s0) eqoF adv L0' n).1.g1.length ≤ c0 + n * (1 + Fintype.card A) ∧
      (run (prm att lam s0) eqoF adv L0' n).1.g2.length ≤ c0 + n * (1 + Fintype.card A) ∧
      (run (prm att lam s0) eqoF adv L0' n).1.gt.length ≤ c0 + n * (1 + Fintype.card A)
  | 0 => by simp only [run]; simpa using ⟨h1, h2, h3⟩
  | n + 1 => by
    obtain ⟨a, b, c⟩ := len_run adv L0' c0 h1 h2 h3 n
    obtain ⟨a', b', c'⟩ := len_step att lam s0 (adv.next (run (prm att lam s0) eqoF adv L0' n).2)
      (run (prm att lam s0) eqoF adv L0' n).1
    simp only [run]
    refine ⟨?_, ?_, ?_⟩ <;> nlinarith

theorem L0_len (T : P F (Fin Q) A CV) :
    (L0 att lam s0 T).g1.length ≤ 3 + Fintype.card L ∧ (L0 att lam s0 T).g2.length ≤ 3 + Fintype.card L ∧
      (L0 att lam s0 T).gt.length ≤ 3 + Fintype.card L := by
  simp [L0, Finset.length_toList]
  omega

theorem mem_gt_deg {l : List (P F (Fin Q) A CV)} {Pr : P F (Fin Q) A CV → Prop} (h : ∀ i, Pr (gp l i))
    (p : P F (Fin Q) A CV) (hp : p ∈ l) : Pr p := by
  obtain ⟨i, hi, rfl⟩ := List.mem_iff_getElem.mp hp
  have := h i
  unfold gp at this
  rwa [List.getD_eq_getElem _ _ hi] at this


open Classical in
/-- **ABE-2 / ABE-3 core (collusion resistance and CPA security of the KEM in the type-3 generic bilinear group model).**
Every adaptive generic adversary that requests `Q` keys for attribute sets none of which satisfies the policy, queries
`H`, and makes `n` generic operations distinguishes `e(g1,g2)^(alpha s)` from an independent uniform element with
advantage at most `30 m^2 / |F|`, `m = 3 + |leaves| + n (1 + |attributes|)`, in the equality-pattern generic group model. -/
theorem abe_ggm_cpa (adv : Adv F A (Finset A)) (hp : Pure lam) (hlin : ∀ x, (lam x).totalDegree ≤ 1)
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh att lam s0 k) (hemp : Sh att lam s0 (∅ : Finset A)) (n : ℕ) :
    |((univ.filter (fun x : Var (Fin Q) A CV → F =>
          result (prm att lam s0) (eqoR x) adv (L0 att lam s0 (TA s0)) n = true)).card : ℚ)
      - ((univ.filter (fun x : Var (Fin Q) A CV → F =>
          result (prm att lam s0) (eqoR x) adv (L0 att lam s0 (TB : P F (Fin Q) A CV)) n = true)).card : ℚ)|
      * Fintype.card F ≤
    2 * ((3 * (3 + Fintype.card L + n * (1 + Fintype.card A)) ^ 2 : ℕ) : ℚ) * (5 : ℕ) *
      (Fintype.card F : ℚ) ^ Fintype.card (Var (Fin Q) A CV) := by
  obtain ⟨hh, hI⟩ := run_inv att lam s0 adv hp hkeys hemp n
  have hform : result (prm att lam s0) eqoF adv (L0 att lam s0 (TA s0)) n =
      result (prm att lam s0) eqoF adv (L0 att lam s0 (TB : P F (Fin Q) A CV)) n := by
    unfold result; rw [hh]
  obtain ⟨la1, la2, la3⟩ := len_run att lam s0 adv _ _ (L0_len att lam s0 (TA s0)).1 (L0_len att lam s0 (TA s0)).2.1
    (L0_len att lam s0 (TA s0)).2.2 n
  obtain ⟨lb1, lb2, lb3⟩ := len_run att lam s0 adv _ _ (L0_len att lam s0 (TB : P F (Fin Q) A CV)).1
    (L0_len att lam s0 (TB : P F (Fin Q) A CV)).2.1 (L0_len att lam s0 (TB : P F (Fin Q) A CV)).2.2 n
  refine transfer (prm att lam s0) adv _ _ n hform 5 (3 * (3 + Fintype.card L + n * (1 + Fintype.card A)) ^ 2)
    ?_ ?_ ?_ ?_
  · intro p hp
    simp only [List.mem_append] at hp
    rcases hp with (hp | hp) | hp
    · exact (deg_rep1 att lam hlin (hI.r1 p hp)).trans (by norm_num)
    · exact (deg_rep2 lam s0 hlin (hI.r2 p hp)).trans (by norm_num)
    · exact mem_gt_deg (Pr := fun q => q.totalDegree ≤ 5) (fun i => (deg_repT att lam s0 hlin (hI.rt i)).1) p hp
  · intro p hp
    simp only [List.mem_append] at hp
    rcases hp with (hp | hp) | hp
    · rw [← hI.g1] at hp
      exact (deg_rep1 att lam hlin (hI.r1 p hp)).trans (by norm_num)
    · rw [← hI.g2] at hp
      exact (deg_rep2 lam s0 hlin (hI.r2 p hp)).trans (by norm_num)
    · exact mem_gt_deg (Pr := fun q => q.totalDegree ≤ 5) (fun i => (deg_repT att lam s0 hlin (hI.rt i)).2) p hp
  · have := Nat.pow_le_pow_left la1 2
    have := Nat.pow_le_pow_left la2 2
    have := Nat.pow_le_pow_left la3 2
    nlinarith
  · have := Nat.pow_le_pow_left lb1 2
    have := Nat.pow_le_pow_left lb2 2
    have := Nat.pow_le_pow_left lb3 2
    nlinarith


open Classical in
/-- probability form: `|Pr_A - Pr_B| <= 30 m^2 / |F|` (probability over the uniform assignment of all randomness) -/
theorem abe_ggm_cpa_prob (adv : Adv F A (Finset A)) (hp : Pure lam) (hlin : ∀ x, (lam x).totalDegree ≤ 1)
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh att lam s0 k) (hemp : Sh att lam s0 (∅ : Finset A)) (n : ℕ) :
    |((univ.filter (fun x : Var (Fin Q) A CV → F =>
          result (prm att lam s0) (eqoR x) adv (L0 att lam s0 (TA s0)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var (Fin Q) A CV)
      - ((univ.filter (fun x : Var (Fin Q) A CV → F =>
          result (prm att lam s0) (eqoR x) adv (L0 att lam s0 (TB : P F (Fin Q) A CV)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var (Fin Q) A CV)|
      ≤ 30 * ((3 + Fintype.card L + n * (1 + Fintype.card A) : ℕ) : ℚ) ^ 2 / Fintype.card F := by
  have h := abe_ggm_cpa att lam s0 adv hp hlin hkeys hemp n
  have hq : (0 : ℚ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have hv : (0 : ℚ) < (Fintype.card F : ℚ) ^ Fintype.card (Var (Fin Q) A CV) := by positivity
  rw [← sub_div, abs_div, abs_of_pos hv, div_le_div_iff₀ hv hq]
  push_cast at h ⊢
  nlinarith [h]

/-! ### linking the model to the access tree of `Abe.lean` -/

/-- the formal shares `lam` are the formal Shamir shares: every sharing of the tree is realised by an assignment of the
ciphertext randomness (the coefficients), with the secret in `s0`. -/
def Realizes (pos : L → ℕ) (Tr : PcaMath.Abe.T) : Prop :=
  ∀ (σ : F) (f : ℕ → F), PcaMath.Abe.T.Ach Tr σ f →
    ∃ w : CV → F, w s0 = σ ∧ ∀ x, pos x ∈ Tr.leaves → eval (ext w : Var (Fin Q) A CV → F) (lam x) = f (pos x)

open Classical in
theorem sh_of_tree (K : ℕ) (hK : PcaMath.Abe.T.GoodIdx F K) (Tr : PcaMath.Abe.T) (hw : PcaMath.Abe.T.Wf K Tr)
    (pos : L → ℕ) (hleaf : ∀ x, pos x ∈ Tr.leaves) (hre : Realizes lam s0 pos Tr) (k : Finset A)
    (hunq : ¬ PcaMath.Abe.T.Qual ((univ.filter fun x => att x ∈ k).image pos) Tr) : Sh att lam s0 k := by
  obtain ⟨f1, hA1, hz⟩ := PcaMath.Abe.T.privacy K hK Tr hw _ hunq (1 : F)
  obtain ⟨w1, h1s, h1e⟩ := hre 1 f1 hA1
  obtain ⟨w0, h0s, h0e⟩ := hre 0 (fun _ => 0) (PcaMath.Abe.T.Ach_zero Tr)
  refine ⟨w1, w0, h1s, h0s, fun x hx => ?_⟩
  rw [h1e x (hleaf x), h0e x (hleaf x)]
  exact hz (pos x) (Finset.mem_image_of_mem _ (by simpa using hx)) (hleaf x)

/-- ABE correctness for arbitrary threshold trees: the decryption equation `e(D,C0) / prod e(D_j,C_x)/e(C'_x,D'_j)^c_x`
has exponent `alpha*s` whenever the leaves used satisfy the tree. -/
theorem correctness (K : ℕ) (hK : PcaMath.Abe.T.GoodIdx F K) (Tr : PcaMath.Abe.T) (hw : PcaMath.Abe.T.Wf K Tr)
    (Xs : Finset ℕ) (hq : PcaMath.Abe.T.Qual Xs Tr) (α r s : F) (f : ℕ → F) (hf : PcaMath.Abe.T.Ach Tr s f)
    (rr h : ℕ → F) :
    ∃ c : ℕ → F, (∀ x, x ∉ Xs → c x = 0) ∧
      (α + r) * s - ∑ x ∈ Tr.leaves, c x * ((r + rr x * h x) * f x - f x * h x * rr x) = α * s := by
  obtain ⟨c, h1, h2, h3⟩ := PcaMath.Abe.T.reconstruction K hK Tr hw Xs hq
  refine ⟨c, h1, ?_⟩
  have e : ∀ x, c x * ((r + rr x * h x) * f x - f x * h x * rr x) = r * (c x * f x) := fun x => by ring
  simp only [e, ← Finset.mul_sum, h3 s f hf]
  ring

/-- concrete figure: BLS12-381 group order, `m <= 2^80` group operations and elements -/
theorem bls_bound : 30 * (2 ^ 80) ^ 2 * 2 ^ 89 ≤
    (0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 : ℕ) := by norm_num

end

end PcaMath.AbeSec
