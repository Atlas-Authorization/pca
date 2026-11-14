import Mathlib
import PcaMath.FameDefs
import PcaMath.GgmTransfer

/-!
# CPA security of FAME in the generic bilinear group model (equality-pattern form)

The adversary sees the public key, the challenge ciphertext header and rows, and either the KEM target (world A) or an
independent GT element (world B).  It queries the random oracles `H`, `H0`, requests keys (one per slot, adaptively chosen
attribute sets none of which satisfies the policy) and applies group operations and the pairing.  The independence statement
`Indep` (proved in `FameGgm.lean`) is a hypothesis of this file so the modules build in parallel; `FameMain.lean` discharges it.
-/

open MvPolynomial Finset PcaMath.FameGgm PcaMath.GgmTransfer

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false
set_option maxHeartbeats 800000
set_option synthInstance.maxSize 1024
set_option synthInstance.maxHeartbeats 100000

namespace PcaMath.FameSec

noncomputable section

variable {F : Type} [Field F] [Fintype F] {Y J : Type} {Q : ℕ}
  [Fintype Y] [Fintype J] [DecidableEq Y] [DecidableEq J]

local notation "AA" => (X (Var.a 0) * X (Var.a 1))

variable (M : Y → J → F) (j0 : J)

def held (aux : List (Finset Y)) (k : Fin Q) (y : Y) : Prop := y ∈ aux.getD (k : ℕ) ∅

def Rep1 (aux : List (Finset Y)) (p : P F Y J Q) : Prop :=
  ∃ c : B1 Y J Q → F, (∀ k y, ¬ held aux k y →
      c (b1K0 (k, y)) = 0 ∧ c (b1K1 (k, y)) = 0 ∧ c (b1K2 (k, y)) = 0) ∧
    p = ∑ b, C (c b) * ev1 M j0 b

def Rep2 (p : P F Y J Q) : Prop := ∃ c : B2 Q → F, p = ev2s c

def RepT (aux : List (Finset Y)) (pa pb : P F Y J Q) : Prop :=
  ∃ (u k0 k1 k2 : F) (c : B1 Y J Q → B2 Q → F), HCg (held aux) c ∧
    pa = C u * TA + WW M j0 c k0 k1 k2 ∧ pb = C u * TB + WW M j0 c k0 k1 k2

def Allowed (aux : List (Finset Y)) (b : B1 Y J Q) : Prop :=
  ∀ k y, ¬ held aux k y → b ≠ b1K0 (k, y) ∧ b ≠ b1K1 (k, y) ∧ b ≠ b1K2 (k, y)

theorem sum_single {ι : Type} [Fintype ι] [DecidableEq ι] (f : ι → P F Y J Q) (b : ι) :
    ∑ b', C (if b' = b then (1 : F) else 0) * f b' = f b := by
  rw [Finset.sum_eq_single b]
  · simp
  · intro b' _ hb'; simp [hb']
  · intro h; exact absurd (Finset.mem_univ b) h

/-! ### closure of the representations -/

theorem rep1_zero (aux : List (Finset Y)) : Rep1 M j0 aux (0 : P F Y J Q) :=
  ⟨fun _ => 0, fun _ _ _ => ⟨rfl, rfl, rfl⟩, by simp⟩

theorem rep1_lin {aux : List (Finset Y)} {p q : P F Y J Q} (hp : Rep1 M j0 aux p) (hq : Rep1 M j0 aux q) (a b : F) :
    Rep1 M j0 aux (C a * p + C b * q) := by
  obtain ⟨c, hc, rfl⟩ := hp
  obtain ⟨c', hc', rfl⟩ := hq
  refine ⟨fun b1 => a * c b1 + b * c' b1, fun k y h => ?_, ?_⟩
  · obtain ⟨a0, a1, a2⟩ := hc k y h
    obtain ⟨b0, b1, b2⟩ := hc' k y h
    simp [a0, a1, a2, b0, b1, b2]
  · simp only [Finset.mul_sum, ← Finset.sum_add_distrib, map_add, map_mul]
    exact Finset.sum_congr rfl fun _ _ => by ring

open Classical in
theorem rep1_basis (aux : List (Finset Y)) (b : B1 Y J Q) (hb : Allowed aux b) :
    Rep1 M j0 aux (ev1 M j0 b) := by
  refine ⟨fun b' => if b' = b then (1 : F) else 0, fun k y h => ?_, ?_⟩
  · obtain ⟨h0, h1, h2⟩ := hb k y h
    exact ⟨if_neg (fun e => h0 e.symm), if_neg (fun e => h1 e.symm), if_neg (fun e => h2 e.symm)⟩
  · rw [Finset.sum_eq_single b]
    · simp
    · intro b' _ hb'; simp [hb']
    · intro h; exact absurd (Finset.mem_univ b) h

theorem rep1_gp {aux : List (Finset Y)} {l : List (P F Y J Q)} (h : ∀ p ∈ l, Rep1 M j0 aux p) (i : ℕ) :
    Rep1 M j0 aux (gp l i) := by
  by_cases hi : i < l.length
  · exact h _ (gp_mem l i hi)
  · unfold gp; rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact rep1_zero M j0 aux

theorem rep2_zero : Rep2 (0 : P F Y J Q) := ⟨fun _ => 0, by simp [ev2s]⟩

theorem rep2_lin {p q : P F Y J Q} (hp : Rep2 p) (hq : Rep2 q) (a b : F) : Rep2 (C a * p + C b * q) := by
  obtain ⟨c, rfl⟩ := hp
  obtain ⟨c', rfl⟩ := hq
  exact ⟨fun x => a * c x + b * c' x, (ev2s_lin c c' a b).symm⟩

open Classical in
theorem rep2_basis (b : B2 Q) : Rep2 (ev2 b : P F Y J Q) :=
  ⟨fun b' => if b' = b then 1 else 0, (sum_single (ev2 : B2 Q → P F Y J Q) b).symm⟩

theorem rep2_gp {l : List (P F Y J Q)} (h : ∀ p ∈ l, Rep2 p) (i : ℕ) : Rep2 (gp l i) := by
  by_cases hi : i < l.length
  · exact h _ (gp_mem l i hi)
  · unfold gp; rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact rep2_zero

theorem hc_zero (aux : List (Finset Y)) : HCg (held (Q := Q) aux) (fun (_ : B1 Y J Q) (_ : B2 Q) => (0 : F)) :=
  fun _ _ _ _ => ⟨rfl, rfl, rfl⟩

theorem repT_zero (aux : List (Finset Y)) : RepT M j0 aux (0 : P F Y J Q) 0 := by
  refine ⟨0, 0, 0, 0, fun _ _ => 0, hc_zero aux, ?_, ?_⟩ <;> simp [WW, G, ev2s]

theorem repT_lin {aux : List (Finset Y)} {pa pb qa qb : P F Y J Q} (hp : RepT M j0 aux pa pb)
    (hq : RepT M j0 aux qa qb) (a b : F) :
    RepT M j0 aux (C a * pa + C b * qa) (C a * pb + C b * qb) := by
  obtain ⟨u, k0, k1, k2, c, hc, rfl, rfl⟩ := hp
  obtain ⟨u', k0', k1', k2', c', hc', rfl, rfl⟩ := hq
  refine ⟨a * u + b * u', a * k0 + b * k0', a * k1 + b * k1', a * k2 + b * k2', fun b1 b2 => a * c b1 b2 + b * c' b1 b2,
    fun k y h q => ?_, ?_, ?_⟩
  · obtain ⟨a0, a1, a2⟩ := hc k y h q
    obtain ⟨b0, b1, b2⟩ := hc' k y h q
    simp [a0, a1, a2, b0, b1, b2]
  · rw [WW_lin]; simp only [map_add, map_mul]; ring
  · rw [WW_lin]; simp only [map_add, map_mul]; ring

theorem repT_gp {aux : List (Finset Y)} {la lb : List (P F Y J Q)} (hl : la.length = lb.length)
    (h : ∀ j (hj : j < la.length), RepT M j0 aux (la[j]) (lb[j]'(hl ▸ hj))) (i : ℕ) :
    RepT M j0 aux (gp la i) (gp lb i) := by
  by_cases hi : i < la.length
  · have hi' : i < lb.length := hl ▸ hi
    unfold gp
    rw [List.getD_eq_getElem _ _ hi, List.getD_eq_getElem _ _ hi']
    exact h i hi
  · have hi' : ¬ i < lb.length := hl ▸ hi
    unfold gp
    rw [List.getD_eq_default _ _ (not_lt.mp hi), List.getD_eq_default _ _ (not_lt.mp hi')]
    exact repT_zero M j0 aux

theorem repT_pair {aux : List (Finset Y)} {p q : P F Y J Q} (hp : Rep1 M j0 aux p) (hq : Rep2 q) :
    RepT M j0 aux (p * q) (p * q) := by
  obtain ⟨c1, hc1, rfl⟩ := hp
  obtain ⟨c2, rfl⟩ := hq
  have hG : G M j0 (fun b1 b2 => c1 b1 * c2 b2) = (∑ b, C (c1 b) * ev1 M j0 b) * ev2s c2 := by
    unfold G
    rw [Finset.sum_mul]
    refine Finset.sum_congr rfl fun b1 _ => ?_
    rw [ev2s_smul]; ring
  refine ⟨0, 0, 0, 0, fun b1 b2 => c1 b1 * c2 b2, fun k y h q => ?_, ?_, ?_⟩
  · obtain ⟨a0, a1, a2⟩ := hc1 k y h
    simp [a0, a1, a2]
  · simp [WW, hG]
  · simp [WW, hG]

theorem repT_basic (aux : List (Finset Y)) :
    RepT M j0 aux (AA : P F Y J Q) AA ∧
    RepT M j0 aux (AA * (X (Var.d 0) * X (Var.a 0) + X (Var.d 2)) : P F Y J Q) (AA * (X (Var.d 0) * X (Var.a 0) + X (Var.d 2))) ∧
    RepT M j0 aux (AA * (X (Var.d 1) * X (Var.a 1) + X (Var.d 2)) : P F Y J Q) (AA * (X (Var.d 1) * X (Var.a 1) + X (Var.d 2))) ∧
    RepT M j0 aux (TA : P F Y J Q) TB := by
  have hG0 : G M j0 (fun (_ : B1 Y J Q) (_ : B2 Q) => (0 : F)) = (0 : P F Y J Q) := by simp [G, ev2s]
  refine ⟨⟨0, 1, 0, 0, fun _ _ => 0, hc_zero aux, ?_, ?_⟩, ⟨0, 0, 1, 0, fun _ _ => 0, hc_zero aux, ?_, ?_⟩,
    ⟨0, 0, 0, 1, fun _ _ => 0, hc_zero aux, ?_, ?_⟩, ⟨1, 0, 0, 0, fun _ _ => 0, hc_zero aux, ?_, ?_⟩⟩ <;>
  simp [WW, hG0]

/-- the key attribute set admits a sharing vector with secret `1` vanishing on its rows -/
def Sh (k : Finset Y) : Prop := ∃ v : J → F, v j0 = 1 ∧ ∀ y ∈ k, ∑ j, M y j * v j = 0

theorem sh_empty : Sh M j0 (∅ : Finset Y) := ⟨Pi.single j0 1, by simp, by simp⟩

theorem AA_ne : (AA : P F Y J Q) ≠ 0 := mul_ne_zero (X_ne_zero _) (X_ne_zero _)

theorem pat (hB : ∀ held : Fin Q → Y → Prop, Priv M j0 held → Indep M j0 held) (aux : List (Finset Y))
    (hsh : ∀ i : Fin Q, Sh M j0 (aux.getD (i : ℕ) ∅))
    {pa pb qa qb : P F Y J Q} (h1 : RepT M j0 aux pa pb) (h2 : RepT M j0 aux qa qb) :
    pa = qa ↔ pb = qb := by
  obtain ⟨u, k0, k1, k2, c, hc, rfl, rfl⟩ := h1
  obtain ⟨u', k0', k1', k2', c', hc', rfl, rfl⟩ := h2
  have hI := hB (held aux) (fun i => hsh i)
  constructor
  · intro h
    have hu : u = u' := by
      by_contra hne
      have hd : u - u' ≠ 0 := sub_ne_zero.mpr hne
      have hinv : (C (u - u')⁻¹ : P F Y J Q) * (C u - C u') = 1 := by
        rw [← map_sub, ← map_mul, inv_mul_cancel₀ hd, map_one]
      refine hI (fun b1 b2 => -(u - u')⁻¹ * c b1 b2 + (u - u')⁻¹ * c' b1 b2)
        (-(u - u')⁻¹ * k0 + (u - u')⁻¹ * k0') (-(u - u')⁻¹ * k1 + (u - u')⁻¹ * k1')
        (-(u - u')⁻¹ * k2 + (u - u')⁻¹ * k2') ?_ ?_
      · intro k y hy q
        obtain ⟨a0, a1, a2⟩ := hc k y hy q
        obtain ⟨b0, b1, b2⟩ := hc' k y hy q
        simp [a0, a1, a2, b0, b1, b2]
      · rw [WW_lin]
        simp only [map_neg]
        linear_combination (C (u - u')⁻¹ : P F Y J Q) * h - (TA : P F Y J Q) * hinv
    subst hu
    have : WW M j0 c k0 k1 k2 = WW M j0 c' k0' k1' k2' := add_left_cancel h
    rw [this]
  · intro h
    have hu : u = u' := by
      have := congrArg (pderiv Var.z) h
      simp only [map_add, TB, Derivation.leibniz, smul_eq_mul, pd_WW_z, pderiv_C, pderiv_X, mul_zero, add_zero] at this
      simp [Pi.single_apply] at this
      have e : (C u * AA : P F Y J Q) = C u' * AA := by
        first | exact this | (simpa [mul_comm, mul_assoc, mul_left_comm] using this)
      exact C_injective _ _ (mul_right_cancel₀ AA_ne e)
    subst hu
    have : WW M j0 c k0 k1 k2 = WW M j0 c' k0' k1' k2' := add_left_cancel h
    rw [this]

/-! ### the game -/

def prm : Params F (Var Y J Q) ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y) where
  ro1 w := Sum.elim (fun q => ev1 M j0 (b1rawH q)) (fun q => ev1 M j0 (b1rawG q)) w
  kq1 t k :=
    if h : t < Q then
      [ev1 M j0 (b1P0 ⟨t, h⟩), ev1 M j0 (b1P1 ⟨t, h⟩), ev1 M j0 (b1P2 ⟨t, h⟩)] ++
        k.toList.map (fun y => ev1 M j0 (b1K0 (⟨t, h⟩, y))) ++
        k.toList.map (fun y => ev1 M j0 (b1K1 (⟨t, h⟩, y))) ++
        k.toList.map (fun y => ev1 M j0 (b1K2 (⟨t, h⟩, y)))
    else []
  kq2 t k :=
    if h : t < Q then [ev2 (b2p0 ⟨t, h⟩), ev2 (b2p1 ⟨t, h⟩), ev2 (b2p2 ⟨t, h⟩)] else []

def L0 (T : P F Y J Q) : Lists F (Var Y J Q) (Finset Y) where
  g1 := [ev1 M j0 b1gen] ++ (Finset.univ.toList.map fun q : Y × Fin 3 => ev1 M j0 (b1C q))
  g2 := [ev2 b2one, ev2 b2a0, ev2 b2a1, ev2 b2c0, ev2 b2c1, ev2 b2c2]
  gt := [AA, AA * (X (Var.d 0) * X (Var.a 0) + X (Var.d 2)), AA * (X (Var.d 1) * X (Var.a 1) + X (Var.d 2)), T]
  aux := []

structure Inv (La Lb : Lists F (Var Y J Q) (Finset Y)) : Prop where
  g1 : La.g1 = Lb.g1
  g2 : La.g2 = Lb.g2
  aux : La.aux = Lb.aux
  r1 : ∀ p ∈ La.g1, Rep1 M j0 La.aux p
  r2 : ∀ p ∈ La.g2, Rep2 p
  gtl : La.gt.length = Lb.gt.length
  rt : ∀ i, RepT M j0 La.aux (gp La.gt i) (gp Lb.gt i)
  sh : ∀ k ∈ La.aux, Sh M j0 k

theorem gp_append_single (l : List (P F Y J Q)) (x : P F Y J Q) (i : ℕ) :
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

theorem held_mono (aux : List (Finset Y)) (k : Finset Y) {i : Fin Q} {a : Y} (h : held aux i a) :
    held (aux ++ [k]) i a := by
  unfold held at *
  by_cases hi : (i : ℕ) < aux.length
  · rwa [List.getD_append _ _ _ _ hi]
  · rw [List.getD_eq_default _ _ (not_lt.mp hi)] at h; simp at h

theorem held_new (aux : List (Finset Y)) (k : Finset Y) {i : Fin Q} (hi : (i : ℕ) = aux.length) {a : Y}
    (ha : a ∈ k) : held (aux ++ [k]) i a := by
  unfold held; rw [hi]; simpa using ha

theorem rep1_mono {aux : List (Finset Y)} (k : Finset Y) {p : P F Y J Q} (h : Rep1 M j0 aux p) :
    Rep1 M j0 (aux ++ [k]) p := by
  obtain ⟨c, hc, e⟩ := h
  exact ⟨c, fun i a hh => hc i a (fun h' => hh (held_mono aux k h')), e⟩

theorem repT_mono {aux : List (Finset Y)} (k : Finset Y) {pa pb : P F Y J Q} (h : RepT M j0 aux pa pb) :
    RepT M j0 (aux ++ [k]) pa pb := by
  obtain ⟨u, k0, k1, k2, c, hc, e1, e2⟩ := h
  exact ⟨u, k0, k1, k2, c, fun i a hh q => hc i a (fun h' => hh (held_mono aux k h')) q, e1, e2⟩

theorem allowed_nonK (aux : List (Finset Y)) (b : B1 Y J Q)
    (h0 : ∀ q, b ≠ b1K0 q) (h1 : ∀ q, b ≠ b1K1 q) (h2 : ∀ q, b ≠ b1K2 q) : Allowed aux b :=
  fun k y _ => ⟨h0 _, h1 _, h2 _⟩

macro "nonK" : tactic => `(tactic| exact allowed_nonK _ _ (fun q e => by simp [b1gen, b1rawH, b1rawG, b1C, b1K0, b1K1, b1K2, b1P0, b1P1, b1P2] at e) (fun q e => by simp [b1gen, b1rawH, b1rawG, b1C, b1K0, b1K1, b1K2, b1P0, b1P1, b1P2] at e) (fun q e => by simp [b1gen, b1rawH, b1rawG, b1C, b1K0, b1K1, b1K2, b1P0, b1P1, b1P2] at e))

theorem allowed_K_new (aux : List (Finset Y)) (k : Finset Y) (t : Fin Q) (ht : (t : ℕ) = aux.length) (y : Y)
    (hy : y ∈ k) :
    Allowed (aux ++ [k]) (b1K0 (t, y) : B1 Y J Q) ∧ Allowed (aux ++ [k]) (b1K1 (t, y) : B1 Y J Q) ∧
      Allowed (aux ++ [k]) (b1K2 (t, y) : B1 Y J Q) := by
  refine ⟨?_, ?_, ?_⟩ <;> intro k' y' hnh
  · refine ⟨?_, by simp [b1K0, b1K1], by simp [b1K0, b1K2]⟩
    intro e
    simp [b1K0] at e
    obtain ⟨rfl, rfl⟩ := e
    exact hnh (held_new aux k ht hy)
  · refine ⟨by simp [b1K0, b1K1], ?_, by simp [b1K1, b1K2]⟩
    intro e
    simp [b1K1] at e
    obtain ⟨rfl, rfl⟩ := e
    exact hnh (held_new aux k ht hy)
  · refine ⟨by simp [b1K0, b1K2], by simp [b1K1, b1K2], ?_⟩
    intro e
    simp [b1K2] at e
    obtain ⟨rfl, rfl⟩ := e
    exact hnh (held_new aux k ht hy)

theorem inv_init : Inv M j0 (L0 M j0 (TA : P F Y J Q)) (L0 M j0 (TB : P F Y J Q)) := by
  refine ⟨rfl, rfl, rfl, ?_, ?_, rfl, ?_, ?_⟩
  · intro p hp
    simp only [L0, List.mem_append, List.mem_singleton, List.mem_map] at hp
    rcases hp with rfl | ⟨q, _, rfl⟩
    · exact rep1_basis M j0 _ b1gen (by nonK)
    · exact rep1_basis M j0 _ (b1C q) (by nonK)
  · intro p hp
    simp only [L0, List.mem_cons, List.not_mem_nil, or_false] at hp
    rcases hp with rfl | rfl | rfl | rfl | rfl | rfl <;> exact rep2_basis _
  · intro i
    obtain ⟨h1, h2, h3, h4⟩ := repT_basic (F := F) (Y := Y) (J := J) (Q := Q) M j0 ([] : List (Finset Y))
    simp only [L0]
    match i with
    | 0 => simpa [gp] using h1
    | 1 => simpa [gp] using h2
    | 2 => simpa [gp] using h3
    | 3 => simpa [gp] using h4
    | n + 4 => simpa [gp] using repT_zero M j0 ([] : List (Finset Y))
  · intro k hk; simp [L0] at hk

theorem inv_step (op : Op F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (hk : ∀ k, op = Op.kq k → Sh M j0 k)
    {La Lb : Lists F (Var Y J Q) (Finset Y)} (h : Inv M j0 La Lb) :
    Inv M j0 (apply (prm M j0) op La) (apply (prm M j0) op Lb) := by
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
    · exact rep1_lin M j0 (rep1_gp M j0 r1 i) (rep1_gp M j0 r1 j) a b
  | lin2 i j a b =>
    refine ⟨rfl, rfl, rfl, r1, ?_, gtl, rt, sh⟩
    intro p hp
    simp only [apply, List.mem_append, List.mem_singleton] at hp
    rcases hp with hp | rfl
    · exact r2 p hp
    · exact rep2_lin (rep2_gp r2 i) (rep2_gp r2 j) a b
  | linT i j a b =>
    refine ⟨rfl, rfl, rfl, r1, r2, ?_, ?_, sh⟩
    · simp [apply, gtl]
    · intro n
      simp only [apply, gp_append_single, ← gtl]
      split_ifs
      · exact rt n
      · exact repT_lin M j0 (rt i) (rt j) a b
      · exact repT_zero M j0 a4
  | pair i j =>
    refine ⟨rfl, rfl, rfl, r1, r2, ?_, ?_, sh⟩
    · simp [apply, gtl]
    · intro n
      simp only [apply, gp_append_single, ← gtl]
      split_ifs
      · exact rt n
      · exact repT_pair M j0 (rep1_gp M j0 r1 i) (rep2_gp r2 j)
      · exact repT_zero M j0 a4
  | roq w =>
    refine ⟨rfl, rfl, rfl, ?_, r2, gtl, rt, sh⟩
    intro p hp
    simp only [apply, List.mem_append, List.mem_singleton] at hp
    rcases hp with hp | rfl
    · exact r1 p hp
    · rcases w with q | q
      · exact rep1_basis M j0 _ (b1rawH q) (by nonK)
      · exact rep1_basis M j0 _ (b1rawG q) (by nonK)
  | kq k =>
    have hkk := hk k rfl
    by_cases hQ : a4.length < Q
    · refine ⟨rfl, rfl, rfl, ?_, ?_, gtl, fun n => repT_mono M j0 k (rt n), ?_⟩
      · intro p hp
        simp only [apply, prm, hQ, dif_pos, List.mem_append, List.mem_cons, List.mem_map, Finset.mem_toList,
          List.not_mem_nil, or_false] at hp
        rcases hp with hp' | (((rfl | rfl | rfl) | ⟨y, hy, rfl⟩) | ⟨y, hy, rfl⟩) | ⟨y, hy, rfl⟩
        · exact rep1_mono M j0 k (r1 p hp')
        · exact rep1_basis M j0 _ (b1P0 ⟨a4.length, hQ⟩) (by nonK)
        · exact rep1_basis M j0 _ (b1P1 ⟨a4.length, hQ⟩) (by nonK)
        · exact rep1_basis M j0 _ (b1P2 ⟨a4.length, hQ⟩) (by nonK)
        · exact rep1_basis M j0 _ _ (allowed_K_new a4 k ⟨a4.length, hQ⟩ rfl y hy).1
        · exact rep1_basis M j0 _ _ (allowed_K_new a4 k ⟨a4.length, hQ⟩ rfl y hy).2.1
        · exact rep1_basis M j0 _ _ (allowed_K_new a4 k ⟨a4.length, hQ⟩ rfl y hy).2.2
      · intro p hp
        simp only [apply, prm, hQ, dif_pos, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hp
        rcases hp with hp' | rfl | rfl | rfl
        · exact r2 p hp'
        all_goals exact rep2_basis _
      · intro k' hk'
        simp only [apply, List.mem_append, List.mem_singleton] at hk'
        rcases hk' with hk' | rfl
        · exact sh k' hk'
        · exact hkk
    · refine ⟨rfl, rfl, rfl, ?_, ?_, gtl, fun n => repT_mono M j0 k (rt n), ?_⟩
      · intro p hp
        simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.append_nil] at hp
        exact rep1_mono M j0 k (r1 p hp)
      · intro p hp
        simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.append_nil] at hp
        exact r2 p hp
      · intro k' hk'
        simp only [apply, List.mem_append, List.mem_singleton] at hk'
        rcases hk' with hk' | rfl
        · exact sh k' hk'
        · exact hkk
  | nop => exact ⟨rfl, rfl, rfl, r1, r2, gtl, rt, sh⟩

theorem obs_of_inv (hB : ∀ held : Fin Q → Y → Prop, Priv M j0 held → Indep M j0 held)
    {La Lb : Lists F (Var Y J Q) (Finset Y)} (h : Inv M j0 La Lb) : obs eqoF La = obs eqoF Lb := by
  have hsh : ∀ i : Fin Q, Sh M j0 (La.aux.getD (i : ℕ) ∅) := by
    intro i
    by_cases hi : (i : ℕ) < La.aux.length
    · rw [List.getD_eq_getElem _ _ hi]; exact h.sh _ (List.getElem_mem hi)
    · rw [List.getD_eq_default _ _ (not_lt.mp hi)]; exact sh_empty M j0
  unfold obs
  have e1 : patL (eqoF : MvPolynomial (Var Y J Q) F → _) La.g1 = patL eqoF Lb.g1 := by rw [h.g1]
  have e2 : patL (eqoF : MvPolynomial (Var Y J Q) F → _) La.g2 = patL eqoF Lb.g2 := by rw [h.g2]
  have e3 : patL (eqoF : MvPolynomial (Var Y J Q) F → _) La.gt = patL eqoF Lb.gt := by
    unfold patL
    rw [← h.gtl]
    refine List.flatMap_congr fun i _ => List.map_congr_left fun j _ => ?_
    simp only [eqoF]
    exact decide_eq_decide.mpr (pat M j0 hB La.aux hsh (h.rt i) (h.rt j))
  rw [e1, e2, e3]

theorem run_inv (hB : ∀ held : Fin Q → Y → Prop, Priv M j0 held → Indep M j0 held)
    (adv : Adv F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh M j0 k) :
    ∀ n, (run (prm M j0) eqoF adv (L0 M j0 (TA : P F Y J Q)) n).2 =
          (run (prm M j0) eqoF adv (L0 M j0 (TB : P F Y J Q)) n).2 ∧
        Inv M j0 (run (prm M j0) eqoF adv (L0 M j0 (TA : P F Y J Q)) n).1
          (run (prm M j0) eqoF adv (L0 M j0 (TB : P F Y J Q)) n).1
  | 0 => by
    refine ⟨?_, inv_init M j0⟩
    simp only [run]
    rw [obs_of_inv M j0 hB (inv_init M j0)]
  | n + 1 => by
    obtain ⟨hh, hI⟩ := run_inv hB adv hkeys n
    have hI' := inv_step M j0 (adv.next (run (prm M j0) eqoF adv (L0 M j0 (TA : P F Y J Q)) n).2)
      (fun k hk => hkeys _ k hk) hI
    refine ⟨?_, ?_⟩
    · simp only [run]
      rw [← hh, obs_of_inv M j0 hB hI']
    · simp only [run]
      rw [← hh]
      exact hI'

/-! ### degrees and sizes -/

theorem tD_mul3 {p q : P F Y J Q} {m n r : ℕ} (hp : p.totalDegree ≤ m) (hq : q.totalDegree ≤ n) (h : m + n ≤ r) :
    (p * q).totalDegree ≤ r := (totalDegree_mul p q).trans ((add_le_add hp hq).trans h)

theorem tD_add2 {p q : P F Y J Q} {r : ℕ} (hp : p.totalDegree ≤ r) (hq : q.totalDegree ≤ r) :
    (p + q).totalDegree ≤ r := (totalDegree_add p q).trans (max_le hp hq)

theorem tD_le {p : P F Y J Q} {m r : ℕ} (hp : p.totalDegree ≤ m) (h : m ≤ r) : p.totalDegree ≤ r := hp.trans h

theorem tD_X (v : Var Y J Q) : (X v : P F Y J Q).totalDegree ≤ 1 := by simp [totalDegree_X]

theorem tD_C (a : F) : (C a : P F Y J Q).totalDegree ≤ 0 := by simp

theorem tD_sum {ι : Type} (s : Finset ι) (f : ι → P F Y J Q) {m : ℕ} (h : ∀ i ∈ s, (f i).totalDegree ≤ m) :
    (∑ i ∈ s, f i).totalDegree ≤ m :=
  (totalDegree_finsetSum s f).trans (Finset.sup_le h)

theorem tD_3 (a b c : Var Y J Q) : (X a * X b * X c : P F Y J Q).totalDegree ≤ 3 :=
  tD_mul3 (tD_mul3 (tD_X a) (tD_X b) (le_refl 2)) (tD_X c) (le_refl 3)

theorem tD_AA : (AA : P F Y J Q).totalDegree ≤ 2 := tD_mul3 (tD_X _) (tD_X _) (le_refl 2)

theorem tD_rr (k : Fin Q) (v : Var Y J Q) :
    (((X (Var.r k 0) + X (Var.r k 1)) * X v : P F Y J Q)).totalDegree ≤ 3 :=
  tD_le (tD_mul3 (tD_add2 (r := 1) (tD_X _) (tD_X _)) (tD_X _) (le_refl 2)) (by norm_num)

theorem tD_key (k : Fin Q) (a h0 h1 h2 sgv : Var Y J Q) :
    (X a * (X (Var.b 0) * X (Var.r k 0) * X h0 + X (Var.b 1) * X (Var.r k 1) * X h1 +
        (X (Var.r k 0) + X (Var.r k 1)) * X h2 + X sgv) : P F Y J Q).totalDegree ≤ 4 :=
  tD_mul3 (tD_X a) (tD_add2 (r := 3) (tD_add2 (tD_add2 (tD_3 _ _ _) (tD_3 _ _ _)) (tD_rr k h2))
    (tD_le (tD_X sgv) (by norm_num))) (le_refl 4)

theorem tD_AAx (v : Var Y J Q) : (AA * X v : P F Y J Q).totalDegree ≤ 4 :=
  tD_le (tD_mul3 tD_AA (tD_X v) (le_refl 3)) (by norm_num)

theorem deg_ev1 (b : B1 Y J Q) : (ev1 M j0 b : P F Y J Q).totalDegree ≤ 4 := by
  rcases b with _ | q | q | q | q | q | q | k | k | k
  · exact tD_le (tD_AA) (by norm_num)
  · exact tD_AAx _
  · exact tD_AAx _
  · have hin : ∀ t : Fin 2, (X (Var.h q.1 q.2 t) + ∑ j, C (M q.1 j) * X (Var.g j q.2 t) : P F Y J Q).totalDegree ≤ 1 :=
      fun t => tD_add2 (tD_X _) (tD_sum _ _ fun j _ => tD_le (tD_mul3 (tD_C _) (tD_X _) (le_refl 1)) (by norm_num))
    have h2 : (X (Var.s 0) * (X (Var.h q.1 q.2 0) + ∑ j, C (M q.1 j) * X (Var.g j q.2 0)) +
        X (Var.s 1) * (X (Var.h q.1 q.2 1) + ∑ j, C (M q.1 j) * X (Var.g j q.2 1)) : P F Y J Q).totalDegree ≤ 2 :=
      tD_add2 (tD_mul3 (tD_X _) (hin 0) (le_refl 2)) (tD_mul3 (tD_X _) (hin 1) (le_refl 2))
    exact tD_le (tD_mul3 tD_AA h2 (le_refl 4)) (le_refl 4)
  · exact tD_key _ _ _ _ _ _
  · exact tD_key _ _ _ _ _ _
  · have : (-(AA * X (Var.sg q.1 q.2)) : P F Y J Q).totalDegree ≤ 4 := by
      rw [totalDegree_neg]; exact tD_AAx _
    exact this
  · exact tD_add2 (tD_key _ _ _ _ _ _) (tD_AAx _)
  · exact tD_add2 (tD_key _ _ _ _ _ _) (tD_AAx _)
  · have : (-(AA * X (Var.sp k)) : P F Y J Q).totalDegree ≤ 4 := by
      rw [totalDegree_neg]; exact tD_AAx _
    exact tD_add2 this (tD_AAx _)

theorem deg_ev2 (b : B2 Q) : (ev2 b : P F Y J Q).totalDegree ≤ 2 := by
  rcases b with _ | _ | _ | _ | _ | _ | k | k | k
  · exact tD_le (tD_C 1) (by norm_num)
  · exact tD_le (tD_X _) (by norm_num)
  · exact tD_le (tD_X _) (by norm_num)
  · exact tD_mul3 (tD_X _) (tD_X _) (le_refl 2)
  · exact tD_mul3 (tD_X _) (tD_X _) (le_refl 2)
  · exact tD_le (tD_add2 (r := 1) (tD_X _) (tD_X _)) (by norm_num)
  · exact tD_mul3 (tD_X _) (tD_X _) (le_refl 2)
  · exact tD_mul3 (tD_X _) (tD_X _) (le_refl 2)
  · exact tD_le (tD_add2 (r := 1) (tD_X _) (tD_X _)) (by norm_num)

theorem deg_rep1 {aux : List (Finset Y)} {p : P F Y J Q} (h : Rep1 M j0 aux p) : p.totalDegree ≤ 4 := by
  obtain ⟨c, _, rfl⟩ := h
  refine tD_sum _ _ fun b _ => ?_
  exact tD_le (tD_mul3 (tD_C _) (deg_ev1 M j0 b) (le_refl 4)) (le_refl 4)

theorem deg_rep2 {p : P F Y J Q} (h : Rep2 p) : p.totalDegree ≤ 2 := by
  obtain ⟨c, rfl⟩ := h
  refine tD_sum _ _ fun b _ => ?_
  exact tD_le (tD_mul3 (tD_C _) (deg_ev2 b) (le_refl 2)) (le_refl 2)

theorem tD_T (a b : Var Y J Q) (d : Var Y J Q) :
    (AA * (X d * X a + X b) : P F Y J Q).totalDegree ≤ 4 :=
  tD_mul3 tD_AA (tD_add2 (r := 2) (tD_mul3 (tD_X _) (tD_X _) (le_refl 2)) (tD_le (tD_X _) (by norm_num))) (le_refl 4)

theorem deg_TA : (TA : P F Y J Q).totalDegree ≤ 5 := by
  have h1 : ((X (Var.d 0) * X (Var.a 0) + X (Var.d 2)) * X (Var.s 0) : P F Y J Q).totalDegree ≤ 3 :=
    tD_mul3 (tD_add2 (r := 2) (tD_mul3 (tD_X _) (tD_X _) (le_refl 2)) (tD_le (tD_X _) (by norm_num))) (tD_X _) (le_refl 3)
  have h2 : ((X (Var.d 1) * X (Var.a 1) + X (Var.d 2)) * X (Var.s 1) : P F Y J Q).totalDegree ≤ 3 :=
    tD_mul3 (tD_add2 (r := 2) (tD_mul3 (tD_X _) (tD_X _) (le_refl 2)) (tD_le (tD_X _) (by norm_num))) (tD_X _) (le_refl 3)
  exact tD_mul3 tD_AA (tD_add2 h1 h2) (le_refl 5)

theorem deg_TB : (TB : P F Y J Q).totalDegree ≤ 3 := tD_mul3 tD_AA (tD_X _) (le_refl 3)

theorem deg_WW (c : B1 Y J Q → B2 Q → F) (k0 k1 k2 : F) :
    (WW M j0 c k0 k1 k2 : P F Y J Q).totalDegree ≤ 6 := by
  have hG : (G M j0 c : P F Y J Q).totalDegree ≤ 6 := by
    unfold G
    refine tD_sum _ _ fun b1 _ => tD_mul3 (n := 2) (deg_ev1 M j0 b1) ?_ (by norm_num)
    unfold ev2s
    exact tD_sum _ _ fun b2 _ => tD_le (tD_mul3 (tD_C _) (deg_ev2 b2) (le_refl 2)) (le_refl 2)
  unfold WW
  exact tD_add2 (tD_add2 (tD_add2 hG (tD_le (tD_mul3 (tD_C _) tD_AA (le_refl 2)) (by norm_num)))
    (tD_le (tD_mul3 (tD_C _) (tD_T (Var.a 0) (Var.d 2) (Var.d 0)) (le_refl 4)) (by norm_num)))
    (tD_le (tD_mul3 (tD_C _) (tD_T (Var.a 1) (Var.d 2) (Var.d 1)) (le_refl 4)) (by norm_num))

theorem deg_repT {aux : List (Finset Y)} {pa pb : P F Y J Q} (h : RepT M j0 aux pa pb) :
    pa.totalDegree ≤ 6 ∧ pb.totalDegree ≤ 6 := by
  obtain ⟨u, k0, k1, k2, c, _, rfl, rfl⟩ := h
  have hw := deg_WW M j0 c k0 k1 k2
  exact ⟨tD_add2 (tD_le (tD_mul3 (tD_C _) deg_TA (le_refl 5)) (by norm_num)) hw,
    tD_add2 (tD_le (tD_mul3 (tD_C _) deg_TB (le_refl 3)) (by norm_num)) hw⟩

theorem len_step (op : Op F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y)) (Lx : Lists F (Var Y J Q) (Finset Y)) :
    (apply (prm M j0) op Lx).g1.length ≤ Lx.g1.length + (3 + 3 * Fintype.card Y) ∧
    (apply (prm M j0) op Lx).g2.length ≤ Lx.g2.length + (3 + 3 * Fintype.card Y) ∧
    (apply (prm M j0) op Lx).gt.length ≤ Lx.gt.length + (3 + 3 * Fintype.card Y) := by
  have hk : ∀ k : Finset Y, k.toList.length ≤ Fintype.card Y := fun k => by
    rw [Finset.length_toList]; exact Finset.card_le_univ k
  cases op with
  | kq k =>
    have := hk k
    by_cases hQ : Lx.aux.length < Q
    · simp only [apply, prm, hQ, dif_pos, List.length_append, List.length_cons, List.length_map, List.length_nil]
      omega
    · simp only [apply, prm, hQ, dif_neg, not_false_eq_true, List.length_append, List.length_nil]
      omega
  | _ => simp only [apply, List.length_append, List.length_singleton, List.length_nil]; omega

theorem len_run (adv : Adv F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (L0' : Lists F (Var Y J Q) (Finset Y)) (c0 : ℕ)
    (h1 : L0'.g1.length ≤ c0) (h2 : L0'.g2.length ≤ c0) (h3 : L0'.gt.length ≤ c0) :
    ∀ n, (run (prm M j0) eqoF adv L0' n).1.g1.length ≤ c0 + n * (3 + 3 * Fintype.card Y) ∧
      (run (prm M j0) eqoF adv L0' n).1.g2.length ≤ c0 + n * (3 + 3 * Fintype.card Y) ∧
      (run (prm M j0) eqoF adv L0' n).1.gt.length ≤ c0 + n * (3 + 3 * Fintype.card Y)
  | 0 => by simp only [run]; simpa using ⟨h1, h2, h3⟩
  | n + 1 => by
    obtain ⟨a, b, c⟩ := len_run adv L0' c0 h1 h2 h3 n
    obtain ⟨a', b', c'⟩ := len_step M j0 (adv.next (run (prm M j0) eqoF adv L0' n).2)
      (run (prm M j0) eqoF adv L0' n).1
    simp only [run]
    refine ⟨?_, ?_, ?_⟩ <;> nlinarith

theorem L0_len (T : P F Y J Q) :
    (L0 M j0 T).g1.length ≤ 6 + 3 * Fintype.card Y ∧ (L0 M j0 T).g2.length ≤ 6 + 3 * Fintype.card Y ∧
      (L0 M j0 T).gt.length ≤ 6 + 3 * Fintype.card Y := by
  simp [L0, Finset.length_toList]
  omega

theorem mem_gt_deg {l : List (P F Y J Q)} {Pr : P F Y J Q → Prop} (h : ∀ i, Pr (gp l i))
    (p : P F Y J Q) (hp : p ∈ l) : Pr p := by
  obtain ⟨i, hi, rfl⟩ := List.mem_iff_getElem.mp hp
  have := h i
  unfold gp at this
  rwa [List.getD_eq_getElem _ _ hi] at this

open Classical in
/-- **CPA security of the FAME KEM in the type-3 generic bilinear group model.**  Every adaptive generic adversary that
requests keys (at most `Q` slots) for attribute sets none of which satisfies the policy, queries `H`, `H0`, and makes `n`
generic operations distinguishes `e(g,h)^(...)` from an independent uniform element with advantage at most
`36 m^2 / |F|`, `m = 6 + 3|Y| + n (3 + 3|Y|)`. -/
theorem fame_ggm_cpa_of (hB : ∀ held : Fin Q → Y → Prop, Priv M j0 held → Indep M j0 held)
    (adv : Adv F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh M j0 k) (n : ℕ) :
    |((univ.filter (fun x : Var Y J Q → F =>
          result (prm M j0) (eqoR x) adv (L0 M j0 (TA : P F Y J Q)) n = true)).card : ℚ)
      - ((univ.filter (fun x : Var Y J Q → F =>
          result (prm M j0) (eqoR x) adv (L0 M j0 (TB : P F Y J Q)) n = true)).card : ℚ)|
      * Fintype.card F ≤
    2 * ((3 * (6 + 3 * Fintype.card Y + n * (3 + 3 * Fintype.card Y)) ^ 2 : ℕ) : ℚ) * (6 : ℕ) *
      (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q) := by
  obtain ⟨hh, hI⟩ := run_inv M j0 hB adv hkeys n
  have hform : result (prm M j0) eqoF adv (L0 M j0 (TA : P F Y J Q)) n =
      result (prm M j0) eqoF adv (L0 M j0 (TB : P F Y J Q)) n := by
    unfold result; rw [hh]
  obtain ⟨la1, la2, la3⟩ := len_run M j0 adv _ _ (L0_len M j0 (TA : P F Y J Q)).1 (L0_len M j0 (TA : P F Y J Q)).2.1
    (L0_len M j0 (TA : P F Y J Q)).2.2 n
  obtain ⟨lb1, lb2, lb3⟩ := len_run M j0 adv _ _ (L0_len M j0 (TB : P F Y J Q)).1
    (L0_len M j0 (TB : P F Y J Q)).2.1 (L0_len M j0 (TB : P F Y J Q)).2.2 n
  refine transfer (prm M j0) adv _ _ n hform 6
    (3 * (6 + 3 * Fintype.card Y + n * (3 + 3 * Fintype.card Y)) ^ 2) ?_ ?_ ?_ ?_
  · intro p hp
    simp only [List.mem_append] at hp
    rcases hp with (hp | hp) | hp
    · exact (deg_rep1 M j0 (hI.r1 p hp)).trans (by norm_num)
    · exact (deg_rep2 (hI.r2 p hp)).trans (by norm_num)
    · exact mem_gt_deg (Pr := fun q => q.totalDegree ≤ 6) (fun i => (deg_repT M j0 (hI.rt i)).1) p hp
  · intro p hp
    simp only [List.mem_append] at hp
    rcases hp with (hp | hp) | hp
    · rw [← hI.g1] at hp
      exact (deg_rep1 M j0 (hI.r1 p hp)).trans (by norm_num)
    · rw [← hI.g2] at hp
      exact (deg_rep2 (hI.r2 p hp)).trans (by norm_num)
    · exact mem_gt_deg (Pr := fun q => q.totalDegree ≤ 6) (fun i => (deg_repT M j0 (hI.rt i)).2) p hp
  · have := Nat.pow_le_pow_left la1 2
    have := Nat.pow_le_pow_left la2 2
    have := Nat.pow_le_pow_left la3 2
    nlinarith
  · have := Nat.pow_le_pow_left lb1 2
    have := Nat.pow_le_pow_left lb2 2
    have := Nat.pow_le_pow_left lb3 2
    nlinarith

open Classical in
/-- probability form: `|Pr_A - Pr_B| <= 36 m^2 / |F|` -/
theorem fame_ggm_cpa_prob_of (hB : ∀ held : Fin Q → Y → Prop, Priv M j0 held → Indep M j0 held)
    (adv : Adv F ((Y × Fin 3 × Fin 2) ⊕ (J × Fin 3 × Fin 2)) (Finset Y))
    (hkeys : ∀ hist k, adv.next hist = Op.kq k → Sh M j0 k) (n : ℕ) :
    |((univ.filter (fun x : Var Y J Q → F =>
          result (prm M j0) (eqoR x) adv (L0 M j0 (TA : P F Y J Q)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q)
      - ((univ.filter (fun x : Var Y J Q → F =>
          result (prm M j0) (eqoR x) adv (L0 M j0 (TB : P F Y J Q)) n = true)).card : ℚ)
        / (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q)|
      ≤ 36 * ((6 + 3 * Fintype.card Y + n * (3 + 3 * Fintype.card Y) : ℕ) : ℚ) ^ 2 / Fintype.card F := by
  have h := fame_ggm_cpa_of M j0 hB adv hkeys n
  have hq : (0 : ℚ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have hv : (0 : ℚ) < (Fintype.card F : ℚ) ^ Fintype.card (Var Y J Q) := by positivity
  rw [← sub_div, abs_div, abs_of_pos hv, div_le_div_iff₀ hv hq]
  push_cast at h ⊢
  nlinarith [h]

end

end PcaMath.FameSec
