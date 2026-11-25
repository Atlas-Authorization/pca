/-!
# FAME decryption correctness (exponent model)  --  `packages/pca-abe` (Agrawal-Chase, CCS 2017)

Core Lean only (no Mathlib).  Every group element of the scheme is `g^x` / `h^x` / `e(g,h)^x`; the pairing multiplies exponents, so
correctness of decryption is an identity between exponents in the scalar ring `R` (any commutative ring; in the library `R = Z_r`).
The random-oracle outputs `H(y,l,t)`, `H0(j,l,t)` are arbitrary ring elements here: correctness does not depend on them.

Notation (as in `fame.ts`; `t` ranges over `{0,1}`, `l` over `{0,1,2}`):

* key   `K_{y,t} = (sum_l H(y,l,t) pow_l + sigma_y) / a_t`,   `K_{y,2} = -sigma_y`
        `K'_t    = (sum_l H0(j0,l,t) pow_l + sigma') / a_t + d_t`,   `K'_2 = -sigma' + d_2`      (`j0` = the secret column)
* ct    `C_{i,l} = sum_t s_t H(rho_i,l,t) + sum_j M_{ij} sum_t s_t H0(j,l,t)`,  `C0 = (a_0 s_0, a_1 s_1, s_0 + s_1)`
* decrypt exponent  `sum_t keyProd_t * C0_t + keyProd_2 * C0_2 - sum_l ctProd_l * pow_l`  with
  `ctProd_l = sum_i w_i C_{i,l}`,  `keyProd_t = sum_i w_i K_{rho_i,t} + K'_t`,  `keyProd_2 = sum_i w_i K_{rho_i,2} + K'_2`.

`decrypt_exponent` : if the weights satisfy `sum_i w_i M_{ij} = [j = j0]` (the span-program reconstruction), the decrypt exponent equals
`(d_0 a_0 + d_2) s_0 + (d_1 a_1 + d_2) s_1`, the exponent of the KEM key `T_1^{s_0} T_2^{s_1}`.  The blinding terms `sigma`, `sigma'`
and every random-oracle value cancel.  The hypothesis `hw` (the weights solve the span program) is discharged for the tree-derived span program and weights by
`PcaComp.Span.span_program_solved` (which assumes only that the Lagrange coefficients satisfy their moment equations; a unit test checks that
for `lagrangeAtZero`).  This file is correctness only; the security statement is the adaptive-security theorem of the paper (see
`docs/pca/security/proofs/05-abe.md` and `cryptoverif/fame_kemdem.cv`).
-/

namespace PcaComp.Fame

open Lean.Grind

variable {R : Type} [CommRing R]

/-- finite sum over an explicit list of indices -/
def sumL {α : Type} (f : α → R) : List α → R
  | [] => 0
  | a :: l => f a + sumL f l

theorem sumL_comb {α : Type} (c0 c1 c2 : R) (f0 f1 f2 f3 : α → R) (l : List α) :
    sumL (fun a => c0 * f0 a + c1 * f1 a + c2 * f2 a + f3 a) l
      = c0 * sumL f0 l + c1 * sumL f1 l + c2 * sumL f2 l + sumL f3 l := by
  induction l with
  | nil => simp only [sumL]; grind
  | cons a l ih => simp only [sumL, ih]; grind

theorem sumL_scale {α : Type} (c : R) (f : α → R) (l : List α) :
    sumL (fun a => c * f a) l = c * sumL f l := by
  induction l with
  | nil => simp only [sumL]; grind
  | cons a l ih => simp only [sumL, ih]; grind

theorem sumL_add {α : Type} (f g : α → R) (l : List α) :
    sumL (fun a => f a + g a) l = sumL f l + sumL g l := by
  induction l with
  | nil => simp only [sumL]; grind
  | cons a l ih => simp only [sumL, ih]; grind

theorem sumL_congr {α : Type} (f g : α → R) (l : List α) (h : ∀ a ∈ l, f a = g a) :
    sumL f l = sumL g l := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    simp only [sumL]
    rw [h a (List.mem_cons_self), ih (fun b hb => h b (List.mem_cons_of_mem _ hb))]

theorem sumL_swap {α β : Type} (f : α → β → R) (l1 : List α) (l2 : List β) :
    sumL (fun a => sumL (fun b => f a b) l2) l1 = sumL (fun b => sumL (fun a => f a b) l1) l2 := by
  induction l1 with
  | nil =>
    simp only [sumL]
    induction l2 with
    | nil => rfl
    | cons b l ih => simp only [sumL]; rw [← ih]; grind
  | cons a l ih =>
    simp only [sumL]
    rw [ih, ← sumL_add]

theorem sumL_zero {α : Type} (l : List α) : sumL (fun _ => (0 : R)) l = 0 := by
  induction l with
  | nil => rfl
  | cons a l ih => simp only [sumL, ih]; grind

theorem sumL_lin2 {α : Type} (c0 c1 : R) (f0 f1 : α → R) (l : List α) :
    sumL (fun a => c0 * f0 a + c1 * f1 a) l = c0 * sumL f0 l + c1 * sumL f1 l := by
  induction l with
  | nil => simp only [sumL]; grind
  | cons a l ih => simp only [sumL, ih]; grind

theorem sumL_pick {κ : Type} [DecidableEq κ] (j0 : κ) (B : κ → R) (cols : List κ)
    (hn : cols.Nodup) (hm : j0 ∈ cols) :
    sumL (fun j => (if j = j0 then (1 : R) else 0) * B j) cols = B j0 := by
  induction cols with
  | nil => simp at hm
  | cons c cs ih =>
    simp only [sumL]
    by_cases hc : c = j0
    · subst hc
      have hnot : ¬ c ∈ cs := (List.nodup_cons.mp hn).1
      have hz : ∀ a ∈ cs, (if a = c then (1 : R) else 0) * B a = 0 := by
        intro a ha
        have hne : a ≠ c := fun h => hnot (h ▸ ha)
        simp [hne]; grind
      rw [sumL_congr _ (fun _ => 0) cs hz, sumL_zero]
      simp; grind
    · have hm' : j0 ∈ cs := by
        cases List.mem_cons.mp hm with
        | inl h => exact absurd h.symm hc
        | inr h => exact h
      rw [ih (List.nodup_cons.mp hn).2 hm']
      simp [hc]; grind

variable {ι κ : Type} [DecidableEq κ]

/-- exponent of `K_{rho_i,t}` -/
def keyAttr (HA : ι → Fin 3 → Fin 2 → R) (pow : Fin 3 → R) (σ : ι → R) (ainv : Fin 2 → R) (i : ι) (t : Fin 2) : R :=
  (HA i 0 t * pow 0 + HA i 1 t * pow 1 + HA i 2 t * pow 2 + σ i) * ainv t

/-- exponent of `K'_t` (t = 0, 1) -/
def keyPrime (HC : κ → Fin 3 → Fin 2 → R) (pow : Fin 3 → R) (σp : R) (ainv d : Fin 2 → R) (j0 : κ) (t : Fin 2) : R :=
  (HC j0 0 t * pow 0 + HC j0 1 t * pow 1 + HC j0 2 t * pow 2 + σp) * ainv t + d t

/-- exponent of the ciphertext element `C_{i,l}` -/
def ctRow (HA : ι → Fin 3 → Fin 2 → R) (HC : κ → Fin 3 → Fin 2 → R) (M : ι → κ → R) (s : Fin 2 → R)
    (cols : List κ) (i : ι) (l : Fin 3) : R :=
  (s 0 * HA i l 0 + s 1 * HA i l 1) + sumL (fun j => M i j * (s 0 * HC j l 0 + s 1 * HC j l 1)) cols

/-- `sum_i w_i C_{i,l}` -/
def ctProd (HA : ι → Fin 3 → Fin 2 → R) (HC : κ → Fin 3 → Fin 2 → R) (M : ι → κ → R) (s : Fin 2 → R)
    (cols : List κ) (rows : List ι) (w : ι → R) (l : Fin 3) : R :=
  sumL (fun i => w i * ctRow HA HC M s cols i l) rows

theorem ctProd_collapse
    (rows : List ι) (cols : List κ) (j0 : κ) (hn : cols.Nodup) (hm : j0 ∈ cols)
    (w : ι → R) (M : ι → κ → R)
    (hw : ∀ j ∈ cols, sumL (fun i => w i * M i j) rows = if j = j0 then 1 else 0)
    (HA : ι → Fin 3 → Fin 2 → R) (HC : κ → Fin 3 → Fin 2 → R) (s : Fin 2 → R) (l : Fin 3) :
    ctProd HA HC M s cols rows w l =
      s 0 * sumL (fun i => w i * HA i l 0) rows + s 1 * sumL (fun i => w i * HA i l 1) rows
        + (s 0 * HC j0 l 0 + s 1 * HC j0 l 1) := by
  let B : κ → R := fun j => s 0 * HC j l 0 + s 1 * HC j l 1
  have e1 : ctProd HA HC M s cols rows w l =
      sumL (fun i => w i * (s 0 * HA i l 0 + s 1 * HA i l 1)) rows
        + sumL (fun i => w i * sumL (fun j => M i j * B j) cols) rows := by
    unfold ctProd ctRow
    rw [← sumL_add]
    apply sumL_congr; intro i _; grind
  have e2 : sumL (fun i => w i * (s 0 * HA i l 0 + s 1 * HA i l 1)) rows
      = s 0 * sumL (fun i => w i * HA i l 0) rows + s 1 * sumL (fun i => w i * HA i l 1) rows := by
    rw [← sumL_lin2]
    apply sumL_congr; intro i _; grind
  have e3 : sumL (fun i => w i * sumL (fun j => M i j * B j) cols) rows = B j0 := by
    have p1 : ∀ i ∈ rows, w i * sumL (fun j => M i j * B j) cols = sumL (fun j => w i * (M i j * B j)) cols := by
      intro i _; rw [sumL_scale]
    rw [sumL_congr _ _ rows p1, sumL_swap]
    have p2 : ∀ j ∈ cols, sumL (fun i => w i * (M i j * B j)) rows = (if j = j0 then (1 : R) else 0) * B j := by
      intro j hj
      rw [← hw j hj]
      have h := sumL_scale (B j) (fun i => w i * M i j) rows
      have h2 : sumL (fun i => w i * (M i j * B j)) rows = sumL (fun i => B j * (w i * M i j)) rows :=
        sumL_congr _ _ rows (by intro i _; grind)
      rw [h2, h]; grind
    rw [sumL_congr _ _ cols p2]
    exact sumL_pick j0 B cols hn hm
  rw [e1, e2, e3]

/-- `sum_i w_i K_{rho_i,t}` -/
theorem keyAttr_collapse (rows : List ι) (w : ι → R) (HA : ι → Fin 3 → Fin 2 → R) (pow : Fin 3 → R)
    (σ : ι → R) (ainv : Fin 2 → R) (t : Fin 2) :
    sumL (fun i => w i * keyAttr HA pow σ ainv i t) rows =
      (pow 0 * sumL (fun i => w i * HA i 0 t) rows + pow 1 * sumL (fun i => w i * HA i 1 t) rows
        + pow 2 * sumL (fun i => w i * HA i 2 t) rows + sumL (fun i => w i * σ i) rows) * ainv t := by
  have : ∀ i ∈ rows, w i * keyAttr HA pow σ ainv i t =
      ainv t * (pow 0 * (w i * HA i 0 t) + pow 1 * (w i * HA i 1 t) + pow 2 * (w i * HA i 2 t) + w i * σ i) := by
    intro i _; unfold keyAttr; grind
  rw [sumL_congr _ _ rows this, sumL_scale, sumL_comb]
  grind

/-- Decryption correctness: the decrypt exponent equals the exponent of the KEM key. -/
theorem decrypt_exponent
    (rows : List ι) (cols : List κ) (j0 : κ) (hn : cols.Nodup) (hm : j0 ∈ cols)
    (w : ι → R) (M : ι → κ → R)
    (hw : ∀ j ∈ cols, sumL (fun i => w i * M i j) rows = if j = j0 then 1 else 0)
    (HA : ι → Fin 3 → Fin 2 → R) (HC : κ → Fin 3 → Fin 2 → R)
    (a ainv d s : Fin 2 → R) (pow : Fin 3 → R) (σ : ι → R) (σp d2 : R)
    (ha0 : a 0 * ainv 0 = 1) (ha1 : a 1 * ainv 1 = 1) :
    (sumL (fun i => w i * keyAttr HA pow σ ainv i 0) rows + keyPrime HC pow σp ainv d j0 0) * (a 0 * s 0)
      + (sumL (fun i => w i * keyAttr HA pow σ ainv i 1) rows + keyPrime HC pow σp ainv d j0 1) * (a 1 * s 1)
      + (sumL (fun i => w i * (-σ i)) rows + (-σp + d2)) * (s 0 + s 1)
      - (ctProd HA HC M s cols rows w 0 * pow 0 + ctProd HA HC M s cols rows w 1 * pow 1
          + ctProd HA HC M s cols rows w 2 * pow 2)
    = (d 0 * a 0 + d2) * s 0 + (d 1 * a 1 + d2) * s 1 := by
  rw [keyAttr_collapse, keyAttr_collapse]
  rw [ctProd_collapse rows cols j0 hn hm w M hw HA HC s 0, ctProd_collapse rows cols j0 hn hm w M hw HA HC s 1,
    ctProd_collapse rows cols j0 hn hm w M hw HA HC s 2]
  have hneg : sumL (fun i => w i * (-σ i)) rows = -(sumL (fun i => w i * σ i) rows) := by
    have : ∀ i ∈ rows, w i * (-σ i) = (-1 : R) * (w i * σ i) := by intro i _; grind
    rw [sumL_congr _ _ rows this, sumL_scale]; grind
  rw [hneg]
  unfold keyPrime
  grind

end PcaComp.Fame
