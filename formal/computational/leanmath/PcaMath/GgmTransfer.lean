import Mathlib

/-!
# Generic-group transfer (Maurer / Shoup / Boneh-Boyen-Goh style) for a bilinear group, proved

`NA-GGM` of the ledger used to contain two things: (i) the generic-group TRANSFER lemma ("formal independence implies
security") and (ii) the statement that the actual group is generic.  This file proves (i) for the equality-pattern
formulation of the generic bilinear group model (type 3: lists in `G1`, `G2`, `GT`, linear operations inside each
group, the pairing `G1 x G2 -> GT`, random-oracle queries, adaptive key queries); (ii) is the modelling choice that
defines the model.

Model.  Group elements the adversary holds are, in the formal world, polynomials of `MvPolynomial σ F`
(`σ` the finite set of randomness variables).  The adversary sees only the equality pattern of each of its three
lists (that is exactly what the random handles of the generic group reveal; here it receives ALL pairwise equalities
after EVERY step, which is at least what any handle-comparison strategy obtains).  The adversary is an arbitrary
(adaptive, deterministic after fixing its coins) function from the history of patterns to the next operation, and to
the output bit.  Two oracles for equality are compared:

* `eqoR x` (real): `p ~ p'` iff `eval x p = eval x p'`, for a uniformly random assignment `x : σ → F`;
* `eqoF` (formal): `p ~ p'` iff `p = p'` as polynomials.

`transfer` : if the two challenge worlds are indistinguishable in the formal oracle, the advantage in the real
oracle is at most `2 * (number of pairs) * d / |F|` (Schwartz-Zippel), `d` the degree bound of all list entries.
-/

open MvPolynomial Finset

set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false

namespace PcaMath.GgmTransfer

section Core

variable {F : Type} [Field F] {σ : Type} {A K : Type}

abbrev Pl (F σ : Type) [CommSemiring F] := MvPolynomial σ F

structure Lists (F σ K : Type) [CommSemiring F] where
  g1 : List (MvPolynomial σ F)
  g2 : List (MvPolynomial σ F)
  gt : List (MvPolynomial σ F)
  aux : List K

structure Params (F σ A K : Type) [CommSemiring F] where
  ro1 : A → MvPolynomial σ F
  kq1 : ℕ → K → List (MvPolynomial σ F)
  kq2 : ℕ → K → List (MvPolynomial σ F)

inductive Op (F A K : Type) : Type
  | lin1 (i j : ℕ) (a b : F)
  | lin2 (i j : ℕ) (a b : F)
  | linT (i j : ℕ) (a b : F)
  | pair (i j : ℕ)
  | roq (a : A)
  | kq (k : K)
  | nop

noncomputable section

def gp (l : List (MvPolynomial σ F)) (i : ℕ) : MvPolynomial σ F := l.getD i 0

def apply (pr : Params F σ A K) : Op F A K → Lists F σ K → Lists F σ K
  | .lin1 i j a b, L => { L with g1 := L.g1 ++ [C a * gp L.g1 i + C b * gp L.g1 j] }
  | .lin2 i j a b, L => { L with g2 := L.g2 ++ [C a * gp L.g2 i + C b * gp L.g2 j] }
  | .linT i j a b, L => { L with gt := L.gt ++ [C a * gp L.gt i + C b * gp L.gt j] }
  | .pair i j, L => { L with gt := L.gt ++ [gp L.g1 i * gp L.g2 j] }
  | .roq a, L => { L with g1 := L.g1 ++ [pr.ro1 a] }
  | .kq k, L => { L with g1 := L.g1 ++ pr.kq1 L.aux.length k, g2 := L.g2 ++ pr.kq2 L.aux.length k,
                          aux := L.aux ++ [k] }
  | .nop, L => L

theorem gp_mem (l : List (MvPolynomial σ F)) (i : ℕ) (hi : i < l.length) : gp l i ∈ l := by
  unfold gp; rw [List.getD_eq_getElem _ _ hi]; exact List.getElem_mem hi

/-- all ordered pairwise equalities of a list, indexed by position -/
def patL (eqo : MvPolynomial σ F → MvPolynomial σ F → Bool) (l : List (MvPolynomial σ F)) : List Bool :=
  (List.range l.length).flatMap fun i => (List.range l.length).map fun j => eqo (gp l i) (gp l j)

abbrev Obs := List Bool × List Bool × List Bool

def obs (eqo : MvPolynomial σ F → MvPolynomial σ F → Bool) (L : Lists F σ K) : Obs :=
  (patL eqo L.g1, patL eqo L.g2, patL eqo L.gt)

structure Adv (F A K : Type) where
  next : List Obs → Op F A K
  out : List Obs → Bool

def run (pr : Params F σ A K) (eqo : MvPolynomial σ F → MvPolynomial σ F → Bool) (adv : Adv F A K)
    (L0 : Lists F σ K) : ℕ → Lists F σ K × List Obs
  | 0 => (L0, [obs eqo L0])
  | n + 1 =>
      let r := run pr eqo adv L0 n
      let L' := apply pr (adv.next r.2) r.1
      (L', r.2 ++ [obs eqo L'])

def result (pr : Params F σ A K) (eqo : MvPolynomial σ F → MvPolynomial σ F → Bool) (adv : Adv F A K)
    (L0 : Lists F σ K) (n : ℕ) : Bool := adv.out (run pr eqo adv L0 n).2

open Classical in
def eqoF : MvPolynomial σ F → MvPolynomial σ F → Bool := fun p p' => decide (p = p')

open Classical in
def eqoR (x : σ → F) : MvPolynomial σ F → MvPolynomial σ F → Bool :=
  fun p p' => decide (eval x p = eval x p')

theorem patL_congr (eqo eqo' : MvPolynomial σ F → MvPolynomial σ F → Bool) (l : List (MvPolynomial σ F))
    (h : ∀ p ∈ l, ∀ p' ∈ l, eqo p p' = eqo' p p') : patL eqo l = patL eqo' l := by
  unfold patL
  refine List.flatMap_congr fun i hi => ?_
  refine List.map_congr_left fun j hj => ?_
  exact h _ (gp_mem l i (List.mem_range.mp hi)) _ (gp_mem l j (List.mem_range.mp hj))

/-- no collision of `x` on the entries of `L` -/
def GoodL (x : σ → F) (L : Lists F σ K) : Prop :=
  ∀ l ∈ [L.g1, L.g2, L.gt], ∀ p ∈ l, ∀ p' ∈ l, eval x p = eval x p' → p = p'

theorem obs_eq_of_good (x : σ → F) (L : Lists F σ K) (hg : GoodL x L) :
    obs (eqoR x) L = obs eqoF L := by
  unfold obs
  have key : ∀ l ∈ [L.g1, L.g2, L.gt], patL (eqoR x) l = patL eqoF l := by
    intro l hl
    refine patL_congr _ _ _ fun p hp p' hp' => ?_
    classical
    unfold eqoR eqoF
    by_cases h : p = p'
    · subst h; simp
    · have : ¬ eval x p = eval x p' := fun e => h (hg l hl p hp p' hp' e)
      simp [h, this]
  rw [key L.g1 (by simp), key L.g2 (by simp), key L.gt (by simp)]

theorem apply_mono (pr : Params F σ A K) (op : Op F A K) (L : Lists F σ K) :
    L.g1 ⊆ (apply pr op L).g1 ∧ L.g2 ⊆ (apply pr op L).g2 ∧ L.gt ⊆ (apply pr op L).gt := by
  cases op <;> simp [apply, List.subset_append_left]

theorem run_mono (pr : Params F σ A K) (eqo) (adv : Adv F A K) (L0 : Lists F σ K) (t n : ℕ) (h : t ≤ n) :
    (run pr eqo adv L0 t).1.g1 ⊆ (run pr eqo adv L0 n).1.g1 ∧ (run pr eqo adv L0 t).1.g2 ⊆ (run pr eqo adv L0 n).1.g2
      ∧ (run pr eqo adv L0 t).1.gt ⊆ (run pr eqo adv L0 n).1.gt := by
  induction n, h using Nat.le_induction with
  | base => exact ⟨fun _ h => h, fun _ h => h, fun _ h => h⟩
  | succ n hn ih =>
    obtain ⟨a, b, c⟩ := apply_mono pr (adv.next (run pr eqo adv L0 n).2) (run pr eqo adv L0 n).1
    exact ⟨fun p hp => a (ih.1 hp), fun p hp => b (ih.2.1 hp), fun p hp => c (ih.2.2 hp)⟩

theorem goodL_mono (x : σ → F) (L L' : Lists F σ K) (h1 : L.g1 ⊆ L'.g1) (h2 : L.g2 ⊆ L'.g2) (h3 : L.gt ⊆ L'.gt)
    (hg : GoodL x L') : GoodL x L := by
  intro l hl p hp p' hp' e
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hl
  rcases hl with rfl | rfl | rfl
  · exact hg L'.g1 (by simp) p (h1 hp) p' (h1 hp') e
  · exact hg L'.g2 (by simp) p (h2 hp) p' (h2 hp') e
  · exact hg L'.gt (by simp) p (h3 hp) p' (h3 hp') e

/-- the real run equals the formal run when `x` has no collision on the final formal lists -/
theorem run_real_eq_formal (pr : Params F σ A K) (adv : Adv F A K) (L0 : Lists F σ K) (x : σ → F) (n : ℕ)
    (hg : GoodL x (run pr eqoF adv L0 n).1) :
    run pr (eqoR x) adv L0 n = run pr eqoF adv L0 n := by
  induction n with
  | zero =>
    have : obs (eqoR x) L0 = obs eqoF L0 := obs_eq_of_good x L0 hg
    simp [run, this]
  | succ n ih =>
    have hgn : GoodL x (run pr eqoF adv L0 n).1 := by
      obtain ⟨a, b, c⟩ := run_mono pr eqoF adv L0 n (n + 1) (Nat.le_succ n)
      exact goodL_mono x _ _ a b c hg
    have ih' := ih hgn
    have hfin : obs (eqoR x) (run pr eqoF adv L0 (n + 1)).1 = obs eqoF (run pr eqoF adv L0 (n + 1)).1 :=
      obs_eq_of_good x _ hg
    simp only [run] at ih' hfin ⊢
    rw [ih']
    simp only [hfin]

end


end Core

section Count

open Classical

variable {F : Type} [Field F] [Fintype F] {σ : Type} [Fintype σ] [DecidableEq σ] {A K : Type}

/-- Schwartz-Zippel over an arbitrary finite set of variables, in the form `#zeros * |F| <= d * |F|^n` -/
theorem sz (p : MvPolynomial σ F) (hp : p ≠ 0) :
    ((univ.filter (fun x : σ → F => eval x p = 0)).card : ℚ) * Fintype.card F
      ≤ p.totalDegree * (Fintype.card F : ℚ) ^ Fintype.card σ := by
  set n := Fintype.card σ
  let e : σ ≃ Fin n := Fintype.equivFin σ
  let p' : MvPolynomial (Fin n) F := rename e p
  have hp' : p' ≠ 0 := fun h => hp ((rename_injective e e.injective) (by simpa [p'] using h))
  have h := MvPolynomial.schwartz_zippel_totalDegree hp' (Finset.univ : Finset F)
  have hq : (0 : ℚ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have hcard : (univ.filter (fun x : σ → F => eval x p = 0)).card =
      ((Fintype.piFinset (fun _ : Fin n => (Finset.univ : Finset F))).filter (fun f => eval f p' = 0)).card := by
    rw [Fintype.piFinset_univ]
    refine Finset.card_bij (fun x _ => x ∘ e.symm) ?_ ?_ ?_
    · intro x hx
      simp only [mem_filter, mem_univ, true_and] at hx ⊢
      simp only [p', eval_rename]
      have : (x ∘ e.symm) ∘ e = x := by ext i; simp
      rw [this]; exact hx
    · intro x _ y _ hxy
      ext i
      have := congrFun hxy (e i)
      simpa using this
    · intro f hf
      refine ⟨f ∘ e, ?_, ?_⟩
      · simp only [mem_filter, mem_univ, true_and] at hf ⊢
        simpa [p', eval_rename] using hf
      · ext i; simp
  rw [hcard]
  have h2 : (((Fintype.piFinset (fun _ : Fin n => (Finset.univ : Finset F))).filter (fun f => eval f p' = 0)).card : ℚ)
      / (Fintype.card F : ℚ) ^ n ≤ (p'.totalDegree : ℚ) / Fintype.card F := by
    have := h
    simp only [Finset.card_univ] at this
    exact_mod_cast this
  have h3 : (p'.totalDegree : ℚ) ≤ p.totalDegree := by exact_mod_cast totalDegree_rename_le e p
  rw [div_le_div_iff₀ (by positivity) hq] at h2
  calc _ ≤ (p'.totalDegree : ℚ) * (Fintype.card F : ℚ) ^ n := by
        exact h2
    _ ≤ _ := by gcongr


/-- union bound for a finite family of nonzero polynomials of degree `<= d` -/
theorem sz_union (Q : Finset (MvPolynomial σ F)) (d : ℕ) (hQ : ∀ q ∈ Q, q ≠ 0 ∧ q.totalDegree ≤ d) :
    ((univ.filter (fun x : σ → F => ∃ q ∈ Q, eval x q = 0)).card : ℚ) * Fintype.card F
      ≤ Q.card * d * (Fintype.card F : ℚ) ^ Fintype.card σ := by
  have hq : (0 : ℚ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have hsub : univ.filter (fun x : σ → F => ∃ q ∈ Q, eval x q = 0) ⊆
      Q.biUnion (fun q => univ.filter (fun x : σ → F => eval x q = 0)) := by
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx
    obtain ⟨q, hqQ, hq0⟩ := hx
    simp only [mem_biUnion, mem_filter, mem_univ, true_and]
    exact ⟨q, hqQ, hq0⟩
  have h1 : ((univ.filter (fun x : σ → F => ∃ q ∈ Q, eval x q = 0)).card : ℚ) ≤
      ∑ q ∈ Q, ((univ.filter (fun x : σ → F => eval x q = 0)).card : ℚ) := by
    have := (card_le_card hsub).trans card_biUnion_le
    exact_mod_cast this
  calc _ ≤ (∑ q ∈ Q, ((univ.filter (fun x : σ → F => eval x q = 0)).card : ℚ)) * Fintype.card F :=
        by gcongr
    _ = ∑ q ∈ Q, ((univ.filter (fun x : σ → F => eval x q = 0)).card : ℚ) * Fintype.card F := by
        rw [Finset.sum_mul]
    _ ≤ ∑ q ∈ Q, (d : ℚ) * (Fintype.card F : ℚ) ^ Fintype.card σ := by
        refine Finset.sum_le_sum fun q hqQ => ?_
        refine (sz q (hQ q hqQ).1).trans ?_
        have : (q.totalDegree : ℚ) ≤ d := by exact_mod_cast (hQ q hqQ).2
        gcongr
    _ = _ := by simp [mul_assoc]

/-- all differences of distinct entries of a polynomial list -/
noncomputable def diffs (l : List (MvPolynomial σ F)) : Finset (MvPolynomial σ F) :=
  ((l.toFinset ×ˢ l.toFinset).filter (fun pp => pp.1 ≠ pp.2)).image (fun pp => pp.1 - pp.2)

theorem diffs_card (l : List (MvPolynomial σ F)) : (diffs l).card ≤ l.length * l.length := by
  unfold diffs
  refine card_image_le.trans ((card_filter_le _ _).trans ?_)
  rw [card_product]
  exact Nat.mul_le_mul (List.toFinset_card_le l) (List.toFinset_card_le l)

theorem diffs_deg (l : List (MvPolynomial σ F)) (d : ℕ) (hd : ∀ p ∈ l, p.totalDegree ≤ d) :
    ∀ q ∈ diffs l, q ≠ 0 ∧ q.totalDegree ≤ d := by
  intro q hq
  unfold diffs at hq
  simp only [mem_image, mem_filter, mem_product, List.mem_toFinset] at hq
  obtain ⟨⟨p, p'⟩, ⟨⟨h1, h2⟩, hne⟩, rfl⟩ := hq
  refine ⟨sub_ne_zero.mpr hne, ?_⟩
  exact (totalDegree_sub p p').trans (max_le (hd p h1) (hd p' h2))

/-- the lists of a state are collision-free at `x` iff `x` is not a zero of any difference -/
theorem good_of_not_bad (x : σ → F) (L : Lists F σ K)
    (h : ∀ q ∈ diffs L.g1 ∪ diffs L.g2 ∪ diffs L.gt, eval x q ≠ 0) : GoodL x L := by
  intro l hl p hp p' hp' e
  by_contra hne
  have hm : p - p' ∈ diffs l := by
    unfold diffs; simp only [mem_image, mem_filter, mem_product, List.mem_toFinset]
    exact ⟨(p, p'), ⟨⟨hp, hp'⟩, hne⟩, rfl⟩
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hl
  have hu : p - p' ∈ diffs L.g1 ∪ diffs L.g2 ∪ diffs L.gt := by
    rcases hl with rfl | rfl | rfl <;> simp [hm]
  exact h _ hu (by simp [e])

/-- **GGM transfer.**  Two challenge worlds whose FORMAL runs coincide (for the adversary at hand, i.e. whatever it
does it cannot see a polynomial identity separating them) are distinguished in the real (random-assignment) world
with advantage at most `2 N d / |F|` where `N` bounds the number of pairs of list entries and `d` their degree. -/
theorem transfer (pr : Params F σ A K) (adv : Adv F A K) (La Lb : Lists F σ K) (n : ℕ)
    (hform : result pr eqoF adv La n = result pr eqoF adv Lb n)
    (d N : ℕ)
    (hda : ∀ p ∈ (run pr eqoF adv La n).1.g1 ++ (run pr eqoF adv La n).1.g2 ++ (run pr eqoF adv La n).1.gt, p.totalDegree ≤ d)
    (hdb : ∀ p ∈ (run pr eqoF adv Lb n).1.g1 ++ (run pr eqoF adv Lb n).1.g2 ++ (run pr eqoF adv Lb n).1.gt, p.totalDegree ≤ d)
    (hNa : (run pr eqoF adv La n).1.g1.length ^ 2 + (run pr eqoF adv La n).1.g2.length ^ 2 + (run pr eqoF adv La n).1.gt.length ^ 2 ≤ N)
    (hNb : (run pr eqoF adv Lb n).1.g1.length ^ 2 + (run pr eqoF adv Lb n).1.g2.length ^ 2 + (run pr eqoF adv Lb n).1.gt.length ^ 2 ≤ N) :
    |((univ.filter (fun x : σ → F => result pr (eqoR x) adv La n = true)).card : ℚ)
      - ((univ.filter (fun x : σ → F => result pr (eqoR x) adv Lb n = true)).card : ℚ)|
      * Fintype.card F ≤ 2 * N * d * (Fintype.card F : ℚ) ^ Fintype.card σ := by
  set Ra := (run pr eqoF adv La n).1
  set Rb := (run pr eqoF adv Lb n).1
  let Q : Finset (MvPolynomial σ F) := diffs Ra.g1 ∪ diffs Ra.g2 ∪ diffs Ra.gt
  let Q' : Finset (MvPolynomial σ F) := diffs Rb.g1 ∪ diffs Rb.g2 ∪ diffs Rb.gt
  have dg : ∀ (R : Lists F σ K), (∀ p ∈ R.g1 ++ R.g2 ++ R.gt, p.totalDegree ≤ d) →
      ∀ q ∈ diffs R.g1 ∪ diffs R.g2 ∪ diffs R.gt, q ≠ 0 ∧ q.totalDegree ≤ d := by
    intro R hR q hq
    simp only [mem_union] at hq
    rcases hq with (hq | hq) | hq
    · exact diffs_deg _ d (fun p hp => hR p (by simp [hp])) q hq
    · exact diffs_deg _ d (fun p hp => hR p (by simp [hp])) q hq
    · exact diffs_deg _ d (fun p hp => hR p (by simp [hp])) q hq
  have cardQ : ∀ R : Lists F σ K, ((diffs R.g1 ∪ diffs R.g2 ∪ diffs R.gt).card : ℚ) ≤
      (R.g1.length ^ 2 + R.g2.length ^ 2 + R.gt.length ^ 2 : ℕ) := by
    intro R
    have h1 := diffs_card R.g1
    have h2 := diffs_card R.g2
    have h3 := diffs_card R.gt
    have : (diffs R.g1 ∪ diffs R.g2 ∪ diffs R.gt).card ≤ R.g1.length ^ 2 + R.g2.length ^ 2 + R.gt.length ^ 2 := by
      refine (card_union_le _ _).trans ?_
      have := card_union_le (diffs R.g1) (diffs R.g2)
      simp only [sq]; omega
    exact_mod_cast this
  set B : Finset (σ → F) := univ.filter (fun x => ∃ q ∈ Q ∪ Q', eval x q = 0)
  have hB := sz_union (Q ∪ Q') d (fun q hq => by
    rcases mem_union.mp hq with h | h
    · exact dg Ra hda q h
    · exact dg Rb hdb q h)
  have hQcard : ((Q ∪ Q').card : ℚ) ≤ 2 * N := by
    have h1 := cardQ Ra; have h2 := cardQ Rb
    have h3 : ((Q ∪ Q').card : ℚ) ≤ Q.card + Q'.card := by exact_mod_cast card_union_le _ _
    have : (((Ra.g1.length ^ 2 + Ra.g2.length ^ 2 + Ra.gt.length ^ 2 : ℕ)) : ℚ) ≤ N := by exact_mod_cast hNa
    have : (((Rb.g1.length ^ 2 + Rb.g2.length ^ 2 + Rb.gt.length ^ 2 : ℕ)) : ℚ) ≤ N := by exact_mod_cast hNb
    linarith
  -- outside `B` both real runs equal the formal runs, which agree
  have hout : ∀ x ∉ B, (result pr (eqoR x) adv La n = true ↔ result pr (eqoR x) adv Lb n = true) := by
    intro x hx
    have hx' : ∀ q ∈ Q ∪ Q', eval x q ≠ 0 := by
      intro q hq h0; exact hx (by simp only [B, mem_filter, mem_univ, true_and]; exact ⟨q, hq, h0⟩)
    have ga : GoodL x Ra := good_of_not_bad x Ra (fun q hq => hx' q (mem_union_left _ hq))
    have gb : GoodL x Rb := good_of_not_bad x Rb (fun q hq => hx' q (mem_union_right _ hq))
    have ea := run_real_eq_formal pr adv La x n ga
    have eb := run_real_eq_formal pr adv Lb x n gb
    unfold result at hform ⊢
    rw [ea, eb, hform]
  set Sa := univ.filter (fun x : σ → F => result pr (eqoR x) adv La n = true)
  set Sb := univ.filter (fun x : σ → F => result pr (eqoR x) adv Lb n = true)
  have hsym : ((Sa \ Sb).card : ℚ) ≤ B.card ∧ ((Sb \ Sa).card : ℚ) ≤ B.card := by
    constructor <;> (norm_cast; refine card_le_card fun x hx => ?_; by_contra hxB
                     simp only [mem_sdiff, Sa, Sb, mem_filter, mem_univ, true_and] at hx
                     first | exact hx.2 ((hout x hxB).mp hx.1) | exact hx.2 ((hout x hxB).mpr hx.1))
  have hd : ((Sa.card : ℚ) - Sb.card) ≤ B.card ∧ ((Sb.card : ℚ) - Sa.card) ≤ B.card := by
    have e1 : (Sa.card : ℚ) - Sb.card ≤ (Sa \ Sb).card := by
      have := card_sdiff_add_card_inter Sa Sb
      have := card_le_card (inter_subset_right (s₁ := Sa) (s₂ := Sb))
      have h5 : Sa.card ≤ (Sa \ Sb).card + Sb.card := by
        have := card_le_card (show Sa ⊆ (Sa \ Sb) ∪ Sb from fun x hx => by
          by_cases h : x ∈ Sb <;> simp [h, hx])
        exact this.trans (card_union_le _ _)
      have : (Sa.card : ℚ) ≤ (Sa \ Sb).card + Sb.card := by exact_mod_cast h5
      linarith
    have e2 : (Sb.card : ℚ) - Sa.card ≤ (Sb \ Sa).card := by
      have h5 : Sb.card ≤ (Sb \ Sa).card + Sa.card := by
        have := card_le_card (show Sb ⊆ (Sb \ Sa) ∪ Sa from fun x hx => by
          by_cases h : x ∈ Sa <;> simp [h, hx])
        exact this.trans (card_union_le _ _)
      have : (Sb.card : ℚ) ≤ (Sb \ Sa).card + Sa.card := by exact_mod_cast h5
      linarith
    exact ⟨e1.trans hsym.1, e2.trans hsym.2⟩
  have hq : (0 : ℚ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have habs : |(Sa.card : ℚ) - Sb.card| ≤ B.card := abs_le.mpr ⟨by linarith [hd.2], hd.1⟩
  calc |(Sa.card : ℚ) - Sb.card| * Fintype.card F ≤ B.card * Fintype.card F := by gcongr
    _ ≤ (Q ∪ Q').card * d * (Fintype.card F : ℚ) ^ Fintype.card σ := hB
    _ ≤ 2 * N * d * (Fintype.card F : ℚ) ^ Fintype.card σ := by gcongr

end Count

end PcaMath.GgmTransfer
