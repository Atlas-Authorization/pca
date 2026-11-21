/-!
# The Shamir-tree weights solve the FAME span program  --  `packages/pca-abe` (`buildRows`, `reconstructionWeights`)

Core Lean only.  `fame.ts` turns a threshold tree into a span program (one row per leaf; a `t`-of-`n` gate allocates `t-1` fresh
columns and gives its child number `i` (1-based) the parent's row vector plus `i^k` in the gate's `k`-th new column, `k = 1..t-1`; column 0
is the secret column and every row has a 1 there) and decrypts with the weights `w_leaf` = the product of the Lagrange coefficients
along the path from the root.  `Fame.decrypt_exponent` needs `sum_i w_i M_ij = [j = 0]` for every column `j`: this file proves it.

Only the leaves a plan SELECTS carry a weight (the others have weight 0 and drop out of the sum), so a plan is the tree restricted to the
selected children: `Plan.gate t sel` with `sel` the list of selected children `(i, lambda_i, subplan)`.  Columns are named by
`(path, k)` where `path` is the list of child numbers from the root to the gate that allocated them; the secret column is `([], 0)`.

* `total p path w v` is the column-wise weighted sum `sum_i w_i * (row of leaf i)` over the leaves of `p`, where `w` is the weight
  accumulated so far and `v` the row vector handed down to this node.
* The only property of the Lagrange coefficients used is the moment equations `sum_i lambda_i * i^k = [k = 0]` for `k < t`
  (`WF`), which is what `lagrangeAtZero` computes (it solves the Vandermonde system; interpolation at 0).

`total_spec` : if every gate of the plan satisfies its moment equations and `v` vanishes on the columns this subtree allocates, then
`total p path w v j = if j is allocated in this subtree then 0 else w * v j`.  Taking the root (`path = []`, `w = 1`, `v` = the unit
vector of the secret column) gives `span_program_solved`: the weights reproduce exactly `(1, 0, ..., 0)`.
-/

namespace PcaComp.Span

open Lean.Grind

variable {R : Type} [CommRing R]

abbrev Col := List Nat × Nat

open Classical in
/-- the column `j` is one of the (non-secret) columns allocated by a gate at `path` or below -/
def Inside (path : List Nat) (j : Col) : Prop := path <+: j.1 ∧ 1 ≤ j.2

def pw (x : R) : Nat → R
  | 0 => 1
  | k + 1 => x * pw x k

mutual
inductive Plan (R : Type) : Type
  | leaf : Plan R
  | gate (t : Nat) (sel : Sels R) : Plan R
inductive Sels (R : Type) : Type
  | nil : Sels R
  | cons (i : Nat) (x lam : R) (p : Plan R) (rest : Sels R) : Sels R
end

open Classical in
/-- the row vector a gate at `path` with threshold `t` hands to its child number `i` -/
noncomputable def stepVec (path : List Nat) (t : Nat) (x : R) (v : Col → R) : Col → R :=
  fun j => v j + (if j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t then pw x j.2 else 0)

mutual
noncomputable def total : Plan R → List Nat → R → (Col → R) → Col → R
  | .leaf, _, w, v => fun j => w * v j
  | .gate t sel, path, w, v => totalS t sel path w v
noncomputable def totalS : Nat → Sels R → List Nat → R → (Col → R) → Col → R
  | _, .nil, _, _, _ => fun _ => 0
  | t, .cons i x lam p rest, path, w, v =>
      fun j => total p (path ++ [i]) (w * lam) (stepVec path t x v) j + totalS t rest path w v j
end

mutual
def momS : Nat → Sels R → R
  | _, .nil => 0
  | k, .cons _ x lam _ rest => lam * pw x k + momS k rest
end

mutual
def WF : Plan R → Prop
  | .leaf => True
  | .gate t sel => 1 ≤ t ∧ (∀ k, k < t → momS k sel = if k = 0 then 1 else 0) ∧ WFS sel
def WFS : Sels R → Prop
  | .nil => True
  | .cons _ _ _ p rest => WF p ∧ WFS rest
end

theorem inside_append {path : List Nat} {i : Nat} {j : Col} (h : Inside (path ++ [i]) j) : Inside path j :=
  ⟨List.IsPrefix.trans (List.prefix_append path [i]) h.1, h.2⟩

theorem not_inside_child {path : List Nat} {i : Nat} {j : Col} (h : j.1 = path) : ¬ Inside (path ++ [i]) j := by
  intro hi
  have := hi.1.length_le
  rw [h] at this
  simp at this
  omega

open Classical in
mutual
theorem total_spec : ∀ (p : Plan R) (path : List Nat) (w : R) (v : Col → R), WF p →
    (∀ j, Inside path j → v j = 0) → ∀ j, total p path w v j = if Inside path j then 0 else w * v j
  | .leaf, path, w, v, _, hv, j => by
      simp only [total]
      by_cases h : Inside path j
      · simp only [h, ite_true, hv j h]; grind
      · simp only [h, ite_false]
  | .gate t sel, path, w, v, ⟨ht, hm, hs⟩, hv, j => by
      simp only [total]
      rw [totalS_spec t sel path w v hs hv j]
      by_cases h : Inside path j
      · by_cases hc : j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t
        · have hk : j.2 ≠ 0 := by have := hc.2.1; omega
          simp only [h, hc, ite_true, hm j.2 hc.2.2, hk, ite_false]; grind
        · simp only [h, hc, ite_true, ite_false]
      · simp only [h, ite_false, hm 0 (by omega), ite_true]; grind
theorem totalS_spec : ∀ (t : Nat) (sel : Sels R) (path : List Nat) (w : R) (v : Col → R), WFS sel →
    (∀ j, Inside path j → v j = 0) → ∀ j, totalS t sel path w v j =
      if Inside path j then (if j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t then w * momS j.2 sel else 0)
      else w * v j * momS 0 sel
  | t, .nil, path, w, v, _, _, j => by
      simp only [totalS, momS]
      by_cases h : Inside path j
      · by_cases hc : j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t <;> simp only [h, hc, ite_true, ite_false] <;> grind
      · simp only [h, ite_false]; grind
  | t, .cons i x lam p rest, path, w, v, ⟨hp, hr⟩, hv, j => by
      have hv' : ∀ j', Inside (path ++ [i]) j' → stepVec path t x v j' = 0 := by
        intro j' hj'
        have hn : ¬ (j'.1 = path ∧ 1 ≤ j'.2 ∧ j'.2 < t) := fun hc => not_inside_child hc.1 hj'
        simp only [stepVec, hv j' (inside_append hj'), hn, ite_false]; grind
      have child := total_spec p (path ++ [i]) (w * lam) (stepVec path t x v) hp hv' j
      have ih := totalS_spec t rest path w v hr hv j
      simp only [totalS, momS]
      rw [child, ih]
      by_cases h : Inside path j
      · by_cases hc : j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t
        · have hni : ¬ Inside (path ++ [i]) j := not_inside_child hc.1
          simp only [hni, h, hc, ite_true, ite_false, stepVec, hv j h]; grind
        · by_cases hi : Inside (path ++ [i]) j
          · simp only [hi, h, hc, ite_true, ite_false]; grind
          · simp only [hi, h, hc, ite_true, ite_false, stepVec, hv j h]; grind
      · have hni : ¬ Inside (path ++ [i]) j := fun hh => h (inside_append hh)
        have hc : ¬ (j.1 = path ∧ 1 ≤ j.2 ∧ j.2 < t) := fun hc => h ⟨by rw [hc.1]; exact List.prefix_refl _, hc.2.1⟩
        simp only [hni, h, hc, ite_false, stepVec, pw]; grind
end

/-- The root: the weights (products of Lagrange coefficients along the paths) reproduce `(1, 0, ..., 0)` on every column of the span
program (the secret column `([], 0)` and the allocated columns `(path, k)`, `k >= 1`). -/
theorem span_program_solved (p : Plan R) (hp : WF p) (j : Col) (hj : j = ([], 0) ∨ 1 ≤ j.2) :
    total p [] 1 (fun j' => if j' = ([], 0) then 1 else 0) j = if j = ([], 0) then 1 else 0 := by
  have hne : ∀ j' : Col, 1 ≤ j'.2 → j' ≠ ([], 0) := fun j' h e => by rw [e] at h; simp at h
  have hv : ∀ j', Inside [] j' → (fun j' : Col => if j' = ([], 0) then (1 : R) else 0) j' = 0 := by
    intro j' h
    simp only [hne j' h.2, ite_false]
  rw [total_spec p [] 1 _ hp hv j]
  rcases hj with e | h1
  · have hn : ¬ Inside [] j := fun h => by have := h.2; rw [e] at this; simp at this
    simp only [hn, ite_false]; subst e; simp only [ite_true]; grind
  · have hi : Inside [] j := ⟨List.nil_prefix, h1⟩
    simp only [hi, ite_true, hne j h1, ite_false]

end PcaComp.Span
