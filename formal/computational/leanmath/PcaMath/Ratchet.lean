import Mathlib

/-!
# GG-2: forward security of the GGM ratchet, depth-generic (no unrolling)

`packages/pca-ratchet` (docs/pca/security/proofs/04-ratchet.md, Theorem GG-2). A root seed is derived from the master
secret by one PRF call (`K0`); every node seed `ρ` is expanded by the length-doubling PRG `G ρ = (left, right)` (GG-1:
HMAC-PRF, advantage equality, EasyCrypt `ec/PcaPrg.ec`); a leaf seed gives the leaf signing key by one more PRF call
(`KL`). Signing at leaf `i` punctures the tree: what an adversary who corrupts the state afterwards learns about the
path to `i` is exactly the list of off-path SIBLINGS. `walk G bs ρ` returns (siblings along the path `bs`, leaf seed).

**Proved here.**
* `hybrid`: for ANY path `bs` (any depth), the real (siblings, leaf seed) is within `bs.length * ε` of independent
  uniform values, for every distinguisher in the class `Eff`. Induction on the path: one PRG hop per level. Depth 20
  is the instance `bs.length = 20`; nothing is unrolled.
* `full`: with the root KDF and the leaf-key derivation, `ε0 + d ε + εL` (the paper's `(d+2) Adv_prf` when all three
  are the HMAC-PRF advantage).
* `expand_factor`: the whole tree of leaf seeds (hence every leaf key and every signature an honest signer can produce)
  is a function of `walk` along any path: an adversary's entire view in the game targeting leaf `i` is a function
  of `walk (bits i)`, which is what lets a reduction simulate it.
* `gg2`: the GG-2 bound `Pr[win] ≤ ε_CR + 2^d (ε0 + d ε + εL + ε_Ed)`. The adaptive choice of the target leaf is the
  union over the `2^d` leaves (`hpt`, a pointwise inequality); in each leaf's ideal game the leaf key is uniform
  and independent of the view, which is the EUF-CMA game of the simulator (`heuf`).

**Efficiency.** Probabilities are exact finite averages (`avg`). "Efficient distinguisher" is abstracted as classes
(`Eff`, `EffP`, ...) and the computational assumptions hold for the members of those classes. The closure hypotheses
(`hstep`, `hpre`, `hroot`, ...) say that each reduction's distinguisher, which is the old one composed with explicit
PRG evaluations, sibling insertions and a fixed prefix, is again in the class. These are the usual
"the reduction is efficient" side conditions, made explicit rather than argued.
-/

set_option linter.unusedSectionVars false

namespace PcaMath.Ratchet

open Finset

/-- uniform expectation over a finite type -/
noncomputable def avg {α : Type*} [Fintype α] (f : α → ℝ) : ℝ := (∑ x, f x) / (Fintype.card α : ℝ)

section avg
variable {α β : Type*} [Fintype α] [Fintype β]

lemma avg_sub (f g : α → ℝ) : avg f - avg g = avg (fun x => f x - g x) := by
  unfold avg; rw [← sub_div, ← Finset.sum_sub_distrib]

lemma abs_avg_le [Nonempty α] (f : α → ℝ) (c : ℝ) (h : ∀ x, |f x| ≤ c) : |avg f| ≤ c := by
  unfold avg
  have hn : (0:ℝ) < Fintype.card α := by exact_mod_cast Fintype.card_pos
  rw [abs_div, abs_of_pos hn, div_le_iff₀ hn]
  calc |∑ x, f x| ≤ ∑ x, |f x| := Finset.abs_sum_le_sum_abs _ _
    _ ≤ ∑ _x : α, c := Finset.sum_le_sum (fun x _ => h x)
    _ = c * Fintype.card α := by rw [Finset.sum_const, Finset.card_univ, nsmul_eq_mul]; ring

lemma avg_mono [Nonempty α] (f g : α → ℝ) (h : ∀ x, f x ≤ g x) : avg f ≤ avg g := by
  unfold avg
  have hn : (0:ℝ) < Fintype.card α := by exact_mod_cast Fintype.card_pos
  exact div_le_div_of_nonneg_right (Finset.sum_le_sum (fun x _ => h x)) hn.le

lemma avg_add (f g : α → ℝ) : avg (fun x => f x + g x) = avg f + avg g := by
  unfold avg; rw [Finset.sum_add_distrib, add_div]

lemma avg_finsum (s : Finset ℕ) (f : ℕ → α → ℝ) : avg (fun x => ∑ i ∈ s, f i x) = ∑ i ∈ s, avg (f i) := by
  unfold avg; rw [Finset.sum_comm, Finset.sum_div]

lemma avg_prod (f : α × β → ℝ) : avg f = avg (fun a => avg (fun b => f (a, b))) := by
  unfold avg
  rw [Fintype.sum_prod_type, Fintype.card_prod, Nat.cast_mul, ← Finset.sum_div]
  ring

lemma avg_comm (g : α → β → ℝ) : avg (fun a => avg (fun b => g a b)) = avg (fun b => avg (fun a => g a b)) := by
  unfold avg
  simp_rw [← Finset.sum_div]
  rw [Finset.sum_comm]
  ring

end avg

section ggm
variable {S : Type*} [Fintype S] [Nonempty S]

/-- (child, sibling) for direction `b` (`false` = go left) -/
def sel (b : Bool) (p : S × S) : S × S := if b then (p.2, p.1) else p

/-- (siblings along the path, leaf seed) -/
def walk (G : S → S × S) : List Bool → S → List S × S
  | [], s => ([], s)
  | b :: bs, s => ((sel b (G s)).2 :: (walk G bs (sel b (G s)).1).1, (walk G bs (sel b (G s)).1).2)

/-- the real view: a uniform node seed, walked down `bs` -/
noncomputable def realE (G : S → S × S) (bs : List Bool) (D : List S × S → ℝ) : ℝ := avg (fun s => D (walk G bs s))

/-- the ideal view: independent uniform siblings and leaf seed -/
noncomputable def idealE : List Bool → (List S × S → ℝ) → ℝ
  | [], D => avg (fun s => D ([], s))
  | _ :: bs, D => avg (fun a => idealE bs (fun w => D (a :: w.1, w.2)))

/-- the distinguisher a reduction runs at the first level of path `b :: bs` -/
def stepD (G : S → S × S) (b : Bool) (bs : List Bool) (D : List S × S → ℝ) (p : S × S) : ℝ :=
  D ((sel b p).2 :: (walk G bs (sel b p).1).1, (walk G bs (sel b p).1).2)

variable (G : S → S × S) (Eff : (List S × S → ℝ) → Prop) (EffP : (S × S → ℝ) → Prop) (ε : ℝ)

lemma first_hop (b : Bool) (bs : List Bool) (D : List S × S → ℝ) :
    avg (stepD G b bs D) = avg (fun a => realE G bs (fun w => D (a :: w.1, w.2))) := by
  rw [avg_prod]
  cases b
  · -- go left: child = left, sibling = right
    simp only [stepD, sel, realE]
    rw [avg_comm]
    rfl
  · simp only [stepD, sel, realE]
    rfl

/-- **Depth-generic hybrid.** PRG security against `EffP` plus the closure of `Eff` under the reduction steps give
    `|real - ideal| ≤ depth · ε` for every path, of any length. -/
theorem hybrid
    (hprg : ∀ D', EffP D' → |avg (fun s => D' (G s)) - avg D'| ≤ ε)
    (hstep : ∀ b bs D, Eff D → EffP (stepD G b bs D))
    (hpre : ∀ a D, Eff D → Eff (fun w => D (a :: w.1, w.2))) :
    ∀ (bs : List Bool) (D : List S × S → ℝ), Eff D → |realE G bs D - idealE bs D| ≤ bs.length * ε := by
  intro bs
  induction bs with
  | nil => intro D _; simp [realE, idealE, walk]
  | cons b bs ih =>
    intro D hD
    have hreal : realE G (b :: bs) D = avg (fun s => stepD G b bs D (G s)) := rfl
    have h1 := hprg _ (hstep b bs D hD)
    have h2 : |avg (stepD G b bs D) - idealE (b :: bs) D| ≤ bs.length * ε := by
      rw [first_hop, idealE, avg_sub]
      exact abs_avg_le _ _ (fun a => ih _ (hpre a D hD))
    rw [hreal]
    calc |avg (fun s => stepD G b bs D (G s)) - idealE (b :: bs) D|
        ≤ |avg (fun s => stepD G b bs D (G s)) - avg (stepD G b bs D)| + |avg (stepD G b bs D) - idealE (b :: bs) D| :=
          abs_sub_le _ _ _
      _ ≤ ε + bs.length * ε := add_le_add h1 h2
      _ = (b :: bs).length * ε := by simp only [List.length_cons]; push_cast; ring

/-! ### root KDF and leaf-key derivation -/

variable {R0 Kk : Type*} [Fintype R0] [Nonempty R0] [Fintype Kk] [Nonempty Kk]

/-- the real game: master secret → root seed (PRF) → walk → leaf key (PRF) -/
noncomputable def realFull (K0 : R0 → S) (KL : S → Kk) (bs : List Bool) (W : List S × Kk → ℝ) : ℝ :=
  avg (fun r => W ((walk G bs (K0 r)).1, KL (walk G bs (K0 r)).2))

/-- the ideal game: uniform siblings and a uniform leaf KEY -/
noncomputable def idealK : List Bool → (List S × Kk → ℝ) → ℝ
  | [], W => avg (fun k => W ([], k))
  | _ :: bs, W => avg (fun a => idealK bs (fun w => W (a :: w.1, w.2)))

lemma leaf_hop (KL : S → Kk) (EffK : (List S × Kk → ℝ) → Prop) (EffL : (Kk → ℝ) → Prop) (εL : ℝ)
    (hleaf : ∀ F, EffL F → |avg (fun s => F (KL s)) - avg F| ≤ εL)
    (hl : ∀ W, EffK W → EffL (fun k => W ([], k)))
    (hpreK : ∀ a W, EffK W → EffK (fun w => W (a :: w.1, w.2))) :
    ∀ (bs : List Bool) (W : List S × Kk → ℝ), EffK W →
      |idealE bs (fun w => W (w.1, KL w.2)) - idealK bs W| ≤ εL := by
  intro bs
  induction bs with
  | nil => intro W hW; exact hleaf _ (hl W hW)
  | cons b bs ih =>
    intro W hW
    simp only [idealE, idealK]
    rw [avg_sub]
    exact abs_avg_le _ _ (fun a => ih _ (hpreK a W hW))

/-- **GGM view, end to end:** `|real - ideal| ≤ ε0 + depth · ε + εL`. -/
theorem full (K0 : R0 → S) (KL : S → Kk) (EffK : (List S × Kk → ℝ) → Prop) (EffR : (S → ℝ) → Prop)
    (EffL : (Kk → ℝ) → Prop) (ε0 εL : ℝ)
    (hprg : ∀ D', EffP D' → |avg (fun s => D' (G s)) - avg D'| ≤ ε)
    (hstep : ∀ b bs D, Eff D → EffP (stepD G b bs D))
    (hpre : ∀ a D, Eff D → Eff (fun w => D (a :: w.1, w.2)))
    (hkdf : ∀ F, EffR F → |avg (fun r => F (K0 r)) - avg F| ≤ ε0)
    (hroot : ∀ bs W, EffK W → EffR (fun s => W ((walk G bs s).1, KL (walk G bs s).2)))
    (hleaf : ∀ F, EffL F → |avg (fun s => F (KL s)) - avg F| ≤ εL)
    (hl : ∀ W, EffK W → EffL (fun k => W ([], k)))
    (hpreK : ∀ a W, EffK W → EffK (fun w => W (a :: w.1, w.2)))
    (hEW : ∀ W, EffK W → Eff (fun w => W (w.1, KL w.2)))
    (bs : List Bool) (W : List S × Kk → ℝ) (hW : EffK W) :
    |realFull G K0 KL bs W - idealK bs W| ≤ ε0 + bs.length * ε + εL := by
  have a1 : |realFull G K0 KL bs W - realE G bs (fun w => W (w.1, KL w.2))| ≤ ε0 :=
    hkdf _ (hroot bs W hW)
  have a2 := hybrid G Eff EffP ε hprg hstep hpre bs _ (hEW W hW)
  have a3 := leaf_hop KL EffK EffL εL hleaf hl hpreK bs W hW
  calc |realFull G K0 KL bs W - idealK bs W|
      ≤ |realFull G K0 KL bs W - realE G bs (fun w => W (w.1, KL w.2))|
        + |realE G bs (fun w => W (w.1, KL w.2)) - idealE bs (fun w => W (w.1, KL w.2))|
        + |idealE bs (fun w => W (w.1, KL w.2)) - idealK bs W| := by
        have := abs_sub_le (realFull G K0 KL bs W) (realE G bs (fun w => W (w.1, KL w.2))) (idealK bs W)
        have := abs_sub_le (realE G bs (fun w => W (w.1, KL w.2))) (idealE bs (fun w => W (w.1, KL w.2))) (idealK bs W)
        linarith
    _ ≤ ε0 + bs.length * ε + εL := by linarith

/-! ### the whole tree is a function of the walk (simulation) -/

/-- all leaf seeds of a depth-`n` tree, left to right -/
def expand : ℕ → S → List S
  | 0, s => [s]
  | n + 1, s => expand n (G s).1 ++ expand n (G s).2

theorem expand_factor : ∀ bs : List Bool, ∃ R : List S × S → List S, ∀ s, expand G bs.length s = R (walk G bs s) := by
  intro bs
  induction bs with
  | nil => exact ⟨fun w => [w.2], fun s => rfl⟩
  | cons b bs ih =>
    obtain ⟨R, hR⟩ := ih
    cases b
    · refine ⟨fun w => match w.1 with
        | a :: rest => R (rest, w.2) ++ expand G bs.length a
        | [] => [], fun s => ?_⟩
      simp only [List.length_cons, expand, walk, sel, hR]
      rfl
    · refine ⟨fun w => match w.1 with
        | a :: rest => expand G bs.length a ++ R (rest, w.2)
        | [] => [], fun s => ?_⟩
      simp only [List.length_cons, expand, walk, sel, hR]
      rfl

/-! ### GG-2 -/

/-- **GG-2.** `bits i` is the path to leaf `i` (`d` levels). `W i` is the reduction's indicator "the adversary forges
    at target leaf `i` with no Merkle collision", computed by the simulator from (siblings, leaf key) of path `i`
    (possible by `expand_factor`). `hpt` is the union over the target leaf (adaptive choice), `hcoll` the Merkle
    second-preimage term, `heuf` the EUF-CMA game of the simulator in the ideal world (uniform independent key). -/
theorem gg2 (K0 : R0 → S) (KL : S → Kk) (EffK : (List S × Kk → ℝ) → Prop) (EffR : (S → ℝ) → Prop)
    (EffL : (Kk → ℝ) → Prop) (ε0 εL εCR εEd : ℝ) (d : ℕ)
    (hprg : ∀ D', EffP D' → |avg (fun s => D' (G s)) - avg D'| ≤ ε)
    (hstep : ∀ b bs D, Eff D → EffP (stepD G b bs D))
    (hpre : ∀ a D, Eff D → Eff (fun w => D (a :: w.1, w.2)))
    (hkdf : ∀ F, EffR F → |avg (fun r => F (K0 r)) - avg F| ≤ ε0)
    (hroot : ∀ bs W, EffK W → EffR (fun s => W ((walk G bs s).1, KL (walk G bs s).2)))
    (hleaf : ∀ F, EffL F → |avg (fun s => F (KL s)) - avg F| ≤ εL)
    (hl : ∀ W, EffK W → EffL (fun k => W ([], k)))
    (hpreK : ∀ a W, EffK W → EffK (fun w => W (a :: w.1, w.2)))
    (hEW : ∀ W, EffK W → Eff (fun w => W (w.1, KL w.2)))
    (bits : ℕ → List Bool) (hlen : ∀ i, (bits i).length = d)
    (W : ℕ → List S × Kk → ℝ) (hW : ∀ i, EffK (W i))
    (win coll : R0 → ℝ)
    (hpt : ∀ r, win r ≤ coll r + ∑ i ∈ range (2 ^ d), W i ((walk G (bits i) (K0 r)).1, KL (walk G (bits i) (K0 r)).2))
    (hcoll : avg coll ≤ εCR)
    (heuf : ∀ i, idealK (bits i) (W i) ≤ εEd) :
    avg win ≤ εCR + 2 ^ d * (ε0 + d * ε + εL + εEd) := by
  have hstep1 : avg win ≤ avg coll + ∑ i ∈ range (2 ^ d), realFull G K0 KL (bits i) (W i) := by
    calc avg win ≤ avg (fun r => coll r + ∑ i ∈ range (2 ^ d),
            W i ((walk G (bits i) (K0 r)).1, KL (walk G (bits i) (K0 r)).2)) := avg_mono _ _ hpt
      _ = avg coll + ∑ i ∈ range (2 ^ d), realFull G K0 KL (bits i) (W i) := by
          rw [avg_add, avg_finsum]; rfl
  have hi : ∀ i, realFull G K0 KL (bits i) (W i) ≤ ε0 + d * ε + εL + εEd := by
    intro i
    have h := full G Eff EffP ε K0 KL EffK EffR EffL ε0 εL hprg hstep hpre hkdf hroot hleaf hl hpreK hEW (bits i) (W i) (hW i)
    rw [hlen i] at h
    have := (abs_le.mp h).2
    have := heuf i
    linarith
  have hsum : ∑ i ∈ range (2 ^ d), realFull G K0 KL (bits i) (W i) ≤ 2 ^ d * (ε0 + d * ε + εL + εEd) := by
    calc ∑ i ∈ range (2 ^ d), realFull G K0 KL (bits i) (W i)
        ≤ ∑ _i ∈ range (2 ^ d), (ε0 + d * ε + εL + εEd) := Finset.sum_le_sum (fun i _ => hi i)
      _ = 2 ^ d * (ε0 + d * ε + εL + εEd) := by rw [Finset.sum_const, Finset.card_range, nsmul_eq_mul]; push_cast; ring
  linarith

end ggm
end PcaMath.Ratchet
