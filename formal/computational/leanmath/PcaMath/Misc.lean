import Mathlib

/-!
# Small combinatorial / algebraic theorems of `docs/pca/security/proofs/*.md`

* MPC-3  monotonicity of the decoded output under arbitrary corrupted inputs
* MPC-4  information-theoretic privacy of additive shares; masked Beaver openings
* TH-4   corrected composition: `allow` implies at least `t_srv` distinct roles
* GG-3   no double-spend resistance against the state holder (definitional)
* AT-1   injective length-prefixed framing
-/

namespace PcaMath.Misc

/-! ## MPC-3 -/

section MPC3
variable {R : Type*} [CommRing R] [Nontrivial R] {ι : Type*} [Fintype ι] [DecidableEq ι]

/-- `allow` is the product of the parties' allow bits: one honest `0` forces output `0`. -/
theorem allow_monotone (x : ι → R) (h : ι) (hh : x h = 0) : ∏ i, x i ≠ 1 := by
  rw [Finset.prod_eq_zero (Finset.mem_univ h) hh]
  exact zero_ne_one

/-- thermometer OR at one position: `1 - ∏ (1 - b_i)`; one honest `1` forces output `1`. -/
theorem or_monotone (b : ι → R) (h : ι) (hh : b h = 1) : 1 - ∏ i, (1 - b i) = 1 := by
  have : ∏ i, (1 - b i) = 0 := Finset.prod_eq_zero (Finset.mem_univ h) (by rw [hh]; ring)
  rw [this]; ring

open Classical in
/-- decoding counts the set positions; an honest thermometer with `t_h` ones forces at least `t_h` set positions. -/
theorem thermometer_monotone (K : ℕ) (b : ι → ℕ → R) (h : ι) (th : ℕ) (hth : th ≤ K)
    (hones : ∀ k < th, b h k = 1) :
    th ≤ ((Finset.range K).filter (fun k => 1 - ∏ i, (1 - b i k) = 1)).card := by
  have hsub : Finset.range th ⊆ (Finset.range K).filter (fun k => 1 - ∏ i, (1 - b i k) = 1) := by
    intro k hk
    simp only [Finset.mem_range] at hk
    simp only [Finset.mem_filter, Finset.mem_range]
    exact ⟨lt_of_lt_of_le hk hth, or_monotone (fun i => b i k) h (hones k hk)⟩
  simpa using Finset.card_le_card hsub

end MPC3

/-! ## MPC-4 -/

section MPC4
variable {G : Type*} [AddCommGroup G] {n : ℕ}

/-- all share vectors of a secret `x` -/
abbrev Shares (n : ℕ) (x : G) := {v : Fin n → G // ∑ i, v i = x}

/-- Independence of any `n-1` shares from the secret: for every pair of secrets there is a bijection between
their sharings that fixes every coordinate except the missing party `j`.  Hence the other `n-1` shares have
the same (uniform) distribution for every secret. -/
theorem shares_independent (j : Fin n) (x y : G) :
    ∃ e : Shares n x ≃ Shares n y, ∀ v : Shares n x, ∀ i, i ≠ j → (e v).1 i = v.1 i := by
  classical
  refine ⟨⟨fun v => ⟨Function.update v.1 j (v.1 j + (y - x)), ?_⟩,
           fun v => ⟨Function.update v.1 j (v.1 j + (x - y)), ?_⟩, ?_, ?_⟩, ?_⟩
  · have hu := Finset.sum_update_of_mem (Finset.mem_univ j) v.1 (v.1 j + (y - x))
    have h2 : ∑ i ∈ Finset.univ \ {j}, v.1 i + v.1 j = x := by
      have := Finset.sum_sdiff (f := v.1) (Finset.subset_univ {j})
      simpa [add_comm] using this.trans v.2
    have hS : ∑ i ∈ Finset.univ \ {j}, v.1 i = x - v.1 j := eq_sub_of_add_eq h2
    rw [hu, hS]; abel
  · have hu := Finset.sum_update_of_mem (Finset.mem_univ j) v.1 (v.1 j + (x - y))
    have h2 : ∑ i ∈ Finset.univ \ {j}, v.1 i + v.1 j = y := by
      have := Finset.sum_sdiff (f := v.1) (Finset.subset_univ {j})
      simpa [add_comm] using this.trans v.2
    have hS : ∑ i ∈ Finset.univ \ {j}, v.1 i = y - v.1 j := eq_sub_of_add_eq h2
    rw [hu, hS]; abel
  · intro v; apply Subtype.ext; funext i
    by_cases hi : i = j
    · subst hi; simp; abel
    · simp [Function.update_of_ne hi]
  · intro v; apply Subtype.ext; funext i
    by_cases hi : i = j
    · subst hi; simp; abel
    · simp [Function.update_of_ne hi]
  · intro v i hi; simp [Function.update_of_ne hi]

/-- Beaver opening `d = x - a` with `a` uniform: `a ↦ x - a` is a bijection, so `d` is uniform for every `x`. -/
theorem masked_opening_bijective (x : G) : Function.Bijective (fun a : G => x - a) := by
  constructor
  · intro a b h; simpa using h
  · intro d; exact ⟨x - d, by simp⟩

end MPC4

/-! ## TH-4 -/

section TH4
variable {Role : Type*} [DecidableEq Role]

/-- `count` = number of distinct roles with a valid role-bound share; the hook accepts iff `t ≤ count`. -/
def hookAccepts (valid : Finset Role) (t : ℕ) : Prop := t ≤ valid.card

theorem th4 (valid : Finset Role) (t tsrv : ℕ) (ht : tsrv ≤ t) (h : hookAccepts valid t) :
    tsrv ≤ valid.card := le_trans ht h

end TH4

/-! ## GG-3 (definitional): the state is a value; whoever holds it signs any message at an unspent leaf -/

theorem no_double_spend_against_holder {State Msg Sig Root : Type*} (sign : State → ℕ → Msg → Sig)
    (verify : Root → ℕ → Msg → Sig → Prop) (root : Root) (S : State) (i : ℕ)
    (complete : ∀ m, verify root i m (sign S i m)) (m m' : Msg) :
    verify root i m (sign S i m) ∧ verify root i m' (sign S i m') :=
  ⟨complete m, complete m'⟩

/-! ## AT-1 -/

section AT1
variable {α : Type*}

/-- `lp f = pfx |f| ++ f` with a fixed-width injective length prefix. -/
def enc (pfx : ℕ → List α) (fs : List (List α)) : List α :=
  fs.flatMap (fun f => pfx f.length ++ f)

theorem enc_injective (pfx : ℕ → List α) (w : ℕ) (hw0 : 0 < w) (hw : ∀ n, (pfx n).length = w)
    (hinj : Function.Injective pfx) : Function.Injective (enc pfx) := by
  intro fs gs h
  induction fs generalizing gs with
  | nil =>
    cases gs with
    | nil => rfl
    | cons g gs =>
      simp only [enc, List.flatMap_nil, List.flatMap_cons] at h
      have := congrArg List.length h
      simp [hw] at this
      omega
  | cons f fs ih =>
    cases gs with
    | nil =>
      simp only [enc, List.flatMap_nil, List.flatMap_cons] at h
      have := congrArg List.length h
      simp [hw] at this
      omega
    | cons g gs =>
      simp only [enc, List.flatMap_cons] at h
      have h1 : pfx f.length ++ (f ++ fs.flatMap (fun f => pfx f.length ++ f)) =
                pfx g.length ++ (g ++ gs.flatMap (fun f => pfx f.length ++ f)) := by
        simpa [List.append_assoc] using h
      have hp := List.append_inj h1 (by rw [hw, hw])
      have hl : f.length = g.length := hinj hp.1
      have h2 := hp.2
      have hf := List.append_inj h2 hl
      have := ih (gs := gs) hf.2
      rw [hf.1, this]

end AT1

end PcaMath.Misc
