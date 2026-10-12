import Mathlib

/-!
# More small structural theorems used by the claim ledger

* L4.1   Merkle inclusion binding (up to a hash collision)
* L1.1   cofactored and cofactorless verification agree on the prime-order subgroup
* C-4    union bound that combines the EasyCrypt bound C-1 with the Lean fact C-3
* FR-4   a verifier that sees only `(X, m, sigma)` cannot depend on how the key was dealt
* PIN    the verification key of a post-quantum signature never comes from the artifact being verified
* CAP    a size / count cap that is enforced before use bounds what is used
-/

namespace PcaMath.Misc2

/-! ## L4.1 Merkle binding -/

section Merkle
variable {α : Type*}

/-- recompute the root from a leaf hash and a path of `(sibling, leaf_is_right_child)` steps. -/
def root (H : α → α → α) : α → List (α × Bool) → α
  | x, [] => x
  | x, (s, d) :: π => root H (if d then H s x else H x s) π

/-- a collision of the node hash -/
def Collision (H : α → α → α) : Prop := ∃ a b c d, (a, b) ≠ (c, d) ∧ H a b = H c d

/-- Binding: two leaves that verify against the same root along paths with the same direction bits
(the index and the tree size are fixed by the verifier) are equal, unless the node hash has a collision. -/
theorem merkle_binding (H : α → α → α) :
    ∀ (π π' : List (α × Bool)) (x y : α), π.map Prod.snd = π'.map Prod.snd →
      root H x π = root H y π' → x = y ∨ Collision H
  | [], [], x, y, _, h => Or.inl h
  | [], _ :: _, _, _, h, _ => by simp at h
  | _ :: _, [], _, _, h, _ => by simp at h
  | (s, d) :: π, (s', d') :: π', x, y, hd, h => by
      simp only [List.map_cons, List.cons.injEq] at hd
      obtain ⟨hdd, hrest⟩ := hd
      subst hdd
      simp only [root] at h
      rcases merkle_binding H π π' _ _ hrest h with he | hc
      · by_cases hxy : x = y
        · exact Or.inl hxy
        · right
          cases d
          · simp only [Bool.false_eq_true, if_false] at he
            exact ⟨x, s, y, s', fun e => hxy (Prod.mk.inj e).1, he⟩
          · simp only [if_true] at he
            exact ⟨s, x, s', y, fun e => hxy (Prod.mk.inj e).2, he⟩
      · exact Or.inr hc

end Merkle

/-! ## L1.1 -/

/-- On the prime-order subgroup (odd order `ℓ`), `[8]x = 0` forces `x = 0`: the cofactored check
`[8]([s]B - R - [h]A) = 0` is equivalent to the cofactorless one. -/
theorem eight_smul_eq_zero {G : Type*} [AddCommGroup G] (ℓ : ℕ) (hodd : Odd ℓ) (x : G)
    (hl : ℓ • x = 0) (h8 : 8 • x = 0) : x = 0 := by
  have h1 : addOrderOf x ∣ ℓ := addOrderOf_dvd_of_nsmul_eq_zero hl
  have h2 : addOrderOf x ∣ 8 := addOrderOf_dvd_of_nsmul_eq_zero h8
  have hc : Nat.Coprime 8 ℓ := by
    have : Nat.Coprime 2 ℓ := (Nat.Prime.coprime_iff_not_dvd Nat.prime_two).mpr hodd.not_two_dvd_nat
    simpa using Nat.Coprime.pow_left 3 this
  have : addOrderOf x ∣ 1 := hc ▸ Nat.dvd_gcd h2 h1
  have h1x := addOrderOf_dvd_iff_nsmul_eq_zero.mp this
  simpa using h1x

/-! ## C-4: union bound on a finite sample space -/

theorem union_bound {Ω : Type*} [Fintype Ω] [DecidableEq Ω] (bad forg coll : Finset Ω)
    (h : bad ⊆ forg ∪ coll) : (bad.card : ℚ) / Fintype.card Ω ≤ forg.card / Fintype.card Ω + coll.card / Fintype.card Ω := by
  rw [← add_div]
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast (Finset.card_le_card h).trans (Finset.card_union_le _ _)

/-! ## FR-4 -/

theorem verifier_sees_only_view {X M S : Type*} (V : X → M → S → Bool) {D : Type*} (deal : D → X × M × S)
    (d d' : D) (h : deal d = deal d') :
    (let t := deal d; V t.1 t.2.1 t.2.2) = (let t := deal d'; V t.1 t.2.1 t.2.2) := by
  simp [h]

/-! ## PIN: PinnedPqKey -/

inductive Source | pin | holderCommit | registry | artifact
  deriving DecidableEq

/-- a verification key is usable only together with the proof that it was not taken from the artifact. -/
structure PinnedKey (K : Type*) where
  key : K
  src : Source
  notArtifact : src ≠ Source.artifact

/-- the only way to obtain a `PinnedKey` (the choke point `resolvePqVerifyKey`) -/
def resolve {K : Type*} (s : Source) (k : K) : Option (PinnedKey K) :=
  if h : s = Source.artifact then none else some ⟨k, s, h⟩

theorem resolve_artifact {K : Type*} (k : K) : resolve Source.artifact k = none := by simp [resolve]

theorem pinned_never_artifact {K : Type*} (p : PinnedKey K) : p.src ≠ Source.artifact := p.notArtifact

theorem resolve_some {K : Type*} (s : Source) (k : K) (p : PinnedKey K) (h : resolve s k = some p) :
    s ≠ Source.artifact ∧ p.key = k := by
  unfold resolve at h
  split_ifs at h with hs
  have h' := Option.some.inj h
  subst h'; exact ⟨hs, rfl⟩

/-! ## CAP -/

def enforceCap {α : Type*} (cap : ℕ) (l : List α) : Option (List α) := if l.length ≤ cap then some l else none

theorem enforceCap_bound {α : Type*} (cap : ℕ) (l l' : List α) (h : enforceCap cap l = some l') : l'.length ≤ cap := by
  unfold enforceCap at h
  split_ifs at h with hc
  · simp at h; subst h; exact hc


/-! ## RP-4, integer step -/

/-- If `c - Σ v_i - σ ≡ 0 (mod q)` with every quantity in `[0, 2^32)` and `(n+1) 2^32 ≤ q`, the congruence
holds over the integers: `Σ v_i + σ = c`, hence `Σ v_i ≤ c` (no wrap-around). -/
theorem budget_integer (q n : ℕ) (v : Fin n → ℕ) (σ c : ℕ) (hv : ∀ i, v i < 2 ^ 32) (hσ : σ < 2 ^ 32)
    (hc : c < 2 ^ 32) (hq : (n + 1) * 2 ^ 32 ≤ q)
    (h : (q : ℤ) ∣ (c : ℤ) - ∑ i, (v i : ℤ) - σ) : ∑ i, v i + σ = c := by
  have hs : ∑ i, v i ≤ n * 2 ^ 32 := by
    calc ∑ i, v i ≤ ∑ _i : Fin n, 2 ^ 32 := Finset.sum_le_sum fun i _ => (hv i).le
      _ = n * 2 ^ 32 := by simp
  have hcast : ((∑ i, v i : ℕ) : ℤ) = ∑ i, (v i : ℤ) := by push_cast; rfl
  have hlt : |(c : ℤ) - ∑ i, (v i : ℤ) - σ| < q := by
    rw [abs_lt]
    have h1 : ((∑ i, v i : ℕ) : ℤ) ≤ n * 2 ^ 32 := by exact_mod_cast hs
    have h2 : (((n + 1) * 2 ^ 32 : ℕ) : ℤ) ≤ q := by exact_mod_cast hq
    push_cast at h2
    rw [hcast] at h1
    constructor <;> nlinarith [(Nat.cast_nonneg (α := ℤ) σ), (Nat.cast_nonneg (α := ℤ) c),
      (show (c : ℤ) < 2 ^ 32 by exact_mod_cast hc), (show (σ : ℤ) < 2 ^ 32 by exact_mod_cast hσ)]
  have h0 := Int.eq_zero_of_abs_lt_dvd h hlt
  have : ((∑ i, v i + σ : ℕ) : ℤ) = c := by push_cast; linarith
  exact_mod_cast this

end PcaMath.Misc2
