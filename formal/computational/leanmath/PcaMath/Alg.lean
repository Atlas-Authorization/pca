import Mathlib

/-!
# Algebraic facts of the ratchet NIZKs and of FROST verification, machine-checked

(proofs/04-ratchet.md RP-1 perfect completeness, RP-6 special honest-verifier zero knowledge,
 proofs/02-threshold-hybrid.md FR-1 verification equivalence.)

Group: an additive module `G` over a field `F` (the prime-order group written additively).
-/

namespace PcaMath.Alg

variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

/-! ## Schnorr (aggregation) proof of `D = w • H` -/

/-- completeness of the Schnorr proof: announcement `k • H`, response `k + e * w`. -/
theorem schnorr_complete (H : G) (w k e : F) :
    (k + e * w) • H = k • H + e • (w • H) := by
  rw [add_smul, mul_smul]

/-! ## The OR proof for `B = b • G + s • H`, `b ∈ {0,1}` (proveBit / verifyBit) -/

/-- verifier equations for one OR transcript `(e0,e1,z0,z1)` with announcements `(a0,a1)`:
    `z_i • H = a_i + e_i • P_i`, `P0 = B`, `P1 = B - G`, and `e0 + e1 = e`. -/
def OrAccepts (Gg H B a0 a1 : G) (e e0 e1 z0 z1 : F) : Prop :=
  z0 • H = a0 + e0 • B ∧ z1 • H = a1 + e1 • (B - Gg) ∧ e0 + e1 = e

/-- the honest prover's transcript for bit `b`, blinding `s`, fresh `(eF, zF, k)` and challenge `e`. -/
def orProve (b : Bool) (s eF zF k e : F) : F × F × F × F :=
  if b then (eF, e - eF, zF, k + (e - eF) * s) else (e - eF, eF, k + (e - eF) * s, zF)

/-- the announcements of the honest prover. -/
def orAnn (Gg H B : G) (b : Bool) (eF zF k : F) : G × G :=
  if b then (zF • H - eF • B, k • H) else (k • H, zF • H - eF • (B - Gg))

/-- **RP-1 for the bit proofs**: the honest OR proof is accepted, for both bit values. -/
theorem or_complete (Gg H : G) (b : Bool) (s eF zF k e : F) :
    OrAccepts Gg H ((if b then (1 : F) else 0) • Gg + s • H)
      (orAnn Gg H ((if b then (1 : F) else 0) • Gg + s • H) b eF zF k).1
      (orAnn Gg H ((if b then (1 : F) else 0) • Gg + s • H) b eF zF k).2
      e (orProve b s eF zF k e).1 (orProve b s eF zF k e).2.1
      (orProve b s eF zF k e).2.2.1 (orProve b s eF zF k e).2.2.2 := by
  cases b <;> simp only [OrAccepts, orProve, orAnn, Bool.false_eq_true, if_false, if_true, zero_smul, zero_add,
    one_smul]
  · refine ⟨?_, ?_, by ring⟩
    · rw [add_smul, mul_smul]
    · simp [sub_smul, smul_sub, smul_smul]
  · refine ⟨?_, ?_, by ring⟩
    · simp [sub_smul, smul_sub, smul_add]
    · rw [add_smul, mul_smul]; simp

/-! ## RP-6: special honest-verifier zero knowledge of the OR proof, exactly.

For fixed statement and challenge `e`, the set of transcripts `(e0,e1,z0,z1)` with `e0 + e1 = e` is the support of
both the real prover and the simulator, and both are uniform on it: the real map
`(eF, zF, k) ↦ transcript` and the simulator map `(e0, z0, z1) ↦ (e0, e - e0, z0, z1)` are bijections of `F³`
onto that set.  The announcements are then the same function of the transcript (`or_complete`).
-/

/-- the set of accepted-shape transcripts for challenge `e`. -/
def OrSet (e : F) : Set (F × F × F × F) := {t | t.1 + t.2.1 = e}

theorem orProve_mem (b : Bool) (s eF zF k e : F) : orProve b s eF zF k e ∈ OrSet e := by
  cases b <;> simp [orProve, OrSet] <;> ring

theorem orProve_injective (b : Bool) (s e : F) :
    Function.Injective (fun x : F × F × F => orProve b s x.1 x.2.1 x.2.2 e) := by
  rintro ⟨eF, zF, k⟩ ⟨eF', zF', k'⟩ h
  cases b <;> simp only [orProve, Bool.false_eq_true, if_false, if_true, Prod.mk.injEq] at h
  · obtain ⟨h1, h2, h3, h4⟩ := h
    have : eF = eF' := h2
    subst this
    have : k = k' := by simpa using h3
    subst this
    simp [h4]
  · obtain ⟨h1, h2, h3, h4⟩ := h
    have : eF = eF' := h1
    subst this
    have : k = k' := by simpa using h4
    subst this
    simp [h3]

theorem orProve_surjective (b : Bool) (s e : F) :
    ∀ t ∈ OrSet e, ∃ x : F × F × F, orProve b s x.1 x.2.1 x.2.2 e = t := by
  rintro ⟨e0, e1, z0, z1⟩ ht
  simp only [OrSet, Set.mem_setOf_eq] at ht
  cases b
  · refine ⟨(e1, z1, z0 - e0 * s), ?_⟩
    simp only [orProve, Bool.false_eq_true, if_false]
    have : e - e1 = e0 := by rw [← ht]; ring
    simp [this]
  · refine ⟨(e0, z0, z1 - e1 * s), ?_⟩
    simp only [orProve, if_true]
    have : e - e0 = e1 := by rw [← ht]; ring
    simp [this]

/-- the simulator: from `(e0, z0, z1)` and the challenge `e`. -/
def orSim (e : F) (x : F × F × F) : F × F × F × F := (x.1, e - x.1, x.2.1, x.2.2)

theorem orSim_mem (e : F) (x : F × F × F) : orSim e x ∈ OrSet e := by
  simp [orSim, OrSet]

theorem orSim_injective (e : F) : Function.Injective (orSim e) := by
  rintro ⟨a, b, c⟩ ⟨a', b', c'⟩ h
  simp [orSim] at h
  obtain ⟨h1, h2, h3⟩ := h
  simp [h1, h2, h3]

theorem orSim_surjective (e : F) : ∀ t ∈ OrSet e, ∃ x : F × F × F, orSim e x = t := by
  rintro ⟨e0, e1, z0, z1⟩ ht
  simp only [OrSet, Set.mem_setOf_eq] at ht
  refine ⟨(e0, z0, z1), ?_⟩
  have : e - e0 = e1 := by rw [← ht]; ring
  simp [orSim, this]

/-- both the real prover and the simulator are bijections from `F³` onto `OrSet e`:
    hence, with uniform inputs, they have the same (uniform) distribution on `OrSet e`: **exact SHVZK**. -/
theorem or_shvzk (b : Bool) (s e : F) :
    ∃ φ : (F × F × F) ≃ OrSet e,
      (∀ x, (φ x : F × F × F × F) = orProve b s x.1 x.2.1 x.2.2 e) ∧
    ∃ ψ : (F × F × F) ≃ OrSet e, ∀ x, (ψ x : F × F × F × F) = orSim e x := by
  refine ⟨Equiv.ofBijective (fun x => ⟨orProve b s x.1 x.2.1 x.2.2 e, orProve_mem _ _ _ _ _ _⟩) ⟨?_, ?_⟩,
    fun x => rfl, Equiv.ofBijective (fun x => ⟨orSim e x, orSim_mem e x⟩) ⟨?_, ?_⟩, fun x => rfl⟩
  · intro x y h
    exact orProve_injective b s e (by simpa using congrArg Subtype.val h)
  · rintro ⟨t, ht⟩
    obtain ⟨x, hx⟩ := orProve_surjective b s e t ht
    exact ⟨x, Subtype.ext hx⟩
  · intro x y h
    exact orSim_injective e (by simpa using congrArg Subtype.val h)
  · rintro ⟨t, ht⟩
    obtain ⟨x, hx⟩ := orSim_surjective e t ht
    exact ⟨x, Subtype.ext hx⟩

/-! ## RP-1 for the aggregation step: `Σ 2^j B_j - V` is a multiple of `H` when the bits are honest. -/

theorem range_agg_complete (Gg H : G) (n : ℕ) (b : Fin n → Bool) (s : Fin n → F) (γ : F) :
    let B : Fin n → G := fun j => (if b j then (1 : F) else 0) • Gg + s j • H
    let v : F := ∑ j : Fin n, (2 : F) ^ (j : ℕ) * (if b j then 1 else 0)
    let V : G := v • Gg + γ • H
    (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j) - V = ((∑ j : Fin n, (2 : F) ^ (j : ℕ) * s j) - γ) • H := by
  intro B v V
  have : ∀ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j
      = (((2 : F) ^ (j : ℕ)) * (if b j then (1 : F) else 0)) • Gg + (((2 : F) ^ (j : ℕ)) * s j) • H := by
    intro j; simp only [B, smul_add, smul_smul]
  rw [Finset.sum_congr rfl (fun j _ => this j), Finset.sum_add_distrib, ← Finset.sum_smul, ← Finset.sum_smul]
  simp only [V, v, sub_smul]
  abel

/-! ## FR-1: FROST verification equation -/

/-- If every participant's response satisfies `z_i B = (D_i + ρ_i E_i) + (c λ_i) X_i`, with `X_i = s_i B`
    and the Lagrange combination `Σ λ_i X_i = X_g`, then the aggregate `(R, z)` with
    `R = Σ (D_i + ρ_i E_i)` and `z = Σ z_i` satisfies `z B = R + c X_g`. -/
theorem frost_verify {ι : Type*} (S : Finset ι) (B R : G) (z : ι → F) (Rn : ι → G) (X : ι → G) (lam : ι → F)
    (c : F) (Xg : G)
    (hz : ∀ i ∈ S, z i • B = Rn i + (c * lam i) • X i)
    (hX : ∑ i ∈ S, lam i • X i = Xg) (hR : R = ∑ i ∈ S, Rn i) :
    (∑ i ∈ S, z i) • B = R + c • Xg := by
  rw [Finset.sum_smul, Finset.sum_congr rfl hz, Finset.sum_add_distrib, hR, ← hX, Finset.smul_sum]
  congr 1
  apply Finset.sum_congr rfl
  intro i _
  rw [mul_smul]


/-! ## RP-6 for the Schnorr proof: real and simulated transcripts coincide exactly -/

/-- real prover: `(k) ↦ (a, z) = (k • H, k + e w)`; simulator: `(z) ↦ (z • H - e • D, z)` with `D = w • H`.
    Both are bijections from `F` onto the set `{(a, z) | z • H = a + e • D}` (when `H` is arbitrary), so with
    uniform inputs the distributions are equal. -/
theorem schnorr_shvzk (H : G) (w e : F) :
    let D : G := w • H
    let S : Set (G × F) := {t | t.2 • H = t.1 + e • D}
    (∃ φ : F ≃ S, ∀ k, (φ k : G × F) = (k • H, k + e * w)) ∧
    (∃ ψ : F ≃ S, ∀ z, (ψ z : G × F) = (z • H - e • D, z)) := by
  intro D S
  have hreal : ∀ k : F, (k • H, k + e * w) ∈ S := by
    intro k; simp only [S, D, Set.mem_setOf_eq, add_smul, mul_smul]
  have hsim : ∀ z : F, (z • H - e • D, z) ∈ S := by
    intro z; show z • H = (z • H - e • D) + e • D; abel
  refine ⟨⟨⟨fun k => ⟨_, hreal k⟩, fun t => t.1.2 - e * w, ?_, ?_⟩, fun k => rfl⟩,
    ⟨⟨fun z => ⟨_, hsim z⟩, fun t => t.1.2, ?_, ?_⟩, fun z => rfl⟩⟩
  · intro k; show (k + e * w) - e * w = k; ring
  · rintro ⟨⟨a, z⟩, hm⟩
    simp only [S, D, Set.mem_setOf_eq] at hm
    apply Subtype.ext
    simp only [Prod.mk.injEq]
    constructor
    · have : (z - e * w) • H = a := by
        rw [sub_smul, mul_smul, hm]; abel
      simpa using this
    · ring
  · intro z; rfl
  · rintro ⟨⟨a, z⟩, hm⟩
    simp only [S, D, Set.mem_setOf_eq] at hm
    apply Subtype.ext
    simp only [Prod.mk.injEq]
    exact ⟨by rw [hm]; abel, trivial⟩

/-! ## Range-gadget wrap (07-stark-fri.md section 5) -/

/-- a negative difference `-d` (`0 < d`, `d < p - 2^63`) has no 63-bit decomposition modulo `p`:
    if `-d ≡ v (mod p)` with `v < 2^63` then `p - d = v < 2^63`, contradicting `d < p - 2^63`. -/
theorem range_wrap (p d v : ℕ) (hd0 : 0 < d) (hdp : d + 2 ^ 63 < p) (hv : v < 2 ^ 63) :
    ¬ ((-(d : ZMod p)) = (v : ZMod p)) := by
  intro h
  have hp : 0 < p := by omega
  haveI : NeZero p := ⟨by omega⟩
  have h2 : ((d + v : ℕ) : ZMod p) = 0 := by
    push_cast; rw [← h]; ring
  rw [ZMod.natCast_eq_zero_iff] at h2
  obtain ⟨c, hc⟩ := h2
  have hpos : 0 < d + v := by omega
  have hc0 : c ≠ 0 := by rintro rfl; omega
  have : p ≤ d + v := by
    rw [hc]; exact Nat.le_mul_of_pos_right p (Nat.pos_of_ne_zero hc0)
  omega

/-- the quoted Goldilocks condition: with `r_raw <= 10^12` and `kappa <= 9 * 10^6`, `10^12 * kappa < p - 2^63`. -/
theorem goldilocks_kappa : (10 : ℕ) ^ 12 * (9 * 10 ^ 6) + 2 ^ 63 < 2 ^ 64 - 2 ^ 32 + 1 := by norm_num

end PcaMath.Alg
