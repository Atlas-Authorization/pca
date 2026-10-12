import Mathlib
import PcaMath.OtLin

/-!
# OT extension rows: distinctness of the hashed inputs (R4-12, part 1)

Idealised PRG: the receiver's rows `t_j` (transposed columns of fresh PRG output, one stream bit per slot) are
independent uniform blocks, and the sender's selector `s` is uniform and independent of them.  The receiver's
choice bits `r` are an ARBITRARY function of all the rows `t` (a malicious receiver knows them), but not of `s`.
The sender hashes the two rows `q_j = t_j + r_j s` and `q_j + s`, i.e. `z(j, beta) = t_j + [r_j /= beta] s`.

`rows_distinct`: the probability that two of the `2Q` sender inputs coincide is at most `(Q (Q-1) + 1) / 2^128`
(`N = |D|`); it implies the bound `(2Q)^2 / 2^128`.
`receiver_input`: the receiver's own hashed input `t_j` equals the sender's input `z(j, r_j)` (always) and differs
from `z(j, 1 - r_j)` unless `s = 0`.
-/

open Finset

namespace PcaMath.OtRows

variable {D : Type} [AddCommGroup D] [Fintype D] [DecidableEq D]
variable {ι : Type} [Fintype ι] [DecidableEq ι]

/-- the sender's hashed input for slot `j` and branch `beta` -/
def zin (r : (ι → D) → ι → Bool) (ω : (ι → D) × D) (a : ι × Bool) : D :=
  ω.1 a.1 + (if (r ω.1 a.1 != a.2) = true then ω.2 else 0)

theorem receiver_input (r : (ι → D) → ι → Bool) (ω : (ι → D) × D) (j : ι) :
    zin r ω (j, r ω.1 j) = ω.1 j ∧ (ω.2 ≠ 0 → zin r ω (j, !(r ω.1 j)) ≠ ω.1 j) := by
  constructor
  · simp [zin]
  · intro hs
    simp [zin, hs]

theorem two_mul_choose_two' (n : ℕ) : 2 * n.choose 2 = n * (n - 1) := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [Nat.choose_succ_succ, Nat.choose_one_right, mul_add, ih]
    cases n <;> simp <;> ring_nf <;> omega

theorem rows_distinct (h2 : ∀ x : D, x + x = 0) (r : (ι → D) → ι → Bool) :
    (Finset.univ.filter (fun ω : (ι → D) × D => ∃ a b : ι × Bool, a ≠ b ∧ zin r ω a = zin r ω b)).card
      ≤ (Fintype.card ι * (Fintype.card ι - 1) + 1) * Fintype.card D ^ (Fintype.card ι) := by
  classical
  set N := Fintype.card D with hN
  set Q := Fintype.card ι with hQ
  have hNpos : 0 < N := Fintype.card_pos
  -- the three kinds of sets
  let S0 : Finset ((ι → D) × D) := Finset.univ.filter (fun ω => ω.2 = 0)
  let S12 : Finset ι → Finset ((ι → D) × D) := fun s => Finset.univ.filter (fun ω =>
    ∃ j ∈ s, ∃ j' ∈ s, j ≠ j' ∧ (ω.1 j = ω.1 j' ∨ ω.2 = ω.1 j + ω.1 j'))
  have hS0 : S0.card ≤ N ^ Q := by
    have : S0 = (Finset.univ : Finset (ι → D)) ×ˢ ({0} : Finset D) := by
      ext ω; simp only [S0, Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_product, Finset.mem_singleton]
    rw [this, Finset.card_product]; simp [Fintype.card_fun, hN, hQ]
  have hS12 : ∀ s ∈ (Finset.univ : Finset ι).powersetCard 2, (S12 s).card ≤ 2 * N ^ Q := by
    intro s hs
    rw [Finset.mem_powersetCard] at hs
    obtain ⟨j, j', hjj, rfl⟩ := Finset.card_eq_two.mp hs.2
    have hsub : S12 {j, j'} ⊆
        (Finset.univ.filter (fun t : ι → D => t j = t j')) ×ˢ (Finset.univ : Finset D) ∪
        (Finset.univ.filter (fun ω : (ι → D) × D => ω.2 = ω.1 j + ω.1 j')) := by
      intro ω hω
      simp only [S12, Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_insert,
        Finset.mem_singleton] at hω
      obtain ⟨a, ha, b, hb, hab, h⟩ := hω
      simp only [Finset.mem_union, Finset.mem_product, Finset.mem_filter, Finset.mem_univ, true_and, and_true]
      rcases ha with rfl | rfl <;> rcases hb with rfl | rfl
      · exact absurd rfl hab
      · rcases h with h | h
        · left; exact h
        · right; exact h
      · rcases h with h | h
        · left; exact h.symm
        · right; rw [h, add_comm]
      · exact absurd rfl hab
    refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
    have h1 : ((Finset.univ.filter (fun t : ι → D => t j = t j')) ×ˢ (Finset.univ : Finset D)).card ≤ N ^ Q := by
      rw [Finset.card_product]
      have := OtLin.card_event_le (Var := ι) (D := D) (some j, 0) (some j', 0) (by simpa using hjj)
      have e : (Finset.univ.filter (fun σ : ι → D => (OtLin.Term.eval σ (some j, 0)) = OtLin.Term.eval σ (some j', 0)))
          = Finset.univ.filter (fun t : ι → D => t j = t j') := by
        apply Finset.filter_congr; intro σ _; simp [OtLin.Term.eval]
      rw [e] at this
      calc _ ≤ N ^ (Q - 1) * Fintype.card D := Nat.mul_le_mul_right _ this
        _ = N ^ Q := by
          have hQ1 : 1 ≤ Q := Fintype.card_pos_iff.mpr ⟨j⟩
          rw [← pow_succ]; congr 1; omega
    have h2' : (Finset.univ.filter (fun ω : (ι → D) × D => ω.2 = ω.1 j + ω.1 j')).card ≤ N ^ Q := by
      have := Finset.card_le_card_of_injOn (s := Finset.univ.filter (fun ω : (ι → D) × D => ω.2 = ω.1 j + ω.1 j'))
        (t := (Finset.univ : Finset (ι → D))) (fun ω => ω.1) (fun _ _ => Finset.mem_coe.mpr (Finset.mem_univ _))
        (by
          intro ω hω ω' hω' h
          simp only [Finset.coe_filter, Finset.mem_univ, true_and, Set.mem_setOf_eq] at hω hω'
          exact Prod.ext h (by rw [hω, hω']; simp only at h; rw [h]))
      simpa [Fintype.card_fun] using this
    omega
  -- covering
  have hcover : (Finset.univ.filter (fun ω : (ι → D) × D => ∃ a b : ι × Bool, a ≠ b ∧ zin r ω a = zin r ω b)) ⊆
      S0 ∪ ((Finset.univ : Finset ι).powersetCard 2).biUnion S12 := by
    intro ω hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω
    obtain ⟨⟨j, β⟩, ⟨j', β'⟩, hne, h⟩ := hω
    simp only [zin] at h
    by_cases hjj : j = j'
    · subst hjj
      have hβ : β ≠ β' := fun e => hne (by rw [e])
      rw [Finset.mem_union]; left
      simp only [S0, Finset.mem_filter, Finset.mem_univ, true_and]
      by_contra hs
      cases hr : r ω.1 j <;> cases β <;> cases β' <;> simp_all [hr]
    · rw [Finset.mem_union]; right
      simp only [Finset.mem_biUnion, Finset.mem_powersetCard, Finset.subset_univ, true_and]
      refine ⟨{j, j'}, Finset.card_pair hjj, ?_⟩
      simp only [S12, Finset.mem_filter, Finset.mem_univ, true_and]
      refine ⟨j, by simp, j', by simp, hjj, ?_⟩
      by_cases c1 : (r ω.1 j != β) = true <;> by_cases c2 : (r ω.1 j' != β') = true
      · rw [if_pos c1, if_pos c2] at h
        left; exact add_right_cancel h
      · rw [if_pos c1, if_neg c2, add_zero] at h
        right
        calc ω.2 = (ω.1 j + ω.1 j) + ω.2 := by rw [h2, zero_add]
          _ = ω.1 j + (ω.1 j + ω.2) := add_assoc _ _ _
          _ = ω.1 j + ω.1 j' := by rw [h]
      · rw [if_neg c1, if_pos c2, add_zero] at h
        right
        calc ω.2 = ω.2 + (ω.1 j' + ω.1 j') := by rw [h2, add_zero]
          _ = (ω.1 j' + ω.2) + ω.1 j' := by abel
          _ = ω.1 j + ω.1 j' := by rw [← h]
      · rw [if_neg c1, if_neg c2, add_zero, add_zero] at h
        left; exact h
  have hcard := Finset.card_le_card hcover
  have hcard2 := Finset.card_union_le S0 (((Finset.univ : Finset ι).powersetCard 2).biUnion S12)
  have hcard3 := Finset.card_biUnion_le (s := (Finset.univ : Finset ι).powersetCard 2) (t := S12)
  have hsum : (∑ s ∈ (Finset.univ : Finset ι).powersetCard 2, (S12 s).card) ≤
      ((Finset.univ : Finset ι).powersetCard 2).card * (2 * N ^ Q) :=
    Finset.sum_le_card_nsmul _ _ _ hS12
  rw [Finset.card_powersetCard, Finset.card_univ] at hsum
  have hch := two_mul_choose_two' Q
  calc _ ≤ S0.card + (((Finset.univ : Finset ι).powersetCard 2).biUnion S12).card := le_trans hcard hcard2
    _ ≤ N ^ Q + Q.choose 2 * (2 * N ^ Q) := Nat.add_le_add hS0 (le_trans hcard3 hsum)
    _ = (Q * (Q - 1) + 1) * N ^ Q := by rw [← hch]; ring

end PcaMath.OtRows
