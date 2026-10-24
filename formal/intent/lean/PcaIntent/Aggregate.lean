import PcaIntent.Compose

/-!
# P8 (Q1, Q2, Q4): weighted-threshold aggregation with vetoers

Principals `i : ι` with grants `G i`, integer weights `w i`, threshold `T`, vetoer set `V`:
`agg G w T V = {ω : ∑_{i : ω ∈ G i} w i ≥ T ∧ ∀ v ∈ V, ω ∈ G v}`.

* Q1: raising the threshold shrinks the grant; with unit weights, threshold `n` is the intersection and
  threshold `1` is the union.
* Q2: a vetoer, or any principal whose weight cannot be outvoted (`W < T + w v`), gets `G ⊆ G v`, so
  `R_v(G) ≤ R_v(G_v)` (a T6 instance).
* Q4 (negative): for a non-vetoer only `R_i(G) ≤ R_i(G_i) + R_i(G ∖ G_i)` holds, and a two-principal
  quorum-1 counterexample has `R_i(G) > R_i(G_i)`.

Q3 (the dynamic programme of `jointAcceptance` equals the brute-force probability) is a statement about the
TypeScript code and is checked there by an exhaustive property test; it is not formalised here.
-/

namespace PcaIntent

open Finset

variable {Ω ι : Type*} [Fintype Ω] [Fintype ι]

open Classical in
/-- Weighted-threshold aggregation with vetoers. -/
noncomputable def agg (G : ι → Finset Ω) (w : ι → ℕ) (T : ℕ) (V : Finset ι) : Finset Ω :=
  univ.filter fun ω => T ≤ ∑ i ∈ univ.filter (fun i => ω ∈ G i), w i ∧ ∀ v ∈ V, ω ∈ G v

open Classical in
lemma mem_agg {G : ι → Finset Ω} {w : ι → ℕ} {T : ℕ} {V : Finset ι} {ω : Ω} :
    ω ∈ agg G w T V ↔ T ≤ ∑ i ∈ univ.filter (fun i => ω ∈ G i), w i ∧ ∀ v ∈ V, ω ∈ G v := by
  unfold agg
  rw [Finset.mem_filter]
  exact ⟨fun h => h.2, fun h => ⟨Finset.mem_univ ω, h⟩⟩

/-- **Q1 (monotone in the threshold).** `T ≤ T' → G_{T'} ⊆ G_T`; in particular `G_{k+1} ⊆ G_k`. -/
theorem Q1_mono (G : ι → Finset Ω) (w : ι → ℕ) (V : Finset ι) {T T' : ℕ} (hT : T ≤ T') :
    agg G w T' V ⊆ agg G w T V := by
  intro ω hω
  rw [mem_agg] at hω ⊢
  exact ⟨le_trans hT hω.1, hω.2⟩

/-- **Q1 (unanimity).** Unit weights, threshold `n = |ι|`: the intersection. -/
theorem Q1_all (G : ι → Finset Ω) (ω : Ω) :
    ω ∈ agg G (fun _ => 1) (Fintype.card ι) ∅ ↔ ∀ i, ω ∈ G i := by
  classical
  rw [mem_agg]
  simp only [Finset.sum_const, smul_eq_mul, mul_one]
  constructor
  · rintro ⟨h, -⟩ i
    have hsub : univ.filter (fun i => ω ∈ G i) ⊆ univ := Finset.filter_subset _ _
    have heq : univ.filter (fun i => ω ∈ G i) = univ :=
      Finset.eq_of_subset_of_card_le hsub (by rw [Finset.card_univ]; exact h)
    have hi : i ∈ univ.filter (fun i => ω ∈ G i) := by rw [heq]; exact Finset.mem_univ i
    exact (Finset.mem_filter.1 hi).2
  · intro h
    refine ⟨?_, fun v hv => absurd hv (Finset.notMem_empty v)⟩
    have heq : univ.filter (fun i => ω ∈ G i) = univ := Finset.filter_true_of_mem fun i _ => h i
    rw [heq, Finset.card_univ]

/-- **Q1 (any-one).** Unit weights, threshold `1`: the union. -/
theorem Q1_any (G : ι → Finset Ω) (ω : Ω) :
    ω ∈ agg G (fun _ => 1) 1 ∅ ↔ ∃ i, ω ∈ G i := by
  classical
  rw [mem_agg]
  simp only [Finset.sum_const, smul_eq_mul, mul_one]
  constructor
  · rintro ⟨h, -⟩
    obtain ⟨i, hi⟩ := Finset.card_pos.1 h
    exact ⟨i, (Finset.mem_filter.1 hi).2⟩
  · rintro ⟨i, hi⟩
    refine ⟨Finset.card_pos.2 ⟨i, Finset.mem_filter.2 ⟨Finset.mem_univ i, hi⟩⟩, ?_⟩
    intro v hv; exact absurd hv (Finset.notMem_empty v)

/-- **Q2 (vetoer).** A vetoer's grant contains the joint grant, so its risk is no larger. -/
theorem Q2_veto (M : Model Ω) (G : ι → Finset Ω) (w : ι → ℕ) (T : ℕ) {V : Finset ι} {v : ι}
    (hv : v ∈ V) : agg G w T V ⊆ G v ∧ M.R (agg G w T V) ≤ M.R (G v) := by
  have hsub : agg G w T V ⊆ G v := fun ω hω => (mem_agg.1 hω).2 v hv
  exact ⟨hsub, M.R_mono hsub⟩

/-- **Q2 (weight that cannot be outvoted).** If `W < T + w v` (with `W = ∑ w`), then `G ⊆ G v`. -/
theorem Q2_weight (M : Model Ω) (G : ι → Finset Ω) (w : ι → ℕ) (T : ℕ) (V : Finset ι) (v : ι)
    (hT : ∑ i, w i < T + w v) : agg G w T V ⊆ G v ∧ M.R (agg G w T V) ≤ M.R (G v) := by
  classical
  have hsub : agg G w T V ⊆ G v := by
    intro ω hω
    by_contra hnot
    have h1 := (mem_agg.1 hω).1
    have hfs : univ.filter (fun i => ω ∈ G i) ⊆ univ.erase v := by
      intro i hi
      rw [Finset.mem_erase]
      refine ⟨fun he => hnot ?_, Finset.mem_univ i⟩
      rw [← he]; exact (Finset.mem_filter.1 hi).2
    have h2 : ∑ i ∈ univ.filter (fun i => ω ∈ G i), w i ≤ ∑ i ∈ univ.erase v, w i :=
      Finset.sum_le_sum_of_subset_of_nonneg hfs fun _ _ _ => Nat.zero_le _
    have h3 := Finset.add_sum_erase univ w (Finset.mem_univ v)
    omega
  exact ⟨hsub, M.R_mono hsub⟩

/-- **Q4 (the only general bound for a non-vetoer).** `R_i(G) ≤ R_i(G_i) + R_i(G ∖ G_i)`. -/
theorem Q4_bound [DecidableEq Ω] (M : Model Ω) (G Gi : Finset Ω) : M.R G ≤ M.R Gi + M.R (G \ Gi) := by
  have hsub : G ⊆ Gi ∪ (G \ Gi) := by
    intro ω hω
    by_cases h : ω ∈ Gi
    · exact Finset.mem_union_left _ h
    · exact Finset.mem_union_right _ (Finset.mem_sdiff.2 ⟨hω, h⟩)
  exact le_trans (M.R_mono hsub) (M.R_union_le Gi (G \ Gi))

/-- Principal 0 accepts only `true`; harm 1; uniform workload. -/
noncomputable def Q4model : Model Bool where
  a := fun b => if b then 1 else 0
  h := fun _ => 1
  μ := fun _ => 1 / 2
  Hmax := 1
  a_nonneg := fun b => by cases b <;> simp
  a_le_one := fun b => by cases b <;> simp
  h_nonneg := fun _ => zero_le_one
  h_le := fun _ => le_rfl
  μ_nonneg := fun _ => by norm_num
  μ_sum := by rw [Fintype.sum_bool]; norm_num

/-- **Q4 (negative).** Two principals, quorum 1 (`G = G_0 ∪ G_1`): principal 0's risk strictly increases. -/
theorem Q4_counterexample :
    let G : Fin 2 → Finset Bool := fun i => if i = 0 then {true} else {false}
    Q4model.R (G 0) < Q4model.R (agg G (fun _ => 1) 1 ∅) := by
  intro G
  have hall : agg G (fun _ => 1) 1 ∅ = univ := by
    ext b
    rw [Q1_any]
    simp only [Finset.mem_univ, iff_true]
    cases b
    · exact ⟨1, by simp [G]⟩
    · exact ⟨0, by simp [G]⟩
  rw [hall]
  have h0 : G 0 = {true} := by simp [G]
  rw [h0]
  norm_num [Model.R, Q4model, Fintype.sum_bool]

end PcaIntent
