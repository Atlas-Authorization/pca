import PcaIntent.Model

/-!
# Multi-principal composition (spec claim T5; brief item 6) and attenuation (T6; brief item 7)

`k` principals `i : ι` share the outcome space; each has its own intent model `M i` (own acceptability, and
possibly own harm and workload) and its own grant `G i`. The *joint grant* is the intersection
`meet G = ⋂ᵢ G i` (an outcome is admitted only if every principal's grant admits it — this is what PCA's
attenuation/intersection of caveats computes).

Results:
* `T5_each`  : `R_i(⋂ G) ≤ R_i(G_i)` for every `i` (spec T5);
* `T5_min`   : for *any* single risk measure `M`, `R(⋂ G) ≤ min_i R(G_i)`;
* `T5_joint` : under conjunctive aggregation of acceptability (`1 − a_J ≤ ∑ᵢ (1 − aᵢ)`, true for `a_J = minᵢ aᵢ`,
  see `agg_min`) with a shared harm and workload, `R_J(⋂ G) ≤ ∑ᵢ R_i(G_i)`; in particular the joint grant of
  individually sound grants is jointly sound (`T5_joint_sound`).
* `T6_attenuation` : the PCA link — any delegated sub-grant `G' ⊆ G` has `R(G') ≤ R(G)`, `B(G') ≥ B(G)`,
  `F(G') ≥ F(G)`; iterated along a delegation chain `G_k ⊆ … ⊆ G_0` the risk is monotone non-increasing.
-/

namespace PcaIntent

open Finset

variable {Ω ι : Type*} [Fintype Ω] [Fintype ι]

open Classical in
/-- The joint grant: outcomes admitted by every principal's grant. -/
noncomputable def meet (G : ι → Finset Ω) : Finset Ω := univ.filter fun ω => ∀ i, ω ∈ G i

lemma mem_meet {G : ι → Finset Ω} {ω : Ω} : ω ∈ meet G ↔ ∀ i, ω ∈ G i := by
  classical
  unfold meet; simp

lemma meet_subset (G : ι → Finset Ω) (i : ι) : meet G ⊆ G i := fun _ hω => mem_meet.1 hω i

/-- **T5.** The joint grant is no riskier, by each principal's own measure, than that principal's grant. -/
theorem T5_each (M : ι → Model Ω) (G : ι → Finset Ω) (i : ι) : (M i).R (meet G) ≤ (M i).R (G i) :=
  (M i).R_mono (meet_subset G i)

/-- **T5 (min form).** Under any one risk measure, the joint grant is at most the least risky grant. -/
theorem T5_min [Nonempty ι] (M : Model Ω) (G : ι → Finset Ω) :
    M.R (meet G) ≤ univ.inf' univ_nonempty (fun i => M.R (G i)) :=
  Finset.le_inf' _ _ fun i _ => M.R_mono (meet_subset G i)

/-- Conjunctive aggregation by `min` satisfies the aggregation hypothesis of `T5_joint`. -/
lemma agg_min [Nonempty ι] (a : ι → Ω → ℝ) (ha : ∀ i ω, a i ω ≤ 1) (ω : Ω) :
    1 - univ.inf' univ_nonempty (fun i => a i ω) ≤ ∑ i, (1 - a i ω) := by
  obtain ⟨i0, _, hi0⟩ := Finset.exists_mem_eq_inf' (univ_nonempty (α := ι)) (fun i => a i ω)
  rw [hi0]
  exact Finset.single_le_sum (f := fun i => 1 - a i ω) (fun i _ => sub_nonneg.2 (ha i ω))
    (Finset.mem_univ i0)

/-- **T5 (joint principal).** Shared harm and workload; joint acceptability aggregated conjunctively
(`1 − a_J ≤ ∑ᵢ (1 − aᵢ)`). Then `R_J(⋂ G) ≤ ∑ᵢ R_i(G_i)`. -/
theorem T5_joint (MJ : Model Ω) (M : ι → Model Ω) (G : ι → Finset Ω)
    (hh : ∀ i ω, (M i).h ω = MJ.h ω) (hμ : ∀ i ω, (M i).μ ω = MJ.μ ω)
    (hagg : ∀ ω, 1 - MJ.a ω ≤ ∑ i, (1 - (M i).a ω)) :
    MJ.R (meet G) ≤ ∑ i, (M i).R (G i) := by
  calc MJ.R (meet G) = ∑ ω ∈ meet G, (1 - MJ.a ω) * MJ.h ω * MJ.μ ω := rfl
    _ ≤ ∑ ω ∈ meet G, ∑ i, (1 - (M i).a ω) * (M i).h ω * (M i).μ ω := by
        refine Finset.sum_le_sum fun ω _ => ?_
        have hhm : 0 ≤ MJ.h ω * MJ.μ ω := mul_nonneg (MJ.h_nonneg ω) (MJ.μ_nonneg ω)
        have e : ∑ i, (1 - (M i).a ω) * (M i).h ω * (M i).μ ω =
            (∑ i, (1 - (M i).a ω)) * (MJ.h ω * MJ.μ ω) := by
          rw [Finset.sum_mul]
          refine Finset.sum_congr rfl fun i _ => ?_
          rw [hh i ω, hμ i ω]; ring
        rw [e, mul_assoc]
        exact mul_le_mul_of_nonneg_right (hagg ω) hhm
    _ = ∑ i, ∑ ω ∈ meet G, (1 - (M i).a ω) * (M i).h ω * (M i).μ ω := Finset.sum_comm
    _ ≤ ∑ i, (M i).R (G i) :=
        Finset.sum_le_sum fun i _ => (M i).R_mono (meet_subset G i)

/-- Individually sound grants compose into a jointly sound grant. -/
theorem T5_joint_sound (MJ : Model Ω) (M : ι → Model Ω) (G : ι → Finset Ω)
    (hh : ∀ i ω, (M i).h ω = MJ.h ω) (hμ : ∀ i ω, (M i).μ ω = MJ.μ ω)
    (hagg : ∀ ω, 1 - MJ.a ω ≤ ∑ i, (1 - (M i).a ω)) (hsound : ∀ i, (M i).R (G i) = 0) :
    MJ.R (meet G) = 0 := by
  have h := T5_joint MJ M G hh hμ hagg
  simp only [hsound, Finset.sum_const_zero] at h
  exact le_antisymm h (MJ.R_nonneg _)

/-- **T6 (attenuation compatibility).** A delegated sub-grant `G' ⊆ G` (PCA attenuation guarantees exactly
this inclusion of admitted outcomes) never raises misalignment risk, never lowers burden, never lowers fidelity. -/
theorem T6_attenuation (M : Model Ω) {G' G : Finset Ω} (hsub : G' ⊆ G) :
    M.R G' ≤ M.R G ∧ M.B G ≤ M.B G' ∧ M.F G ≤ M.F G' :=
  ⟨M.R_mono hsub, M.B_anti hsub, M.F_anti hsub⟩

/-- Along a delegation chain (each grant attenuates its parent) risk is monotone non-increasing. -/
theorem T6_chain (M : Model Ω) (chain : ℕ → Finset Ω) (hchain : ∀ k, chain (k + 1) ⊆ chain k) :
    ∀ k, M.R (chain k) ≤ M.R (chain 0)
  | 0 => le_rfl
  | k + 1 => le_trans (M.R_mono (hchain k)) (T6_chain M chain hchain k)

end PcaIntent
