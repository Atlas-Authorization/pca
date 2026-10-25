import Mathlib

/-!
# Intent as a measurable object (spec §2.1–§2.3), finite outcome space

`docs/specs/pca-intent-layer.md` §2 fixes the outcome space Ω as a *finite* set (finitely many verbs, each with
finitely many dimensions over finite value sets). We therefore model Ω as a `Fintype` and every integral
`∫_G f dμ` as the finite sum `∑ ω ∈ G, f ω * μ ω`. (`PcaIntent.Measure` restates the risk and attenuation results
for an arbitrary measure space, so nothing here depends on finiteness except computability.)

* `a : Ω → [0,1]`  acceptability,
* `h : Ω → [0, Hmax]` harm,
* `μ : Ω → ℝ≥0`, `∑ μ = 1`  the workload distribution,
* a grant is a `Finset Ω`.

Metrics (spec §2.3):
* `R G = ∑_{ω∈G} (1 − a ω) · h ω · μ ω`      misalignment risk,
* `B G = ∑_{ω∉G} a ω · μ ω`                  over-restriction burden,
* `Rmax = R univ`,  `F G = 1 − R G / Rmax`  (`F = 1` when `Rmax = 0`)  intent fidelity.
-/

namespace PcaIntent

open Finset

/-- An intent model over a finite outcome space `Ω` (spec §2.1–2.2). -/
structure Model (Ω : Type*) [Fintype Ω] where
  a : Ω → ℝ
  h : Ω → ℝ
  μ : Ω → ℝ
  Hmax : ℝ
  a_nonneg : ∀ ω, 0 ≤ a ω
  a_le_one : ∀ ω, a ω ≤ 1
  h_nonneg : ∀ ω, 0 ≤ h ω
  h_le : ∀ ω, h ω ≤ Hmax
  μ_nonneg : ∀ ω, 0 ≤ μ ω
  μ_sum : ∑ ω, μ ω = 1

namespace Model

variable {Ω : Type*} [Fintype Ω] (M : Model Ω)

open Classical in
/-- Misalignment risk `R(G) = ∫_G (1 − a) h dμ`. -/
noncomputable def R (G : Finset Ω) : ℝ := ∑ ω ∈ G, (1 - M.a ω) * M.h ω * M.μ ω

open Classical in
/-- Over-restriction burden `B(G) = ∫_{Ω∖G} a dμ`. -/
noncomputable def B (G : Finset Ω) : ℝ := ∑ ω ∈ Gᶜ, M.a ω * M.μ ω

/-- `R_max = R(Ω)`, the risk of allowing everything. -/
noncomputable def Rmax : ℝ := M.R univ

/-- Intent fidelity `F(G) = 1 − R(G)/R_max`, with `F = 1` when `R_max = 0`. -/
noncomputable def F (G : Finset Ω) : ℝ := if M.Rmax = 0 then 1 else 1 - M.R G / M.Rmax

lemma Hmax_nonneg [Nonempty Ω] : 0 ≤ M.Hmax :=
  le_trans (M.h_nonneg (Classical.arbitrary Ω)) (M.h_le _)

lemma riskTerm_nonneg (ω : Ω) : 0 ≤ (1 - M.a ω) * M.h ω * M.μ ω :=
  mul_nonneg (mul_nonneg (sub_nonneg.2 (M.a_le_one ω)) (M.h_nonneg ω)) (M.μ_nonneg ω)

lemma burdenTerm_nonneg (ω : Ω) : 0 ≤ M.a ω * M.μ ω :=
  mul_nonneg (M.a_nonneg ω) (M.μ_nonneg ω)

lemma R_nonneg (G : Finset Ω) : 0 ≤ M.R G :=
  Finset.sum_nonneg fun ω _ => M.riskTerm_nonneg ω

lemma B_nonneg (G : Finset Ω) : 0 ≤ M.B G :=
  Finset.sum_nonneg fun ω _ => M.burdenTerm_nonneg ω

/-- **T6 (attenuation, risk).** A sub-grant is never riskier: `G' ⊆ G → R(G') ≤ R(G)`. -/
theorem R_mono {G' G : Finset Ω} (hsub : G' ⊆ G) : M.R G' ≤ M.R G :=
  Finset.sum_le_sum_of_subset_of_nonneg hsub fun ω _ _ => M.riskTerm_nonneg ω

/-- **T6 (attenuation, burden).** A sub-grant denies at least as much wanted work: `G' ⊆ G → B(G) ≤ B(G')`. -/
theorem B_anti {G' G : Finset Ω} (hsub : G' ⊆ G) : M.B G ≤ M.B G' := by
  classical
  unfold B
  refine Finset.sum_le_sum_of_subset_of_nonneg ?_ fun ω _ _ => M.burdenTerm_nonneg ω
  intro ω hω
  simp only [Finset.mem_compl] at hω ⊢
  exact fun h => hω (hsub h)

lemma R_le_Rmax (G : Finset Ω) : M.R G ≤ M.Rmax := M.R_mono (Finset.subset_univ G)

lemma Rmax_nonneg : 0 ≤ M.Rmax := M.R_nonneg _

/-- Fidelity lies in `[0,1]`. -/
theorem F_mem_Icc (G : Finset Ω) : 0 ≤ M.F G ∧ M.F G ≤ 1 := by
  unfold F
  split_ifs with h0
  · exact ⟨zero_le_one, le_rfl⟩
  · have hpos : 0 < M.Rmax := lt_of_le_of_ne M.Rmax_nonneg (Ne.symm h0)
    have h1 : M.R G / M.Rmax ≤ 1 := (div_le_one hpos).2 (M.R_le_Rmax G)
    have h2 : 0 ≤ M.R G / M.Rmax := div_nonneg (M.R_nonneg G) hpos.le
    constructor <;> linarith

/-- Attenuation never lowers fidelity: `G' ⊆ G → F(G) ≤ F(G')`. -/
theorem F_anti {G' G : Finset Ω} (hsub : G' ⊆ G) : M.F G ≤ M.F G' := by
  unfold F
  split_ifs with h0
  · exact le_rfl
  · have hpos : 0 < M.Rmax := lt_of_le_of_ne M.Rmax_nonneg (Ne.symm h0)
    have := div_le_div_of_nonneg_right (M.R_mono hsub) hpos.le
    linarith

/-- `R(G) = 0` whenever every admitted outcome is fully acceptable. -/
theorem R_eq_zero_of_accept {G : Finset Ω} (hG : ∀ ω ∈ G, M.a ω = 1) : M.R G = 0 :=
  Finset.sum_eq_zero fun ω hω => by simp [hG ω hω]

/-- Risk is at most `Hmax` times the unacceptable mass of the grant. -/
theorem R_le_Hmax_mul (G : Finset Ω) : M.R G ≤ M.Hmax * ∑ ω ∈ G, (1 - M.a ω) * M.μ ω := by
  unfold R
  rw [Finset.mul_sum]
  refine Finset.sum_le_sum fun ω _ => ?_
  have h1 : 0 ≤ 1 - M.a ω := sub_nonneg.2 (M.a_le_one ω)
  have := mul_le_mul_of_nonneg_left (M.h_le ω) (mul_nonneg h1 (M.μ_nonneg ω))
  nlinarith [M.μ_nonneg ω]

/-- `Hmax ≥ 0` (Ω is non-empty because `μ` has total mass one). -/
lemma Hmax_nonneg' : 0 ≤ M.Hmax := by
  by_cases hne : Nonempty Ω
  · haveI := hne; exact M.Hmax_nonneg
  · exfalso
    have : (∑ ω : Ω, M.μ ω) = 0 := by
      rw [Finset.univ_eq_empty_iff.2 (not_nonempty_iff.1 hne)]; simp
    rw [M.μ_sum] at this; exact one_ne_zero this

/-- The workload mass of any grant is at most one. -/
lemma mass_le_one (G : Finset Ω) : ∑ ω ∈ G, M.μ ω ≤ 1 := by
  rw [← M.μ_sum]
  exact Finset.sum_le_sum_of_subset_of_nonneg (Finset.subset_univ G) fun ω _ _ => M.μ_nonneg ω

/-- Expected harm of a grant is at most `Hmax · μ(G) ≤ Hmax`. -/
lemma harm_le (G : Finset Ω) : ∑ ω ∈ G, M.h ω * M.μ ω ≤ M.Hmax * ∑ ω ∈ G, M.μ ω := by
  rw [Finset.mul_sum]
  exact Finset.sum_le_sum fun ω _ => mul_le_mul_of_nonneg_right (M.h_le ω) (M.μ_nonneg ω)

/-- `R ≤ Hmax` (the workload is a probability distribution). -/
theorem R_le_Hmax (G : Finset Ω) : M.R G ≤ M.Hmax := by
  have hH : 0 ≤ M.Hmax := M.Hmax_nonneg'
  refine le_trans (M.R_le_Hmax_mul G) ?_
  have hs : ∑ ω ∈ G, (1 - M.a ω) * M.μ ω ≤ ∑ ω, M.μ ω := by
    calc ∑ ω ∈ G, (1 - M.a ω) * M.μ ω ≤ ∑ ω ∈ G, M.μ ω :=
          Finset.sum_le_sum fun ω _ => by nlinarith [M.a_nonneg ω, M.μ_nonneg ω]
      _ ≤ ∑ ω, M.μ ω :=
          Finset.sum_le_sum_of_subset_of_nonneg (Finset.subset_univ G) fun ω _ _ => M.μ_nonneg ω
  rw [M.μ_sum] at hs
  nlinarith

/-- Subadditivity of risk under grant union. -/
theorem R_union_le (G₁ G₂ : Finset Ω) [DecidableEq Ω] : M.R (G₁ ∪ G₂) ≤ M.R G₁ + M.R G₂ := by
  unfold R
  have hi := Finset.sum_union_inter (s₁ := G₁) (s₂ := G₂) (f := fun ω => (1 - M.a ω) * M.h ω * M.μ ω)
  have h0 : 0 ≤ ∑ ω ∈ G₁ ∩ G₂, (1 - M.a ω) * M.h ω * M.μ ω :=
    Finset.sum_nonneg fun ω _ => M.riskTerm_nonneg ω
  beta_reduce at hi
  linarith

end Model

end PcaIntent
