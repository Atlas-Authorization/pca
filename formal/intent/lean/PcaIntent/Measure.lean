import Mathlib

/-!
# The risk metrics on an arbitrary measure space

The spec's Ω is finite, but nothing in the risk/attenuation/composition results needs that. Here `Ω` is any
measurable space, `μ` any measure, and acceptability `a`, harm `h` are `ℝ≥0∞`-valued (`a ≤ 1` where used).

* `Rm G = ∫⁻_G (1 − a) · h dμ`, `Bm G = ∫⁻_{Gᶜ} a dμ`.
* `Rm_mono` / `Bm_anti`        : T6 (attenuation) for arbitrary sets `G' ⊆ G` (no measurability needed);
* `Rm_iInter_le`, `Rm_iInter_le_iInf` : T5 for any (possibly infinite) family of principals;
* `Rm_eq_zero_of_accept`        : T1's last step — a measurable grant on which `a = 1` has zero risk.
-/

namespace PcaIntent.Meas

open MeasureTheory
open scoped ENNReal

variable {Ω : Type*} [MeasurableSpace Ω] (μ : Measure Ω) (a h : Ω → ℝ≥0∞)

/-- Misalignment risk on a measure space. -/
noncomputable def Rm (G : Set Ω) : ℝ≥0∞ := ∫⁻ ω in G, (1 - a ω) * h ω ∂μ

/-- Over-restriction burden on a measure space. -/
noncomputable def Bm (G : Set Ω) : ℝ≥0∞ := ∫⁻ ω in Gᶜ, a ω ∂μ

variable {μ a h}

/-- **T6 (measure form).** `G' ⊆ G → R(G') ≤ R(G)`. -/
theorem Rm_mono {G' G : Set Ω} (hsub : G' ⊆ G) : Rm μ a h G' ≤ Rm μ a h G :=
  lintegral_mono_set hsub

/-- **T6 (measure form, burden).** `G' ⊆ G → B(G) ≤ B(G')`. -/
theorem Bm_anti {G' G : Set Ω} (hsub : G' ⊆ G) : Bm μ a G ≤ Bm μ a G' :=
  lintegral_mono_set (Set.compl_subset_compl.2 hsub)

/-- **T5 (measure form).** The intersection of any family of grants is no riskier than each member. -/
theorem Rm_iInter_le {ι : Sort*} (G : ι → Set Ω) (i : ι) : Rm μ a h (⋂ j, G j) ≤ Rm μ a h (G i) :=
  Rm_mono (Set.iInter_subset G i)

/-- **T5 (measure form, min).** `R(⋂ G) ≤ ⨅ᵢ R(Gᵢ)`. -/
theorem Rm_iInter_le_iInf {ι : Sort*} (G : ι → Set Ω) : Rm μ a h (⋂ j, G j) ≤ ⨅ i, Rm μ a h (G i) :=
  le_iInf fun i => Rm_iInter_le G i

/-- A measurable grant on which every outcome is fully acceptable has zero risk. -/
theorem Rm_eq_zero_of_accept {G : Set Ω} (hG : MeasurableSet G) (hacc : ∀ ω ∈ G, a ω = 1) :
    Rm μ a h G = 0 := by
  unfold Rm
  have hae : (fun ω => (1 - a ω) * h ω) =ᵐ[μ.restrict G] fun _ => 0 := by
    filter_upwards [ae_restrict_mem hG] with ω hω
    simp [hacc ω hω]
  rw [lintegral_congr_ae hae, lintegral_zero]

end PcaIntent.Meas
