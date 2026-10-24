import PcaIntent.Measure
import PcaProof.Attenuation

/-!
# Link to PCA's attenuation theorem (brief item 7)

`formal/pca-lean/PcaProof/Attenuation.lean` (Theorem 2) proves that PCA delegation only narrows effective
authority: `Eff (parent ++ ext) ⊆ Eff parent` (`eff_antitone_append`) and, along any append-only chain,
`Eff hop ⊆ Eff root` (`within_root`) and `Eff child ⊆ Eff parent` for consecutive hops (`chainMono_hops`).

Reading a hop's effective authority as a grant `G = {x : Eff hop x}` over PCA's own action universe, and
composing with the measure-space risk monotonicity `Meas.Rm_mono`, gives: **for every workload measure,
acceptability and harm, delegation never raises misalignment risk and never lowers burden** — the intent
metric is compatible with PCA's existing attenuation guarantee, by composition of the two machine-checked
results (no new assumption).
-/

namespace PcaIntent.Link

open MeasureTheory PcaProof.Attenuation PcaIntent.Meas
open scoped ENNReal

/-- Every set of actions is an event (the action universe is countable and discrete). -/
instance : MeasurableSpace Action := ⊤

/-- The grant a hop admits. -/
def grantOf (hop : List Caveat) : Set Action := {x | Eff hop x}

variable (μ : Measure Action) (a h : Action → ℝ≥0∞)

/-- One delegation step never raises risk. -/
theorem risk_antitone_append (parent ext : List Caveat) :
    Rm μ a h (grantOf (parent ++ ext)) ≤ Rm μ a h (grantOf parent) :=
  Rm_mono (by intro x hx; exact eff_antitone_append parent ext x hx)

/-- One delegation step never lowers burden. -/
theorem burden_monotone_append (parent ext : List Caveat) :
    Bm μ a (grantOf parent) ≤ Bm μ a (grantOf (parent ++ ext)) :=
  Bm_anti (by intro x hx; exact eff_antitone_append parent ext x hx)

/-- Every hop of any append-only delegation chain is at most as risky as the root grant. -/
theorem risk_within_root (root : List Caveat) (exts : List (List Caveat)) :
    ∀ hop ∈ hops root exts, Rm μ a h (grantOf hop) ≤ Rm μ a h (grantOf root) :=
  fun hop hmem => Rm_mono (by intro x hx; exact within_root root exts hop hmem x hx)

end PcaIntent.Link
