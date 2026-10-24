import PcaIntent.Refine
import PcaIntent.Ramp

/-!
# v2: closed world, layers, facts, classifiers, frames, profiles, optimality, provenance
(claims T12, T18, T19, T20, T21, T24, T25, T26)
-/

namespace PcaIntent

open Finset

variable {Ω : Type*} [Fintype Ω]

/-! ## T12 (Schema): closed world -/

/-- **T12.** Actions are classified into `Option Ω` (`none` is the fail-closed cell ⊠). If no grant contains ⊠,
every admitted action lies in a schema cell, and that cell is one the grant constrains. -/
theorem T12_closed_world {Act : Type*} (classify : Act → Option Ω) (G : Finset (Option Ω))
    (hbox : none ∉ G) (a : Act) (hadm : classify a ∈ G) : ∃ ω, classify a = some ω ∧ some ω ∈ G := by
  cases h : classify a with
  | none => rw [h] at hadm; exact absurd hadm hbox
  | some ω => exact ⟨ω, rfl, h ▸ hadm⟩

/-! ## T18 (Layers): ceilings cannot be bypassed -/

/-- The effective grant: org ∩ site ∩ standing ∩ (task ∪ deltas), minus vetoes. -/
def effGrant [DecidableEq Ω] (org site std task vetoed : Finset Ω) : Finset Ω :=
  (org ∩ site ∩ std ∩ task) \ vetoed

/-- **T18.** The effective grant is inside every ceiling, for every answer sequence (the task part is
arbitrary). -/
theorem T18_no_bypass [DecidableEq Ω] (org site std task vetoed : Finset Ω) :
    effGrant org site std task vetoed ⊆ org ∧ effGrant org site std task vetoed ⊆ site ∧
      effGrant org site std task vetoed ⊆ std := by
  unfold effGrant
  refine ⟨fun ω h => ?_, fun ω h => ?_, fun ω h => ?_⟩ <;>
    (simp only [Finset.mem_sdiff, Finset.mem_inter] at h; tauto)

/-- **T18 (per-owner risk).** Each layer owner's risk of the effective grant is at most that of its own layer. -/
theorem T18_owner_risk [DecidableEq Ω] (M : Model Ω) (org site std task vetoed : Finset Ω) :
    M.R (effGrant org site std task vetoed) ≤ M.R org ∧ M.R (effGrant org site std task vetoed) ≤ M.R site ∧
      M.R (effGrant org site std task vetoed) ≤ M.R std := by
  obtain ⟨h1, h2, h3⟩ := T18_no_bypass org site std task vetoed
  exact ⟨M.R_mono h1, M.R_mono h2, M.R_mono h3⟩

/-! ## T24 (Profile): safe import -/

/-- **T24.** Importing deny rules as a layer, or negative observations as vetoes, is an attenuation: risk never
rises. Positive imports add only cells of the explicit standing-permission layer. -/
theorem T24_deny_import [DecidableEq Ω] (M : Model Ω) (G deny vetoes perm : Finset Ω) :
    M.R ((G ∩ deny) \ vetoes) ≤ M.R G ∧ (G ∪ perm) \ G ⊆ perm := by
  refine ⟨M.R_mono ?_, ?_⟩
  · intro ω h
    exact (Finset.mem_inter.1 (Finset.mem_sdiff.1 h).1).1
  · intro ω h
    rcases Finset.mem_union.1 (Finset.mem_sdiff.1 h).1 with hg | hp
    · exact absurd hg (Finset.mem_sdiff.1 h).2
    · exact hp

/-! ## T19 (Facts) -/

/-- **T19 (median bracket).** If at least `f + 1` reported values are `≤ m` and at least `f + 1` are `≥ m`
(true of the median of `n ≥ 2f + 1` values), and at most `f` reporters are faulty, then some honest value is
`≤ m` and some honest value is `≥ m`: the median lies between the smallest and largest honest values. -/
theorem T19_median_bracket {n f : ℕ} (vals : Fin n → ℝ) (faulty : Finset (Fin n)) (hf : faulty.card ≤ f)
    (m : ℝ) (hlo : f + 1 ≤ (univ.filter fun i => vals i ≤ m).card)
    (hhi : f + 1 ≤ (univ.filter fun i => m ≤ vals i).card) :
    (∃ i, i ∉ faulty ∧ vals i ≤ m) ∧ (∃ j, j ∉ faulty ∧ m ≤ vals j) := by
  have key : ∀ s : Finset (Fin n), f + 1 ≤ s.card → ∃ i ∈ s, i ∉ faulty := by
    intro s hs
    by_contra hall
    push_neg at hall
    have := Finset.card_le_card (show s ⊆ faulty from hall)
    omega
  obtain ⟨i, hi, hif⟩ := key _ hlo
  obtain ⟨j, hj, hjf⟩ := key _ hhi
  exact ⟨⟨i, hif, (Finset.mem_filter.1 hi).2⟩, ⟨j, hjf, (Finset.mem_filter.1 hj).2⟩⟩

/-- **T19 (freshness).** A fact observed at `t_obs` (true observation time within skew `s` of `t_obs`) admitted at
`t` with `t − t_obs ≤ Δ` reflects the world at a time in `[t − Δ − s, t]`. -/
theorem T19_fresh {t tobs τo Δ s : ℤ} (hfresh : t - tobs ≤ Δ) (hskew : tobs - s ≤ τo) (hle : τo ≤ t) :
    t - Δ - s ≤ τo ∧ τo ≤ t := ⟨by linarith, hle⟩

/-! ## T20 (Classifier) -/

section Classifier

variable {Xc L : Type*} [Fintype Xc] [Fintype L]

open Classical in
/-- The true-coordinate risk of a grant over `(x, ℓ̂)`: average over the true `(x, ℓ)` and the classifier's
output `ℓ̂ ∼ Γ(· | ℓ)`. -/
noncomputable def Rkappa (μ a h : Xc → L → ℝ) (Γ : L → L → ℝ) (G : Finset (Xc × L)) : ℝ :=
  ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * h x ℓ * ∑ ℓh, Γ ℓh ℓ * (if (x, ℓh) ∈ G then 1 else 0)

open Classical in
/-- `Γ(A_G(x) | ℓ)`: the probability that the classifier puts `x` into the grant's labels. -/
noncomputable def GammaSet (Γ : L → L → ℝ) (G : Finset (Xc × L)) (x : Xc) (ℓ : L) : ℝ :=
  ∑ ℓh ∈ univ.filter (fun ℓh => (x, ℓh) ∈ G), Γ ℓh ℓ

/-- **T20 (decomposition).** `R_κ(G) = ∑ μ (1 − a) h Γ(A_G(x) | ℓ)`. -/
theorem T20_decomp [DecidableEq Xc] [DecidableEq L] (μ a h : Xc → L → ℝ) (Γ : L → L → ℝ)
    (G : Finset (Xc × L)) :
    Rkappa μ a h Γ G = ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * h x ℓ * GammaSet Γ G x ℓ := by
  unfold Rkappa GammaSet
  refine Finset.sum_congr rfl fun x _ => Finset.sum_congr rfl fun ℓ _ => ?_
  congr 1
  rw [Finset.sum_filter]
  refine Finset.sum_congr rfl fun ℓh _ => ?_
  split_ifs <;> simp

/-- **T20 (bound).** With `0 ≤ a ≤ 1`, `0 ≤ h ≤ H_max`, `μ, Γ ≥ 0`:
`R_κ(G) ≤ H_max · ∑ μ (1 − a) Γ(A_G(x) | ℓ)`; for 0/1 acceptability the sum runs over the `a = 0` points, as in
the spec (the bound holds whether or not `G` is label-sound). -/
theorem T20_label_sound_bound [DecidableEq Xc] [DecidableEq L] (μ a h : Xc → L → ℝ) (Γ : L → L → ℝ)
    (G : Finset (Xc × L)) (Hmax : ℝ) (hμ : ∀ x ℓ, 0 ≤ μ x ℓ) (ha : ∀ x ℓ, a x ℓ ≤ 1)
    (hh : ∀ x ℓ, h x ℓ ≤ Hmax) (hΓ : ∀ ℓh ℓ, 0 ≤ Γ ℓh ℓ) :
    Rkappa μ a h Γ G ≤ Hmax * ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * GammaSet Γ G x ℓ := by
  rw [T20_decomp, Finset.mul_sum]
  refine Finset.sum_le_sum fun x _ => ?_
  rw [Finset.mul_sum]
  refine Finset.sum_le_sum fun ℓ _ => ?_
  have hg : 0 ≤ GammaSet Γ G x ℓ := Finset.sum_nonneg fun ℓh _ => hΓ ℓh ℓ
  have hc : 0 ≤ μ x ℓ * (1 - a x ℓ) * GammaSet Γ G x ℓ :=
    mul_nonneg (mul_nonneg (hμ x ℓ) (sub_nonneg.2 (ha x ℓ))) hg
  have := mul_le_mul_of_nonneg_left (hh x ℓ) hc
  nlinarith

end Classifier

/-! ## T21 (Frame) -/

section Frame

variable {Var Val : Type*} [Fintype Var] [DecidableEq Var] [DecidableEq Val]

/-- Out-of-frame changes: variables outside the write set that changed and are not attributed to another actor. -/
def frameViolations (pre post : Var → Val) (W : Finset Var) (attr : Var → Bool) : Finset Var :=
  univ.filter fun v => v ∉ W ∧ pre v ≠ post v ∧ attr v = false

/-- **T21.** With an honest effect oracle (`pre`, `post` are the true states), every unattributed change outside
the write set is reported; reporting vetoes the action's cell at that step, and the veto is permanent. -/
theorem T21_frame_detect [DecidableEq Ω] (pre post : Var → Val) (W : Finset Var) (attr : Var → Bool) (v : Var)
    (hv : v ∉ W) (hch : pre v ≠ post v) (hattr : attr v = false) (cell : Ω) (new : ℕ → Finset Ω) (t : ℕ)
    (hveto : frameViolations pre post W attr ≠ ∅ → cell ∈ new t) (base : ℕ → Finset Ω) :
    v ∈ frameViolations pre post W attr ∧ ∀ t' ≥ t + 1, cell ∉ grantAt base new t' := by
  have hmem : v ∈ frameViolations pre post W attr := by
    unfold frameViolations; simp [hv, hch, hattr]
  refine ⟨hmem, fun t' ht' => ?_⟩
  have hne : frameViolations pre post W attr ≠ ∅ := Finset.ne_empty_of_mem hmem
  have hin : cell ∈ vetoedAt new (t + 1) := Finset.mem_union_right _ (hveto hne)
  exact R1_sticky base new ht' hin

end Frame

/-! ## T25 (Optimality) -/

/-- **T25.** With a coverage-complete offer set, an admitted booking whose excess over the cheapest matching
offer is at most `s` costs at most any matching offer plus `s`. -/
theorem T25_optimal {Offer : Type*} (O : Finset Offer) (F : Offer → Prop) [DecidablePred F]
    (price : Offer → ℝ) (hne : (O.filter F).Nonempty) (p s : ℝ)
    (hexcess : p - (O.filter F).inf' hne price ≤ s) : ∀ o ∈ O, F o → p ≤ price o + s := by
  intro o ho hFo
  have := Finset.inf'_le price (Finset.mem_filter.2 ⟨ho, hFo⟩)
  linarith

/-! ## T26 (Cells extend): adding a provenance dimension is a refinement -/

section Provenance

variable {Pv Θc : Type*} [Fintype Pv] [Nonempty Pv]

/-- **T26.** Adding a dimension `Pv` (e.g. provenance) refines Ω (the projection is onto, every old cell is the
union of its new cells). By T8, with exactly lifted region answers, the refined conservative grant lies in the
preimage of the old one: refinement never widens the grant. -/
theorem T26_prov_refine (acc : Θc → Ω → Bool) (Hc : Finset Θc) (Hf : Finset Θc) (hH : ∀ θ ∈ Hc, θ ∈ Hf)
    (obs : List (Finset Ω × Bool)) :
    ∀ x ∈ G1 (fun θ (x : Ω × Pv) => acc θ x.1)
        (VS (accR fun θ (x : Ω × Pv) => acc θ x.1) Hf (obs.map fun o => (liftRegion Prod.fst o.1, o.2))),
      x.1 ∈ G1 acc (VS (accR acc) Hc obs) :=
  T8_regions Prod.fst (fun ω => ⟨(ω, Classical.arbitrary Pv), rfl⟩) acc (fun θ x => acc θ x.1) id
    (fun _ _ => rfl) hH obs

end Provenance

end PcaIntent
