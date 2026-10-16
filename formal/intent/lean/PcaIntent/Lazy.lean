import PcaIntent.Cells
import PcaIntent.Credence

/-!
# v2 lazy elicitation, answer channel, priors (claims T13, T14, T16, T17, T23)

* **T13** (lazy burden, NF). The uncertain set `U_k = DIS(VS_k) ∩ A_k` (allowed by the ceilings, not vetoed;
  `A_k` only shrinks) only shrinks (`T13_uncertain_anti`); an informative run asks each cell at most once
  (`T13_once_per_cell`); a session asks at most `|U_0 ∩ Vis|` questions (`T13_burden`); and in expectation at
  most `∑_{c ∈ U_0} P(c ∈ Vis)` (`T13_expected`, finite probability space, linearity of expectation).
  Under NF with a full-support prior, `0 < p_k(c) < 1` iff `c ∈ DIS(VS_k)` (see `T23_prior_neutral`'s proof), so
  `DIS` is the uncertain set at τ = 1.
* **T14** (lazy safety). Every delta is a subset of a conservative grant computed from *some* list of
  noise-free answers (any order); the effective grant is then inside the truth (`T14_lazy_sound`). That the
  accepted deltas are the principal's (EUF-CMA, T15) is a cryptographic assumption, entering as the premise.
* **T16** (canary neutrality). Canary observations are filtered out before the learner, so the version space,
  `G_1` and every posterior built from the learner observations are unchanged (`T16_canary_neutral`).
* **T17** (credence under any likelihood). `credence_bound` and `truth_mass_sound` hold for every posterior,
  hence for the asymmetric-noise likelihood (`likAsym`, `T17_credence_any_lik`).
* **T23** (prior neutrality). Under NF and τ = 1, for every full-support prior the Bayes `G_1` equals
  `G_1(VS_n)`, so it does not depend on the prior (`T23_prior_neutral`).
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω]

/-! ## T13 -/

/-- **T13(a).** The uncertain set only shrinks when the version space and the allowed set shrink. -/
theorem T13_uncertain_anti {acc : Θ → Ω → Bool} [DecidableEq Ω] {V V' : Finset Θ} {A A' : Finset Ω}
    (hV : V' ⊆ V) (hA : A' ⊆ A) : DIS acc V' ∩ A' ⊆ DIS acc V ∩ A :=
  Finset.inter_subset_inter (DIS_mono hV) hA

/-- **T13(b).** Each cell is asked at most once. -/
theorem T13_once_per_cell {acc : Θ → Ω → Bool} (H : Finset Θ) (obs : List (Ω × Bool))
    (hrun : InformRun acc H obs) : (obs.map Prod.fst).Nodup :=
  inform_questions_nodup H obs hrun

/-- **T13(b).** `Q ≤ |U_0 ∩ Vis|`: every question is a distinct cell of `U_0` the session visited. -/
theorem T13_burden {acc : Θ → Ω → Bool} [DecidableEq Ω] (H : Finset Θ) (obs : List (Ω × Bool))
    (hrun : InformRun acc H obs) (U0 Vis : Finset Ω) (hq : ∀ o ∈ obs, o.1 ∈ U0 ∩ Vis) :
    obs.length ≤ (U0 ∩ Vis).card := by
  have hnd := T13_once_per_cell H obs hrun
  have hsub : (obs.map Prod.fst).toFinset ⊆ U0 ∩ Vis := by
    intro x hx
    obtain ⟨o, ho, rfl⟩ := List.mem_map.1 (List.mem_toFinset.1 hx)
    exact hq o ho
  have := Finset.card_le_card hsub
  rw [List.toFinset_card_of_nodup hnd, List.length_map] at this
  exact this

/-- **T13(c).** Over a finite space of sessions with probabilities `P`, the expected number of questions is at
most `∑_{c ∈ U_0} P(c ∈ Vis)`. -/
theorem T13_expected [DecidableEq Ω] {S : Type*} [Fintype S] (P : S → ℝ) (hP : ∀ s, 0 ≤ P s)
    (Q : S → ℕ) (U0 : Finset Ω) (Vis : S → Finset Ω) (hQ : ∀ s, Q s ≤ (U0 ∩ Vis s).card) :
    ∑ s, P s * Q s ≤ ∑ c ∈ U0, ∑ s, P s * (if c ∈ Vis s then 1 else 0) := by
  have hcard : ∀ s, ((U0 ∩ Vis s).card : ℝ) = ∑ c ∈ U0, (if c ∈ Vis s then (1 : ℝ) else 0) := by
    intro s
    rw [Finset.sum_boole]
    congr 1
  calc ∑ s, P s * Q s ≤ ∑ s, P s * ((U0 ∩ Vis s).card : ℝ) := by
        refine Finset.sum_le_sum fun s _ => mul_le_mul_of_nonneg_left ?_ (hP s)
        exact_mod_cast hQ s
    _ = ∑ s, ∑ c ∈ U0, P s * (if c ∈ Vis s then 1 else 0) := by
        refine Finset.sum_congr rfl fun s _ => ?_
        rw [hcard, Finset.mul_sum]
    _ = ∑ c ∈ U0, ∑ s, P s * (if c ∈ Vis s then 1 else 0) := Finset.sum_comm

/-! ## T14 -/

/-- **T14 (lazy safety, any question order).** If every delta cell lies in the conservative grant of *some*
noise-free answer list, the effective grant (ceilings ∩ (initial ∪ deltas), minus vetoes) is inside the truth. -/
theorem T14_lazy_sound [DecidableEq Ω] {acc : Θ → Ω → Bool} {H : Finset Θ} {θs : Θ} (hH : θs ∈ H)
    {K : Type*} (ks : Finset K) (D : K → Finset Ω) (G0 ceil vetoed : Finset Ω)
    (hD : ∀ k ∈ ks, ∀ ω ∈ D k, ∃ obs : List (Ω × Bool), Consistent acc θs obs ∧ ω ∈ G1 acc (VS acc H obs))
    (hG0 : ∀ ω ∈ G0, ∃ obs : List (Ω × Bool), Consistent acc θs obs ∧ ω ∈ G1 acc (VS acc H obs)) :
    ∀ ω ∈ (ceil ∩ (G0 ∪ ks.biUnion D)) \ vetoed, acc θs ω = true := by
  intro ω hω
  have hω' := (Finset.mem_inter.1 (Finset.mem_sdiff.1 hω).1).2
  rcases Finset.mem_union.1 hω' with h0 | hd
  · obtain ⟨obs, hc, hg⟩ := hG0 ω h0
    exact G1_subset_truth (truth_mem_VS hH hc) hg
  · obtain ⟨k, hk, hωk⟩ := Finset.mem_biUnion.1 hd
    obtain ⟨obs, hc, hg⟩ := hD k hk ω hωk
    exact G1_subset_truth (truth_mem_VS hH hc) hg

/-! ## T16 -/

/-- Observations tagged `(cell, answer, isCanary)`; the learner only sees the untagged ones. -/
def learnerObs (l : List (Ω × Bool × Bool)) : List (Ω × Bool) :=
  (l.filter fun o => !o.2.2).map fun o => (o.1, o.2.1)

/-- **T16 (canary neutrality).** Appending canary answers changes neither the learner's observations nor,
therefore, the version space or the conservative grant. -/
theorem T16_canary_neutral {acc : Θ → Ω → Bool} (H : Finset Θ) (l c : List (Ω × Bool × Bool))
    (hc : ∀ o ∈ c, o.2.2 = true) :
    learnerObs (l ++ c) = learnerObs l ∧
      G1 acc (VS acc H (learnerObs (l ++ c))) = G1 acc (VS acc H (learnerObs l)) := by
  have h : learnerObs (l ++ c) = learnerObs l := by
    unfold learnerObs
    rw [List.filter_append]
    have hnil : c.filter (fun o => !o.2.2) = [] := by
      rw [List.filter_eq_nil_iff]
      intro o ho
      simp [hc o ho]
    rw [hnil, List.append_nil]
  exact ⟨h, by rw [h]⟩

/-! ## T17 -/

variable (acc : Θ → Ω → Bool) in
/-- The asymmetric-noise likelihood of spec v2 §2.5 (`ηp` false-yes rate, `ηm` false-no rate). -/
def likAsym (ηp ηm : ℝ) (θ : Θ) : List (Ω × Bool) → ℝ
  | [] => 1
  | o :: obs =>
      (if o.2 = true then (if acc θ o.1 = true then 1 - ηm else ηp)
        else (if acc θ o.1 = true then ηm else 1 - ηp)) * likAsym ηp ηm θ obs

/-- The normalised posterior of any non-negative weight function. -/
noncomputable def normPost (H : Finset Θ) (w : Θ → ℝ) (hw : ∀ θ, 0 ≤ w θ) (hZ : 0 < ∑ θ ∈ H, w θ) :
    Posterior Θ where
  H := H
  π θ := w θ / ∑ θ' ∈ H, w θ'
  nonneg θ := div_nonneg (hw θ) hZ.le
  sum_one := by rw [← Finset.sum_div, div_self hZ.ne']

lemma likAsym_nonneg {acc : Θ → Ω → Bool} {ηp ηm : ℝ} (hp0 : 0 ≤ ηp) (hp1 : ηp ≤ 1) (hm0 : 0 ≤ ηm)
    (hm1 : ηm ≤ 1) (θ : Θ) : ∀ obs : List (Ω × Bool), 0 ≤ likAsym acc ηp ηm θ obs
  | [] => zero_le_one
  | o :: obs => by
      simp only [likAsym]
      refine mul_nonneg ?_ (likAsym_nonneg hp0 hp1 hm0 hm1 θ obs)
      split_ifs <;> linarith

/-- **T17.** For the asymmetric-noise posterior (any `η⁺, η⁻`), the credence bound and truth-mass soundness
hold, because those v1 theorems hold for every posterior. -/
theorem T17_credence_any_lik (M : Model Ω) {acc : Θ → Ω → Bool} (H : Finset Θ) (π0 : Θ → ℝ)
    (hπ0 : ∀ θ, 0 ≤ π0 θ) {ηp ηm : ℝ} (hp0 : 0 ≤ ηp) (hp1 : ηp ≤ 1) (hm0 : 0 ≤ ηm) (hm1 : ηm ≤ 1)
    (obs : List (Ω × Bool)) (hZ : 0 < ∑ θ ∈ H, π0 θ * likAsym acc ηp ηm θ obs) {δ : ℝ} (hδ : 0 ≤ δ) :
    let P := normPost H (fun θ => π0 θ * likAsym acc ηp ηm θ obs)
      (fun θ => mul_nonneg (hπ0 θ) (likAsym_nonneg hp0 hp1 hm0 hm1 θ obs)) hZ
    Rhat acc M P (Gτ acc P (1 - δ)) ≤ δ * M.Hmax ∧
      (∀ θs, Realizes (acc θs) M → θs ∈ H → δ < P.π θs → M.R (Gτ acc P (1 - δ)) = 0) := by
  intro P
  refine ⟨(credence_bound M P hδ).2, fun θs hreal hH hmass => ?_⟩
  exact truth_mass_sound M P hreal hH (by linarith)

/-! ## T23 -/

/-- **T23 (prior neutrality).** Under NF and τ = 1, with a full-support prior, the Bayes conservative grant is
exactly `G_1(VS_n)`; in particular it is the same for every full-support prior. -/
theorem T23_prior_neutral {acc : Θ → Ω → Bool} {H : Finset Θ} {π0 : Θ → ℝ} (hπ0 : ∀ θ, 0 ≤ π0 θ)
    (hfull : ∀ θ ∈ H, 0 < π0 θ) (obs : List (Ω × Bool)) (hZ : 0 < ∑ θ ∈ H, π0 θ * lik acc 0 θ obs) :
    Gτ acc (bayes H π0 hπ0 le_rfl zero_le_one obs hZ) 1 = G1 acc (VS acc H obs) := by
  classical
  set P := bayes H π0 hπ0 le_rfl zero_le_one obs hZ with hP
  ext ω
  rw [mem_Gτ, mem_G1]
  have hsum := one_sub_pAcc (acc := acc) P ω
  have hterm : ∀ θ ∈ P.H, 0 ≤ P.π θ * (if acc θ ω = true then 0 else 1) := fun θ _ =>
    mul_nonneg (P.nonneg θ) (by split_ifs <;> norm_num)
  -- π θ ≠ 0 ↔ θ ∈ VS, for θ ∈ H
  have hpos : ∀ θ ∈ H, (P.π θ = 0 ↔ ¬ Consistent acc θ obs) := by
    intro θ hθ
    show π0 θ * lik acc 0 θ obs / _ = 0 ↔ _
    rw [lik_zero]
    by_cases hc : Consistent acc θ obs
    · rw [if_pos hc, mul_one]
      simp only [hc, not_true_eq_false, iff_false]
      exact (div_pos (hfull θ hθ) hZ).ne'
    · rw [if_neg hc, mul_zero, zero_div]
      simp [hc]
  constructor
  · intro h1 θ hθ
    rw [mem_VS] at hθ
    have hle : 1 - pAcc acc P ω ≤ 0 := by linarith
    rw [hsum] at hle
    have hz := (Finset.sum_eq_zero_iff_of_nonneg hterm).1 (le_antisymm hle (Finset.sum_nonneg hterm))
    have := hz θ hθ.1
    by_contra hrej
    rw [if_neg hrej, mul_one] at this
    exact ((hpos θ hθ.1).1 this) hθ.2
  · intro h
    have hz : ∑ θ ∈ P.H, P.π θ * (if acc θ ω = true then 0 else 1) = 0 := by
      refine Finset.sum_eq_zero fun θ hθ => ?_
      by_cases hc : Consistent acc θ obs
      · rw [if_pos (h θ (mem_VS.2 ⟨hθ, hc⟩)), mul_zero]
      · rw [(hpos θ hθ).2 hc, zero_mul]
    rw [hz] at hsum
    linarith

end PcaIntent
