import PcaIntent.VersionSpace

/-!
# Credence-threshold synthesis (spec §2.4–2.5; brief item 2, second half)

A posterior is a finite set of hypotheses with non-negative weights summing to one. With it:

* `pAcc P ω = π({θ : ω ∈ θ})`                          acceptance probability `p_n(ω)`,
* `Gτ P τ = {ω : p_n(ω) ≥ τ}`                           conservative grant at threshold `τ = 1 − δ`,
* `Rhat M P G = ∑_{ω∈G} (1 − p_n ω) h ω μ ω`            estimated residual risk `R̂_n(G)`,
* `Rθ M θ G`                                            the risk of `G` if `θ` were the truth.

Results:
* `Rhat_eq_expected`  : `R̂_n(G) = E_{θ∼π_n}[R_θ(G)]`  (the estimate is the posterior-expected risk);
* `Rhat_le_disagreement` : `R̂_n(G) ≤ Hmax · ∑_{ω∈G} μ(ω) · π_n(θ rejects ω)`  (posterior disagreement mass × max harm);
* `credence_bound`    : `R̂_n(G_{1−δ}) ≤ δ · Hmax · μ(G_{1−δ}) ≤ δ · Hmax`;
* `truth_mass_sound`  : if the true hypothesis has posterior mass `> δ`, then the true risk `R(G_{1−δ}) = 0`;
* the Bayes posterior with noise rate `η` (`bayes`), and for `η = 0` its support is the version space
  (`bayes_zero_support`) and `R(G_1) = 0` (`T1_bayes`) — T1 recovered from the credence form.
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω]

/-- A posterior over a finite hypothesis set. -/
structure Posterior (Θ : Type*) where
  H : Finset Θ
  π : Θ → ℝ
  nonneg : ∀ θ, 0 ≤ π θ
  sum_one : ∑ θ ∈ H, π θ = 1

variable (acc : Θ → Ω → Bool)

open Classical in
/-- Acceptance probability `p_n(ω) = π({θ : a_θ(ω) = 1})`. -/
noncomputable def pAcc (P : Posterior Θ) (ω : Ω) : ℝ :=
  ∑ θ ∈ P.H.filter (fun θ => acc θ ω = true), P.π θ

open Classical in
/-- The conservative grant at threshold `τ`. -/
noncomputable def Gτ (P : Posterior Θ) (τ : ℝ) : Finset Ω := univ.filter fun ω => τ ≤ pAcc acc P ω

/-- Estimated residual risk `R̂_n(G) = ∫_G (1 − p_n) h dμ`. -/
noncomputable def Rhat (M : Model Ω) (P : Posterior Θ) (G : Finset Ω) : ℝ :=
  ∑ ω ∈ G, (1 - pAcc acc P ω) * M.h ω * M.μ ω

/-- The risk of `G` if `θ` were the truth. -/
noncomputable def Rθ (M : Model Ω) (θ : Θ) (G : Finset Ω) : ℝ :=
  ∑ ω ∈ G, (if acc θ ω = true then 0 else 1) * M.h ω * M.μ ω

variable {acc}

lemma mem_Gτ {P : Posterior Θ} {τ : ℝ} {ω : Ω} : ω ∈ Gτ acc P τ ↔ τ ≤ pAcc acc P ω := by
  classical
  unfold Gτ; simp

lemma pAcc_nonneg (P : Posterior Θ) (ω : Ω) : 0 ≤ pAcc acc P ω := by
  classical
  unfold pAcc; exact Finset.sum_nonneg fun θ _ => P.nonneg θ

lemma pAcc_le_one (P : Posterior Θ) (ω : Ω) : pAcc acc P ω ≤ 1 := by
  classical
  unfold pAcc
  rw [← P.sum_one]
  exact Finset.sum_le_sum_of_subset_of_nonneg (Finset.filter_subset _ _) fun θ _ _ => P.nonneg θ

/-- `1 − p_n(ω)` is the posterior mass of hypotheses that reject `ω`. -/
lemma one_sub_pAcc (P : Posterior Θ) (ω : Ω) :
    1 - pAcc acc P ω = ∑ θ ∈ P.H, P.π θ * (if acc θ ω = true then 0 else 1) := by
  classical
  have h := Finset.sum_filter_add_sum_filter_not P.H (fun θ => acc θ ω = true) P.π
  have h2 : ∑ θ ∈ P.H, P.π θ * (if acc θ ω = true then 0 else 1) =
      ∑ θ ∈ P.H.filter (fun θ => ¬ acc θ ω = true), P.π θ := by
    rw [Finset.sum_filter]
    refine Finset.sum_congr rfl fun θ _ => ?_
    by_cases hc : acc θ ω = true <;> simp [hc]
  unfold pAcc
  rw [h2, ← P.sum_one]
  linarith

/-- **The estimate is the posterior-expected risk**: `R̂_n(G) = ∑_θ π_n(θ) · R_θ(G)`. -/
theorem Rhat_eq_expected (M : Model Ω) (P : Posterior Θ) (G : Finset Ω) :
    Rhat acc M P G = ∑ θ ∈ P.H, P.π θ * Rθ acc M θ G := by
  unfold Rhat Rθ
  calc ∑ ω ∈ G, (1 - pAcc acc P ω) * M.h ω * M.μ ω
      = ∑ ω ∈ G, ∑ θ ∈ P.H, P.π θ * ((if acc θ ω = true then 0 else 1) * M.h ω * M.μ ω) := by
        refine Finset.sum_congr rfl fun ω _ => ?_
        rw [one_sub_pAcc, Finset.sum_mul, Finset.sum_mul]
        exact Finset.sum_congr rfl fun θ _ => by ring
    _ = ∑ θ ∈ P.H, ∑ ω ∈ G, P.π θ * ((if acc θ ω = true then 0 else 1) * M.h ω * M.μ ω) :=
        Finset.sum_comm
    _ = ∑ θ ∈ P.H, P.π θ * ∑ ω ∈ G, (if acc θ ω = true then 0 else 1) * M.h ω * M.μ ω := by
        refine Finset.sum_congr rfl fun θ _ => ?_
        rw [Finset.mul_sum]

/-- **Posterior disagreement mass × max harm.** `R̂_n(G) ≤ Hmax · ∑_{ω∈G} μ(ω) · π_n(θ rejects ω)`. -/
theorem Rhat_le_disagreement (M : Model Ω) (P : Posterior Θ) (G : Finset Ω) :
    Rhat acc M P G ≤ M.Hmax * ∑ ω ∈ G, M.μ ω * (1 - pAcc acc P ω) := by
  unfold Rhat
  rw [Finset.mul_sum]
  refine Finset.sum_le_sum fun ω _ => ?_
  have h1 : 0 ≤ 1 - pAcc acc P ω := sub_nonneg.2 (pAcc_le_one P ω)
  have := mul_le_mul_of_nonneg_left (M.h_le ω) (mul_nonneg h1 (M.μ_nonneg ω))
  nlinarith [M.μ_nonneg ω]

/-- **Credence-threshold bound.** For `τ = 1 − δ` (`0 ≤ δ`), the conservative grant has
`R̂_n(G_τ) ≤ δ · Hmax · μ(G_τ) ≤ δ · Hmax`: posterior-expected misalignment risk is at most `δ · Hmax`. -/
theorem credence_bound (M : Model Ω) (P : Posterior Θ) {δ : ℝ} (hδ : 0 ≤ δ) :
    Rhat acc M P (Gτ acc P (1 - δ)) ≤ δ * M.Hmax * ∑ ω ∈ Gτ acc P (1 - δ), M.μ ω ∧
    Rhat acc M P (Gτ acc P (1 - δ)) ≤ δ * M.Hmax := by
  have hmain : Rhat acc M P (Gτ acc P (1 - δ)) ≤ δ * M.Hmax * ∑ ω ∈ Gτ acc P (1 - δ), M.μ ω := by
    refine le_trans (Rhat_le_disagreement M P _) ?_
    have : ∑ ω ∈ Gτ acc P (1 - δ), M.μ ω * (1 - pAcc acc P ω) ≤
        ∑ ω ∈ Gτ acc P (1 - δ), δ * M.μ ω := by
      refine Finset.sum_le_sum fun ω hω => ?_
      have hp := mem_Gτ.1 hω
      have : 1 - pAcc acc P ω ≤ δ := by linarith
      nlinarith [M.μ_nonneg ω]
    rw [← Finset.mul_sum] at this
    have hH := M.Hmax_nonneg'
    nlinarith
  refine ⟨hmain, le_trans hmain ?_⟩
  have hm := M.mass_le_one (Gτ acc P (1 - δ))
  have hm0 : 0 ≤ ∑ ω ∈ Gτ acc P (1 - δ), M.μ ω := Finset.sum_nonneg fun ω _ => M.μ_nonneg ω
  have hH := M.Hmax_nonneg'
  have : 0 ≤ δ * M.Hmax := mul_nonneg hδ hH
  nlinarith

/-- **Frequentist soundness at a credence threshold.** If the true hypothesis keeps posterior mass `> 1 − τ`,
every outcome of `G_τ` is accepted by the truth, so the *true* risk is zero. -/
theorem truth_mass_sound (M : Model Ω) (P : Posterior Θ) {θs : Θ} (hreal : Realizes (acc θs) M)
    (hθ : θs ∈ P.H) {τ : ℝ} (hmass : 1 - τ < P.π θs) : M.R (Gτ acc P τ) = 0 := by
  classical
  apply M.R_eq_zero_of_accept
  intro ω hω
  have hp := mem_Gτ.1 hω
  have hacc : acc θs ω = true := by
    by_contra hrej
    have hsub : P.H.filter (fun θ => acc θ ω = true) ⊆ P.H.erase θs := by
      intro θ hθf
      rw [Finset.mem_filter] at hθf
      rw [Finset.mem_erase]
      exact ⟨fun he => hrej (he ▸ hθf.2), hθf.1⟩
    have hle : pAcc acc P ω ≤ ∑ θ ∈ P.H.erase θs, P.π θ := by
      unfold pAcc
      exact Finset.sum_le_sum_of_subset_of_nonneg hsub fun θ _ _ => P.nonneg θ
    have herase := Finset.add_sum_erase P.H P.π hθ
    rw [P.sum_one] at herase
    linarith
  rw [hreal ω, hacc]; simp

/-! ## The noisy-answer Bayes posterior -/

variable (acc) in
/-- Likelihood of the answers under hypothesis `θ` with symmetric noise rate `η`. -/
def lik (η : ℝ) (θ : Θ) : List (Ω × Bool) → ℝ
  | [] => 1
  | o :: obs => (if acc θ o.1 = o.2 then 1 - η else η) * lik η θ obs

lemma consistent_cons {θ : Θ} {o : Ω × Bool} {obs : List (Ω × Bool)} :
    Consistent acc θ (o :: obs) ↔ acc θ o.1 = o.2 ∧ Consistent acc θ obs := by
  unfold Consistent; rw [List.forall_mem_cons]

lemma lik_nonneg {η : ℝ} (h0 : 0 ≤ η) (h1 : η ≤ 1) (θ : Θ) :
    ∀ obs : List (Ω × Bool), 0 ≤ lik acc η θ obs
  | [] => zero_le_one
  | o :: obs => by
      simp only [lik]
      refine mul_nonneg ?_ (lik_nonneg h0 h1 θ obs)
      split_ifs <;> linarith

open Classical in
/-- With noise-free answers the likelihood is the consistency indicator. -/
lemma lik_zero (θ : Θ) :
    ∀ obs : List (Ω × Bool), lik acc 0 θ obs = if Consistent acc θ obs then 1 else 0
  | [] => by simp [lik, Consistent]
  | o :: obs => by
      simp only [lik]
      rw [lik_zero θ obs]
      by_cases h1 : acc θ o.1 = o.2 <;> by_cases h2 : Consistent acc θ obs <;>
        simp [h1, h2, consistent_cons]

/-- The Bayes posterior (spec §2.4): `π_n(θ) ∝ π_0(θ) · ∏ (1−η)^{[agree]} η^{[disagree]}`. -/
noncomputable def bayes (H : Finset Θ) (π0 : Θ → ℝ) (hπ0 : ∀ θ, 0 ≤ π0 θ) {η : ℝ} (hη0 : 0 ≤ η)
    (hη1 : η ≤ 1) (obs : List (Ω × Bool)) (hZ : 0 < ∑ θ ∈ H, π0 θ * lik acc η θ obs) : Posterior Θ where
  H := H
  π θ := π0 θ * lik acc η θ obs / ∑ θ' ∈ H, π0 θ' * lik acc η θ' obs
  nonneg θ := div_nonneg (mul_nonneg (hπ0 θ) (lik_nonneg hη0 hη1 θ obs)) hZ.le
  sum_one := by rw [← Finset.sum_div, div_self hZ.ne']

/-- Noise-free answers + realizability + a prior that does not exclude the truth: the normaliser is positive. -/
lemma Z_pos_of_truth {H : Finset Θ} {π0 : Θ → ℝ} (hπ0 : ∀ θ, 0 ≤ π0 θ) {θs : Θ} (hH : θs ∈ H)
    (hpos : 0 < π0 θs) {obs : List (Ω × Bool)} (hc : Consistent acc θs obs) :
    0 < ∑ θ ∈ H, π0 θ * lik acc 0 θ obs := by
  classical
  have hle := Finset.single_le_sum (f := fun θ => π0 θ * lik acc 0 θ obs)
    (fun θ _ => mul_nonneg (hπ0 θ) (lik_nonneg le_rfl zero_le_one θ obs)) hH
  have : π0 θs * lik acc 0 θs obs = π0 θs := by rw [lik_zero, if_pos hc, mul_one]
  linarith

/-- For `η = 0` the posterior is supported on the version space. -/
theorem bayes_zero_support {H : Finset Θ} {π0 : Θ → ℝ} (hπ0 : ∀ θ, 0 ≤ π0 θ) (obs : List (Ω × Bool))
    (hZ : 0 < ∑ θ ∈ H, π0 θ * lik acc 0 θ obs) {θ : Θ} (hθ : θ ∈ H)
    (hne : (bayes H π0 hπ0 le_rfl zero_le_one obs hZ).π θ ≠ 0) : θ ∈ VS acc H obs := by
  classical
  refine mem_VS.2 ⟨hθ, ?_⟩
  by_contra hc
  apply hne
  show π0 θ * lik acc 0 θ obs / _ = 0
  rw [lik_zero, if_neg hc, mul_zero, zero_div]

/-- **T1 recovered from the credence form.** Noise-free answers, realizability, `π_0(θ*) > 0`: the Bayes
posterior's `τ = 1` grant has zero true risk. -/
theorem T1_bayes (M : Model Ω) {H : Finset Θ} {π0 : Θ → ℝ} (hπ0 : ∀ θ, 0 ≤ π0 θ) {θs : Θ}
    (hreal : Realizes (acc θs) M) (hH : θs ∈ H) (hpos : 0 < π0 θs) {obs : List (Ω × Bool)}
    (hc : Consistent acc θs obs) :
    M.R (Gτ acc (bayes H π0 hπ0 le_rfl zero_le_one obs (Z_pos_of_truth hπ0 hH hpos hc)) 1) = 0 := by
  apply truth_mass_sound M _ hreal hH
  show 1 - 1 < π0 θs * lik acc 0 θs obs / _
  rw [lik_zero, if_pos hc, mul_one, sub_self]
  exact div_pos hpos (Z_pos_of_truth hπ0 hH hpos hc)

/-- With genuine noise `0 < η < 1` and a positive prior, *no* hypothesis is ever ruled out: the posterior is
positive everywhere on `H`. (So `τ = 1` grants only what every prior-supported hypothesis accepts; the
credence form `τ = 1 − δ` is the operative one under noise.) -/
theorem bayes_noisy_pos {H : Finset Θ} {π0 : Θ → ℝ} (hπ0 : ∀ θ, 0 ≤ π0 θ) {η : ℝ} (hη0 : 0 < η)
    (hη1 : η < 1) (obs : List (Ω × Bool)) (hZ : 0 < ∑ θ ∈ H, π0 θ * lik acc η θ obs) {θ : Θ}
    (hpos : 0 < π0 θ) : 0 < (bayes H π0 hπ0 hη0.le hη1.le obs hZ).π θ := by
  have hl : ∀ obs : List (Ω × Bool), 0 < lik acc η θ obs := by
    intro obs
    induction obs with
    | nil => exact zero_lt_one
    | cons o obs ih =>
        simp only [lik]
        refine mul_pos ?_ ih
        split_ifs <;> linarith
  exact div_pos (mul_pos hpos (hl obs)) hZ

end PcaIntent
