import PcaIntent.Credence

/-!
# PAC bound for the Monte Carlo residual-risk estimate (spec claim T4; brief item 5)

Fully machine-checked from Mathlib's sub-Gaussian library (`Mathlib.Probability.Moments.SubGaussian`:
Hoeffding's lemma `hasSubgaussianMGF_of_mem_Icc` and the sub-Gaussian sum tail
`HasSubgaussianMGF.measure_sum_range_ge_le_of_iIndepFun`). Nothing is assumed about Hoeffding.

Setting: a probability space `(S, P)`, samples `X j : S → ℝ` (`j : ℕ`), mutually independent, measurable,
valued in `[0, H]` with common mean `r`. With `M` samples and empirical mean `X̄ = (1/M) ∑_{j<M} X j`:

* `hoeffding_upper`     : `P(X̄ − r ≥ t) ≤ exp(−2 M t² / H²)`;
* `hoeffding_two_sided` : `P(|X̄ − r| ≥ t) ≤ 2 exp(−2 M t² / H²)`;
* `hoeffding_conf`      : with `t = H √(ln(2/δ')/(2M))`, `P(|X̄ − r| ≥ t) ≤ δ'`   (spec T4 verbatim).

Instantiation (`mc_residual_risk`): samples `ω_j ∼ μ` i.i.d. (stated as: independent, and `P(ω_j = ω) = μ(ω)`),
`X j = 1[ω_j ∈ G] (1 − p_n(ω_j)) h(ω_j)`. The deterministic parts — `X j ∈ [0, Hmax]` (`mcTerm_mem_Icc`) and
`E[X j] = R̂_n(G)` (`mcTerm_mean`) — are proved, so `R̂^MC` is within `Hmax √(ln(2/δ')/(2M))` of `R̂_n(G)` with
probability `≥ 1 − δ'`.
-/

namespace PcaIntent.MC

open MeasureTheory ProbabilityTheory Real Finset
open scoped NNReal

variable {S : Type*} [MeasurableSpace S] {P : Measure S} [IsProbabilityMeasure P]

/-- The Hoeffding sub-Gaussian parameter of a `[0, H]`-valued variable, `((H − 0)/2)²`, equals `H²/4`. -/
lemma hparam {H : ℝ} (hH : 0 < H) : (((‖H - 0‖₊ / 2) ^ 2 : ℝ≥0) : ℝ) = H ^ 2 / 4 := by
  rw [NNReal.coe_pow, NNReal.coe_div, coe_nnnorm, sub_zero, Real.norm_eq_abs, abs_of_pos hH]
  push_cast
  ring

/-- The sub-Gaussian sum tail, with the parameter specialised to `H²/4`. -/
lemma sum_tail {m : ℕ} (hm : 0 < m) {H : ℝ} (hH : 0 < H) (Y : ℕ → S → ℝ) (hind : iIndepFun Y P)
    (hsub : ∀ j < m, HasSubgaussianMGF (Y j) ((‖H - 0‖₊ / 2) ^ 2) P) {ε : ℝ} (hε : 0 ≤ ε) :
    P.real {s | ε ≤ ∑ j ∈ range m, Y j s} ≤ exp (-2 * ε ^ 2 / (m * H ^ 2)) := by
  refine le_trans (HasSubgaussianMGF.measure_sum_range_ge_le_of_iIndepFun hind hsub hε) (le_of_eq ?_)
  rw [hparam hH]
  congr 1
  have hm' : (m : ℝ) ≠ 0 := by exact_mod_cast hm.ne'
  have hH2 : H ^ 2 ≠ 0 := pow_ne_zero 2 hH.ne'
  rw [div_eq_div_iff (mul_ne_zero (mul_ne_zero two_ne_zero hm') (div_ne_zero hH2 four_ne_zero))
    (mul_ne_zero hm' hH2)]
  ring

variable {m : ℕ} {H r : ℝ} (X : ℕ → S → ℝ)

/-- Centering a sample at its (common) mean keeps it sub-Gaussian with parameter `H²/4`. -/
lemma centered_subG (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 H)
    (hmean : ∀ j, P[X j] = r) (j : ℕ) :
    HasSubgaussianMGF ((fun x => x - r) ∘ X j) ((‖H - 0‖₊ / 2) ^ 2) P := by
  have h := hasSubgaussianMGF_of_mem_Icc (μ := P) (hmeas j).aemeasurable (ae_of_all _ (hb j))
  rw [hmean j] at h
  exact h

/-- Upper tail of the centred sum. -/
lemma sum_upper (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P) (hmeas : ∀ j, Measurable (X j))
    (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r) {ε : ℝ} (hε : 0 ≤ ε) :
    P.real {s | ε ≤ ∑ j ∈ range m, (X j s - r)} ≤ exp (-2 * ε ^ 2 / (m * H ^ 2)) :=
  sum_tail hm hH (fun j => (fun x => x - r) ∘ X j)
    (hind.comp (fun _ x => x - r) (fun _ => measurable_id.sub_const r))
    (fun j _ => centered_subG X hmeas hb hmean j) hε

/-- Lower tail of the centred sum. -/
lemma sum_lower (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P) (hmeas : ∀ j, Measurable (X j))
    (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r) {ε : ℝ} (hε : 0 ≤ ε) :
    P.real {s | ε ≤ ∑ j ∈ range m, -(X j s - r)} ≤ exp (-2 * ε ^ 2 / (m * H ^ 2)) :=
  sum_tail hm hH (fun j => (fun x => -(x - r)) ∘ X j)
    (hind.comp (fun _ x => -(x - r)) (fun _ => (measurable_id.sub_const r).neg))
    (fun j _ => (centered_subG X hmeas hb hmean j).neg) hε

/-- Empirical mean. -/
noncomputable def mean (m : ℕ) (s : S) : ℝ := (∑ j ∈ range m, X j s) / m

lemma mean_sub_eq (hm : 0 < m) (s : S) :
    (m : ℝ) * (mean X m s - r) = ∑ j ∈ range m, (X j s - r) := by
  have hm' : (m : ℝ) ≠ 0 := by exact_mod_cast hm.ne'
  unfold mean
  rw [Finset.sum_sub_distrib, Finset.sum_const, Finset.card_range, nsmul_eq_mul, mul_sub,
    mul_div_cancel₀ _ hm']

/-- **Hoeffding, upper tail of the mean.** `P(X̄ − r ≥ t) ≤ exp(−2 M t² / H²)`. -/
theorem hoeffding_upper (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P)
    (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r)
    {t : ℝ} (ht : 0 ≤ t) :
    P.real {s | t ≤ mean X m s - r} ≤ exp (-2 * m * t ^ 2 / H ^ 2) := by
  have hm0 : (0 : ℝ) < m := by exact_mod_cast hm
  have hsub : {s | t ≤ mean X m s - r} ⊆ {s | m * t ≤ ∑ j ∈ range m, (X j s - r)} := by
    intro s hs
    simp only [Set.mem_setOf_eq] at hs ⊢
    rw [← mean_sub_eq X hm s]
    exact mul_le_mul_of_nonneg_left hs hm0.le
  refine le_trans (measureReal_mono hsub) (le_trans (sum_upper X hm hH hind hmeas hb hmean
    (mul_nonneg hm0.le ht)) (le_of_eq ?_))
  congr 1
  have hm' : (m : ℝ) ≠ 0 := hm0.ne'
  have hH2 : H ^ 2 ≠ 0 := pow_ne_zero 2 hH.ne'
  rw [div_eq_div_iff (mul_ne_zero hm' hH2) hH2]
  ring

/-- **Hoeffding, lower tail of the mean.** `P(r − X̄ ≥ t) ≤ exp(−2 M t² / H²)`. -/
theorem hoeffding_lower (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P)
    (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r)
    {t : ℝ} (ht : 0 ≤ t) :
    P.real {s | t ≤ -(mean X m s - r)} ≤ exp (-2 * m * t ^ 2 / H ^ 2) := by
  have hm0 : (0 : ℝ) < m := by exact_mod_cast hm
  have hsub : {s | t ≤ -(mean X m s - r)} ⊆ {s | m * t ≤ ∑ j ∈ range m, -(X j s - r)} := by
    intro s hs
    simp only [Set.mem_setOf_eq] at hs ⊢
    rw [Finset.sum_neg_distrib, ← mean_sub_eq X hm s, ← mul_neg]
    exact mul_le_mul_of_nonneg_left hs hm0.le
  refine le_trans (measureReal_mono hsub) (le_trans (sum_lower X hm hH hind hmeas hb hmean
    (mul_nonneg hm0.le ht)) (le_of_eq ?_))
  congr 1
  have hm' : (m : ℝ) ≠ 0 := hm0.ne'
  have hH2 : H ^ 2 ≠ 0 := pow_ne_zero 2 hH.ne'
  rw [div_eq_div_iff (mul_ne_zero hm' hH2) hH2]
  ring

/-- **Hoeffding, two-sided.** `P(|X̄ − r| ≥ t) ≤ 2 exp(−2 M t² / H²)`. -/
theorem hoeffding_two_sided (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P)
    (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r)
    {t : ℝ} (ht : 0 ≤ t) :
    P.real {s | t ≤ |mean X m s - r|} ≤ 2 * exp (-2 * m * t ^ 2 / H ^ 2) := by
  have hsub : {s | t ≤ |mean X m s - r|} ⊆
      {s | t ≤ mean X m s - r} ∪ {s | t ≤ -(mean X m s - r)} := by
    intro s hs
    simp only [Set.mem_setOf_eq, Set.mem_union] at hs ⊢
    rcases le_total 0 (mean X m s - r) with h | h
    · left; rwa [abs_of_nonneg h] at hs
    · right; rwa [abs_of_nonpos h] at hs
  calc P.real {s | t ≤ |mean X m s - r|}
      ≤ P.real ({s | t ≤ mean X m s - r} ∪ {s | t ≤ -(mean X m s - r)}) := measureReal_mono hsub
    _ ≤ P.real {s | t ≤ mean X m s - r} + P.real {s | t ≤ -(mean X m s - r)} :=
        measureReal_union_le _ _
    _ ≤ exp (-2 * m * t ^ 2 / H ^ 2) + exp (-2 * m * t ^ 2 / H ^ 2) :=
        add_le_add (hoeffding_upper X hm hH hind hmeas hb hmean ht)
          (hoeffding_lower X hm hH hind hmeas hb hmean ht)
    _ = 2 * exp (-2 * m * t ^ 2 / H ^ 2) := by ring

/-- The confidence radius of spec T4: `ε(M, δ') = H √(ln(2/δ') / (2M))`. -/
noncomputable def radius (H : ℝ) (m : ℕ) (δ' : ℝ) : ℝ := H * Real.sqrt (Real.log (2 / δ') / (2 * m))

lemma radius_tail (hm : 0 < m) (hH : 0 < H) {δ' : ℝ} (hδ0 : 0 < δ') (hδ2 : δ' ≤ 2) :
    2 * exp (-2 * m * radius H m δ' ^ 2 / H ^ 2) = δ' := by
  have hm0 : (0 : ℝ) < m := by exact_mod_cast hm
  have hlog : 0 ≤ Real.log (2 / δ') := Real.log_nonneg (by rw [le_div_iff₀ hδ0]; linarith)
  have hsq : radius H m δ' ^ 2 = H ^ 2 * (Real.log (2 / δ') / (2 * m)) := by
    unfold radius
    rw [mul_pow, Real.sq_sqrt (div_nonneg hlog (by positivity))]
  have hexp : -2 * m * radius H m δ' ^ 2 / H ^ 2 = -Real.log (2 / δ') := by
    have hm' : (m : ℝ) ≠ 0 := hm0.ne'
    have hH' : H ≠ 0 := hH.ne'
    rw [hsq]
    field_simp
    try ring
  rw [hexp, Real.exp_neg, Real.exp_log (div_pos two_pos hδ0), inv_div]
  ring

/-- **T4 (spec, verbatim).** With probability at least `1 − δ'`, the empirical mean of `M` independent
`[0, H]`-valued samples with common mean `r` is within `H √(ln(2/δ')/(2M))` of `r`. -/
theorem hoeffding_conf (hm : 0 < m) (hH : 0 < H) (hind : iIndepFun X P)
    (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 H) (hmean : ∀ j, P[X j] = r)
    {δ' : ℝ} (hδ0 : 0 < δ') (hδ2 : δ' ≤ 2) :
    P.real {s | radius H m δ' ≤ |mean X m s - r|} ≤ δ' := by
  have hrad : 0 ≤ radius H m δ' := mul_nonneg hH.le (Real.sqrt_nonneg _)
  have := hoeffding_two_sided X hm hH hind hmeas hb hmean hrad
  rwa [radius_tail hm hH hδ0 hδ2] at this

/-! ## Instantiation: the Monte Carlo residual-risk estimator -/

section Estimator

variable {Ω Θ : Type*} [Fintype Ω] [MeasurableSpace Ω] [DiscreteMeasurableSpace Ω]
  (acc : Θ → Ω → Bool) (M : Model Ω) (Q : Posterior Θ) (G : Finset Ω)

open Classical in
/-- One Monte Carlo term `1[ω ∈ G] (1 − p_n(ω)) h(ω)`. -/
noncomputable def mcTerm (ω : Ω) : ℝ := if ω ∈ G then (1 - pAcc acc Q ω) * M.h ω else 0

lemma mcTerm_mem_Icc (ω : Ω) : mcTerm acc M Q G ω ∈ Set.Icc 0 M.Hmax := by
  classical
  unfold mcTerm
  have h0 : 0 ≤ 1 - pAcc acc Q ω := sub_nonneg.2 (pAcc_le_one Q ω)
  have h1 : 1 - pAcc acc Q ω ≤ 1 := by linarith [pAcc_nonneg (acc := acc) Q ω]
  split_ifs
  · refine ⟨mul_nonneg h0 (M.h_nonneg ω), ?_⟩
    calc (1 - pAcc acc Q ω) * M.h ω ≤ 1 * M.h ω := mul_le_mul_of_nonneg_right h1 (M.h_nonneg ω)
      _ = M.h ω := one_mul _
      _ ≤ M.Hmax := M.h_le ω
  · exact ⟨le_rfl, M.Hmax_nonneg'⟩

/-- The deterministic identity behind unbiasedness: `∑_ω mcTerm(ω) μ(ω) = R̂_n(G)`. -/
lemma mcTerm_expect : ∑ ω, mcTerm acc M Q G ω * M.μ ω = Rhat acc M Q G := by
  classical
  unfold mcTerm Rhat
  have : ∀ ω, (if ω ∈ G then (1 - pAcc acc Q ω) * M.h ω else 0) * M.μ ω =
      if ω ∈ G then (1 - pAcc acc Q ω) * M.h ω * M.μ ω else 0 := by
    intro ω; split_ifs <;> simp
  simp_rw [this]
  rw [Finset.sum_ite_mem, Finset.univ_inter]

/-- **Unbiasedness.** If the sample `ω_j` has law `μ` (`P(ω_j = ω) = μ(ω)`), then `E[mcTerm(ω_j)] = R̂_n(G)`. -/
lemma mcTerm_mean (sample : S → Ω) (hs : Measurable sample)
    (hlaw : ∀ ω, P.real (sample ⁻¹' {ω}) = M.μ ω) :
    P[fun s => mcTerm acc M Q G (sample s)] = Rhat acc M Q G := by
  have hmeasf : Measurable (mcTerm acc M Q G) := Measurable.of_discrete
  rw [← integral_map hs.aemeasurable hmeasf.aestronglyMeasurable]
  have hfin : IsFiniteMeasure (P.map sample) := inferInstance
  have hint : Integrable (mcTerm acc M Q G) (P.map sample) := by
    refine Integrable.of_mem_Icc 0 M.Hmax hmeasf.aemeasurable (ae_of_all _ fun ω => ?_)
    exact mcTerm_mem_Icc acc M Q G ω
  rw [integral_fintype hint, ← mcTerm_expect acc M Q G]
  refine Finset.sum_congr rfl fun ω _ => ?_
  rw [map_measureReal_apply hs (MeasurableSet.singleton ω), hlaw ω, smul_eq_mul, mul_comm]

/-- **T4 for the residual-risk estimator.** `M` i.i.d. samples `ω_j ∼ μ`, `Hmax > 0`. With probability
`≥ 1 − δ'`, `|R̂^MC − R̂_n(G)| < Hmax √(ln(2/δ')/(2M))`. -/
theorem mc_residual_risk (hm : 0 < m) (hH : 0 < M.Hmax) (sample : ℕ → S → Ω)
    (hind : iIndepFun sample P) (hs : ∀ j, Measurable (sample j))
    (hlaw : ∀ j ω, P.real (sample j ⁻¹' {ω}) = M.μ ω) {δ' : ℝ} (hδ0 : 0 < δ') (hδ2 : δ' ≤ 2) :
    P.real {s | radius M.Hmax m δ' ≤
      |mean (fun j s => mcTerm acc M Q G (sample j s)) m s - Rhat acc M Q G|} ≤ δ' := by
  have hmeasf : Measurable (mcTerm acc M Q G) := Measurable.of_discrete
  refine hoeffding_conf (fun j s => mcTerm acc M Q G (sample j s)) hm hH ?_ ?_ ?_ ?_ hδ0 hδ2
  · exact hind.comp (fun _ => mcTerm acc M Q G) (fun _ => hmeasf)
  · exact fun j => hmeasf.comp (hs j)
  · exact fun j s => mcTerm_mem_Icc acc M Q G (sample j s)
  · exact fun j => mcTerm_mean acc M Q G (sample j) (hs j) (hlaw j)

end Estimator

end PcaIntent.MC
