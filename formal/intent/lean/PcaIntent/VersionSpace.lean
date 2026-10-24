import PcaIntent.Model

/-!
# Version spaces, conservative synthesis, monotonicity (spec §2.4–2.5; claims T1, T2)

A hypothesis class is any type `Θ` with an acceptance map `acc : Θ → Ω → Bool` (spec: `a_θ(ω) = 1[ω ∈ θ]`), and a
finite candidate set `H : Finset Θ` (spec: `Θ_v`, boxes over cells plus the deny-verb hypothesis; nothing below
depends on the box shape, so the results hold for *every* finite hypothesis class — Mitchell's version-space
setting).

* an observation is `(ω, y) : Ω × Bool`, the principal's answer to "should ω be allowed?";
* `VS H obs = {θ ∈ H : a_θ(ωᵢ) = yᵢ for all i}`  (version space, Mitchell 1982);
* `G1 V = {ω : ∀ θ ∈ V, a_θ(ω) = 1}`              (the unanimous / τ = 1 conservative grant, `∩ VS`);
* `DIS V = {ω : ∃ θ θ' ∈ V, a_θ(ω) ≠ a_θ'(ω)}`     (disagreement region, Hanneke 2014);
* `Rvs V G`                                         (worst-case residual risk over the version space).

Realizability (`θ* ∈ H`, `M.a = a_θ*`) and noise-free answers (`Consistent θ* obs`) are explicit hypotheses.
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω] (acc : Θ → Ω → Bool)

/-- `θ` agrees with every answer in `obs`. -/
def Consistent (θ : Θ) (obs : List (Ω × Bool)) : Prop := ∀ o ∈ obs, acc θ o.1 = o.2

open Classical in
/-- The version space: hypotheses of `H` consistent with all answers. -/
noncomputable def VS (H : Finset Θ) (obs : List (Ω × Bool)) : Finset Θ :=
  H.filter fun θ => Consistent acc θ obs

open Classical in
/-- The unanimous (τ = 1) conservative grant: outcomes every hypothesis of `V` accepts. -/
noncomputable def G1 (V : Finset Θ) : Finset Ω :=
  univ.filter fun ω => ∀ θ ∈ V, acc θ ω = true

open Classical in
/-- The disagreement region of `V`. -/
noncomputable def DIS (V : Finset Θ) : Finset Ω :=
  univ.filter fun ω => ∃ θ ∈ V, ∃ θ' ∈ V, acc θ ω ≠ acc θ' ω

/-- The realizable model: the principal's true acceptability is the indicator of `θ*`. -/
def Realizes {Ω' : Type*} [Fintype Ω'] (accT : Ω' → Bool) (M : Model Ω') : Prop :=
  ∀ ω, M.a ω = if accT ω then 1 else 0

variable {acc}

lemma mem_VS {H : Finset Θ} {obs : List (Ω × Bool)} {θ : Θ} :
    θ ∈ VS acc H obs ↔ θ ∈ H ∧ Consistent acc θ obs := by
  classical
  unfold VS; rw [Finset.mem_filter]

lemma mem_G1 {V : Finset Θ} {ω : Ω} : ω ∈ G1 acc V ↔ ∀ θ ∈ V, acc θ ω = true := by
  classical
  unfold G1; simp

lemma mem_DIS {V : Finset Θ} {ω : Ω} :
    ω ∈ DIS acc V ↔ ∃ θ ∈ V, ∃ θ' ∈ V, acc θ ω ≠ acc θ' ω := by
  classical
  unfold DIS; simp

/-! ## Monotonicity (T2 and item 3 of the brief) -/

/-- **More answers never enlarge the version space.** If every answer of `obs` also occurs in `obs'`
(e.g. `obs' = new ++ obs`), then `VS(obs') ⊆ VS(obs)`. -/
theorem VS_anti {H : Finset Θ} {obs obs' : List (Ω × Bool)} (hsub : ∀ o ∈ obs, o ∈ obs') :
    VS acc H obs' ⊆ VS acc H obs := by
  intro θ hθ
  rw [mem_VS] at hθ ⊢
  exact ⟨hθ.1, fun o ho => hθ.2 o (hsub o ho)⟩

/-- One more answer: `VS_{n+1} ⊆ VS_n`. -/
theorem VS_cons_subset (H : Finset Θ) (o : Ω × Bool) (obs : List (Ω × Bool)) :
    VS acc H (o :: obs) ⊆ VS acc H obs :=
  VS_anti fun _ h => List.mem_cons_of_mem _ h

/-- The version space after one more answer is the filter of the old one. -/
theorem VS_cons (H : Finset Θ) (o : Ω × Bool) (obs : List (Ω × Bool)) :
    VS acc H (o :: obs) = (VS acc H obs).filter (fun θ => acc θ o.1 = o.2) := by
  classical
  ext θ
  rw [Finset.mem_filter, mem_VS, mem_VS]
  unfold Consistent
  rw [List.forall_mem_cons]
  tauto

/-- Under realizability and noise-free answers the truth never leaves the version space. -/
theorem truth_mem_VS {H : Finset Θ} {obs : List (Ω × Bool)} {θs : Θ} (hH : θs ∈ H)
    (hc : Consistent acc θs obs) : θs ∈ VS acc H obs :=
  mem_VS.2 ⟨hH, hc⟩

/-- The conservative grant only grows as the version space shrinks. -/
theorem G1_anti {V V' : Finset Θ} (hsub : V' ⊆ V) : G1 acc V ⊆ G1 acc V' := by
  intro ω hω
  rw [mem_G1] at hω ⊢
  exact fun θ hθ => hω θ (hsub hθ)

/-- So `G1(VS_n)` is monotone non-decreasing in the answers. -/
theorem G1_grows {H : Finset Θ} {obs obs' : List (Ω × Bool)} (hsub : ∀ o ∈ obs, o ∈ obs') :
    G1 acc (VS acc H obs) ⊆ G1 acc (VS acc H obs') :=
  G1_anti (VS_anti hsub)

/-- The disagreement region only shrinks. -/
theorem DIS_mono {V V' : Finset Θ} (hsub : V' ⊆ V) : DIS acc V' ⊆ DIS acc V := by
  intro ω hω
  rw [mem_DIS] at hω ⊢
  obtain ⟨θ, hθ, θ', hθ', hne⟩ := hω
  exact ⟨θ, hsub hθ, θ', hsub hθ', hne⟩

/-! ## T1: soundness of conservative synthesis -/

/-- The unanimous grant is inside the truth whenever the truth is in the version space. -/
theorem G1_subset_truth {V : Finset Θ} {θs : Θ} (hθ : θs ∈ V) {ω : Ω} (hω : ω ∈ G1 acc V) :
    acc θs ω = true :=
  (mem_G1.1 hω) θs hθ

/-- **T1 (soundness of conservative synthesis).** Realizability (`θ* ∈ H`, `a = a_θ*`) plus noise-free answers
(`θ*` consistent with every answer) give `R(G1(VS_n)) = 0`. -/
theorem T1_soundness (M : Model Ω) {H : Finset Θ} {obs : List (Ω × Bool)} {θs : Θ}
    (hreal : Realizes (acc θs) M) (hH : θs ∈ H) (hc : Consistent acc θs obs) :
    M.R (G1 acc (VS acc H obs)) = 0 := by
  apply M.R_eq_zero_of_accept
  intro ω hω
  rw [hreal ω, G1_subset_truth (truth_mem_VS hH hc) hω]
  simp

/-! ## T2: burden of the conservative grant is bounded by the disagreement mass -/

/-- `B(G1(V)) ≤ μ(DIS(V))` when the truth is in `V`. -/
theorem B_G1_le_DIS (M : Model Ω) {V : Finset Θ} {θs : Θ} (hreal : Realizes (acc θs) M)
    (hθ : θs ∈ V) : M.B (G1 acc V) ≤ ∑ ω ∈ DIS acc V, M.μ ω := by
  classical
  unfold Model.B
  calc ∑ ω ∈ (G1 acc V)ᶜ, M.a ω * M.μ ω
      = ∑ ω ∈ (G1 acc V)ᶜ, (if acc θs ω = true then M.μ ω else 0) := by
        refine Finset.sum_congr rfl fun ω _ => ?_
        rw [hreal ω]; split_ifs <;> simp
    _ = ∑ ω ∈ (G1 acc V)ᶜ.filter (fun ω => acc θs ω = true), M.μ ω := by
        rw [Finset.sum_filter]
    _ ≤ ∑ ω ∈ DIS acc V, M.μ ω := by
        refine Finset.sum_le_sum_of_subset_of_nonneg ?_ fun ω _ _ => M.μ_nonneg ω
        intro ω hω
        rw [Finset.mem_filter, Finset.mem_compl, mem_G1] at hω
        obtain ⟨hnot, hacc⟩ := hω
        have hex : ∃ θ ∈ V, acc θ ω ≠ true := by
          by_contra hc
          apply hnot
          intro θ hθ'
          by_contra hne
          exact hc ⟨θ, hθ', hne⟩
        obtain ⟨θ, hθV, hrej⟩ := hex
        rw [mem_DIS]
        exact ⟨θs, hθ, θ, hθV, fun h => hrej (h ▸ hacc)⟩

/-- T2 as stated in the spec: `B(G1(VS_n)) ≤ μ(DIS(VS_n))`, and that bound is non-increasing in the answers. -/
theorem T2_burden (M : Model Ω) {H : Finset Θ} {obs obs' : List (Ω × Bool)} {θs : Θ}
    (hreal : Realizes (acc θs) M) (hH : θs ∈ H) (hc : Consistent acc θs obs) :
    M.B (G1 acc (VS acc H obs)) ≤ ∑ ω ∈ DIS acc (VS acc H obs), M.μ ω ∧
    ((∀ o ∈ obs, o ∈ obs') →
      ∑ ω ∈ DIS acc (VS acc H obs'), M.μ ω ≤ ∑ ω ∈ DIS acc (VS acc H obs), M.μ ω) :=
  ⟨B_G1_le_DIS M hreal (truth_mem_VS hH hc), fun hsub =>
    Finset.sum_le_sum_of_subset_of_nonneg (DIS_mono (VS_anti hsub)) fun ω _ _ => M.μ_nonneg ω⟩

/-- When the version space is unanimous everywhere (`DIS = ∅`), the conservative grant *is* the truth:
risk and burden are both zero. -/
theorem exact_of_DIS_empty (M : Model Ω) {V : Finset Θ} {θs : Θ} (hreal : Realizes (acc θs) M)
    (hθ : θs ∈ V) (hdis : DIS acc V = ∅) :
    (∀ ω, ω ∈ G1 acc V ↔ acc θs ω = true) ∧ M.R (G1 acc V) = 0 ∧ M.B (G1 acc V) = 0 := by
  have hiff : ∀ ω, ω ∈ G1 acc V ↔ acc θs ω = true := by
    intro ω
    refine ⟨fun hω => G1_subset_truth hθ hω, fun ht => mem_G1.2 fun θ hθV => ?_⟩
    by_contra hne
    have : ω ∈ DIS acc V := mem_DIS.2 ⟨θs, hθ, θ, hθV, fun h => hne (h ▸ ht)⟩
    rw [hdis] at this; exact absurd this (Finset.notMem_empty ω)
  refine ⟨hiff, ?_, ?_⟩
  · apply M.R_eq_zero_of_accept
    intro ω hω; rw [hreal ω, (hiff ω).1 hω]; simp
  · have h := B_G1_le_DIS M hreal hθ
    rw [hdis, Finset.sum_empty] at h
    exact le_antisymm h (M.B_nonneg _)

/-! ## Worst-case residual-risk estimate over the version space (item 3: non-increasing) -/

variable (acc) in
open Classical in
/-- `Rvs V G = ∑_{ω∈G, some θ∈V rejects ω} h(ω) μ(ω)`: the residual risk of `G` if the worst hypothesis still
consistent with the answers is the truth (pointwise). -/
noncomputable def Rvs (M : Model Ω) (V : Finset Θ) (G : Finset Ω) : ℝ :=
  ∑ ω ∈ G, (if ∃ θ ∈ V, acc θ ω = false then M.h ω * M.μ ω else 0)


/-- The estimate is a sound upper bound on the true risk whenever the truth is consistent. -/
theorem R_le_Rvs (M : Model Ω) {V : Finset Θ} {θs : Θ} (hreal : Realizes (acc θs) M) (hθ : θs ∈ V)
    (G : Finset Ω) : M.R G ≤ Rvs acc M V G := by
  classical
  unfold Model.R Rvs
  refine Finset.sum_le_sum fun ω _ => ?_
  rw [hreal ω]
  by_cases ht : acc θs ω = true
  · rw [if_pos ht, sub_self, zero_mul, zero_mul]
    split_ifs
    · exact mul_nonneg (M.h_nonneg ω) (M.μ_nonneg ω)
    · exact le_rfl
  · have hf : acc θs ω = false := by simpa using ht
    have hex : ∃ θ ∈ V, acc θ ω = false := ⟨θs, hθ, hf⟩
    rw [if_pos hex, hf]
    simp

/-- **Monotonicity of the residual-risk estimate.** For a fixed grant, more (correct or not) answers never
increase `Rvs`. -/
theorem Rvs_anti (M : Model Ω) {V V' : Finset Θ} (hsub : V' ⊆ V) (G : Finset Ω) :
    Rvs acc M V' G ≤ Rvs acc M V G := by
  classical
  unfold Rvs
  refine Finset.sum_le_sum fun ω _ => ?_
  by_cases h' : ∃ θ ∈ V', acc θ ω = false
  · obtain ⟨θ, hθ, hf⟩ := h'
    have h1 : ∃ θ ∈ V', acc θ ω = false := ⟨θ, hθ, hf⟩
    have h2 : ∃ θ ∈ V, acc θ ω = false := ⟨θ, hsub hθ, hf⟩
    rw [if_pos h1, if_pos h2]
  · rw [if_neg h']
    split_ifs
    · exact mul_nonneg (M.h_nonneg ω) (M.μ_nonneg ω)
    · exact le_rfl

/-- Along an elicitation run (answers only accumulate), the estimate is non-increasing. -/
theorem Rvs_run_anti (M : Model Ω) {H : Finset Θ} {obs obs' : List (Ω × Bool)}
    (hsub : ∀ o ∈ obs, o ∈ obs') (G : Finset Ω) :
    Rvs acc M (VS acc H obs') G ≤ Rvs acc M (VS acc H obs) G :=
  Rvs_anti M (VS_anti hsub) G

/-- The conservative grant has zero estimated residual risk, for every version space. -/
theorem Rvs_G1 (M : Model Ω) (V : Finset Θ) : Rvs acc M V (G1 acc V) = 0 := by
  classical
  unfold Rvs
  refine Finset.sum_eq_zero fun ω hω => ?_
  have hn : ¬ ∃ θ ∈ V, acc θ ω = false := by
    rintro ⟨θ, hθ, hf⟩
    rw [(mem_G1.1 hω) θ hθ] at hf
    simp at hf
  rw [if_neg hn]

end PcaIntent
