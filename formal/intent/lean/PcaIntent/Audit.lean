import PcaIntent.VersionSpace

/-!
# T7: audit soundness, without realizability (spec §2.6 T7, §4.2c audit round)

`conf = {ω : (ω, yes) was observed}`. The only assumption on the principal is that **"yes" answers are
truthful** (`a(ω) = 1` whenever the answer at ω was yes; with cell questions, "yes" means the whole cell is
acceptable). Nothing is assumed about the hypothesis class: θ* need not exist.

* `T7_audit`      : any grant inside `conf` has zero risk;
* `G1_subset_conf`: if the audit round has observed every outcome of `G_1(VS_n)` and the version space is
  non-empty, every one of those observations was a "yes" (a "no" would contradict every θ ∈ VS accepting ω);
* `T7_G1`         : hence a completed audit gives `R(G_1(VS_n)) = 0`, with no realizability assumption;
* `T7_partial`    : a partial audit leaves `R(G) ≤ ∑_{ω ∈ G ∖ conf} h(ω) μ(ω)`.
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω]

/-- Truthful "yes" answers. -/
def YesTruthful (M : Model Ω) (obs : List (Ω × Bool)) : Prop := ∀ ω, (ω, true) ∈ obs → M.a ω = 1

/-- **T7 (core).** A grant every outcome of which received a truthful "yes" has zero misalignment risk. -/
theorem T7_audit (M : Model Ω) {obs : List (Ω × Bool)} (hyes : YesTruthful M obs) {G : Finset Ω}
    (hconf : ∀ ω ∈ G, (ω, true) ∈ obs) : M.R G = 0 :=
  M.R_eq_zero_of_accept fun ω hω => hyes ω (hconf ω hω)

/-- A completed audit of `G_1` sees only "yes" answers (non-empty version space). -/
theorem G1_subset_conf {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)}
    (hne : (VS acc H obs).Nonempty) (haudit : ∀ ω ∈ G1 acc (VS acc H obs), ∃ y, (ω, y) ∈ obs) :
    ∀ ω ∈ G1 acc (VS acc H obs), (ω, true) ∈ obs := by
  intro ω hω
  obtain ⟨y, hy⟩ := haudit ω hω
  obtain ⟨θ, hθ⟩ := hne
  have h1 : acc θ ω = true := (mem_G1.1 hω) θ hθ
  have h2 : acc θ ω = y := (mem_VS.1 hθ).2 (ω, y) hy
  rw [h1] at h2
  rw [h2]; exact hy

/-- **T7.** Completed audit round + truthful "yes" answers ⇒ `R(G_1(VS_n)) = 0`, without realizability. -/
theorem T7_G1 (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)}
    (hyes : YesTruthful M obs) (hne : (VS acc H obs).Nonempty)
    (haudit : ∀ ω ∈ G1 acc (VS acc H obs), ∃ y, (ω, y) ∈ obs) :
    M.R (G1 acc (VS acc H obs)) = 0 :=
  T7_audit M hyes (G1_subset_conf hne haudit)

open Classical in
/-- **T7 (partial audit).** Only the unconfirmed part of the grant carries risk. -/
theorem T7_partial (M : Model Ω) {obs : List (Ω × Bool)} (hyes : YesTruthful M obs) (G : Finset Ω) :
    M.R G ≤ ∑ ω ∈ G.filter (fun ω => (ω, true) ∉ obs), M.h ω * M.μ ω := by
  unfold Model.R
  rw [Finset.sum_filter]
  refine Finset.sum_le_sum fun ω _ => ?_
  by_cases hc : (ω, true) ∈ obs
  · rw [if_neg (not_not.2 hc), hyes ω hc]; simp
  · rw [if_pos hc]
    have h1 : 1 - M.a ω ≤ 1 := by linarith [M.a_nonneg ω]
    have hh : 0 ≤ M.h ω * M.μ ω := mul_nonneg (M.h_nonneg ω) (M.μ_nonneg ω)
    calc (1 - M.a ω) * M.h ω * M.μ ω = (1 - M.a ω) * (M.h ω * M.μ ω) := by ring
      _ ≤ 1 * (M.h ω * M.μ ω) := mul_le_mul_of_nonneg_right h1 hh
      _ = M.h ω * M.μ ω := one_mul _

end PcaIntent
