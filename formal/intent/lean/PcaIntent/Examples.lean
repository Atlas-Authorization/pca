import PcaIntent.Credence

/-!
# A machine-checked caveat: the Bayesian estimate `R̂_n(G)` for a *fixed* grant is not monotone

One outcome `()`, two hypotheses (`true` accepts it, `false` rejects it), uniform prior, harm 1, workload 1.
Before any answer `p(()) = 1/2`, so `R̂_0({()}) = 1/2`. After the noise-free answer "no", the version space is
`{false}`, the posterior is the point mass on `false`, `p(()) = 0`, and `R̂_1({()}) = 1 > 1/2`.

So the monotone quantities are the version space, the conservative grant, the disagreement mass and the
worst-case estimate `Rvs` (`PcaIntent.VersionSpace`), and the posterior-expected risk of the *re-synthesised*
conservative grant, which stays `≤ δ · Hmax` at every step (`credence_bound`). The estimate of a grant that is
held fixed while answers arrive may go up: an answer can reveal that the grant was riskier than believed.
-/

namespace PcaIntent.Examples

open Finset

/-- `θ` accepts the single outcome iff `θ = true`. -/
def accB : Bool → Unit → Bool := fun θ _ => θ

/-- Harm 1, workload 1, true acceptability 0. -/
noncomputable def M1 : Model Unit where
  a := fun _ => 0
  h := fun _ => 1
  μ := fun _ => 1
  Hmax := 1
  a_nonneg := fun _ => le_rfl
  a_le_one := fun _ => zero_le_one
  h_nonneg := fun _ => zero_le_one
  h_le := fun _ => le_rfl
  μ_nonneg := fun _ => zero_le_one
  μ_sum := by simp

/-- Uniform prior. -/
noncomputable def prior : Posterior Bool where
  H := univ
  π := fun _ => 1 / 2
  nonneg := fun _ => by norm_num
  sum_one := by norm_num [Fintype.sum_bool]

/-- Point mass on `false` (the noise-free posterior after the answer "no"). -/
noncomputable def after : Posterior Bool where
  H := univ
  π := fun θ => if θ = true then 0 else 1
  nonneg := fun θ => by cases θ <;> simp
  sum_one := by simp [Fintype.sum_bool]

/-- The version space after the answer "no" is `{false}`, which is the support of `after`. -/
theorem vs_after : VS accB (univ : Finset Bool) [((), false)] = {false} := by
  ext θ
  rw [mem_VS]
  cases θ <;> simp [Consistent, accB]

theorem after_support (θ : Bool) (h : after.π θ ≠ 0) : θ ∈ VS accB (univ : Finset Bool) [((), false)] := by
  rw [vs_after]
  cases θ
  · simp
  · exact absurd (show after.π true = 0 by simp [after]) h

theorem rhat_prior : Rhat accB M1 prior {()} = 1 / 2 := by
  norm_num [Rhat, pAcc, prior, M1, accB, Finset.filter_insert, Finset.filter_singleton]

theorem rhat_after : Rhat accB M1 after {()} = 1 := by
  have hp : pAcc accB after () = 0 := by
    unfold pAcc
    apply Finset.sum_eq_zero
    intro θ hθ
    rw [Finset.mem_filter] at hθ
    obtain ⟨-, h2⟩ := hθ
    simp only [accB] at h2
    subst h2
    simp [after]
  simp [Rhat, hp, M1]

/-- **The fixed-grant Bayesian estimate can increase after a correct answer.** -/
theorem rhat_not_monotone : Rhat accB M1 prior {()} < Rhat accB M1 after {()} := by
  rw [rhat_prior, rhat_after]; norm_num

end PcaIntent.Examples
