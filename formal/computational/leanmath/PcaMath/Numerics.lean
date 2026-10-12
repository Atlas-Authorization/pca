import Mathlib

/-!
# Arithmetic specialisations quoted in `docs/pca/security/computational-proofs.md`, machine-checked

* `retry_quarter`: the specialisation of `Star.retry_mass_ge` to `delta = p/(2kq)`, `T >= (4kq/p) ln(2k)`.
* `total_online_bounds`: the exact figure `MAC + 208 * sacrifice <= 53 * 2^-120 * (1 + 2^-58)`
  lies in `(2^-114.28, 2^-114.27]` (the "2^-114.27" of `06-mpc.md` section 4).
* `seq_num`: `2^40` sessions of the SPDZ MAC-check cost at most `2^-80 * (1 + 2^-58)`.
-/

open Real

namespace PcaMath.Numerics

/-- the specialisation: `(p - k δ q) (1 - (1 - (δ - ε))^T)^k >= p / 4`. -/
theorem retry_quarter (p ε q : ℝ) (k T : ℕ) (hp : 0 < p) (hp1 : p ≤ 1) (hk : 1 ≤ k) (hq : 1 ≤ q)
    (hε : 0 ≤ ε) (hεδ : ε ≤ p / (4 * k * q)) (hT : (4 * k * q / p) * Real.log (2 * k) ≤ T) :
    (p - k * (p / (2 * k * q)) * q) *
      (1 - (1 - (p / (2 * k * q) - ε)) ^ T) ^ k ≥ p / 4 := by
  have hk0 : (0 : ℝ) < k := by exact_mod_cast hk
  have hk1 : (1 : ℝ) ≤ k := by exact_mod_cast hk
  have hkq : 0 < (k : ℝ) * q := by positivity
  set x : ℝ := p / (2 * k * q) - ε with hx
  have e1 : p / (2 * k * q) = 2 * (p / (4 * k * q)) := by field_simp; ring
  have hx_lo : p / (4 * k * q) ≤ x := by rw [hx, e1]; linarith
  have hxpos : 0 < x := lt_of_lt_of_le (by positivity) hx_lo
  have hxle : x ≤ 1 / 2 := by
    have : p / (2 * k * q) ≤ 1 / 2 := by
      rw [div_le_div_iff₀ (by positivity) (by norm_num)]
      nlinarith
    rw [hx]; linarith
  -- (1 - x)^T <= exp(-x T) <= 1/(2k)
  have h2k : (0 : ℝ) < 2 * k := by positivity
  have hxT : Real.log (2 * k) ≤ x * T := by
    have h1 : x * ((4 * k * q / p) * Real.log (2 * k)) ≥ Real.log (2 * k) := by
      have hlog : 0 ≤ Real.log (2 * k) := Real.log_nonneg (by linarith)
      have : x * (4 * k * q / p) ≥ 1 := by
        have := mul_le_mul_of_nonneg_right hx_lo (show 0 ≤ 4 * k * q / p by positivity)
        have e : p / (4 * k * q) * (4 * k * q / p) = 1 := by field_simp
        linarith
      nlinarith
    nlinarith [mul_le_mul_of_nonneg_left hT hxpos.le]
  have hpow : (1 - x) ^ T ≤ 1 / (2 * k) := by
    have h0 : 0 ≤ 1 - x := by linarith
    have h1 : 1 - x ≤ Real.exp (-x) := by linarith [Real.add_one_le_exp (-x)]
    calc (1 - x) ^ T ≤ (Real.exp (-x)) ^ T := pow_le_pow_left₀ h0 h1 T
      _ = Real.exp (-(x * T)) := by rw [← Real.exp_nat_mul]; congr 1; ring
      _ ≤ Real.exp (-Real.log (2 * k)) := Real.exp_le_exp.mpr (by linarith)
      _ = 1 / (2 * k) := by rw [Real.exp_neg, Real.exp_log h2k]; simp
  have hc : 1 - 1 / (2 * (k : ℝ)) ≤ 1 - (1 - x) ^ T := by linarith
  have hc0 : 0 ≤ 1 - 1 / (2 * (k : ℝ)) := by
    have : 1 / (2 * (k : ℝ)) ≤ 1 := by rw [div_le_one h2k]; linarith
    linarith
  have hbern : (1 : ℝ) / 2 ≤ (1 - 1 / (2 * (k : ℝ))) ^ k := by
    have := one_add_mul_le_pow (a := -(1 / (2 * (k : ℝ)))) (by
      have : 1 / (2 * (k : ℝ)) ≤ 1 := by rw [div_le_one h2k]; linarith
      linarith) k
    have e : (1 : ℝ) + k * -(1 / (2 * (k : ℝ))) = 1 / 2 := by field_simp; ring
    rw [e] at this
    simpa [sub_eq_add_neg] using this
  have hpk : (1 - 1 / (2 * (k : ℝ))) ^ k ≤ (1 - (1 - x) ^ T) ^ k := pow_le_pow_left₀ hc0 hc k
  have e3 : (k : ℝ) * (p / (2 * k * q)) * q = p / 2 := by field_simp
  rw [e3]
  nlinarith

/-! ### the online total -/

/-- `53 * 2^-120 * (1 + 2^-58)` lies in `(2^-114.28, 2^-114.27]`: with `X = 53 * (2^58 + 1) / 2^58`,
    `2^5.72 < X <= 2^5.73`, i.e. (raising to the 100th power and clearing the denominator `2^5800`)
    `2^(572+5800) < (53 * (2^58 + 1))^100 <= 2^(573+5800)`. -/
theorem total_online_bounds :
    (2 : ℕ) ^ (572 + 5800) < (53 * (2 ^ 58 + 1)) ^ 100 ∧ (53 * (2 ^ 58 + 1) : ℕ) ^ 100 ≤ 2 ^ (573 + 5800) := by
  constructor <;> decide +kernel

/-- the sequential figure: `2^40 * ((2^60 + 4) / 2^180) = 2^-80 * (1 + 2^-58)`... up to the exact term. -/
theorem seq_num : (2 : ℚ) ^ 40 * ((2 ^ 60 + 4) / (2 ^ 60) ^ 3) = (1 / 2 ^ 80) * (1 + 4 / 2 ^ 60) := by
  norm_num

theorem seq_num_le : (2 : ℚ) ^ 40 * ((2 ^ 60 + 4) / (2 ^ 60) ^ 3) ≤ (1 / 2 ^ 80) * (1 + 1 / 2 ^ 58) := by
  norm_num

end PcaMath.Numerics
