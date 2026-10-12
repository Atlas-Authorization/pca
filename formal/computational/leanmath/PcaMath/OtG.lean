import Mathlib
import PcaMath.OtPerm

open Finset

namespace PcaMath.OtDefs

theorem ratio_arith (N M Vn k g h kp kh : ℕ) (Gc cX : ℕ) (hN : 0 < N) (hk : k ≤ kp) (hh : h ≤ kh)
    (hg : g ≤ h) (hhM : h ≤ M)
    (hG : (N : ℝ) ^ (Vn + g) * N ≤ (Gc : ℝ) * N + (((k + g + h) * (k + g + h - 1) : ℕ) : ℝ) * (N : ℝ) ^ (Vn + g))
    (hcX : Gc * (N - (k + g + h)).factorial ≤ cX) :
    (1 - (((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) / N) *
        ((((N - k).factorial * N ^ (M - h) : ℕ) : ℝ) / ((N.factorial * N ^ M : ℕ) : ℝ))
      ≤ (cX : ℝ) / ((N.factorial * N ^ Vn : ℕ) : ℝ) := by
  have hNr : (0 : ℝ) < N := by exact_mod_cast hN
  set L := k + g + h with hL
  have hL0 : L ≤ kp + 2 * kh := by omega
  have hLL : L * (L - 1) ≤ (kp + 2 * kh) * (kp + 2 * kh - 1) :=
    Nat.mul_le_mul hL0 (Nat.sub_le_sub_right hL0 1)
  set ε0 : ℝ := (((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) / N with hε0
  set εL : ℝ := ((L * (L - 1) : ℕ) : ℝ) / N with hεL
  have hεle : εL ≤ ε0 := by
    apply div_le_div_of_nonneg_right _ hNr.le
    exact_mod_cast hLL
  have hNf : (0 : ℝ) < N.factorial := by exact_mod_cast Nat.factorial_pos _
  have hRHSnn : 0 ≤ (cX : ℝ) / ((N.factorial * N ^ Vn : ℕ) : ℝ) := by positivity
  by_cases hε : 1 ≤ ε0
  · have : (1 - ε0) ≤ 0 := by linarith
    have hnn : 0 ≤ ((((N - k).factorial * N ^ (M - h) : ℕ) : ℝ) / ((N.factorial * N ^ M : ℕ) : ℝ)) := by positivity
    nlinarith
  · push_neg at hε
    have hε' : εL < 1 := lt_of_le_of_lt hεle hε
    have hLN : L ≤ N := by
      by_contra hc
      push_neg at hc
      have hlt : L * (L - 1) < N := by
        have : ((L * (L - 1) : ℕ) : ℝ) < N := by
          have := hε'; rw [hεL, div_lt_one hNr] at this; exact this
        exact_mod_cast this
      have h3 : (N + 1) * N ≤ L * (L - 1) := Nat.mul_le_mul hc (by omega)
      nlinarith
    -- factorial inequality
    have hfac : (N - k).factorial ≤ N ^ (g + h) * (N - L).factorial := by
      have hc : g + h ≤ N - k := by omega
      have h1 := OtPerm.factorial_le_sub_mul_pow (N - k) (g + h) hc
      have h2 : N - k - (g + h) = N - L := by omega
      rw [h2] at h1
      calc (N - k).factorial ≤ (N - L).factorial * (N - k) ^ (g + h) := h1
        _ ≤ (N - L).factorial * N ^ (g + h) := Nat.mul_le_mul_left _ (Nat.pow_le_pow_left (Nat.sub_le _ _) _)
        _ = _ := by ring
    have hfacr : ((N - k).factorial : ℝ) ≤ (N : ℝ) ^ g * (N : ℝ) ^ h * (N - L).factorial := by
      have := (Nat.cast_le (α := ℝ)).mpr hfac
      push_cast at this
      rw [pow_add] at this
      exact this
    -- Gc lower bound
    have hGr : (N : ℝ) ^ (Vn + g) * (1 - εL) ≤ Gc := by
      have h1 : (N : ℝ) ^ (Vn + g) * (1 - εL) * N ≤ Gc * N := by
        have : (N : ℝ) ^ (Vn + g) * (1 - εL) * N = (N : ℝ) ^ (Vn + g) * N - ((L * (L - 1) : ℕ) : ℝ) * (N : ℝ) ^ (Vn + g) := by
          rw [hεL]; field_simp
        linarith
      exact le_of_mul_le_mul_right h1 hNr
    have hcXr : (Gc : ℝ) * (N - L).factorial ≤ cX := by exact_mod_cast hcX
    have hMh : (N : ℝ) ^ M = (N : ℝ) ^ (M - h) * (N : ℝ) ^ h := by
      rw [← pow_add]; congr 1; omega
    push_cast
    have hP : (0 : ℝ) < (N : ℝ) ^ h := by positivity
    have hQ : (0 : ℝ) < (N : ℝ) ^ g := by positivity
    have hR : (0 : ℝ) < (N : ℝ) ^ Vn := by positivity
    have hS : (0 : ℝ) < (N : ℝ) ^ (M - h) := by positivity
    have hF2 : (0 : ℝ) ≤ ((N - L).factorial : ℝ) := by positivity
    have hF1 : (0 : ℝ) ≤ ((N - k).factorial : ℝ) := by positivity
    rw [hMh, ← mul_div_assoc, div_le_div_iff₀ (by positivity) (by positivity)]
    have h1ε : 0 ≤ 1 - ε0 := by linarith
    have h1εL : 0 ≤ 1 - εL := by linarith
    -- (1-ε0) * (F1 * S) * (Nf * R) ≤ cX * (Nf * S * P)
    have step1 : (1 - ε0) * (((N - k).factorial : ℝ)) ≤ (1 - εL) * ((N : ℝ) ^ g * (N : ℝ) ^ h * (N - L).factorial) := by
      calc (1 - ε0) * (((N - k).factorial : ℝ)) ≤ (1 - εL) * ((N - k).factorial : ℝ) :=
            mul_le_mul_of_nonneg_right (by linarith) hF1
        _ ≤ _ := mul_le_mul_of_nonneg_left hfacr h1εL
    have step2 : (N : ℝ) ^ (Vn + g) * (1 - εL) * ((N - L).factorial : ℝ) ≤ cX := by
      calc _ ≤ (Gc : ℝ) * ((N - L).factorial : ℝ) := mul_le_mul_of_nonneg_right hGr hF2
        _ ≤ _ := hcXr
    rw [pow_add] at step2
    have hpos : 0 ≤ (N : ℝ) ^ (M - h) * (N.factorial : ℝ) := by positivity
    calc (1 - ε0) * (((N - k).factorial : ℝ) * (N : ℝ) ^ (M - h)) * ((N.factorial : ℝ) * (N : ℝ) ^ Vn)
        = ((1 - ε0) * ((N - k).factorial : ℝ)) * ((N : ℝ) ^ (M - h) * (N.factorial : ℝ) * (N : ℝ) ^ Vn) := by ring
      _ ≤ ((1 - εL) * ((N : ℝ) ^ g * (N : ℝ) ^ h * (N - L).factorial)) *
            ((N : ℝ) ^ (M - h) * (N.factorial : ℝ) * (N : ℝ) ^ Vn) :=
          mul_le_mul_of_nonneg_right step1 (by positivity)
      _ = ((N : ℝ) ^ Vn * (N : ℝ) ^ g * (1 - εL) * ((N - L).factorial : ℝ)) *
            ((N : ℝ) ^ h * ((N : ℝ) ^ (M - h) * (N.factorial : ℝ))) := by ring
      _ ≤ (cX : ℝ) * ((N : ℝ) ^ h * ((N : ℝ) ^ (M - h) * (N.factorial : ℝ))) :=
          mul_le_mul_of_nonneg_right step2 (by positivity)
      _ = _ := by ring

end PcaMath.OtDefs
