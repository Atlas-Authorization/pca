import Mathlib

/-!
# STARK / FRI proven-security figures, computed in the checker from the pinned parameters

`docs/pca/security/proofs/07-stark-fri.md` quotes the proven-security terms of Winterfell 0.13.1
(`winter-air::proof::security`, Theorems 2 and 3 of ePrint 2024/1553) for `sdks/stark-pca`
(blow-up 8, 37 queries, no grinding, trace 64 x 56, f128 field `2^128 - 45*2^40 + 1`) and the same formulas
applied to `sdks/stark-pca-plonky3` (log-blowup 2, 64 queries, 8 query-PoW bits, Goldilocks^2 challenge field,
110 constraints, 60 committed polynomials, algebraic batching).

Here every term is checked as an exact rational inequality `X * 2^b <= |F|` ("the error term is at least `b` bits"),
using the formulas of the cited theorems as given (the theorem statements themselves are the named assumption A-DEEP;
this file does not re-derive them).  Square roots are removed by squaring.  The proximity parameter
`m` is the one the document reports as optimal (18 and 23); lower bounds on the best bits do not need optimality.

Terms (rho = 1/blowup, lde = 64 * blowup, l = m / (rho - 2m/lde), d = blowup + 1, alpha_m = (1 + 1/(2m)) sqrt(rho)):
ALI  : |F| / (l * (C-1)^[alg])           DEEP : |F| / (l^2 (d (n+1) + n - 1))
commit: |F| / ((m+1/2)^7 / (3 rho^(3/2)) * lde^2 * (Nc-1)^[alg])        query: 2^g / alpha_m^q
(UDR: ALI |F|/(C-1)^[alg], DEEP |F|/(d(n+1)+n-1), commit |F|/(lde (Nc-1)^[alg]), layer |F|/((f-1)(lde+1)),
 query 2^g / ((1 + rho+)/2)^q with rho+ = (n+2)/lde.)
-/

namespace PcaMath.Stark

/-- Winterfell field size. -/
def FW : ℚ := 2 ^ 128 - 45 * 2 ^ 40 + 1
/-- Plonky3 challenge field size: Goldilocks squared. -/
def FP : ℚ := (2 ^ 64 - 2 ^ 32 + 1) ^ 2

/-! ### stark-pca (Winterfell), 37 queries, blow-up 8: proven list decoding >= 54 bits at m = 18 -/

theorem winterfell_ldr_54 :
    -- ALI
    (2304 / 7 : ℚ) * 2 ^ 54 ≤ FW ∧
    -- DEEP: l^2 * (9 * 65 + 63)
    (2304 / 7 : ℚ) ^ 2 * 648 * 2 ^ 54 ≤ FW ∧
    -- FRI commit (squared): ((37/2)^7)^2 * (16 sqrt 2 / 3)^2 * (512^2)^2 * 2^108 <= |F|^2
    (((37 : ℚ) / 2) ^ 7) ^ 2 * (512 / 9) * (512 ^ 2) ^ 2 * 2 ^ 108 ≤ FW ^ 2 ∧
    -- FRI query (squared): alpha^2 = (37/36)^2 / 8
    ((((37 : ℚ) / 36) ^ 2) / 8) ^ 37 * 2 ^ 108 ≤ 1 := by
  unfold FW; refine ⟨?_, ?_, ?_, ?_⟩ <;> norm_num

/-- ... and the query term is binding: it is below 55 bits, so the quoted 54 is the minimum. -/
theorem winterfell_ldr_query_below_55 :
    1 < ((((37 : ℚ) / 36) ^ 2) / 8) ^ 37 * 2 ^ 110 := by norm_num

/-- proven unique decoding >= 30 bits (alpha_UD = (1 + 66/512)/2 = 289/512, 3 FRI layers of 8). -/
theorem winterfell_udr_30 :
    (2 : ℚ) ^ 30 ≤ FW ∧ 648 * (2 : ℚ) ^ 30 ≤ FW ∧ 512 * (2 : ℚ) ^ 30 ≤ FW ∧ 7 * 513 * (2 : ℚ) ^ 30 ≤ FW ∧
    ((289 : ℚ) / 512) ^ 37 * 2 ^ 30 ≤ 1 := by
  unfold FW; refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> norm_num

theorem winterfell_udr_query_below_31 : 1 < ((289 : ℚ) / 512) ^ 37 * 2 ^ 31 := by norm_num

/-- conjectured (ethSTARK Conjecture 1 as used by Winterfell): `min(min(128, 3 * 37) - 1, 128) = 110`. -/
theorem winterfell_conjectured : min (min 128 (3 * 37) - 1) 128 = 110 := by norm_num

/-! ### stark-pca-plonky3, 64 queries, rate 1/4, 8 PoW bits: proven list decoding >= 70 at m = 23 -/

theorem plonky3_ldr_70 :
    (2944 / 9 : ℚ) * 109 * 2 ^ 70 ≤ FP ∧
    (2944 / 9 : ℚ) ^ 2 * 388 * 2 ^ 70 ≤ FP ∧
    -- commit: (23.5)^7 / (3 * (1/4)^(3/2)) = (47/2)^7 * 8/3, times lde^2 = 256^2 and (Nc - 1) = 59
    (((47 : ℚ) / 2) ^ 7 * (8 / 3)) * 256 ^ 2 * 59 * 2 ^ 70 ≤ FP ∧
    -- query: alpha = (1 + 1/46)/2 = 47/92, 8 grinding bits
    ((47 : ℚ) / 92) ^ 64 * 2 ^ 62 ≤ 1 := by
  unfold FP; refine ⟨?_, ?_, ?_, ?_⟩ <;> norm_num

theorem plonky3_ldr_query_below_71 : 1 < ((47 : ℚ) / 92) ^ 64 * 2 ^ 63 := by norm_num

/-- proven unique decoding >= 50 bits (rho+ = 66/256, alpha_UD = 161/256, folding 2). -/
theorem plonky3_udr_50 :
    109 * (2 : ℚ) ^ 50 ≤ FP ∧ 388 * (2 : ℚ) ^ 50 ≤ FP ∧ 256 * 59 * (2 : ℚ) ^ 50 ≤ FP ∧ 257 * (2 : ℚ) ^ 50 ≤ FP ∧
    ((161 : ℚ) / 256) ^ 64 * 2 ^ 42 ≤ 1 := by
  unfold FP; refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> norm_num

theorem plonky3_udr_query_below_51 : 1 < ((161 : ℚ) / 256) ^ 64 * 2 ^ 43 := by norm_num

/-- neither configuration reaches 80 bits proven: the query terms are below 2^-55 / 2^-71 (so no 80). -/
theorem neither_80_proven :
    1 < ((((37 : ℚ) / 36) ^ 2) / 8) ^ 37 * 2 ^ 160 ∧ 1 < ((47 : ℚ) / 92) ^ 64 * 2 ^ 72 := by
  constructor <;> norm_num

end PcaMath.Stark
