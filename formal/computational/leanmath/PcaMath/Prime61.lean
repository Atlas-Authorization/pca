import Mathlib

/-!
Primality of `2^61 - 1`.  Lucas-Lehmer: Mathlib's `lucas_lehmer_sufficiency` (a full proof that the
test implies primality of `2^p - 1`) plus its `norm_num` extension, which evaluates the 59
iterations `s -> s^2 - 2 (mod 2^61 - 1)` by kernel-checked natural-number arithmetic.
-/
namespace PcaMath

theorem lucasLehmer_61 : LucasLehmer.LucasLehmerTest 61 := by norm_num

theorem M61_prime : Nat.Prime (2 ^ 61 - 1) := by
  have := lucas_lehmer_sufficiency 61 (by norm_num) lucasLehmer_61
  simpa [mersenne] using this

end PcaMath
