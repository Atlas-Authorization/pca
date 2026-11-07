/-!
  Wesolowski VDF timelock (`pca-vdf`, `vdf.ts`, `timelock.ts`).

  The verifier computes the Fiat-Shamir prime `l = hashToPrime(x, y, T, N)`, `r = 2^T mod l`, and accepts iff
  `pi^l * x^r = y (mod N)`.

  PROVED:
    * `wesolowski_complete`: for every ring `R` (here `Z/N`), every `x`, every `T` and every prime-or-not `l`, the
      honest proof `pi = x^q` with `2^T = l*q + r` makes the verification equation hold with `y = x^(2^T)`. So an
      honest prover is never rejected, whatever `l` the hash yields.
    * `x_binding`: the VDF input is derived from the action AND the beacon AND the modulus; two different triples that
      give the same input are a hash collision, so a proof for one action or beacon does not verify for another.
  ASSUMED (named; NOT mechanised): soundness and sequentiality.
    NA-AROOT: the adaptive root assumption in the group `Z/N*` for the RSA-2048 challenge modulus (Boneh, Bunz,
    Fischlin 2018 / Wesolowski 2019): an accepting proof means `y = x^(2^T)`; NA-RSA: nobody holds the factorisation of
    that modulus (the trapdoor); NA-SEQ: computing `x^(2^T)` takes `T` sequential squarings (no known shortcut), which is
    what makes the delay a delay; NA-ROM for `hashToPrime`. A VDF's wall-clock guarantee is a hardware statement and
    is not a theorem about the code.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Vdf

open Lean.Grind

theorem padd {R : Type} [CommRing R] (x : R) (a b : Nat) : x ^ (a + b) = x ^ a * x ^ b := by
  induction b with
  | zero => simp [Semiring.pow_zero]; grind
  | succ b ih => rw [← Nat.add_assoc, Semiring.pow_succ, Semiring.pow_succ, ih]; grind

theorem ppow {R : Type} [CommRing R] (x : R) (q l : Nat) : (x ^ q) ^ l = x ^ (l * q) := by
  induction l with
  | zero => simp [Semiring.pow_zero]
  | succ l ih => rw [Semiring.pow_succ, ih, Nat.succ_mul, padd]

/-- with `T` the exponent `2^steps` (as a natural number), `T = l * q + r`, the honest `pi = x^q` verifies -/
theorem wesolowski_complete {R : Type} [CommRing R] (x : R) (T l q r : Nat) (h : T = l * q + r) :
    (x ^ q) ^ l * x ^ r = x ^ T := by
  subst h; rw [ppow, padd]

def Coll {α β : Type} (H : α → β) : Prop := ∃ a b, a ≠ b ∧ H a = H b

/-- the VDF input commits to (action digest, beacon, modulus) -/
theorem x_binding {A B N X : Type} (hx : A × B × N → X) (u v : A × B × N) (h : hx u = hx v) : u = v ∨ Coll hx := by
  by_cases e : u = v
  · exact Or.inl e
  · exact Or.inr ⟨u, v, e, h⟩

end PcaComp.Vdf
