import Mathlib

/-!
# FR-3 (algebraic core): Feldman-VSS share verification and PedPoP key aggregation

`frost-dkg.ts` is PedPoP: every participant `p` deals a polynomial `f_p` of degree `< t`, broadcasts the
commitments `C_{p,k} = a_{p,k} • B` (with a Schnorr proof of possession for `C_{p,0}`), and sends the share
`f_p(i)` to participant `i`, who checks `f_p(i) • B = Σ_k i^k • C_{p,k}`.  The group key is `X = Σ_p C_{p,0}` and
the signing share of `i` is `s_i = Σ_p f_p(i)`.

Proved here (no assumption except `B ≠ 0`):
* `verify_sound`        a share that passes the check IS the value of the committed polynomial at `i`
* `shares_interpolate`  any `t` signing shares interpolate (Lagrange at 0) to the group key: `Σ λ_i • (s_i • B) = X`
The security of the proof of possession (no rogue-key attack) is NOT proved here: it is knowledge soundness of
the Schnorr proof (see `Extract.lean`) plus the FROST/AOMDL assumption (named assumption NA-FROST).
-/

open Finset Polynomial

namespace PcaMath.Dkg

variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

theorem smul_inj_B (B : G) (hB : B ≠ 0) : Function.Injective (fun s : F => s • B) := by
  intro a b h
  by_contra hne
  have : (a - b) • B = 0 := by simpa [sub_smul, sub_eq_zero] using h
  rcases smul_eq_zero.mp this with h1 | h1
  · exact hne (sub_eq_zero.mp h1)
  · exact hB h1

/-- the verification equation of participant `i` for dealer polynomial `f` (degree `< t`) -/
def VerifyShare (B : G) (t : ℕ) (C : ℕ → G) (i : F) (s : F) : Prop :=
  s • B = ∑ k ∈ Finset.range t, (i ^ k) • C k

theorem verify_sound (B : G) (hB : B ≠ 0) (t : ℕ) (f : F[X]) (hf : f.degree < t) (i s : F)
    (h : VerifyShare B t (fun k => f.coeff k • B) i s) : s = f.eval i := by
  unfold VerifyShare at h
  have e : ∑ k ∈ Finset.range t, (i ^ k) • (f.coeff k • B) = (f.eval i) • B := by
    by_cases hz : f = 0
    · subst hz; simp
    · rw [Polynomial.eval_eq_sum_range' (n := t) ((natDegree_lt_iff_degree_lt hz).mpr hf)]
      rw [Finset.sum_smul]
      refine Finset.sum_congr rfl fun k _ => ?_
      rw [smul_smul, mul_comm]
  rw [e] at h
  exact smul_inj_B B hB h

/-- the group key and the signing shares of a DKG with dealers `P` -/
theorem shares_interpolate {ι : Type*} (B : G) (t : ℕ) (P : Finset ι) (f : ι → F[X]) (hf : ∀ p ∈ P, (f p).degree < t)
    {κ : Type*} [DecidableEq κ] (S : Finset κ) (v : κ → F) (hv : Set.InjOn v S) (hS : S.card = t) :
    ∑ j ∈ S, (Lagrange.basis S v j).eval 0 • ((∑ p ∈ P, (f p).eval (v j)) • B)
      = ∑ p ∈ P, (f p).coeff 0 • B := by
  set g : F[X] := ∑ p ∈ P, f p with hg
  have hgdeg : g.degree < S.card := by
    rw [hS]
    refine lt_of_le_of_lt (degree_sum_le _ _) ?_
    exact (Finset.sup_lt_iff (WithBot.bot_lt_coe t)).mpr (fun p hp => hf p hp)
  have hint := Lagrange.eq_interpolate (v := v) hv hgdeg
  have h0 : g.eval 0 = ∑ j ∈ S, g.eval (v j) * (Lagrange.basis S v j).eval 0 := by
    conv_lhs => rw [hint]
    rw [Lagrange.interpolate_apply, eval_finsetSum]
    simp [eval_mul, eval_C]
  have hev : ∀ x, g.eval x = ∑ p ∈ P, (f p).eval x := fun x => by simp [hg, eval_finsetSum]
  have h00 : g.eval 0 = ∑ p ∈ P, (f p).coeff 0 := by
    rw [hev]; simp [coeff_zero_eq_eval_zero]
  calc ∑ j ∈ S, (Lagrange.basis S v j).eval 0 • ((∑ p ∈ P, (f p).eval (v j)) • B)
      = (∑ j ∈ S, g.eval (v j) * (Lagrange.basis S v j).eval 0) • B := by
        rw [Finset.sum_smul]
        refine Finset.sum_congr rfl fun j _ => ?_
        rw [smul_smul, ← hev, mul_comm]
    _ = g.eval 0 • B := by rw [← h0]
    _ = ∑ p ∈ P, (f p).coeff 0 • B := by rw [h00, Finset.sum_smul]

end PcaMath.Dkg
