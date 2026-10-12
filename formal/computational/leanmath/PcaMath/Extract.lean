import PcaMath.Rom

/-!
# Knowledge soundness of Fiat-Shamir sigma proofs in the random-oracle model

Composition of two checked facts:
* `PcaMath.Rom.fork_rom` : the forking lemma (counting form, any `q`, any answer space `H`);
* special soundness of the sigma protocol (here proved for the Schnorr proof over any module over a
  field, the algebra of the prime-order group; the OR proof and the range proof are the
  EasyCrypt lemmas `or_ss`, `range_extract`, see the doc for the exact scope).

`knowledge_soundness`: for any random-oracle prover (`out`: accepted run -> fork index, announcement,
response; it makes at most `q` queries and is causal), the forking extractor outputs a valid witness with
probability at least `acc * (acc / q - 1 / |H|)`.
-/

open Finset

namespace PcaMath.Extract

open PcaMath.Fork PcaMath.Rom

section KS
variable {R H A Z W X : Type*} [Fintype R] [Fintype H] [DecidableEq R] [DecidableEq H] {q : ℕ}

/-- special soundness of a sigma protocol with challenge space `H`. -/
structure SpecialSound (X W A H Z : Type*) where
  Rel : X → W → Prop
  V : X → A → H → Z → Prop
  ext : X → A → H → Z → H → Z → W
  sound : ∀ x a e z e' z', e ≠ e' → V x a e z → V x a e' z' → Rel x (ext x a e z e' z')

/-- The prover, as a function of its coins and the table of random-oracle answers.  `out ω = some (i, a, z)`
    iff the run is accepting, the proof's challenge was the answer to query `i`, announcement `a`, response `z`. -/
structure Prover (S : SpecialSound X W A H Z) (x : X) (q : ℕ) where
  out : R × (Fin q → H) → Option (Fin q × A × Z)
  accepts : ∀ ω i a z, out ω = some (i, a, z) → S.V x a (ω.2 i) z
  causal : ∀ i ω ω' a z a' z', cls i ω' = cls i ω → out ω = some (i, a, z) →
    out ω' = some (i, a', z') → a = a'

/-- accepting probability numerator and the forking index. -/
def Prover.idx {S : SpecialSound X W A H Z} {x : X} (P : Prover (R := R) S x q) :
    R × (Fin q → H) → Option (Fin q) := fun ω => (P.out ω).map Prod.fst

open Classical in
/-- the extraction mass: forked pairs on which the extractor's output is a witness. -/
noncomputable def extMass {S : SpecialSound X W A H Z} {x : X} (P : Prover (R := R) S x q) : ℝ :=
  ∑ i, ∑ ω ∈ accSet P.idx i,
    ((univ.filter (fun ω' : R × (Fin q → H) => ω' ∈ accSet P.idx i ∧ cls i ω' = cls i ω ∧ ans i ω' ≠ ans i ω ∧
      ∃ a z a' z', P.out ω = some (i, a, z) ∧ P.out ω' = some (i, a', z') ∧
        S.Rel x (S.ext x a (ans i ω) z (ans i ω') z'))).card : ℝ) / (csize q H i : ℝ)

open Classical in
theorem ext_eq_frk {S : SpecialSound X W A H Z} {x : X} (P : Prover (R := R) S x q) :
    extMass P = frkMass P.idx := by
  classical
  unfold extMass frkMass forkMass
  apply Finset.sum_congr rfl; intro i _
  apply Finset.sum_congr rfl; intro ω hω
  congr 3
  apply Finset.filter_congr
  intro ω' _
  constructor
  · rintro ⟨h1, h2, h3, _⟩; exact ⟨h1, h2, h3⟩
  · rintro ⟨h1, h2, h3⟩
    refine ⟨h1, h2, h3, ?_⟩
    simp only [accSet, Finset.mem_filter, Finset.mem_univ, true_and, Prover.idx, Option.map_eq_some_iff] at hω h1
    obtain ⟨⟨i1, a, z⟩, ho, hi⟩ := hω
    obtain ⟨⟨i2, a', z'⟩, ho', hi'⟩ := h1
    simp only at hi hi'
    subst hi; subst hi'
    refine ⟨a, z, a', z', ho, ho', ?_⟩
    have ha : a = a' := P.causal _ ω ω' a z a' z' h2 ho ho'
    subst ha
    exact S.sound x a _ z _ z' (fun h => h3 h.symm) (P.accepts ω _ a z ho) (P.accepts ω' _ a z' ho')

/-- **Knowledge soundness in the ROM** (Pointcheval-Stern / Bellare-Neven).  With `acc` the probability that
the prover's proof is accepted and `Pr_ext` the probability that the forking extractor outputs a witness,
`Pr_ext >= acc * (acc / q - 1 / |H|)`. -/
theorem knowledge_soundness [Nonempty R] [Nonempty H] {S : SpecialSound X W A H Z} {x : X}
    (P : Prover (R := R) S x q) :
    extMass P / (Fintype.card (R × (Fin q → H)) : ℝ) ≥
      (accMass (accSet P.idx) / (Fintype.card (R × (Fin q → H)) : ℝ)) *
        ((accMass (accSet P.idx) / (Fintype.card (R × (Fin q → H)) : ℝ)) / (q : ℝ)
          - 1 / (Fintype.card H : ℝ)) := by
  rw [ext_eq_frk]; exact fork_rom P.idx

end KS

/-! ## The Schnorr instance: statement `D`, base `h`, relation `D = w • h`
    (the additive group of the prime-order group as a module over the scalar field). -/
section Schnorr
variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

def schnorrSS (h : G) : SpecialSound G F G F F where
  Rel D w := D = w • h
  V D a e z := z • h = a + e • D
  ext _ _ e z e' z' := (e - e')⁻¹ * (z - z')
  sound := by
    intro D a e z e' z' hne h1 h2
    have hne' : e - e' ≠ 0 := sub_ne_zero.mpr hne
    have h3 : (z - z') • h = (e - e') • D := by
      rw [sub_smul, sub_smul, h1, h2]; abel
    rw [mul_smul, h3, smul_smul, inv_mul_cancel₀ hne', one_smul]

end Schnorr

end PcaMath.Extract
