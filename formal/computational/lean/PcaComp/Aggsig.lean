/-!
  BLS aggregate signatures with proof of possession (`pca-aggsig`; draft-irtf-cfrg-bls-signature, "pop" scheme):
  the rogue-key defence.

  Model: exponent view, as in `Oprf.lean`. A public key is the scalar `pk` (standing for `g^pk`), `hm` the discrete
  log of the hash-to-curve image of the message, a signature the scalar `sigma`, and the pairing equation
  `e(sigma, g) = e(H(m), pk)` reads `sigma = pk * hm` (`Valid`). The aggregate of a key list verifies against the SUM of
  its keys. Hardness (that nobody can compute `sk` from `pk`) cannot be stated in the exponent view; it enters through
  the named assumptions below.

  PROVED:
    * `rogue_key_attack`: WITHOUT proof of possession the attack is real: for honest `pkh` and any scalar `x` the
      attacker registers `pka = x - pkh` and forges an aggregate on any message from `x` alone, without `pkh`'s secret.
      This is why the registry exists.
    * `pop_reduction`: WITH proof of possession every admitted key has an extracted secret; then ANY verifying aggregate
      on a message yields a verifying SINGLE-key signature of the honest key on the same message,
      `sigma - (sum of extracted secrets) * hm`. So an aggregate forgery is a single-key forgery (the Ristenpart-Yilek
      reduction).
    * `pop_domain_separation`: a message signature is a valid proof of possession only if the message-domain and
      pop-domain hash images collide, which the distinct DSTs rule out.
    * `agg_verify_requires_registered`: the verifier's acceptance condition names registered, distinct keys only.
  ASSUMED (named): NA-POP (proof-of-possession extraction: a key admitted with a valid PoP has a secret the reduction
  can extract; the Fiat-Shamir or ROM extraction of the PoP, which is itself a BLS signature), NA-BLS (single-key BLS is
  EUF-CMA in the ROM under co-GDH on BLS12-381; Boneh, Lynn, Shacham 2004; Boneh, Drijvers, Neven 2018), NA-ROM for
  hash-to-curve. The BLS12-381 arithmetic and the 96-byte encodings are not modelled; the "distinct keys" rule and the
  exact subgroup checks are implementation facts checked by the vectors.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Aggsig

open Lean.Grind

variable {F : Type} [CommRing F]

/-- the pairing equation in the exponent -/
def Valid (pk hm sigma : F) : Prop := sigma = pk * hm

/-- an aggregate: the sum of the keys -/
def sumF : List F → F
  | [] => 0
  | a :: l => a + sumF l

/-- The rogue key `x - pkh` makes the aggregate key `x`, whose "secret" the attacker holds. -/
theorem rogue_key_attack (pkh x hm : F) : Valid (pkh + (x - pkh)) hm (x * hm) := by
  unfold Valid; grind

/-- With extracted secrets for every non-honest key, an aggregate signature is a single-key signature in disguise. -/
theorem pop_reduction (pkh hm sigma : F) (rogue : List F)
    (hv : Valid (pkh + sumF rogue) hm sigma) : Valid pkh hm (sigma - sumF rogue * hm) := by
  unfold Valid at *; grind

/-- With a nonzero key, a message signature is a PoP signature only if the two hash domains collide. -/
theorem pop_domain_separation {K : Type} [Field K] (pk hm hp sigma : K) (hpk : pk ≠ 0)
    (hs : Valid pk hm sigma) (hpop : Valid pk hp sigma) : hm = hp := by
  unfold Valid at *
  have h : pk * (hm - hp) = 0 := by grind
  have hinv : pk⁻¹ * pk = 1 := by grind
  grind

/-- The verifier's acceptance condition: distinct, registered keys and a valid aggregate. -/
def AggVerify (registered : F → Prop) (keys : List F) (hm sigma : F) : Prop :=
  keys.Nodup ∧ (∀ k, k ∈ keys → registered k) ∧ Valid (sumF keys) hm sigma

theorem agg_verify_requires_registered (registered : F → Prop) (keys : List F) (hm sigma : F)
    (h : AggVerify registered keys hm sigma) : ∀ k, k ∈ keys → registered k := h.2.1

theorem agg_verify_requires_distinct (registered : F → Prop) (keys : List F) (hm sigma : F)
    (h : AggVerify registered keys hm sigma) : keys.Nodup := h.1

end PcaComp.Aggsig
