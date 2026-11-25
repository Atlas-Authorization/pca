/-!
  FROST threshold signing (RFC 9591) as used by `frost.ts`, `frost-net.ts`, the PedPoP DKG and `pca-pq-threshold`:
  the PROTOCOL LOGIC around the published security reduction.

  Model: exponent view (see `Oprf.lean`): a group element is its discrete log in a scalar ring `F`.

  PROVED:
    * `aggregate_verifies` (ROBUSTNESS / completeness): if every participant's response passes the per-share check
      `z_i = R_i + c * lam_i * Y_i` against its verification share, the aggregate `z = sum z_i` satisfies the Schnorr
      verification equation `z = R + c * Y` with `R = sum R_i`, `Y = sum lam_i * Y_i` (the group key by interpolation).
    * `cheater_identified` (identifiable abort): if the aggregate fails, some participant failed its own check, so a
      bad aggregate is always attributable and one bad share cannot silently stall the others.
    * `accepted_has_honest_signer`: acceptance needs `t` DISTINCT participants whose shares are for exactly the
      signed `(msg, L)`; with at most `t - 1` corrupted, one of them is honest. Together with the binding factor
      below, an honest participant signed exactly this message and this signer set.
    * `binding_factor_binds`: the binding factor `rho_i = H(i, msg, L)` is injective in `(i, msg, L)` up to a
      collision of the hash, so a share cannot be moved to another message or signer set (the symbolic Tamarin and
      ProVerif models check the same property against an active network adversary).
  ALREADY MECHANISED ELSEWHERE (not repeated): the verification equation and the Feldman and interpolation core of the
  DKG (`leanmath/PcaMath/Alg.lean` FR-1, `Dkg.lean` DKG-core), the descriptor binding (CryptoVerif FR-5), the
  rogue-key defence of the DKG (ProVerif `pca_frost_dkg.pv`, Tamarin `pca_frost_dkg.spthy`), and the AND-combiner of
  `pca-pq-threshold` (EasyCrypt H-1, H-3).
  ASSUMED (named): NA-FROST, the published unforgeability of FROST / PedPoP (Bellare, Tessaro, Zhu, Crypto 2022 for
  FROST1 and FROST2 under OMDL in the ROM, static corruption; Komlo and Goldberg 2020 for the protocol), which is what
  makes "a share the adversary produced for an uncorrupted participant" a forgery; and NA-ED for the PQ co-signature.
  Not modelled: nonce generation and the nonce-reuse guards (SPENT_NONCES; the Tamarin model covers reuse), timing,
  the authenticated channel of the DKG.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Frost

open Lean.Grind

variable {F : Type} [CommRing F]

/-- one participant's data in the exponent: Lagrange coefficient, verification share, nonce part `R_i = d_i + e_i rho_i`
    and response `z_i` -/
structure Share (F : Type) where
  lam : F
  Y : F
  R : F
  z : F

/-- the per-share check of RFC 9591 section 5.3 -/
def ShareOk (c : F) (sh : Share F) : Prop := sh.z = sh.R + c * sh.lam * sh.Y

def sumZ : List (Share F) → F
  | [] => 0
  | s :: l => s.z + sumZ l
def sumR : List (Share F) → F
  | [] => 0
  | s :: l => s.R + sumR l
def sumY : List (Share F) → F
  | [] => 0
  | s :: l => s.lam * s.Y + sumY l

theorem aggregate_verifies (c : F) (shares : List (Share F)) (h : ∀ s, s ∈ shares → ShareOk c s) :
    sumZ shares = sumR shares + c * sumY shares := by
  induction shares with
  | nil => simp [sumZ, sumR, sumY]; grind
  | cons s l ih =>
      have hs := h s (List.mem_cons_self ..)
      have hl := ih (fun x hx => h x (List.mem_cons_of_mem _ hx))
      unfold ShareOk at hs
      simp only [sumZ, sumR, sumY]
      grind

theorem cheater_identified (c : F) (shares : List (Share F))
    (hbad : sumZ shares ≠ sumR shares + c * sumY shares) : ∃ s, s ∈ shares ∧ ¬ ShareOk c s := by
  refine Classical.byContradiction fun hno => hbad ?_
  apply aggregate_verifies
  intro s hs
  exact Classical.byContradiction fun hn => hno ⟨s, hs, hn⟩

/-! ### Counting and binding -/

/-- `t` distinct participants answered for `(msg, L)`; at most `t - 1` are corrupted: some answerer is honest. -/
theorem accepted_has_honest_signer {P : Type} [DecidableEq P] (t : Nat) (ids corrupted : List P)
    (hnd : ids.Nodup) (hlen : t ≤ ids.length) (hc : corrupted.length < t) :
    ∃ p, p ∈ ids ∧ p ∉ corrupted := by
  refine Classical.byContradiction fun hno => ?_
  have hsub : ids ⊆ corrupted := by
    intro p hp
    exact Classical.byContradiction fun hpc => hno ⟨p, hp, hpc⟩
  have := List.Nodup.length_le_of_subset hnd hsub
  omega

def Coll {α β : Type} (H : α → β) : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-- the binding factor commits to the participant, the message and the signer set -/
theorem binding_factor_binds {P M S B : Type} (H : P × M × S → B) (a b : P × M × S) (h : H a = H b) :
    a = b ∨ Coll H := by
  by_cases hab : a = b
  · exact Or.inl hab
  · exact Or.inr ⟨a, b, hab, h⟩

end PcaComp.Frost
