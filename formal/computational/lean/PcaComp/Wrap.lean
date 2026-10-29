/-!
  The glue around the signature and proof backends: `pca-bbs` (presentation transcript), `pca-fndsa` / `pca-less-wasm`
  (suite pinning in the hybrid wrappers) and `stark-pca` / `pca-folding-ivc` (statement binding). The core
  cryptography of those backends is NOT proved here; what is proved is the PCA-side wrapper logic that every claim about
  them relies on.

  PROVED:
    * `transcript_inj`: the BBS presentation challenge input is a fixed-width prefix followed by the length-prefixed
      presentation header; two transcripts with the same encoding have the same prefix and the same header, so a
      presentation made for one action (header) cannot be replayed under another, and the disclosed set cannot be
      swapped for one with the same encoding. `lp_inj` is the underlying length-prefix lemma.
    * `pinned_accepts_only_pinned_suite` / `hybrid_needs_both`: the verifier takes the suite from the PINNED key, never
      from the signature; a signature claiming another suite is rejected (no downgrade, no algorithm confusion), and a
      hybrid (FN-DSA or LESS with Ed25519) accepts only when both component verifications accept (the EasyCrypt
      AND-combiner H-1 then carries the security argument).
    * `statement_bound`: the proof verifier is run on the statement digest the VERIFIER recomputes from the claim
      (policy digest, action digest), never one the prover supplies; so an accepted proof is a proof about this claim,
      and two claims with one digest are a hash collision. With knowledge soundness of the proof system
      (`NA-STARK`, `NA-NOVA`) an accepted claim has a witness for the relation.
  ASSUMED (named): NA-BBS (unforgeability, q-SDH on BLS12-381, draft-irtf-cfrg-bbs-signatures; the draft may still
  change, which is why the package awaits the final standard), NA-PQ (FN-DSA and LESS), NA-ED, NA-STARK (the FRI soundness
  numbers of NUM-4 and the DEEP-ALI theorem, NA-PG, NA-DEEP), NA-NOVA (Nova folding knowledge soundness in the ROM,
  Kothapalli, Setty, Tzialla 2022; Poseidon as a random oracle), NA-ROM. Zero knowledge of the STARK is NOT claimed (the
  ledger's STARK-ZK row records that openings reveal witness columns).

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Wrap

/-- a length-prefixed field: the length as one symbol, then the bytes -/
def lp (x : List Nat) : List Nat := x.length :: x

theorem lp_inj {x y : List Nat} (h : lp x = lp y) : x = y := by
  simp only [lp, List.cons.injEq] at h
  exact h.2

/-- fixed-width prefix `p` then the length-prefixed header: `enc p h = p ++ lp h` -/
def enc (p h : List Nat) : List Nat := p ++ lp h

theorem transcript_inj {p p' h h' : List Nat} (hlen : p.length = p'.length) (e : enc p h = enc p' h') :
    p = p' ∧ h = h' := by
  unfold enc at e
  obtain ⟨e1, e2⟩ := List.append_inj e hlen
  exact ⟨e1, lp_inj e2⟩

/-! ### Suite pinning -/

/-- the verifier's decision for a key, a claimed suite and a signature: the suite comes from the pin -/
def VerifyPinned {K S : Type} [DecidableEq S] (pin : K → Option S) (ver : S → K → Prop) (k : K) (claimed : S) : Prop :=
  pin k = some claimed ∧ ver claimed k

theorem pinned_accepts_only_pinned_suite {K S : Type} [DecidableEq S] (pin : K → Option S) (ver : S → K → Prop)
    (k : K) (claimed : S) (h : VerifyPinned pin ver k claimed) : pin k = some claimed := h.1

theorem no_downgrade {K S : Type} [DecidableEq S] (pin : K → Option S) (ver : S → K → Prop)
    (k : K) (s s' : S) (hs : VerifyPinned pin ver k s) (hs' : VerifyPinned pin ver k s') : s = s' := by
  have := hs.1.symm.trans hs'.1
  exact Option.some.inj this

/-- a hybrid wrapper accepts iff both component verifications accept -/
def Hybrid (v1 v2 : Prop) : Prop := v1 ∧ v2

theorem hybrid_needs_both {v1 v2 : Prop} (h : Hybrid v1 v2) : v1 ∧ v2 := h

/-! ### Statement binding -/

def Coll {α β : Type} (H : α → β) : Prop := ∃ a b, a ≠ b ∧ H a = H b

/-- the verifier recomputes the statement digest from the claim and runs the proof verifier on it -/
def Accept {C D P : Type} (digest : C → D) (pverify : D → P → Prop) (c : C) (pi : P) : Prop := pverify (digest c) pi

theorem statement_bound {C D P : Type} (digest : C → D) (pverify : D → P → Prop) (rel : D → Prop)
    (sound : ∀ d pi, pverify d pi → rel d) (c : C) (pi : P) (h : Accept digest pverify c pi) : rel (digest c) :=
  sound _ _ h

theorem claims_collide {C D : Type} (digest : C → D) (c c' : C)
    (hd : digest c = digest c') (hne : c ≠ c') :
    Coll digest := ⟨c, c', hne, hd⟩

end PcaComp.Wrap
