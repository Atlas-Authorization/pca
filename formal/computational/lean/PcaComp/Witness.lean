/-!
  Transparency-ledger witness quorum (`ledger.ts`: `WitnessPolicy`, `verifyWitnessCosignatures`; C2SP tlog-witness).

  A tree head is accepted when at least `k` DISTINCT trusted witnesses (out of the `n` listed) hold a valid cosignature
  for it. This file proves the quorum-intersection argument that makes "no split view" follow:

    * `quorums_share_honest`: if `2k > n + f` (`f` = number of dishonest trusted witnesses), any two accepting
      quorums contain a common HONEST witness. (The `k + k - n` overlap exceeds `f`.)
    * `no_split_view`: if honest witnesses keep a consistent view (an honest witness never cosigns two heads that are
      not consistent with each other, the tlog-witness rule enforced by checking a consistency proof, which the Dafny
      model `formal/dafny/Merkle.dfy` (`ConsSound`, `ConsPrefix`) proves sound for ALL tree sizes), then any two heads that
      both reach the quorum are consistent. In particular, at the same size they are the same root, so a log cannot show
      two roots at one size to two verifiers that both require the quorum.
  The counting is over the deduplicated trusted key set, as the implementation does (`new Set`).

  ASSUMED (named): NA-WITNESS, that fewer than `2k - n` of the trusted witnesses are dishonest, and that an honest
  witness applies the consistency rule before it cosigns; NA-ED for the cosignatures themselves (EasyCrypt C-1);
  independent operation of the witnesses (the policy cannot check it; it is a deployment property, listed in
  `maturity.md` under "independent witnesses"). A witness set run by one party is one witness. Liveness (that a quorum
  is reachable) is not claimed.

  Core Lean only, no `sorry`.
-/
namespace PcaComp.Witness

theorem count_and_or {α : Type} (l : List α) (a b : α → Bool) :
    l.countP (fun x => a x && b x) + l.countP (fun x => a x || b x) = l.countP a + l.countP b := by
  induction l with
  | nil => simp
  | cons x l ih =>
      simp only [List.countP_cons]
      cases ha : a x <;> cases hb : b x <;> simp [ha, hb] <;> omega

/-- two quorums of at least `k` out of `n` trusted witnesses, with `f < 2k - n` faulty ones, share an honest witness -/
theorem quorums_share_honest {α : Type} (U : List α) (A B Fl : α → Bool) (k f : Nat)
    (hA : k ≤ U.countP A) (hB : k ≤ U.countP B) (hF : U.countP Fl ≤ f) (hk : f + U.length < 2 * k) :
    ∃ w, w ∈ U ∧ A w = true ∧ B w = true ∧ Fl w = false := by
  refine Classical.byContradiction fun hno => ?_
  have hsub : ∀ x, x ∈ U → (A x && B x) = true → Fl x = true := by
    intro x hx hab
    refine Classical.byContradiction fun hf => hno ⟨x, hx, ?_, ?_, ?_⟩
    · simpa using (Bool.and_eq_true_iff.mp hab).1
    · simpa using (Bool.and_eq_true_iff.mp hab).2
    · simpa using hf
  have h1 : U.countP (fun x => A x && B x) ≤ U.countP Fl := List.countP_mono_left hsub
  have h2 := count_and_or U A B
  have h3 : U.countP (fun x => A x || B x) ≤ U.length := List.countP_le_length
  omega

/-- A head type with a size, a consistency relation, and cosigning by witnesses. -/
theorem no_split_view {α H : Type} (U : List α) (signed : α → H → Bool) (Fl : α → Bool)
    (Cons : H → H → Prop) (size : H → Nat) (k f : Nat)
    (hF : U.countP Fl ≤ f) (hk : f + U.length < 2 * k)
    (honest_consistent : ∀ w, w ∈ U → Fl w = false → ∀ h1 h2, signed w h1 = true → signed w h2 = true →
        size h1 ≤ size h2 → Cons h1 h2)
    (h1 h2 : H) (hs : size h1 ≤ size h2)
    (q1 : k ≤ U.countP (fun w => signed w h1)) (q2 : k ≤ U.countP (fun w => signed w h2)) :
    Cons h1 h2 := by
  obtain ⟨w, hw, a, b, c⟩ := quorums_share_honest U (fun w => signed w h1) (fun w => signed w h2) Fl k f q1 q2 hF hk
  exact honest_consistent w hw c h1 h2 a b hs

end PcaComp.Witness
