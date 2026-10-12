import PcaProof.Attenuation

/-!
  Capability attenuation over delegation chains of ANY length, at the level of what the
  verifier actually compares (digests), with the hash-collision escape made explicit.

  `formal/pca-lean/PcaProof/Attenuation.lean` proves the semantic fact: appending caveats can
  only narrow effective authority.  It takes "the child's caveat list extends the parent's"
  as given.  `verifyChain` (capability.ts) does not compare caveats; it compares
  `hashCanonical` digests element by element.  This file adds the missing bridge:

    * `digest_prefix_or_collision` : a digest-level prefix check implies a semantic prefix
      OR exhibits two DIFFERENT caveats with the same digest (a hash collision);
    * `ChainOk` : an inductive validity predicate for chains of arbitrary length
      (issuer = parent's holder, parent link, digest-prefix of the caveat lists);
    * `chain_attenuation` : for every valid chain, either a collision exists among its
      caveats, or the effective authority is antitone along the whole chain;
    * `no_widening_after` : once a hop `h` is in the chain, every later hop's effective
      authority is contained in `h`'s (the Lean image of Corollary C-4);
    * `accepted_action_in_every_hop` : an action satisfying the leaf's caveats satisfies
      every earlier hop's caveats (Theorem C-3).

  It does NOT model signatures; that is the EasyCrypt side (`ec/PcaCore.ec`).  The two
  results compose as in `docs/pca/security/computational-proofs.md`.
-/
namespace PcaComp.Chain

open PcaProof.Attenuation

/-! ### digest-level prefix → semantic prefix, or a collision -/

/-- The verifier's check: the list of per-caveat digests of the parent is a prefix of the
    list of digests of the child. -/
def DigestPrefix {D : Type} (cdig : Caveat → D) (p c : List Caveat) : Prop :=
  List.map cdig p <+: List.map cdig c

theorem digest_prefix_or_collision {D : Type} (cdig : Caveat → D) :
    ∀ (p c : List Caveat), DigestPrefix cdig p c →
      p <+: c ∨ ∃ x y, x ≠ y ∧ cdig x = cdig y ∧ x ∈ p ∧ y ∈ c := by
  intro p
  induction p with
  | nil => intro c _; exact Or.inl (List.nil_prefix)
  | cons x p' ih =>
    intro c h
    cases c with
    | nil =>
      simp [DigestPrefix] at h
    | cons y c' =>
      simp only [DigestPrefix, List.map_cons, List.cons_prefix_cons] at h
      obtain ⟨hxy, hrest⟩ := h
      by_cases hx : x = y
      · subst hx
        rcases ih c' hrest with hpre | ⟨a, b, hab, hd, ha, hb⟩
        · exact Or.inl (List.cons_prefix_cons.mpr ⟨rfl, hpre⟩)
        · exact Or.inr ⟨a, b, hab, hd, List.mem_cons_of_mem _ ha, List.mem_cons_of_mem _ hb⟩
      · exact Or.inr ⟨x, y, hx, hxy, List.mem_cons_self, List.mem_cons_self⟩

/-! ### chains of any length -/

/-- A delegation hop as the verifier sees it. `K` = keys, `D` = digests. -/
structure Hop (K D : Type) where
  issuer  : K
  holder  : K
  parent  : Option D
  caveats : List Caveat

/-- The link rule between consecutive hops (capability.ts `verifyChain`, hop index ≥ 1):
    the child is issued by the parent's holder, names the parent's digest, and its caveat
    digests extend the parent's. -/
def Link {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D) (p c : Hop K D) : Prop :=
  c.issuer = p.holder ∧ c.parent = some (capHash p) ∧ DigestPrefix cdig p.caveats c.caveats

/-- Valid chains of arbitrary length: a root, then one linked hop at a time. -/
inductive ChainOk {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D) :
    List (Hop K D) → Prop
  | root (c : Hop K D) : c.parent = none → ChainOk capHash cdig [c]
  | step (l : List (Hop K D)) (p c : Hop K D) :
      ChainOk capHash cdig (l ++ [p]) → Link capHash cdig p c →
      ChainOk capHash cdig (l ++ [p, c])

/-- Digest-prefix is transitive. -/
theorem digestPrefix_trans {D : Type} (cdig : Caveat → D) {a b c : List Caveat} :
    DigestPrefix cdig a b → DigestPrefix cdig b c → DigestPrefix cdig a c :=
  fun h1 h2 => List.IsPrefix.trans h1 h2

/-- Every pair of hops, earlier before later, is related by digest-prefix of caveats.
    Proof by induction on the validity derivation (so for ALL lengths). -/
theorem chain_pairwise_digest {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D)
    {l : List (Hop K D)} (h : ChainOk capHash cdig l) :
    l.Pairwise (fun a b => DigestPrefix cdig a.caveats b.caveats) := by
  induction h with
  | root c _ => simp
  | step l p c _ hlink ih =>
    have hlast : (l ++ [p, c]) = (l ++ [p]) ++ [c] := by simp
    rw [hlast, List.pairwise_append]
    refine ⟨ih, by simp, ?_⟩
    intro a ha b hb
    simp at hb
    subst hb
    simp [List.mem_append] at ha
    rcases ha with ha | ha
    · -- a ∈ l : a ≤ p ≤ c
      have hpa : DigestPrefix cdig a.caveats p.caveats := by
        have := List.pairwise_append.mp ih
        exact this.2.2 a ha p (by simp)
      exact digestPrefix_trans cdig hpa hlink.2.2
    · subst ha; exact hlink.2.2

/-- Semantic pairwise prefix, or a collision among caveats of the chain. -/
theorem chain_attenuation {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D)
    {l : List (Hop K D)} (h : ChainOk capHash cdig l) :
    (∃ x y : Caveat, x ≠ y ∧ cdig x = cdig y) ∨
    l.Pairwise (fun a b => EffSub b.caveats a.caveats) := by
  classical
  by_cases hcol : ∃ x y : Caveat, x ≠ y ∧ cdig x = cdig y
  · exact Or.inl hcol
  · right
    have hp := chain_pairwise_digest capHash cdig h
    refine List.Pairwise.imp_of_mem ?_ hp
    intro a b _ _ hab
    rcases digest_prefix_or_collision cdig a.caveats b.caveats hab with hpre | ⟨x, y, hxy, hd, _, _⟩
    · obtain ⟨t, ht⟩ := hpre
      exact eff_sub_of_prefix ⟨t, ht.symm⟩
    · exact absurd ⟨x, y, hxy, hd⟩ hcol

/-- Corollary C-4 (Lean image).  Without a caveat-digest collision, no hop after `h` widens
    `h`'s authority, however many corrupted delegates follow, however long the chain. -/
theorem no_widening_after {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D)
    {l₁ l₂ : List (Hop K D)} {h : Hop K D}
    (hok : ChainOk capHash cdig (l₁ ++ h :: l₂))
    (hnc : ¬ ∃ x y : Caveat, x ≠ y ∧ cdig x = cdig y) :
    ∀ c ∈ l₂, EffSub c.caveats h.caveats := by
  intro c hc
  rcases chain_attenuation capHash cdig hok with hcol | hpw
  · exact absurd hcol hnc
  · have := List.pairwise_append.mp hpw
    have h2 := (List.pairwise_cons.mp this.2.1).1
    exact h2 c hc

/-- Theorem C-3 (Lean image).  An action that satisfies the leaf's caveats satisfies the
    caveats of every earlier hop of the chain (absent a collision). -/
theorem accepted_action_in_every_hop {K D : Type} (capHash : Hop K D → D) (cdig : Caveat → D)
    {l₁ l₂ : List (Hop K D)} {h leaf : Hop K D}
    (hok : ChainOk capHash cdig (l₁ ++ h :: l₂))
    (hnc : ¬ ∃ x y : Caveat, x ≠ y ∧ cdig x = cdig y)
    (hleaf : leaf ∈ l₂) (a : Action) (ha : Eff leaf.caveats a) :
    Eff h.caveats a :=
  no_widening_after capHash cdig hok hnc leaf hleaf a ha

end PcaComp.Chain
