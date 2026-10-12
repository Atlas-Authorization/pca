/-
  Theorem 2 — PCA capability-attenuation monotonicity.

  The machine-checked (Lean) image of `formal/pca/Attenuation.tla`, already
  model-checked by TLC (see formal/pca/README.md). Where TLC checks
  `Eff(chain[k]) ⊆ Eff(chain[k-1])` over finite chains, this file PROVES it for
  all capabilities and all append-only chains of any length.

  Source correspondence (TLA+  ↔  capability.ts / predicates.ts  ↔  Lean here):
    * TLA `Actions`                         ↔ action universe            ↔ `Action`
    * TLA `Caveats` (verb_in/resource_in/max_blast) ↔ predicates.ts families ↔ `Caveat`
    * TLA `Satisfies`                        ↔ caveat predicate            ↔ `Satisfies`
    * TLA `Eff(caveatSeq)`                   ↔ effective authority         ↔ `Eff` / `EffSub`
    * TLA `IsPrefix` (verifyChain prefix rule)↔ capability.ts append-only   ↔ `IsPrefix`
    * TLA `Delegate` (append one caveat)      ↔ capability.ts `delegate`    ↔ `hops`
    * TLA `Monotone`                          ↔ the attenuation guarantee   ↔ `eff_antitone_append`, `chainMono_hops`
    * TLA `WithinRoot`                        ↔ transitive form             ↔ `within_root`

  We model `verifyChain`'s SHIPPED structural rule directly: a child hop's caveat
  list is its parent's list with caveats APPENDED (an exact prefix, no drop / reorder
  / edit), each caveat a conjunctive constraint. We then prove the semantic
  consequence the structure exists to guarantee: effective authority only narrows.
-/
namespace PcaProof.Attenuation

/-- A concrete action the capability could authorise (TLA `Actions`:
    `[verb, resource, blast]`). Levels are naturals; nothing depends on their size. -/
structure Action where
  verb : Nat
  resource : Nat
  blast : Nat
deriving Repr, DecidableEq

/-- Caveat kinds = the conjunctive constraint families of `predicates.ts` /
    `capability.ts` (TLA `Caveats`):
      * `verb_in`     — `action.verb` must lie in an allowed set        (scope / verb)
      * `resource_in` — `action.resource` must lie in an allowed set    (scope / prefix)
      * `max_blast`   — `action.blast` must be ≤ a cap                  (budget / blast-radius) -/
inductive Caveat where
  | verb_in (allowed : List Nat)
  | resource_in (allowed : List Nat)
  | max_blast (cap : Nat)
deriving Repr

/-- `Satisfies cav a` — a single conjunctive constraint (TLA `Satisfies`). -/
def Satisfies : Caveat → Action → Prop
  | .verb_in s,     a => a.verb ∈ s
  | .resource_in s, a => a.resource ∈ s
  | .max_blast c,   a => a.blast ≤ c

/-- Effective authority of a hop: the actions satisfying EVERY caveat on it
    (TLA `Eff(caveatSeq) == { a : ∀ i, Satisfies(caveatSeq[i], a) }`). -/
def Eff (hop : List Caveat) (a : Action) : Prop :=
  ∀ cav ∈ hop, Satisfies cav a

/-- `child`'s effective authority is a subset of `parent`'s (`Eff child ⊆ Eff parent`).
    The Prop-level reading of `⊆` on the action universe. -/
def EffSub (child parent : List Caveat) : Prop :=
  ∀ a, Eff child a → Eff parent a

/-- `p` is an exact prefix of `c` — the structural rule `verifyChain` enforces
    hop-to-hop (TLA `IsPrefix`): the child keeps the parent's caveats verbatim and
    only appends. -/
def IsPrefix (p c : List Caveat) : Prop := ∃ s, c = p ++ s

/-- **Theorem 2 — THE MONOTONICITY INVARIANT (one hop).** Appending caveats can only
    NARROW authority: for any parent hop and any appended caveats `ext`,
    `Eff (parent ++ ext) ⊆ Eff parent`. No hop can widen scope / verb / budget.
    (TLA `Monotone`; capability.ts prefix-equality + append-only.) -/
theorem eff_antitone_append (parent ext : List Caveat) :
    EffSub (parent ++ ext) parent := by
  intro a ha cav hcav
  exact ha cav (List.mem_append_left ext hcav)

/-- Monotonicity in prefix form: if `p` is an exact prefix of `c`, then
    `Eff c ⊆ Eff p` (the shape `verifyChain` guarantees for every hop). -/
theorem eff_sub_of_prefix {p c : List Caveat} (h : IsPrefix p c) : EffSub c p := by
  obtain ⟨s, rfl⟩ := h
  exact eff_antitone_append p s

/-- The hop states of a delegation chain, built by the append-only construction of
    TLA `Delegate` / capability.ts `delegate`: starting from `root`, each entry in
    `exts` is the caveat(s) appended at that hop. Produces
    `[root, root++ext₀, root++ext₀++ext₁, …]`. -/
def hops (root : List Caveat) : List (List Caveat) → List (List Caveat)
  | []           => [root]
  | ext :: rest  => root :: hops (root ++ ext) rest

/-- Every chain produced by `hops` starts at its root. -/
theorem hops_eq_cons (root : List Caveat) (exts : List (List Caveat)) :
    ∃ t, hops root exts = root :: t := by
  cases exts with
  | nil        => exact ⟨[], rfl⟩
  | cons e r   => exact ⟨hops (root ++ e) r, rfl⟩

/-- Every hop in a delegation chain keeps the root as an exact prefix (append-only
    is preserved along the whole chain). -/
theorem mem_hops_prefix (root : List Caveat) (exts : List (List Caveat))
    (hop : List Caveat) (hmem : hop ∈ hops root exts) : IsPrefix root hop := by
  induction exts generalizing root with
  | nil =>
      simp only [hops, List.mem_singleton] at hmem
      subst hmem
      exact ⟨[], by simp⟩
  | cons ext rest ih =>
      simp only [hops, List.mem_cons] at hmem
      rcases hmem with rfl | hmem
      · exact ⟨[], by simp⟩
      · obtain ⟨s, hs⟩ := ih (root ++ ext) hmem
        exact ⟨ext ++ s, by rw [hs, List.append_assoc]⟩

/-- **Theorem 2 — TRANSITIVE form (TLA `WithinRoot`).** Every hop in a delegation
    chain stays within the ROOT's authority: `Eff hop ⊆ Eff root`, for a chain of
    any length. "The capability chain is the budget tree." -/
theorem within_root (root : List Caveat) (exts : List (List Caveat)) :
    ∀ hop ∈ hops root exts, EffSub hop root :=
  fun hop hmem => eff_sub_of_prefix (mem_hops_prefix root exts hop hmem)

/-- Consecutive monotonicity as a self-contained predicate over the hop list:
    every adjacent (parent, child) pair has `Eff child ⊆ Eff parent`
    (TLA `Monotone == ∀ k ∈ 2..Len : Eff(chain[k]) ⊆ Eff(chain[k-1])`). -/
def ChainMono : List (List Caveat) → Prop
  | []                      => True
  | [_]                     => True
  | parent :: child :: rest => EffSub child parent ∧ ChainMono (child :: rest)

/-- **Theorem 2 — CONSECUTIVE form (TLA `Monotone`).** For EVERY append-only chain,
    each child hop's authority is a subset of its immediate parent's. -/
theorem chainMono_hops (root : List Caveat) (exts : List (List Caveat)) :
    ChainMono (hops root exts) := by
  induction exts generalizing root with
  | nil => trivial
  | cons ext rest ih =>
      obtain ⟨t, ht⟩ := hops_eq_cons (root ++ ext) rest
      have hstep : hops root (ext :: rest) = root :: (root ++ ext) :: t := by
        simp only [hops, ht]
      rw [hstep]
      exact ⟨eff_antitone_append root ext, by rw [← ht]; exact ih (root ++ ext)⟩

/- ------------------------------------------------------------------------- -/
/-  Non-vacuity checks (the analogue of the TLA negative control): the        -/
/-  ordering is STRICT — appending a caveat genuinely drops actions, so        -/
/-  without the append-only/prefix rule a child could out-scope its parent.    -/
/- ------------------------------------------------------------------------- -/

/-- Appending `verb_in {1}` to the empty (root) hop narrows: `Eff child ⊆ Eff root`
    holds, but the reverse does NOT — the root authorises a verb-2 action the child
    forbids. This is exactly the widening `verifyChain`'s prefix rule forbids. -/
example :
    EffSub [Caveat.verb_in [1]] [] ∧ ¬ EffSub [] [Caveat.verb_in [1]] := by
  refine ⟨eff_antitone_append [] [Caveat.verb_in [1]], ?_⟩
  intro hcontra
  have hroot : Eff ([] : List Caveat) ⟨2, 0, 0⟩ := by
    intro cav hcav; simp at hcav
  have hchild : Eff [Caveat.verb_in [1]] ⟨2, 0, 0⟩ := hcontra ⟨2, 0, 0⟩ hroot
  have : (2 : Nat) ∈ [1] := hchild (Caveat.verb_in [1]) (by simp)
  simp at this

end PcaProof.Attenuation
