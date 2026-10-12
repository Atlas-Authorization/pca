--------------------------- MODULE Attenuation ---------------------------
(***************************************************************************)
(* Formal, machine-checkable model of PCA capability-chain attenuation over *)
(* a caveat lattice.                                                        *)
(*                                                                         *)
(* Source of truth:                                                        *)
(*   - docs/specs/agentic-auth-proof-carrying-authority.md section 5.2      *)
(*     (attenuable delegation; the capability chain is the budget tree).    *)
(*   - packages/pca/src/capability.ts : verifyChain enforces STRUCTURAL     *)
(*     attenuation -- a child's caveat list must contain the parent's list  *)
(*     as an EXACT PREFIX (no drop, reorder or edit) and may only APPEND     *)
(*     caveats, each a conjunctive constraint.                              *)
(*   - packages/pca/src/predicates.ts : the constraint families (verb set,  *)
(*     resource match, blast-radius / budget cap) a caveat can impose.      *)
(*                                                                         *)
(* We model the SHIPPED construction directly (append-only hops) and prove  *)
(* the semantic consequence the structure exists to guarantee:             *)
(*                                                                         *)
(*     a child's effective authority is always a subset of its parent's    *)
(*     -- adding caveats only narrows; no hop can widen scope/verb/budget.  *)
(*                                                                         *)
(* A negative control (AllowWiden) adds an ILLEGAL hop that drops a parent  *)
(* caveat, so TLC can exhibit the counterexample and confirm the invariant  *)
(* has teeth: without the prefix rule, monotonicity fails.                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Verbs,        \* universe of verbs,     e.g. {v1, v2}
    Resources,    \* universe of resources, e.g. {r1, r2}
    MaxBlast,     \* max blast-radius level a budget caveat can cap (0..MaxBlast)
    MaxDepth,     \* longest delegation chain explored (<= 4 keeps TLC finite)
    AllowWiden    \* negative control: if TRUE, a hop may illegally DROP its last caveat

ASSUME MaxBlast \in Nat
ASSUME MaxDepth \in Nat /\ MaxDepth >= 1
ASSUME AllowWiden \in BOOLEAN

\* The universe of concrete actions a capability could authorise.
Actions == [verb: Verbs, resource: Resources, blast: 0..MaxBlast]

(***************************************************************************)
(* Caveat kinds (the constraint families of predicates.ts / capability.ts): *)
(*   verb_in      -> action.verb must lie in an allowed verb set  (scope/verb)*)
(*   resource_in  -> action.resource must lie in an allowed set   (scope/prefix)*)
(*   max_blast    -> action.blast must be <= a cap   (budget / max_blast_radius)*)
(* Each caveat is a CONJUNCTIVE constraint: an action is authorised only if  *)
(* it satisfies every caveat on the hop.                                     *)
(***************************************************************************)
Caveats ==
          [type: {"verb_in"},     set: (SUBSET Verbs) \ {{}}]
    \cup  [type: {"resource_in"}, set: (SUBSET Resources) \ {{}}]
    \cup  [type: {"max_blast"},   cap: 0..MaxBlast]

Satisfies(cav, a) ==
    CASE cav.type = "verb_in"     -> a.verb \in cav.set
      [] cav.type = "resource_in" -> a.resource \in cav.set
      [] cav.type = "max_blast"   -> a.blast <= cav.cap

\* Effective authority of a hop = the set of actions satisfying EVERY caveat on it.
Eff(caveatSeq) ==
    { a \in Actions : \A i \in 1..Len(caveatSeq) : Satisfies(caveatSeq[i], a) }

\* s is an exact prefix of t (the structural rule verifyChain enforces hop-to-hop).
IsPrefix(s, t) ==
    /\ Len(s) <= Len(t)
    /\ \A i \in 1..Len(s) : s[i] = t[i]

VARIABLES chain   \* a sequence of hops; chain[k] is hop k's caveat sequence

vars == << chain >>

\* Root grant: a single root hop carrying no caveats (the full committed envelope).
Init == chain = << << >> >>

\* Legal delegate/attenuate: append a new hop whose caveats are the parent's caveats
\* followed by exactly one freshly added conjunctive caveat (capability.ts delegate).
Delegate ==
    /\ Len(chain) < MaxDepth
    /\ \E cav \in Caveats :
         chain' = Append(chain, Append(chain[Len(chain)], cav))

\* Negative control: an ILLEGAL hop that drops the parent's last caveat -- a widening
\* the shipped verifier rejects.  Enabled only when AllowWiden is TRUE.
Widen ==
    /\ AllowWiden
    /\ Len(chain) < MaxDepth
    /\ Len(chain[Len(chain)]) > 0
    /\ chain' = Append(chain,
                       SubSeq(chain[Len(chain)], 1, Len(chain[Len(chain)]) - 1))

\* Stutter so the chain terminating at MaxDepth is not reported as a deadlock.
Next == Delegate \/ Widen \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ chain \in Seq(Seq(Caveats))
    /\ Len(chain) \in 1..MaxDepth

\* Structural rule the verifier enforces: every hop keeps its parent's caveats as an
\* exact prefix (append-only).  Violated by a Widen hop.
PrefixPreserved ==
    \A k \in 2..Len(chain) : IsPrefix(chain[k-1], chain[k])

\* THE MONOTONICITY INVARIANT: a child's effective authority is a subset of its
\* parent's.  Adding caveats only narrows; no hop can widen scope/verb/budget.
Monotone ==
    \A k \in 2..Len(chain) : Eff(chain[k]) \subseteq Eff(chain[k-1])

\* Transitive form: every hop stays within the root's authority (implied by Monotone
\* by transitivity of subset; checked independently).
WithinRoot ==
    \A k \in 1..Len(chain) : Eff(chain[k]) \subseteq Eff(chain[1])

Invariant ==
    /\ Monotone
    /\ WithinRoot
    /\ PrefixPreserved
=============================================================================
