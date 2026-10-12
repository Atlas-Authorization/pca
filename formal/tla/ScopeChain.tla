------------------------------- MODULE ScopeChain -------------------------------
(* scope (verb_in) and resource (resource_in, path prefix) caveats along a delegation chain: the SAME check as
   formal/tamarin/pca_scope_resource.spthy, for bounded model checking.

   Tamarin                    here
   Principal_Grant            Grant(cv): a chain <<cv>> (the root grant's caveat is chain[1])
   Delegate                   Delegate(cv): append a hop.  In Tamarin the honest delegator signs WHATEVER caveat
                              it is handed (In(sc), In(rp)), so every sequence of caveats is a constructible chain.
   Walk_Start                 the LEAF hop (last element here): scope AND resource checked
   Walk_Step                  every ANCESTOR hop: scope and resource checked;
                              Bug = "no_ancestor_res"   checks only the scope   (NO_ANCESTOR_RES)
                              Bug = "no_ancestor_scope" checks only the resource (NO_ANCESTOR_SCOPE)
   Accept                     Act(v, r): the verifier accepted verb v on resource path r with this chain

   The state is ONE chain under construction plus the last accepted action: the properties are per accepted
   action, and two chains never interact (signatures are perfect, as in the symbolic model), so exploring every
   chain up to MaxDepth one at a time covers every accepted (chain, action) pair up to that bound.

   Invariants (Tamarin lemma):
     ResourceNarrowing   resource_narrowing_all_hops / attack_resource_escalation
     ScopeNarrowing      scope_narrowing_all_hops    / attack_scope_escalation
     RootBoundsAction    root_scope_bounds_action /\ root_resource_bounds_action
*)
EXTENDS Naturals, Sequences

CONSTANTS Verbs, Atoms, MaxLen, MaxDepth, Bug

Paths      == UNION {[1..k -> Atoms] : k \in 0..MaxLen}        \* resource patterns (prefixes); <<>> = everything
Resources  == UNION {[1..k -> Atoms] : k \in 1..MaxLen}
Scopes     == SUBSET Verbs \ {{}}                              \* a verb_in set; Verbs itself plays 'any'
Caveats    == [scope : Scopes, pat : Paths]

IsPrefix(p, r) == Len(p) <= Len(r) /\ SubSeq(r, 1, Len(p)) = p

VARIABLES chain, acc      \* acc = <<>> or <<verb, resource>> of the last action the verifier accepted on chain

vars == <<chain, acc>>

HopOK(i, v, r, leaf) ==
  /\ (leaf \/ Bug # "no_ancestor_scope") => v \in chain[i].scope
  /\ (leaf \/ Bug # "no_ancestor_res")   => IsPrefix(chain[i].pat, r)

Init == chain = <<>> /\ acc = <<>>

Grant(cv)    == chain = <<>> /\ chain' = <<cv>> /\ acc' = <<>>
Delegate(cv) == 0 < Len(chain) /\ Len(chain) < MaxDepth /\ chain' = Append(chain, cv) /\ acc' = <<>>
Act(v, r)    == /\ 0 < Len(chain)
                /\ \A i \in 1..Len(chain) : HopOK(i, v, r, i = Len(chain))
                /\ acc' = <<v, r>> /\ UNCHANGED chain

Next == \/ \E cv \in Caveats : Grant(cv) \/ Delegate(cv)
        \/ \E v \in Verbs, r \in Resources : Act(v, r)

Spec == Init /\ [][Next]_vars

ResourceNarrowing == acc # <<>> => \A i \in 1..Len(chain) : IsPrefix(chain[i].pat, acc[2])
ScopeNarrowing    == acc # <<>> => \A i \in 1..Len(chain) : acc[1] \in chain[i].scope
RootBoundsAction  == acc # <<>> => acc[1] \in chain[1].scope /\ IsPrefix(chain[1].pat, acc[2])
=================================================================================
