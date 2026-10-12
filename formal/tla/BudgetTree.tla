------------------------------- MODULE BudgetTree -------------------------------
(* budget_alloc delegation tree, the SAME model as formal/tamarin/pca_budget_v4.spthy, for bounded model checking.

   Tamarin v4 rule            here
   Root_Grant                 Init (root meter cnt[Root] = RootLim)
   Alloc_Child_R/_D           Alloc(n, p, l): child limit l <= parent LIMIT lim[p] (the !Le(climit, plim) premise);
                              Bug = "no_parent_check" drops that check (NO_PARENT_CHECK)
   Spend_Begin_Root/_Node     Begin(s, n): a spend of one unit by the holder of node n
   Debit_Mid / Debit_Root     DebitHop(s): ONE hop, atomic: meter > 0, decrement, move to the parent;
                              at the root the spend is complete (Spent)
   DEBIT_LEAF_ONLY            Bug = "leaf_only": Begin debits only the acting node's own meter and is Spent at once
   NONATOMIC_DEBIT            Bug = "nonatomic": a hop is Read (snapshot meter-1) then, later, a blind Write of the
                              snapshot (lost update), as Debit_Read_* / Debit_Write_*
   Meters count down from the allocation; a meter at 0 cannot be debited (Tamarin: no !Dec row for c0).
   A spend that meets an empty meter is stuck (Tamarin: no rule applies); there is no rollback in the model.

   Invariants (Tamarin lemma):
     RootBound        root_bound / attack_overspend: at most RootLim completed spends
     NodeBound        node_bound (generalised to any limit): a node is debited by at most lim[n] distinct spends
     AllocMonotone    alloc_monotone
     SpendDebitsRoot  spend_debits_root
     NoNegative       no_negative_spend
*)
EXTENDS Naturals, FiniteSets

CONSTANTS Nodes,      \* non-root node ids (allocated dynamically, any shape of tree)
          Root,       \* the root node id
          Spends,     \* spend ids (each begins at most once: Fr(~sid))
          RootLim,    \* the root limit (Tamarin: 'c2', -DROOT3: 'c3')
          MaxLim,     \* largest limit a child may request (Tamarin: 'c3')
          Bug         \* "none" | "leaf_only" | "nonatomic" | "no_parent_check"

AllN == Nodes \cup {Root}

VARIABLES alloc,     \* allocated non-root nodes
          parent,    \* parent of each allocated node
          lim,       \* allocation (limit) of each node
          cnt,       \* meter of each node
          st,        \* spend state: "idle" | "debit" | "write" | "done"
          at,        \* the node a spend is currently debiting
          snap,      \* NONATOMIC: the value read, to be blindly written
          debited,   \* debited[n] = spends that decremented n's meter
          spent      \* completed spends (Tamarin Spent(sid, root))

vars == <<alloc, parent, lim, cnt, st, at, snap, debited, spent>>

Init ==
  /\ alloc = {}
  /\ parent = [n \in Nodes |-> Root]
  /\ lim = [n \in AllN |-> IF n = Root THEN RootLim ELSE 0]
  /\ cnt = [n \in AllN |-> IF n = Root THEN RootLim ELSE 0]
  /\ st = [s \in Spends |-> "idle"]
  /\ at = [s \in Spends |-> Root]
  /\ snap = [s \in Spends |-> 0]
  /\ debited = [n \in AllN |-> {}]
  /\ spent = {}

Alloc(n, p, l) ==
  /\ n \in Nodes \ alloc
  /\ p \in alloc \cup {Root}
  /\ Bug = "no_parent_check" \/ l <= lim[p]
  /\ alloc' = alloc \cup {n}
  /\ parent' = [parent EXCEPT ![n] = p]
  /\ lim' = [lim EXCEPT ![n] = l]
  /\ cnt' = [cnt EXCEPT ![n] = l]
  /\ UNCHANGED <<st, at, snap, debited, spent>>

Begin(s, n) ==
  /\ st[s] = "idle"
  /\ n \in alloc \cup {Root}
  /\ IF Bug = "leaf_only"
       THEN /\ cnt[n] > 0
            /\ cnt' = [cnt EXCEPT ![n] = @ - 1]
            /\ debited' = [debited EXCEPT ![n] = @ \cup {s}]
            /\ spent' = spent \cup {s}
            /\ st' = [st EXCEPT ![s] = "done"]
            /\ at' = [at EXCEPT ![s] = n]
       ELSE /\ st' = [st EXCEPT ![s] = "debit"]
            /\ at' = [at EXCEPT ![s] = n]
            /\ UNCHANGED <<cnt, debited, spent>>
  /\ UNCHANGED <<alloc, parent, lim, snap>>

\* after the meter of node m has been written for spend s: continue to the parent, or complete at the root
Advance(s, m) ==
  IF m = Root THEN /\ spent' = spent \cup {s}
                   /\ st' = [st EXCEPT ![s] = "done"]
                   /\ UNCHANGED at
              ELSE /\ at' = [at EXCEPT ![s] = parent[m]]
                   /\ st' = [st EXCEPT ![s] = "debit"]
                   /\ UNCHANGED spent

\* shipped: one atomic hop (Debit_Mid / Debit_Root)
DebitHop(s) ==
  LET m == at[s] IN
  /\ Bug \notin {"nonatomic", "leaf_only"}
  /\ st[s] = "debit"
  /\ cnt[m] > 0
  /\ cnt' = [cnt EXCEPT ![m] = @ - 1]
  /\ debited' = [debited EXCEPT ![m] = @ \cup {s}]
  /\ Advance(s, m)
  /\ UNCHANGED <<alloc, parent, lim, snap>>

\* NONATOMIC_DEBIT: read ...
DebitRead(s) ==
  LET m == at[s] IN
  /\ Bug = "nonatomic"
  /\ st[s] = "debit"
  /\ cnt[m] > 0
  /\ snap' = [snap EXCEPT ![s] = cnt[m] - 1]
  /\ st' = [st EXCEPT ![s] = "write"]
  /\ UNCHANGED <<alloc, parent, lim, cnt, at, debited, spent>>

\* ... and later blind-write the value read (lost update)
DebitWrite(s) ==
  LET m == at[s] IN
  /\ Bug = "nonatomic"
  /\ st[s] = "write"
  /\ cnt' = [cnt EXCEPT ![m] = snap[s]]
  /\ debited' = [debited EXCEPT ![m] = @ \cup {s}]
  /\ Advance(s, m)
  /\ UNCHANGED <<alloc, parent, lim, snap>>

Next ==
  \/ \E n \in Nodes, p \in AllN, l \in 0..MaxLim : Alloc(n, p, l)
  \/ \E s \in Spends, n \in AllN : Begin(s, n)
  \/ \E s \in Spends : DebitHop(s) \/ DebitRead(s) \/ DebitWrite(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ alloc \subseteq Nodes
  /\ st \in [Spends -> {"idle", "debit", "write", "done"}]
  /\ spent \subseteq Spends

RootBound       == Cardinality(spent) <= RootLim
NodeBound       == \A n \in alloc \cup {Root} : Cardinality(debited[n]) <= lim[n]
AllocMonotone   == \A n \in alloc : lim[n] <= lim[parent[n]]
SpendDebitsRoot == \A s \in spent : s \in debited[Root]
NoNegative      == \A n \in AllN : cnt[n] >= 0
=================================================================================
