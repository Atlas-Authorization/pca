------------------------------- MODULE PCA -------------------------------
(***************************************************************************)
(* Proof-Carrying Authority (PCA): the admission state machine.            *)
(*                                                                         *)
(* This is the TLA+ twin of tools/pca-model-check/model.ts (same guards,   *)
(* same effects, same invariants).  Sources of the semantics:              *)
(*   packages/pca/src/capability.ts   append-only caveats, hop signatures  *)
(*   packages/pca/src/risk.ts         requiredThreshold, admit(), debit,   *)
(*                                    recharge, safetyBound                *)
(*   packages/pca/src/revocation.ts   revocation set + guardian epoch,     *)
(*                                    PCActn.freshness.epoch >= epoch      *)
(*   packages/pca/src/policy-vm.ts    policy = hard gate (release)         *)
(*   packages/backend/src/pca/verify.ts  the check conjunction             *)
(*   reference-server route pca       adjudicateInner: gate (re-read under *)
(*                                    the lock), counter CAS, budget debit *)
(*                                    under FOR UPDATE, threshold, commit  *)
(*                                                                         *)
(* HOW TO RUN (needs Java + tla2tools.jar; neither was installed when this *)
(* was written, so the spec is UNCHECKED BY TLC -- the TypeScript twin is  *)
(* the executed evidence):                                                 *)
(*   java -cp tla2tools.jar tlc2.TLC -workers auto -config PCA.cfg PCA.tla *)
(* Use PCA_race.cfg to exhibit the commit-order race (expected violation   *)
(* of RevocationSafety) and PCA_fix.cfg for the re-gate-at-commit fix.     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    NG,            \* number of grants (<= 2 in the shipped cfg)
    MaxCtr,        \* counters range over 1..MaxCtr
    MaxEpochClaim, \* an action may claim freshness.epoch in 0..MaxEpochClaim
    Theta1, Theta2, Kappa, BMax, Rho, RiskMax,
    AdmLimit, RevLimit, FreezeLimit, LeakLimit, DelLimit, BeaconLimit,
    Interleave,    \* BOOLEAN: gate-read and commit of an admission are separate steps
    Recheck,       \* BOOLEAN: (only if Interleave) the commit re-runs the gate (the fix)
    BeaconMode     \* BOOLEAN: dead-man liveness beacon required

Grants     == 1..NG
Holders    == 1..2
Principals == 1..NG
Nodes      == 1..3
Plans      == 1..2
Caps       == 1..4            \* 1..NG are the roots (RootOf), the rest are delegated
RootOf(g)   == g              \* root capability of grant g
PrincOf(g)  == g              \* grant g is issued by principal g
HolderOf(g) == g              \* ... and initially held by agent key g.  principal # holder:
                              \* principals and holders are DISJOINT key domains (assumption A1)
NONE == 0                     \* sentinel (for parent / absent record)
Policies == (SUBSET Nodes) \ {{}}
Caveats  == SUBSET Nodes      \* one caveat = a restriction to a node set

\* risk thresholds (risk.ts requiredThreshold): r<=theta1 -> 1, r<=theta2 -> 2, else 3
TOf(r) == IF r <= Theta1 THEN 1 ELSE IF r <= Theta2 THEN 2 ELSE 3

VARIABLES
    risk,       \* [Nodes -> 0..RiskMax]  SERVER-computed risk (Tier 0); chosen once, ALL assignments explored
    princ,      \* [Principals -> {"none","enrolled","disabled"}]
    grants,     \* [Grants -> NONE \cup grant record]
    plans,      \* [Plans -> NONE \cup [g, nodes, auth \in {"none","principal","envelope"}, ps]]
                \* ps = ghost: a principal signature over {grant_ref, plan_root} was actually produced
    caps,       \* [Caps -> NONE \cup [g, holder, parent, cav : Seq(Caveats)]]
    revoked,    \* SUBSET Caps
    epoch,      \* [Grants -> Nat]   guardian-signed revocation epoch number
    frozen,     \* BOOLEAN  instance kill switch
    beacon,     \* BOOLEAN  dead-man beacon fresh
    ctr,        \* [Grants -> [Holders -> Nat]]  last accepted counter
    budget,     \* [Grants -> 0..BMax]
    rch,        \* [Grants -> Nat]   number of human recharges so far (ghost)
    log,        \* Seq of admitted-entry records (the ledger, plus ghosts)
    pend,       \* NONE \cup pending admission (Interleave mode)
    cnt         \* event counters

vars == <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

---------------------------------------------------------------------------
(* Derived predicates *)

RECURSIVE Chain(_)
Chain(c) == IF caps[c].parent = NONE THEN {c} ELSE {c} \cup Chain(caps[c].parent)

CavSet(c) == {caps[c].cav[i] : i \in 1..Len(caps[c].cav)}

\* the authority of a capability = signed root policy  INTERSECT  every caveat on the chain
Authority(c) == {n \in grants[caps[c].g].policy : \A i \in 1..Len(caps[c].cav) : n \in caps[c].cav[i]}

ChainRevoked(c) == \E x \in Chain(c) : x \in revoked

IsPrefix(a, b) == Len(a) <= Len(b) /\ \A i \in 1..Len(a) : a[i] = b[i]

\* ghost: reasons an admission would be illegitimate in the TRUE state at the commit instant
Bad(g, c, e) ==
    (IF grants[g].active = FALSE \/ ChainRevoked(c) THEN {"revoked"} ELSE {})
    \cup (IF frozen THEN {"frozen"} ELSE {})
    \cup (IF e < epoch[g] THEN {"staleEpoch"} ELSE {})
    \cup (IF grants[g].tier = "verified" /\ princ[grants[g].p] # "enrolled" THEN {"principalDisabled"} ELSE {})
    \cup (IF BeaconMode /\ ~beacon THEN {"staleBeacon"} ELSE {})

\* the gate (verify.ts + adjudicateInner.gate): status, kill switch, revocation, principal, beacon, freshness epoch
GateOk(g, c, e) == Bad(g, c, e) = {}

---------------------------------------------------------------------------
(* Initial state: every risk assignment is a distinct initial state *)

Init ==
    /\ risk \in [Nodes -> 0..RiskMax]
    /\ princ = [p \in Principals |-> "none"]
    /\ grants = [g \in Grants |-> NONE]
    /\ plans = [pl \in Plans |-> NONE]
    /\ caps = [c \in Caps |-> NONE]
    /\ revoked = {}
    /\ epoch = [g \in Grants |-> 0]
    /\ frozen = FALSE
    /\ beacon = TRUE
    /\ ctr = [g \in Grants |-> [h \in Holders |-> 0]]
    /\ budget = [g \in Grants |-> BMax]
    /\ rch = [g \in Grants |-> 0]
    /\ log = <<>>
    /\ pend = NONE
    /\ cnt = [adm |-> 0, rev |-> 0, frz |-> 0, leak |-> 0, del |-> 0, bcn |-> 0]

---------------------------------------------------------------------------
(* Registry, grants, plans *)

Enrol(p) ==
    /\ princ[p] = "none"
    /\ princ' = [princ EXCEPT ![p] = "enrolled"]
    /\ UNCHANGED <<risk, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

Disable(p) ==
    /\ princ[p] = "enrolled"
    /\ princ' = [princ EXCEPT ![p] = "disabled"]
    /\ UNCHANGED <<risk, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

\* The grant is the principal's SIGNED root capability.  tier = verified iff the principal is enrolled now.
Register(g, policy, ac) ==
    /\ grants[g] = NONE
    /\ grants' = [grants EXCEPT ![g] = [p |-> PrincOf(g),
                    tier |-> IF princ[PrincOf(g)] = "enrolled" THEN "verified" ELSE "unverified",
                    holder |-> HolderOf(g), policy |-> policy, ac |-> ac, active |-> TRUE]]
    /\ caps' = [caps EXCEPT ![RootOf(g)] = [g |-> g, holder |-> HolderOf(g), parent |-> NONE, cav |-> <<>>]]
    /\ UNCHANGED <<risk, princ, plans, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

\* ANYONE (including the agent) may commit a plan.  It is authorized only by the principal's signature
\* (AuthorizePlan) or by the grant's SIGNED envelope opt-in (ac, "agent_commit"): never automatically.
CommitPlan(pl, g, nodes) ==
    /\ plans[pl] = NONE /\ grants[g] # NONE
    /\ plans' = [plans EXCEPT ![pl] = [g |-> g, nodes |-> nodes,
                    auth |-> IF grants[g].ac THEN "envelope" ELSE "none", ps |-> FALSE]]
    /\ UNCHANGED <<risk, princ, grants, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

AuthorizePlan(pl) ==                      \* requires the PRINCIPAL's signature over {grant_ref, plan_root}
    /\ plans[pl] # NONE /\ plans[pl].auth = "none"
    /\ plans' = [plans EXCEPT ![pl].auth = "principal", ![pl].ps = TRUE]
    /\ UNCHANGED <<risk, princ, grants, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend, cnt>>

\* Delegation: child.cav = parent.cav ++ added (verifyChain: parent caveats must be an exact PREFIX).
\* The delegator proposes ANY list; only append-only extensions pass the verifier.
Delegate(par, c, h, cav) ==
    /\ cnt.del < DelLimit
    /\ caps[par] # NONE /\ ~ChainRevoked(par) /\ caps[c] = NONE /\ c > NG
    /\ IsPrefix(caps[par].cav, cav)                         \* the verifier's append-only check
    /\ \A i \in 1..Len(cav) : cav[i] \in Caveats
    /\ caps' = [caps EXCEPT ![c] = [g |-> caps[par].g, holder |-> h, parent |-> par, cav |-> cav]]
    /\ cnt' = [cnt EXCEPT !.del = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, revoked, epoch, frozen, beacon, ctr, budget, rch, log, pend>>

---------------------------------------------------------------------------
(* Revocation, kill switch, beacon, leak *)

\* Principal-signed.  Bumps the signed epoch in the same transaction; revoking the root kills the grant.
Revoke(c) ==
    /\ cnt.rev < RevLimit
    /\ caps[c] # NONE /\ c \notin revoked
    /\ revoked' = revoked \cup {c}
    /\ epoch' = [epoch EXCEPT ![caps[c].g] = @ + 1]
    /\ grants' = IF caps[c].parent = NONE THEN [grants EXCEPT ![caps[c].g].active = FALSE] ELSE grants
    /\ cnt' = [cnt EXCEPT !.rev = @ + 1]
    /\ UNCHANGED <<risk, princ, plans, caps, frozen, beacon, ctr, budget, rch, log, pend>>

Freeze ==
    /\ ~frozen /\ cnt.frz < FreezeLimit
    /\ frozen' = TRUE /\ cnt' = [cnt EXCEPT !.frz = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, beacon, ctr, budget, rch, log, pend>>

Unfreeze ==
    /\ frozen /\ frozen' = FALSE
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, beacon, ctr, budget, rch, log, pend, cnt>>

BeaconStep ==
    /\ BeaconMode /\ cnt.bcn < BeaconLimit
    /\ beacon' = ~beacon /\ cnt' = [cnt EXCEPT !.bcn = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, ctr, budget, rch, log, pend>>

Leak(g) ==                                \* passive decay only ever LOWERS the budget
    /\ pend = NONE /\ cnt.leak < LeakLimit /\ grants[g] # NONE /\ budget[g] > 0
    /\ budget' = [budget EXCEPT ![g] = @ - 1] /\ cnt' = [cnt EXCEPT !.leak = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, rch, log, pend>>

---------------------------------------------------------------------------
(* Action admission *)

\* All guards of verifyPCActn + adjudicateInner.  Note `claim` (the agent's claimed risk) is quantified
\* over but NEVER read: the risk is risk[n], computed by the server (deriveRisk / authoritativeClass).
Admissible(c, pl, n, e, k, claim, human, touch) ==
    LET g    == caps[c].g
        h    == caps[c].holder
        r    == risk[n]
        t0   == TOf(r)
        cost == Kappa * r
        t    == IF t0 < 3 /\ ~(budget[g] >= cost) THEN 3 ELSE t0   \* admit(): unaffordable => human step-up
    IN  /\ caps[c] # NONE /\ grants[g] # NONE
        /\ plans[pl] # NONE /\ plans[pl].g = g /\ plans[pl].auth # "none"   \* committed, principal-authorized plan
        /\ n \in plans[pl].nodes                                          \* plan inclusion
        /\ n \in Authority(c)                                             \* signed policy + all caveats (hard gate)
        /\ GateOk(g, c, e)                                                \* status/freeze/revocation/principal/beacon/epoch
        /\ k > ctr[g][h]                                                  \* counter CAS
        /\ (t = 3 => human)                                               \* t=3 needs the principal-device share
        /\ (touch => human)                                               \* recharge only on a human co-sign

Effects(c, pl, n, e, k, human, touch) ==
    LET g    == caps[c].g
        h    == caps[c].holder
        r    == risk[n]
        t0   == TOf(r)
        t    == IF t0 < 3 /\ ~(budget[g] >= Kappa * r) THEN 3 ELSE t0
        b1   == IF t < 3 THEN budget[g] - Kappa * r ELSE budget[g]          \* machine-only => debit kappa*r
        b2   == IF touch THEN (IF b1 + Rho > BMax THEN BMax ELSE b1 + Rho) ELSE b1
        ent  == [g |-> g, cap |-> c, holder |-> h, n |-> n, pl |-> pl, k |-> k, t |-> t,
                 human |-> human, r |-> r, rch |-> rch[g], bad |-> Bad(g, c, e)]
    IN  /\ log'    = Append(log, ent)
        /\ budget' = [budget EXCEPT ![g] = b2]
        /\ rch'    = [rch EXCEPT ![g] = IF touch THEN @ + 1 ELSE @]
        /\ ctr'    = [ctr EXCEPT ![g][h] = IF k > @ THEN k ELSE @]

\* design intent: decision and commit are one atomic step (what the code comments claim)
AdmitAtomic(c, pl, n, e, k, claim, human, touch) ==
    /\ ~Interleave /\ pend = NONE /\ cnt.adm < AdmLimit
    /\ Admissible(c, pl, n, e, k, claim, human, touch)
    /\ Effects(c, pl, n, e, k, human, touch)
    /\ cnt' = [cnt EXCEPT !.adm = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, pend>>

\* code reading under READ COMMITTED: the gate is read, then (async verification, ledger append) the txn
\* commits; revoke/freeze take only the advisory epoch lock, NOT the budget/counter row locks, so they can
\* commit in between.  Admissions are serialized among themselves (row locks).
AdmitBegin(c, pl, n, e, k, claim, human, touch) ==
    /\ Interleave /\ pend = NONE /\ cnt.adm < AdmLimit
    /\ Admissible(c, pl, n, e, k, claim, human, touch)
    /\ pend' = [c |-> c, pl |-> pl, n |-> n, e |-> e, k |-> k, human |-> human, touch |-> touch]
    /\ cnt' = [cnt EXCEPT !.adm = @ + 1]
    /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log>>

AdmitCommit ==
    /\ Interleave /\ pend # NONE
    /\ LET p == pend IN
       IF Recheck /\ ~GateOk(caps[p.c].g, p.c, p.e)
       THEN /\ pend' = NONE                                   \* fix: abort when the re-read gate fails
            /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, ctr, budget, rch, log, cnt>>
       ELSE /\ Effects(p.c, p.pl, p.n, p.e, p.k, p.human, p.touch)
            /\ pend' = NONE
            /\ UNCHANGED <<risk, princ, grants, plans, caps, revoked, epoch, frozen, beacon, cnt>>

Next ==
    \/ \E p \in Principals : Enrol(p) \/ Disable(p)
    \/ \E g \in Grants, pol \in Policies, ac \in BOOLEAN : Register(g, pol, ac)
    \/ \E pl \in Plans, g \in Grants, nodes \in SUBSET Nodes : CommitPlan(pl, g, nodes)
    \/ \E pl \in Plans : AuthorizePlan(pl)
    \/ \E par \in Caps, c \in Caps, h \in Holders, cav \in UNION {[1..m -> Caveats] : m \in 0..2} :
          Delegate(par, c, h, cav)
    \/ \E c \in Caps : Revoke(c)
    \/ Freeze \/ Unfreeze \/ BeaconStep
    \/ \E g \in Grants : Leak(g)
    \/ \E c \in Caps, pl \in Plans, n \in Nodes, e \in 0..MaxEpochClaim, k \in 1..MaxCtr,
          claim \in {0, RiskMax}, human \in BOOLEAN, touch \in BOOLEAN :
          AdmitAtomic(c, pl, n, e, k, claim, human, touch) \/ AdmitBegin(c, pl, n, e, k, claim, human, touch)
    \/ AdmitCommit

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* TYPE / SHAPE *)

TypeOK ==
    /\ risk \in [Nodes -> 0..RiskMax]
    /\ revoked \subseteq Caps
    /\ \A g \in Grants : budget[g] \in 0..BMax

---------------------------------------------------------------------------
(* SAFETY INVARIANTS *)

\* (1) Reachability / Authorization safety: no admitted action unless it is an included node of a
\*     PRINCIPAL-authorized plan of its grant AND within the signed policy+caveats.  `risk` is a state variable
\*     ranging over ALL assignments in Init, so this holds for every risk value: risk can never authorize.
AuthorizationSafety ==
    \A i \in 1..Len(log) :
        LET e == log[i] IN
            /\ plans[e.pl] # NONE
            /\ plans[e.pl].g = e.g
            /\ plans[e.pl].auth # "none"
            /\ (plans[e.pl].auth = "principal" => plans[e.pl].ps)   \* authorized <=> principal actually signed
            /\ (plans[e.pl].auth = "envelope" => grants[e.g].ac)
            /\ e.n \in plans[e.pl].nodes
            /\ e.n \in Authority(e.cap)

\* (2) Attenuation monotonicity: a child's authority is a subset of its parent's; caveats are append-only.
AttenuationMonotonicity ==
    \A c \in Caps :
        (caps[c] # NONE /\ caps[c].parent # NONE) =>
            /\ caps[c].g = caps[caps[c].parent].g
            /\ IsPrefix(caps[caps[c].parent].cav, caps[c].cav)
            /\ Authority(c) \subseteq Authority(caps[c].parent)

\* (3) Replay freedom: a counter is admitted at most once per (grant, holder); the register is the max admitted.
ReplayFreedom ==
    /\ \A i, j \in 1..Len(log) :
          (i # j /\ log[i].g = log[j].g /\ log[i].holder = log[j].holder) => log[i].k # log[j].k
    /\ \A g \in Grants, h \in Holders :
          ctr[g][h] = IF \E i \in 1..Len(log) : log[i].g = g /\ log[i].holder = h
                      THEN CHOOSE m \in {log[i].k : i \in {j \in 1..Len(log) : log[j].g = g /\ log[j].holder = h}} :
                              \A x \in {log[i].k : i \in {j \in 1..Len(log) : log[j].g = g /\ log[j].holder = h}} : x <= m
                      ELSE 0

\* (4) Budget bound: between two human recharges, the sum of risk debited (machine-only, t<3) is <= bMax/kappa.
RECURSIVE RiskSum(_)
RiskSum(S) == IF S = {} THEN 0 ELSE LET i == CHOOSE x \in S : TRUE IN Kappa * risk[log[i].n] + RiskSum(S \ {i})

SpentSince(g) ==
    LET idx == {i \in 1..Len(log) : log[i].g = g /\ log[i].t < 3 /\ log[i].rch = rch[g]}   \* priced at SERVER risk below
    IN  RiskSum(idx)

BudgetBound ==
    \A g \in Grants : /\ SpentSince(g) <= BMax          \* sum(kappa*r) <= bMax  <=>  sum(r) <= bMax/kappa
                      /\ budget[g] >= 0 /\ budget[g] <= BMax

\* (5) Revocation / Freeze safety (+ epoch, principal, beacon): at the COMMIT instant of every admission the
\*     true state had no revoked chain, no kill switch, a fresh epoch, an active principal and a live beacon.
RevocationSafety == \A i \in 1..Len(log) : "revoked" \notin log[i].bad
FreezeSafety     == \A i \in 1..Len(log) : "frozen" \notin log[i].bad
EpochFreshness   == \A i \in 1..Len(log) : "staleEpoch" \notin log[i].bad
PrincipalSafety  == \A i \in 1..Len(log) : "principalDisabled" \notin log[i].bad
BeaconSafety     == \A i \in 1..Len(log) : "staleBeacon" \notin log[i].bad

\* (6) Threshold safety: t=3 needs the human share; t never below the server-risk threshold.
ThresholdSafety == \A i \in 1..Len(log) : /\ (log[i].t = 3 => log[i].human)
                                          /\ log[i].t >= TOf(risk[log[i].n])

Safety == TypeOK /\ AuthorizationSafety /\ AttenuationMonotonicity /\ ReplayFreedom /\ BudgetBound
          /\ RevocationSafety /\ FreezeSafety /\ EpochFreshness /\ PrincipalSafety /\ BeaconSafety /\ ThresholdSafety

---------------------------------------------------------------------------
(* TEMPORAL / ACTION PROPERTIES (checked as PROPERTY in the cfg) *)

\* revocation and epochs are monotone: a revoked capability stays revoked; the epoch never decreases
RevocationStable == [][revoked \subseteq revoked' /\ \A g \in Grants : epoch[g] <= epoch'[g]]_vars

\* counters never decrease and a ledger entry, once appended, is never altered or removed (append-only)
CounterMonotone == [][\A g \in Grants, h \in Holders : ctr[g][h] <= ctr'[g][h]]_vars
LedgerAppendOnly == [][Len(log) <= Len(log') /\ \A i \in 1..Len(log) : log'[i] = log[i]]_vars

\* the trust budget only increases through a human co-sign (the new ledger entry carries human = TRUE)
BudgetRisesOnlyByHuman ==
    [][\A g \in Grants : budget'[g] > budget[g] =>
          (Len(log') = Len(log) + 1 /\ log'[Len(log')].human /\ log'[Len(log')].g = g)]_vars

\* once a grant is revoked it stays inactive (no un-revoke), hence no later admission can pass the gate
RevokedGrantStaysDead == [][\A g \in Grants : (grants[g] # NONE /\ ~grants[g].active) => (grants'[g] # NONE /\ ~grants'[g].active)]_vars

===========================================================================
