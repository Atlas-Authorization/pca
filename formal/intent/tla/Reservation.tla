----------------------------- MODULE Reservation -----------------------------
(***************************************************************************)
(* v2 §3.1 / T11: post-action caps with reservations, concurrent sites and  *)
(* a sequencer. A reservation counts as soon as it is made. Sites may crash;*)
(* their open reservations expire.                                          *)
(*   LIN = TRUE : the sequencer checks counted + amt <= Cap atomically.     *)
(*   LIN = FALSE: a site checks against a snapshot read earlier (no lock),  *)
(*                which permits the double-spend trace (expected fail).     *)
(*   Receipts carry a sequence number; a byzantine sequencer (BYZ) may give *)
(*   two receipts the same number. With INCL = TRUE a receipt is accepted   *)
(*   only with an inclusion proof in the public log, so every equivocating  *)
(*   pair is in the log (detectable).                                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Sites, Cap, Amts, MaxIds, LIN, BYZ, INCL

Ids == 1..MaxIds
Status == {"none", "reserved", "committed", "released"}

VARIABLES rsv, snap, nextId, issued, log, crashed
vars == <<rsv, snap, nextId, issued, log, crashed>>

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0 ELSE LET i == CHOOSE x \in S : TRUE IN rsv[i].amt + SumAmt(S \ {i})
Counted == SumAmt({i \in Ids : rsv[i].st \in {"reserved", "committed"}})

TypeOK == /\ rsv \in [Ids -> [st : Status, amt : Amts \cup {0}, site : Sites \cup {"-"}]]
          /\ snap \in [Sites -> 0..(MaxIds * 10) \cup {-1}]
          /\ nextId \in 1..(MaxIds + 1)
          /\ crashed \subseteq Sites

Init == /\ rsv = [i \in Ids |-> [st |-> "none", amt |-> 0, site |-> "-"]]
        /\ snap = [s \in Sites |-> -1]
        /\ nextId = 1
        /\ issued = {}
        /\ log = {}
        /\ crashed = {}

Read(s) == /\ ~LIN /\ s \notin crashed /\ snap[s] = -1
           /\ snap' = [snap EXCEPT ![s] = Counted]
           /\ UNCHANGED <<rsv, nextId, issued, log, crashed>>

Reserve(s, a) ==
  /\ s \notin crashed
  /\ nextId <= MaxIds
  /\ IF LIN THEN Counted + a <= Cap ELSE (snap[s] # -1 /\ snap[s] + a <= Cap)
  /\ rsv' = [rsv EXCEPT ![nextId] = [st |-> "reserved", amt |-> a, site |-> s]]
  /\ snap' = [snap EXCEPT ![s] = -1]
  /\ issued' = issued \cup {<<nextId, s>>}
  /\ log' = IF INCL THEN log \cup {<<nextId, s>>} ELSE log
  /\ nextId' = nextId + 1
  /\ UNCHANGED crashed

\* a byzantine sequencer hands out a second receipt with an old sequence number
Equivocate(i, s) == /\ BYZ /\ rsv[i].st # "none" /\ rsv[i].site # s
                    /\ issued' = issued \cup {<<i, s>>}
                    /\ log' = IF INCL THEN log \cup {<<i, s>>} ELSE log
                    /\ UNCHANGED <<rsv, snap, nextId, crashed>>

Commit(i)  == /\ rsv[i].st = "reserved" /\ rsv[i].site \notin crashed
              /\ rsv' = [rsv EXCEPT ![i].st = "committed"]
              /\ UNCHANGED <<snap, nextId, issued, log, crashed>>
Release(i) == /\ rsv[i].st = "reserved"
              /\ rsv' = [rsv EXCEPT ![i].st = "released"]
              /\ UNCHANGED <<snap, nextId, issued, log, crashed>>
Crash(s)   == /\ s \notin crashed /\ crashed' = crashed \cup {s}
              /\ UNCHANGED <<rsv, snap, nextId, issued, log>>

Next == \/ \E s \in Sites : Read(s)
        \/ \E s \in Sites, a \in Amts : Reserve(s, a)
        \/ \E i \in Ids, s \in Sites : Equivocate(i, s)
        \/ \E i \in Ids : Commit(i) \/ Release(i)
        \/ \E s \in Sites : Crash(s)

\* Release(i) is also the expiry of an abandoned reservation: weak fairness makes it happen
Spec == Init /\ [][Next]_vars /\ \A i \in Ids : WF_vars(Release(i))

NoOverspend == Counted <= Cap
ReleaseEventually == \A i \in Ids : (rsv[i].st = "reserved") ~> (rsv[i].st \in {"committed", "released"})
EquivocationDetected == \A r1, r2 \in issued : (r1[1] = r2[1] /\ r1 # r2) => (r1 \in log /\ r2 \in log)
=============================================================================
