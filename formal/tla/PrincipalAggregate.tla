---------------------------- MODULE PrincipalAggregate ----------------------------
(***************************************************************************)
(* Goal-to-decision T4 / spec G-T8: a principal-scope aggregate cap shared  *)
(* by every session and delegated agent of one principal, kept in a durable *)
(* BudgetLedger (packages/pca/src/budget-ledger.ts).                        *)
(*                                                                          *)
(*  Protocol per action: Read (snapshot) -> Reserve (CAS on the version AND *)
(*  the cap check, one atomic step; counts at once) -> Start (the effect is *)
(*  about to run) -> Run (the effect happens) -> Commit; or Release (the    *)
(*  effect did not happen). Expire frees an open reservation that was NEVER *)
(*  started: it is enabled at ANY time, so the model covers a caller with   *)
(*  an arbitrary (skewed) clock. A started reservation never expires, so a  *)
(*  crash after the effect only over-restricts. Sessions may crash at any   *)
(*  point; the ledger may restart (it is durable: nothing changes).         *)
(*                                                                          *)
(*  Safety, for any interleaving of concurrent sessions:                    *)
(*    NoOverspend   Counted <= Cap            (the ledger's own total)      *)
(*    SpentBounded  the sum of effects that RAN <= Cap                      *)
(*    RanCounted    every effect that ran is still counted                  *)
(*                                                                          *)
(*  Bug selects an expected-fail mutant (each must violate an invariant):   *)
(*    "none"               the shipped protocol                             *)
(*    "stale"              cap checked against the snapshot, no CAS         *)
(*    "no_cap"             no cap check at all                              *)
(*    "per_session_key"    state keyed by session, not principal (W9)       *)
(*    "late_commit"        a released reservation can be committed          *)
(*    "release_committed"  a committed reservation can be released          *)
(*    "release_unreserved" release of an unknown id credits budget          *)
(*    "expire_started"     expiry also frees started reservations           *)
(*    "amnesia"            the ledger forgets on restart (not durable)      *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Sessions, Cap, Amts, MaxIds, Bug

Ids == 1..MaxIds
Status == {"none", "reserved", "committed", "released"}

\* snap[s]: "none" (no read), "ok" (read, no ledger write since: the CAS version still matches), "stale" (a write happened since)
\* sc[s]: the counted total the session read (only kept for the "stale" mutant, which trusts it instead of re-checking)
VARIABLES ev, snap, sc, nextId, ran, crashed, credit
vars == <<ev, snap, sc, nextId, ran, crashed, credit>>
Inv(m) == [t \in Sessions |-> IF m[t] = "ok" THEN "stale" ELSE m[t]]

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0 ELSE LET i == CHOOSE x \in S : TRUE IN ev[i].amt + SumAmt(S \ {i})
CountedIds == {i \in Ids : ev[i].st \in {"reserved", "committed"}}
Counted == SumAmt(CountedIds) - credit
CountedBy(s) == SumAmt({i \in CountedIds : ev[i].sess = s})
Spent == SumAmt(ran)

TypeOK == /\ ev \in [Ids -> [st : Status, amt : Amts \cup {0}, sess : Sessions \cup {"-"}, started : BOOLEAN]]
          /\ snap \in [Sessions -> {"none", "ok", "stale"}]
          /\ sc \in [Sessions -> 0..(MaxIds * 10)]
          /\ nextId \in 1..(MaxIds + 1)
          /\ ran \subseteq Ids
          /\ crashed \subseteq Sessions
          /\ credit \in 0..Cap

Init == /\ ev = [i \in Ids |-> [st |-> "none", amt |-> 0, sess |-> "-", started |-> FALSE]]
        /\ snap = [s \in Sessions |-> "none"]
        /\ sc = [s \in Sessions |-> 0]
        /\ nextId = 1
        /\ ran = {}
        /\ crashed = {}
        /\ credit = 0

Read(s) == /\ s \notin crashed /\ snap[s] = "none"
           /\ snap' = [snap EXCEPT ![s] = "ok"]
           /\ sc' = [sc EXCEPT ![s] = IF Bug = "stale" THEN Counted ELSE 0]
           /\ UNCHANGED <<ev, nextId, ran, crashed, credit>>

\* a session gives up its snapshot (a CAS conflict makes it re-read)
Drop(s) == /\ snap[s] # "none"
           /\ snap' = [snap EXCEPT ![s] = "none"]
           /\ sc' = [sc EXCEPT ![s] = 0]
           /\ UNCHANGED <<ev, nextId, ran, crashed, credit>>

\* The atomic step of the ledger: the version still matches (snap "ok") AND the cap holds for the CURRENT total.
Guard(s, a) ==
  CASE Bug = "stale"           -> sc[s] + a <= Cap
    [] Bug = "no_cap"          -> TRUE
    [] Bug = "per_session_key" -> CountedBy(s) + a <= Cap
    [] OTHER                   -> snap[s] = "ok" /\ Counted + a <= Cap

Reserve(s, a) ==
  /\ s \notin crashed /\ nextId <= MaxIds /\ snap[s] # "none"
  /\ Guard(s, a)
  /\ ev' = [ev EXCEPT ![nextId] = [st |-> "reserved", amt |-> a, sess |-> s, started |-> FALSE]]
  /\ snap' = [t \in Sessions |-> IF t = s THEN "none" ELSE Inv(snap)[t]]
  /\ sc' = [sc EXCEPT ![s] = 0]
  /\ nextId' = nextId + 1
  /\ UNCHANGED <<ran, crashed, credit>>

Start(i) == /\ ev[i].st = "reserved" /\ ~ev[i].started /\ ev[i].sess \notin crashed
            /\ ev' = [ev EXCEPT ![i].started = TRUE]
            /\ snap' = Inv(snap)
            /\ UNCHANGED <<sc, nextId, ran, crashed, credit>>

\* the effect happens: only after Start, only while the reservation is open
Run(i) == /\ ev[i].st = "reserved" /\ ev[i].started /\ i \notin ran /\ ev[i].sess \notin crashed
          /\ ran' = ran \cup {i}
          /\ UNCHANGED <<ev, snap, sc, nextId, crashed, credit>>

Commit(i) == /\ ev[i].sess \notin crashed
             /\ \/ (ev[i].st = "reserved" /\ i \in ran)
                \/ (Bug = "late_commit" /\ ev[i].st = "released")
             /\ ev' = [ev EXCEPT ![i].st = "committed"]
             /\ snap' = Inv(snap)
             /\ UNCHANGED <<sc, nextId, ran, crashed, credit>>

\* released because the effect did NOT happen
Release(i) == /\ ev[i].sess \notin crashed
              /\ \/ (ev[i].st = "reserved" /\ i \notin ran)
                 \/ (Bug = "release_committed" /\ ev[i].st = "committed")
              /\ ev' = [ev EXCEPT ![i].st = "released"]
              /\ snap' = Inv(snap)
              /\ UNCHANGED <<sc, nextId, ran, crashed, credit>>

\* expiry: any time (an arbitrary clock), by anyone, but never a started reservation
Expire(i) == /\ ev[i].st = "reserved" /\ (~ev[i].started \/ Bug = "expire_started")
             /\ ev' = [ev EXCEPT ![i].st = "released"]
             /\ snap' = Inv(snap)
             /\ UNCHANGED <<sc, nextId, ran, crashed, credit>>

Credit == /\ Bug = "release_unreserved" /\ credit < Cap
          /\ credit' = credit + 1
          /\ snap' = Inv(snap)
          /\ UNCHANGED <<ev, sc, nextId, ran, crashed>>

Crash(s) == /\ s \notin crashed /\ crashed' = crashed \cup {s}
            /\ UNCHANGED <<ev, snap, sc, nextId, ran, credit>>

\* the ledger process restarts: durable state is unchanged (a stutter); the amnesia mutant loses it
Restart == /\ Bug = "amnesia"
           /\ ev' = [i \in Ids |-> [st |-> "none", amt |-> 0, sess |-> "-", started |-> FALSE]]
           /\ UNCHANGED <<snap, sc, nextId, ran, crashed, credit>>

Next == \/ \E s \in Sessions : Read(s) \/ Drop(s) \/ Crash(s)
        \/ \E s \in Sessions, a \in Amts : Reserve(s, a)
        \/ \E i \in Ids : Start(i) \/ Run(i) \/ Commit(i) \/ Release(i) \/ Expire(i)
        \/ Credit
        \/ Restart

Spec == Init /\ [][Next]_vars

NoOverspend == Counted <= Cap
SpentBounded == Spent <= Cap
RanCounted == \A i \in ran : ev[i].st \in {"reserved", "committed"}
=============================================================================
