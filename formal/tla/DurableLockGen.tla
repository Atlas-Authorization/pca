---------------------------- MODULE DurableLockGen ----------------------------
(***************************************************************************
 The REPLACEMENT lock protocol of packages/pca/src/durable-state.ts.

 The old protocol (DurableLock.tla) judged a lock stale by AGE and broke it by
 renaming whatever sat at one path to a graveyard, which can move a FRESH lock
 and lets a stalled owner resume inside a lock that was given away.  Both are
 impossible here because
   * the lock is a set of immutable, numbered files  state.lock.<g>  created with
     link(2)/O_EXCL (atomic, complete, never renamed, never rewritten);
   * the lock is HELD by the process named in the highest-numbered file, FREE if
     that file says so; the only way to take it is to create generation g+1
     (O_EXCL: exactly one creator wins), and a live holder's generation is
     never superseded: a lock is breakable ONLY when its holder is provably
     dead (same host: kill(pid,0) fails).  A stalled-but-alive holder keeps the
     lock; waiters time out (fail closed) instead of stealing;
   * release creates generation g+1 = "free".
 AgeBreak = TRUE models the old rule (also treat an alive holder as breakable)
 inside the same generation scheme: it must violate MutualExclusion.

 Operator recovery (R5-F1, recoverDurableState({force, expectedHolder})) is OUT OF BAND and adds no action here.
 CORRECTION (R6-CORE-01): the earlier note here said a late-resuming old holder then fails assertLockHeld and writes
 nothing. That holds only for a holder paused BEFORE its pre-rename re-check; one paused between the re-check and its
 rename(2) still renames. Recovery of a paused holder, the re-checks before the journal and head renames, the
 per-record generation, the state.fence cut and the stale-head repair are modelled in DurableFence.tla.
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, MaxG, AgeBreak, Crash, PreStale, Gc, Verify

VARIABLES lk, pc, sg, cont, mygen, val, seen, res, wlog
vars == <<lk, pc, sg, cont, mygen, val, seen, res, wlog>>

ABSENT == [st |-> "absent", o |-> "-"]
FREE == [st |-> "free", o |-> "-"]
Crit == {"rd", "wr"}
Gens == 0..MaxG

Init ==
  /\ lk = [g \in Gens |-> IF PreStale /\ g = 0 THEN [st |-> "held", o |-> "D"] ELSE ABSENT]
  /\ pc = [c \in Clients |-> "scan"] /\ sg = [c \in Clients |-> -1] /\ cont = [c \in Clients |-> ABSENT]
  /\ mygen = [c \in Clients |-> -1] /\ val = 0 /\ seen = [c \in Clients |-> 0]
  /\ res = [c \in Clients |-> "none"] /\ wlog = <<>>

Present == {g \in Gens : lk[g] # ABSENT}
Top == IF Present = {} THEN -1 ELSE CHOOSE g \in Present : \A h \in Present : h <= g
Dead(o) == o = "D" \/ (o \in Clients /\ pc[o] = "dead")

Go(c, s) == pc' = [pc EXCEPT ![c] = s]

Scan(c) == /\ pc[c] = "scan"
           /\ sg' = [sg EXCEPT ![c] = Top]
           /\ cont' = [cont EXCEPT ![c] = IF Top = -1 THEN ABSENT ELSE lk[Top]]
           /\ Go(c, "decide")
           /\ UNCHANGED <<lk, mygen, val, seen, res, wlog>>
Decide(c) == /\ pc[c] = "decide"
             /\ IF cont[c] = ABSENT \/ cont[c] = FREE
                  THEN Go(c, "create")
                  ELSE IF Dead(cont[c].o) \/ AgeBreak THEN Go(c, "create") ELSE Go(c, "scan")
             /\ UNCHANGED <<lk, sg, cont, mygen, val, seen, res, wlog>>
Create(c) == /\ pc[c] = "create"
             /\ LET t == sg[c] + 1 IN
                IF t <= MaxG /\ lk[t] = ABSENT
                  THEN /\ lk' = [lk EXCEPT ![t] = [st |-> "held", o |-> c]] /\ mygen' = [mygen EXCEPT ![c] = t] /\ Go(c, IF Verify THEN "verify" ELSE "rd")
                  ELSE /\ Go(c, "scan") /\ UNCHANGED <<lk, mygen>>      \* EEXIST: somebody else won; look again
             /\ UNCHANGED <<sg, cont, val, seen, res, wlog>>
\* after a successful create the generation must still be the HIGHEST one: a creator working from a stale view can re-create
\* a generation that garbage collection already removed ("ABA"); such a grab is buried below the real top and is abandoned.
VerifyTop(c) == /\ pc[c] = "verify" /\ Go(c, IF Top = mygen[c] THEN "rd" ELSE "scan")
                /\ UNCHANGED <<lk, sg, cont, mygen, val, seen, res, wlog>>
\* garbage collection of a superseded generation
DoGc == /\ Gc /\ \E g \in Present : g < Top /\ lk' = [lk EXCEPT ![g] = ABSENT]
        /\ UNCHANGED <<pc, sg, cont, mygen, val, seen, res, wlog>>
Rd(c) == /\ pc[c] = "rd" /\ seen' = [seen EXCEPT ![c] = val] /\ Go(c, "wr")
         /\ UNCHANGED <<lk, sg, cont, mygen, val, res, wlog>>
Wr(c) == /\ pc[c] = "wr"
         /\ IF seen[c] < 1 THEN val' = 1 /\ wlog' = Append(wlog, 1) /\ res' = [res EXCEPT ![c] = "T"]
            ELSE UNCHANGED <<val, wlog>> /\ res' = [res EXCEPT ![c] = "F"]
         /\ Go(c, "rel") /\ UNCHANGED <<lk, sg, cont, mygen, seen>>
Rel(c) == /\ pc[c] = "rel"
          /\ LET t == mygen[c] + 1 IN
             IF t <= MaxG /\ lk[t] = ABSENT THEN lk' = [lk EXCEPT ![t] = FREE] ELSE UNCHANGED lk
          /\ Go(c, "done") /\ UNCHANGED <<sg, cont, mygen, val, seen, res, wlog>>
Die(c) == /\ Crash /\ pc[c] \notin {"done", "dead"} /\ Go(c, "dead")
          /\ UNCHANGED <<lk, sg, cont, mygen, val, seen, res, wlog>>

Next == \/ \E c \in Clients : Scan(c) \/ Decide(c) \/ Create(c) \/ VerifyTop(c) \/ Rd(c) \/ Wr(c) \/ Rel(c) \/ Die(c)
        \/ DoGc
Spec == Init /\ [][Next]_vars

MutualExclusion == Cardinality({c \in Clients : pc[c] \in Crit}) <= 1
WriteMono == \A i \in 1..(Len(wlog) - 1) : wlog[i] < wlog[i + 1]
AtMostOneTrue == Cardinality({c \in Clients : res[c] = "T"}) <= 1
Safe == MutualExclusion /\ WriteMono /\ AtMostOneTrue
=============================================================================
