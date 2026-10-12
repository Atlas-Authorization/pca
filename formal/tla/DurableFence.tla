----------------------------- MODULE DurableFence -----------------------------
(***************************************************************************
 R6-CORE-01: operator recovery (recoverDurableState) of a PAUSED, not dead, lock
 holder in packages/pca/src/durable-state.ts, on top of the generation lock of
 DurableLockGen.tla (whose mutual exclusion is checked there; here acquisition is
 one atomic CAS step and there is no GC).

 What is modelled
   * The store: `journal` (a sequence of records [w = writer, g = writer's lock
     generation]; every commit REPLACES it whole, like the rename of a fully
     rewritten file), `head` ([seq, h = the journal prefix it names (its hash),
     g = the generation that wrote it]) and `fences` (state.fence; it too is
     rewritten whole: a writer reads the fence list, adds its entry, renames).
   * Clients: acquire -> load (+ head repair) -> re-check -> journal rename ->
     re-check -> head rename -> release. Every arrow is its own step, so a client
     can be PAUSED (simply not scheduled) between ANY two of them for as long as
     you like, including the residual window between a re-check and its rename.
   * The operator: recovers the CURRENT holder at any moment, whether it is dead,
     alive or paused (the attestation may be wrong): read the top generation g,
     TAKE the lock (link g+1 held by the operator; EEXIST = the holder released,
     abort), read the journal under it (the CUT: its tail seq S and the record
     there), write the fence [g+1, S, that record], link g+2 "free".
   * RECOVERY ITSELF CRASHES (OpCrash): the operator process can die after ANY of
     its steps (before taking the lock, holding g+1 before the cut, after the cut
     before the fence rename, after the fence before the release). Its g+1 then
     names a dead process. Two ways out, both modelled:
       - TAKEOVER (Takeover): a waiter in the same PID namespace judges that
         holder dead (kill(pid, 0)) and takes the lock over, exactly as from any
         dead holder. The recovery lock body is marked `recovering`, so the taker
         first CUTS AND FENCES under its own generation (TakeoverFence), before it
         loads; a taker of a marked lock marks its own lock too (Inherit), so a
         taker that itself dies before its fence lands passes the duty on.
         Takeover of an ordinary dead client is modelled too (no fence needed:
         a dead process renames nothing).
       - RE-RUN: the operator runs recovery again on the dead recovery lock
         (another PID namespace: a waiter cannot judge it, so it waits).
   * Load (load() in durable-state.ts): hash chain implicit; generations must not
     decrease along the chain; the journal must extend the exact journal a
     fence was cut at, and a record after the cut must come from a generation
     >= the fence; the head must name a prefix of the journal and lag
     at most one record, except a STALE LATE head (generation below a fence,
     position at or before its cut, journal extended past the cut), which is
     repaired; a lag record from a generation below the head's is refused.

 Ghost bookkeeping (not in the implementation)
   * stale: writers whose late journal rename (made without holding the lock)
     must be refused: it landed after a cut that became DURABLE (its fence was
     written; `cutG` = every generation below it is cut), or after a newer
     generation already loaded the store (it may overwrite that holder's work).
     A rename that lands after a cutter READ its cut but before that cutter's
     fence rename is PENDING (`seen[cutter]`): stale if the fence lands, benign if
     the cutter dies first (nothing was fenced; the next cut, by a re-run or a
     taker, is taken after it and includes it, like a rename before any cut).
     With the naive order, a rename after the cut while the writer still held
     the lock is stale as well.
   * acked: writers whose update() returned success (head written).
   * robbed: clients whose generation an operator recovery superseded.
   * rdgen: generations that loaded the store successfully.

 Properties (invariants)
   NoStaleAccepted     whenever the store loads, no stale writer's record is in it.
   NoAckedLost         whenever the store loads, every acknowledged write is in it.
   ReadableUnlessStale if no stale JOURNAL rename ever happened, the store loads
                       (stale heads, crashes, crashed recoveries and wrong
                       attestations included).
 A stale journal rename DOES make the store fail closed (it replaced the newer
 holder's journal); that is the residual cost the implementation documents.

 Properties (liveness, LiveSpec: weak fairness for clients and for the operator
 steps of a recovery in progress; never for a crash or a client death)
   NoWedge             a client waiting while a crashed recovery holds the lock
                       eventually finishes (it is not blocked forever).
   AckedOrFailedClosed ... and its write is acknowledged, unless an operator
                       recovery released it or a stale rename made the store
                       fail closed (documented costs, both detected).
   With Takeover the fairness of the waiters alone suffices; without it (the
   recovery ran in another PID namespace) ReRunFair says the operator eventually
   re-runs recovery on the dead recovery lock. ReRunFair = FALSE there must fail.

 Toggles (each one must break a property when switched off, see cases.txt)
   Fence       recovery writes the fence and load checks fences + generation order.
   HeadCheck   re-check before the head rename (and before the head repair).
   HeadRepair  load recognises and repairs a stale late head.
   TakeLock    recovery takes the lock before the cut (FALSE = read S, fence,
               release: a holder that is in fact running can commit after the
               cut and before the fence, and another holder can load it).
   FencePin    the fence pins the exact journal the operator cut at (the
               record at seq S, i.e. its hash, and that the journal reaches S),
               not only "records after S need generation >= G". FALSE fails
               with two recoveries: a cut taken over an already-refused stale
               record lets a later stale rename at seq <= S through.
   TakeoverFence  a taker of a lock marked `recovering` cuts and fences first.
               FALSE (the implementation before this change) fails: recovery
               crashes holding g+1 before its fence, a waiter takes over and
               commits, the paused holder of g renames late, nothing refuses it.
   Inherit     the taker marks its own lock `recovering`. FALSE fails: the taker
               dies before its fence lands, the next taker does not fence.
   FenceFiles  each fence is its own immutable file (the implementation). FALSE
               (one list file rewritten whole: read, add, rename) fails: a taker
               paused mid-fence is recovered by the operator, who read the list
               before the taker's fence landed and renames after it, dropping it;
               the operator's later cut then pins a record that fence refused.
               (Found by TLC on df_rcrash_both_3c_2rec; fixed in durable-state.ts.)
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, MaxG, MaxRec, Fence, HeadCheck, HeadRepair, Crash, TakeLock, FencePin,
          OpCrash, MaxOpCrash, Takeover, TakeoverFence, Inherit, ReRunFair, FenceFiles

VARIABLES lk, pc, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec,
          ncrash, cutG, seen, tcj, tfs, robbed, rdgen
vars == <<lk, pc, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec,
          ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>

\* a lock generation file: st = absent/free/held, o = owner (a client, "op", "opdead"), rc = the `recovering` mark
ABSENT == [st |-> "absent", o |-> "-", rc |-> FALSE]
FREE == [st |-> "free", o |-> "-", rc |-> FALSE]
OP == [st |-> "held", o |-> "op", rc |-> TRUE]
Gens == 0..MaxG
NoHead == [seq |-> 0, h |-> <<>>, g |-> 0]
Cutters == Clients \cup {"op"}
Max(a, b) == IF a >= b THEN a ELSE b

Init ==
  /\ lk = [g \in Gens |-> ABSENT]
  /\ pc = [c \in Clients |-> "acq"] /\ mygen = [c \in Clients |-> -1] /\ lj = [c \in Clients |-> <<>>]
  /\ journal = <<>> /\ head = NoHead /\ fences = {}
  /\ stale = {} /\ acked = {}
  /\ rpc = "idle" /\ rg = -1 /\ rS = <<>> /\ rF = {} /\ nrec = 0
  /\ ncrash = 0 /\ cutG = -1 /\ seen = [x \in Cutters |-> {}]
  /\ tcj = [c \in Clients |-> <<>>] /\ tfs = [c \in Clients |-> {}]
  /\ robbed = {} /\ rdgen = {}

Present == {g \in Gens : lk[g] # ABSENT}
Top == IF Present = {} THEN -1 ELSE CHOOSE g \in Present : \A h \in Present : h <= g
TopFree == IF Top = -1 THEN TRUE ELSE lk[Top] = FREE
Holds(c) == mygen[c] >= 0 /\ Top = mygen[c] /\ lk[Top].st = "held" /\ lk[Top].o = c
Rec(c) == [w |-> c, g |-> mygen[c]]
Go(c, s) == pc' = [pc EXCEPT ![c] = s]
\* a holder the lock protocol itself judges dead (same PID namespace, kill(pid, 0) fails)
DeadOwner(o) == o = "opdead" \/ (o \in Clients /\ pc[o] = "dead")

\* ---- load() -----------------------------------------------------------------
Mono(j) == \A i \in 1..(Len(j) - 1) : j[i].g <= j[i + 1].g
FenceOk(j, F) == \A f \in F : /\ FencePin => (Len(j) >= f.s /\ SubSeq(j, 1, f.s) = f.h)
                                /\ \A i \in 1..Len(j) : i > f.s => j[i].g >= f.g
Prefix(j, hd) == hd.seq <= Len(j) /\ SubSeq(j, 1, hd.seq) = hd.h
LagGen(j, hd) == Len(j) = hd.seq + 1 => j[Len(j)].g >= hd.g
StaleHead(j, hd, F) == HeadRepair /\ Len(j) > hd.seq + 1 /\ \E f \in F : hd.g < f.g /\ hd.seq <= f.s /\ Len(j) > f.s
LoadOk(j, hd, F) ==
  /\ (Fence => (Mono(j) /\ FenceOk(j, F) /\ LagGen(j, hd)))
  /\ Prefix(j, hd)
  /\ (Len(j) <= hd.seq + 1 \/ StaleHead(j, hd, F))
Loads == LoadOk(journal, head, fences)

\* FenceFiles: every fence is its own immutable file, so a write adds to whatever is on disk NOW. FALSE: one shared list
\* file rewritten whole from the copy the writer READ earlier (read, add, rename): fences that landed in between are lost.
FenceBase(readCopy) == IF FenceFiles THEN fences ELSE readCopy

\* ---- ghost: active cutters (read their cut, fence not yet renamed) -----------
CutGen(x) == IF x = "op" THEN (IF rpc = "fence" THEN rg + 1 ELSE -1)
             ELSE (IF pc[x] = "tfw" THEN mygen[x] ELSE -1)

\* ---- clients -----------------------------------------------------------------
Acq(c) == /\ pc[c] = "acq" /\ TopFree /\ Top + 1 <= MaxG /\ lk[Top + 1] = ABSENT
          /\ lk' = [lk EXCEPT ![Top + 1] = [st |-> "held", o |-> c, rc |-> FALSE]] /\ mygen' = [mygen EXCEPT ![c] = Top + 1]
          /\ Go(c, "rd")
          /\ UNCHANGED <<lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
\* withLock: the top holder is dead in this PID namespace -> create Top+1. A `recovering` mark obliges a cut + fence first.
TakeOver(c) == /\ Takeover /\ pc[c] = "acq" /\ Top >= 0 /\ lk[Top].st = "held" /\ DeadOwner(lk[Top].o)
               /\ Top + 1 <= MaxG /\ lk[Top + 1] = ABSENT
               /\ lk' = [lk EXCEPT ![Top + 1] = [st |-> "held", o |-> c, rc |-> (Inherit /\ lk[Top].rc)]]
               /\ mygen' = [mygen EXCEPT ![c] = Top + 1]
               /\ Go(c, IF TakeoverFence /\ lk[Top].rc THEN "tcut" ELSE "rd")
               /\ UNCHANGED <<lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
\* writeFence(dir, myGen - 1): read the fence list and the journal tail ...
TCut(c) == /\ pc[c] = "tcut"
           /\ tcj' = [tcj EXCEPT ![c] = journal] /\ tfs' = [tfs EXCEPT ![c] = fences] /\ seen' = [seen EXCEPT ![c] = {}]
           /\ Go(c, "tfw")
           /\ UNCHANGED <<lk, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, robbed, rdgen>>
\* ... then rename the rewritten fence file (no re-check: pessimistic, it may land late)
TFW(c) == /\ pc[c] = "tfw"
          /\ fences' = IF Fence THEN FenceBase(tfs[c]) \cup {[g |-> mygen[c], s |-> Len(tcj[c]), h |-> tcj[c]]} ELSE fences
          /\ stale' = stale \cup seen[c] /\ seen' = [seen EXCEPT ![c] = {}] /\ cutG' = Max(cutG, mygen[c])
          /\ Go(c, "rd")
          /\ UNCHANGED <<lk, mygen, lj, journal, head, acked, rpc, rg, rS, rF, nrec, ncrash, tcj, tfs, robbed, rdgen>>
\* load under the lock; a head that lags (or is a recognised stale head) is repaired first, like set()/update()
Rd(c) == /\ pc[c] = "rd"
         /\ IF Loads
              THEN /\ lj' = [lj EXCEPT ![c] = journal] /\ rdgen' = rdgen \cup {mygen[c]}
                   /\ Go(c, IF head.seq # Len(journal) THEN "repchk" ELSE "chk1")
              ELSE /\ Go(c, "lost") /\ UNCHANGED <<lj, rdgen>>   \* fail closed (corrupt/rollback); withLock still releases
         /\ UNCHANGED <<lk, mygen, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed>>
RepChk(c) == /\ pc[c] = "repchk" /\ Go(c, IF ~HeadCheck \/ Holds(c) THEN "repw" ELSE "lost")
             /\ UNCHANGED <<lk, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
RepW(c) == /\ pc[c] = "repw"
           /\ head' = [seq |-> Len(lj[c]), h |-> lj[c], g |-> mygen[c]] /\ Go(c, "chk1")
           /\ UNCHANGED <<lk, mygen, lj, journal, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
Chk1(c) == /\ pc[c] = "chk1" /\ Go(c, IF Holds(c) THEN "jren" ELSE "lost")
           /\ UNCHANGED <<lk, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
\* the rename itself: may happen long after chk1 (paused in the window). Ghost classification, see the header.
\* (the third disjunct is the naive order only: with TakeLock an active cutter holds the lock itself, so c cannot)
DirectStale(c) == \/ mygen[c] < cutG
                  \/ (~Holds(c) /\ \E g \in rdgen : g > mygen[c])
                  \/ (Holds(c) /\ CutGen("op") > mygen[c])
JRen(c) == /\ pc[c] = "jren"
           /\ journal' = Append(lj[c], Rec(c))
           /\ stale' = IF DirectStale(c) THEN stale \cup {c} ELSE stale
           /\ seen' = [x \in Cutters |-> IF CutGen(x) > mygen[c] THEN seen[x] \cup {c} ELSE seen[x]]
           /\ Go(c, "chk2")
           /\ UNCHANGED <<lk, mygen, lj, head, fences, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, tcj, tfs, robbed, rdgen>>
Chk2(c) == /\ pc[c] = "chk2" /\ Go(c, IF ~HeadCheck \/ Holds(c) THEN "hren" ELSE "lost")
           /\ UNCHANGED <<lk, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
HRen(c) == /\ pc[c] = "hren"
           /\ head' = [seq |-> Len(lj[c]) + 1, h |-> Append(lj[c], Rec(c)), g |-> mygen[c]]
           /\ acked' = acked \cup {c}                                    \* update() returns success
           /\ Go(c, "rel")
           /\ UNCHANGED <<lk, mygen, lj, journal, fences, stale, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
Rel(c) == /\ pc[c] \in {"rel", "lost"}
          /\ LET t == mygen[c] + 1 IN
             IF t <= MaxG /\ lk[t] = ABSENT THEN lk' = [lk EXCEPT ![t] = FREE] ELSE UNCHANGED lk   \* EEXIST after recovery
          /\ Go(c, "done")
          /\ UNCHANGED <<mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
Die(c) == /\ Crash /\ pc[c] \notin {"done", "dead"} /\ Go(c, "dead")
          /\ seen' = [seen EXCEPT ![c] = {}]          \* a taker that dies before its fence rename fenced nothing
          /\ UNCHANGED <<lk, mygen, lj, journal, head, fences, stale, acked, rpc, rg, rS, rF, nrec, ncrash, cutG, tcj, tfs, robbed, rdgen>>

\* ---- the operator (recoverDurableState) ---------------------------------------
\* TakeLock (the implementation): 1. link g+1 HELD by the operator (EEXIST: the holder released, abort), 2. read the cut S
\* (and the fence list) under that lock, 3. rename the rewritten fence file, 4. link g+2 free. TakeLock = FALSE is the naive
\* order (read S, fence, link g+1 free). A re-run on a crashed recovery's lock does not count against MaxRec (bounded by
\* MaxOpCrash instead).
RTop == /\ rpc = "idle" /\ Top >= 0 /\ lk[Top].st = "held" /\ lk[Top].o # "op"   \* dead, alive, paused, or a dead recovery
        /\ (lk[Top].o = "opdead" \/ nrec < MaxRec)
        /\ rg' = Top /\ rpc' = (IF TakeLock THEN "lockop" ELSE "readS")
        /\ nrec' = (IF lk[Top].o = "opdead" THEN nrec ELSE nrec + 1)
        /\ robbed' = (IF ~TakeLock /\ lk[Top].o \in Clients THEN robbed \cup {lk[Top].o} ELSE robbed)
        /\ UNCHANGED <<lk, pc, mygen, lj, journal, head, fences, stale, acked, rS, rF, ncrash, cutG, seen, tcj, tfs, rdgen>>
RLockOp == /\ rpc = "lockop"
           /\ IF rg + 1 <= MaxG /\ lk[rg + 1] = ABSENT
                THEN /\ lk' = [lk EXCEPT ![rg + 1] = OP] /\ rpc' = "readS"
                     /\ robbed' = (IF lk[rg].o \in Clients THEN robbed \cup {lk[rg].o} ELSE robbed)
                ELSE UNCHANGED <<lk, robbed>> /\ rpc' = "idle"           \* superseded while recovering: nothing written
           /\ UNCHANGED <<pc, mygen, lj, journal, head, fences, stale, acked, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, rdgen>>
RReadS == /\ rpc = "readS" /\ rS' = journal /\ rF' = fences /\ rpc' = "fence"     \* the cut: the journal exactly as it is now
          /\ seen' = [seen EXCEPT !["op"] = {}]
          /\ UNCHANGED <<lk, pc, mygen, lj, journal, head, fences, stale, acked, rg, nrec, ncrash, cutG, tcj, tfs, robbed, rdgen>>
RFence == /\ rpc = "fence"
          /\ fences' = IF Fence THEN FenceBase(rF) \cup {[g |-> rg + 1, s |-> Len(rS), h |-> rS]} ELSE fences
          /\ stale' = stale \cup seen["op"] /\ seen' = [seen EXCEPT !["op"] = {}] /\ cutG' = Max(cutG, rg + 1)
          /\ rpc' = "link"
          /\ UNCHANGED <<lk, pc, mygen, lj, journal, head, acked, rg, rS, rF, nrec, ncrash, tcj, tfs, robbed, rdgen>>
RLink == /\ rpc = "link"
         /\ LET t == IF TakeLock THEN rg + 2 ELSE rg + 1 IN
            IF t <= MaxG /\ lk[t] = ABSENT THEN lk' = [lk EXCEPT ![t] = FREE] ELSE UNCHANGED lk
         /\ rpc' = "idle"
         /\ UNCHANGED <<pc, mygen, lj, journal, head, fences, stale, acked, rg, rS, rF, nrec, ncrash, cutG, seen, tcj, tfs, robbed, rdgen>>
\* the recovery process dies (SIGKILL, OOM, power) after any of its steps: a lock it holds now names a dead process; a cut it
\* read but did not rename into state.fence is gone (renames it saw since are no longer pending against it).
ROpCrash == /\ OpCrash /\ ncrash < MaxOpCrash /\ rpc \in {"lockop", "readS", "fence", "link"}
            /\ lk' = [g \in Gens |-> IF lk[g].o = "op" THEN [lk[g] EXCEPT !.o = "opdead"] ELSE lk[g]]
            /\ rpc' = "idle" /\ ncrash' = ncrash + 1 /\ seen' = [seen EXCEPT !["op"] = {}]
            /\ UNCHANGED <<pc, mygen, lj, journal, head, fences, stale, acked, rg, rS, rF, nrec, cutG, tcj, tfs, robbed, rdgen>>

ClientStep(c) == Acq(c) \/ TakeOver(c) \/ TCut(c) \/ TFW(c) \/ Rd(c) \/ RepChk(c) \/ RepW(c) \/ Chk1(c) \/ JRen(c) \/ Chk2(c) \/ HRen(c) \/ Rel(c)
Next == \/ \E c \in Clients : ClientStep(c) \/ Die(c)
        \/ RTop \/ RLockOp \/ RReadS \/ RFence \/ RLink \/ ROpCrash
Spec == Init /\ [][Next]_vars

\* Liveness: clients and a recovery in progress are weakly fair; crashes and deaths never are. ReRunFair: the operator
\* eventually re-runs recovery on a crashed recovery's lock.
OpDeadTop == Top >= 0 /\ lk[Top].st = "held" /\ lk[Top].o = "opdead"
ReRun == RTop /\ lk[Top].o = "opdead"
LiveSpec == /\ Spec
            /\ \A c \in Clients : WF_vars(ClientStep(c))
            /\ WF_vars(RLockOp) /\ WF_vars(RReadS) /\ WF_vars(RFence) /\ WF_vars(RLink)
            /\ (ReRunFair => WF_vars(ReRun))
NoWedge == \A c \in Clients : (pc[c] = "acq" /\ OpDeadTop) ~> (pc[c] = "done")
AckedOrFailedClosed == \A c \in Clients : (pc[c] = "acq" /\ OpDeadTop) ~> (c \in acked \/ c \in robbed \/ stale # {})

Writers(j) == {j[i].w : i \in 1..Len(j)}
\* Loads only happen under the lock: while the (live) operator itself holds it (mid-recovery) nobody can load.
OpHolds == IF Top = -1 THEN FALSE ELSE lk[Top].o = "op"
NoStaleAccepted == (~OpHolds /\ Loads) => (Writers(journal) \cap stale = {})
NoAckedLost == (~OpHolds /\ Loads) => (acked \ stale) \subseteq Writers(journal)
ReadableUnlessStale == (stale = {}) => Loads
Safe == NoStaleAccepted /\ NoAckedLost /\ ReadableUnlessStale
=============================================================================
