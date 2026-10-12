----------------------------- MODULE RequirePcaLock -----------------------------
(***************************************************************************
 packages/pca/src/server/require-pca.ts : the get -> verify -> put critical
 section that enforces the replay counter for a self-hosted resource server.

   section = state.get(key) ; verifyPCActn ; counter > lastCounter ? ;
             state.put(key, { lastCounter: counter })

 It is a read-modify-write on a PcaStateStore, so correctness depends entirely
 on how `withKeyLock(grant.id, section)` excludes the other nodes:

   exclusive     a row lock / pg_advisory lock / DB-session mutex: held until the
                 holder finishes OR dies, never expires under it         GOOD
   lease         a Redis `SET lock NX PX ttl` mutex: the lease can expire while
                 the holder is paused (GC, SIGSTOP, slow get/put), a second
                 holder enters, and the first then completes its `put`   BAD
   lease_fenced  the same lease, but `put` is a compare-and-set on the version
                 read by `get` (a fencing token)                          GOOD
   nolock        a store without withKeyLock on a MULTI-node deployment
                 (the in-process fallback lock only covers one process)   BAD
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, Mode, MaxC

VARIABLES owner, val, ver, pc, cv, seen, seenVer, res, wlog
vars == <<owner, val, ver, pc, cv, seen, seenVer, res, wlog>>
NOONE == "none"

Init ==
  /\ owner = NOONE /\ val = 0 /\ ver = 0 /\ wlog = <<>>
  /\ pc = [c \in Clients |-> "start"] /\ seen = [c \in Clients |-> 0] /\ seenVer = [c \in Clients |-> 0]
  /\ res = [c \in Clients |-> "none"]
  /\ cv \in [Clients -> 1..MaxC]

Go(c, s) == pc' = [pc EXCEPT ![c] = s]
Done(c, r) == /\ pc' = [pc EXCEPT ![c] = "done"] /\ res' = [res EXCEPT ![c] = r]

Acquire(c) == /\ pc[c] = "start"
              /\ IF Mode = "nolock" THEN Go(c, "get") /\ UNCHANGED owner
                 ELSE owner = NOONE /\ owner' = c /\ Go(c, "get")
              /\ UNCHANGED <<val, ver, seen, seenVer, res, wlog>>

\* a lease runs out while its holder is paused; the holder does not know
Expire == /\ Mode \in {"lease", "lease_fenced"} /\ owner # NOONE /\ owner' = NOONE
          /\ UNCHANGED <<val, ver, pc, seen, seenVer, res, wlog>>

Get(c) == /\ pc[c] = "get" /\ seen' = [seen EXCEPT ![c] = val] /\ seenVer' = [seenVer EXCEPT ![c] = ver] /\ Go(c, "decide")
          /\ UNCHANGED <<owner, val, ver, res, wlog>>

Decide(c) == /\ pc[c] = "decide"
             /\ IF cv[c] > seen[c] THEN Go(c, "put") /\ UNCHANGED <<owner, res>>
                ELSE Done(c, "F") /\ owner' = IF owner = c THEN NOONE ELSE owner
             /\ UNCHANGED <<val, ver, seen, seenVer, wlog>>

Put(c) == /\ pc[c] = "put"
          /\ IF Mode = "lease_fenced" /\ ver # seenVer[c]
               THEN Done(c, "err") /\ UNCHANGED <<val, ver, wlog>>      \* fenced out: fail closed
               ELSE /\ val' = cv[c] /\ ver' = ver + 1 /\ wlog' = Append(wlog, <<cv[c], c>>) /\ Done(c, "T")
          /\ owner' = IF owner = c THEN NOONE ELSE owner
          /\ UNCHANGED <<seen, seenVer>>

Next == (\/ \E c \in Clients : Acquire(c) \/ Get(c) \/ Decide(c) \/ Put(c)
         \/ Expire) /\ UNCHANGED cv
Spec == Init /\ [][Next]_vars

WriteMono == \A i, j \in 1..Len(wlog) :
  (i < j /\ res[wlog[i][2]] = "T" /\ res[wlog[j][2]] = "T") => wlog[i][1] < wlog[j][1]
AtMostOneTrue == \A c, d \in Clients : (c # d /\ res[c] = "T" /\ res[d] = "T") => cv[c] # cv[d]
Safe == WriteMono /\ AtMostOneTrue
=============================================================================
