------------------------------ MODULE DurableLock ------------------------------
(***************************************************************************
 The cross-process lock + journal protocol of packages/pca/src/durable-state.ts
 (openDurableState: withLock / tryBreakStale / commit), used as a monotone
 "highest accepted" register (update(key, fn)).  `val` is the journal content,
 replaced atomically by write-temp + rename.

 Lock protocol (as coded):
   acquire : open(lock, O_EXCL)                                   [start]
   else    : read lock (raw); decide stale (dead pid | too old); rename lock
             -> graveyard; if graveyard content != raw ("we moved a FRESH
             lock") put it back IF the slot is free; else unlink graveyard
   crit    : load journal; fn; atomicWrite(journal)
   release : read lock; if nonce == mine: unlink(lock)  (two syscalls)

 HungSteal : a holder that is alive but stalled (SIGSTOP, GC, slow fsync)
             longer than staleLockMs may have its lock broken.
 Recheck   : the nonce re-check right before the commit rename that the header
             comment of durable-state.ts describes (it is a separate syscall).
 Invariants:  MutualExclusion, WriteMono, AtMostOneTrue.
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, HungSteal, Recheck, Crash, PreStale

VARIABLES lockf, val, pc, raw, gy, mine, seen, res, wlog
vars == <<lockf, val, pc, raw, gy, mine, seen, res, wlog>>

NOFILE == "none"
Crit == {"rd", "rchk", "wr"}

Init ==
  /\ lockf = IF PreStale THEN "D" ELSE NOFILE       \* "D": lock left by a dead process
  /\ val = 0 /\ wlog = <<>>
  /\ pc = [c \in Clients |-> "start"] /\ raw = [c \in Clients |-> NOFILE] /\ gy = [c \in Clients |-> NOFILE]
  /\ mine = [c \in Clients |-> FALSE] /\ seen = [c \in Clients |-> 0] /\ res = [c \in Clients |-> "none"]

Go(c, s) == pc' = [pc EXCEPT ![c] = s]
Stale(x) == x = "D" \/ (x \in Clients /\ (pc[x] = "dead" \/ HungSteal))

Start(c) == /\ pc[c] = "start"
            /\ IF lockf = NOFILE THEN lockf' = c /\ Go(c, "rd") ELSE Go(c, "brk_read") /\ UNCHANGED lockf
            /\ UNCHANGED <<val, raw, gy, mine, seen, res, wlog>>
BrkRead(c) == /\ pc[c] = "brk_read"
              /\ raw' = [raw EXCEPT ![c] = lockf]
              /\ IF lockf = NOFILE THEN Go(c, "start") ELSE Go(c, "brk_decide")
              /\ UNCHANGED <<lockf, val, gy, mine, seen, res, wlog>>
BrkDecide(c) == /\ pc[c] = "brk_decide"
                /\ IF Stale(raw[c]) THEN Go(c, "brk_rename") ELSE Go(c, "start")
                /\ UNCHANGED <<lockf, val, raw, gy, mine, seen, res, wlog>>
BrkRename(c) == /\ pc[c] = "brk_rename"
                /\ IF lockf = NOFILE THEN Go(c, "start") /\ UNCHANGED <<lockf, gy>>
                   ELSE Go(c, "brk_cmp") /\ gy' = [gy EXCEPT ![c] = lockf] /\ lockf' = NOFILE
                /\ UNCHANGED <<val, raw, mine, seen, res, wlog>>
BrkCmp(c) == /\ pc[c] = "brk_cmp"
             /\ IF gy[c] = raw[c] THEN Go(c, "start") ELSE Go(c, "brk_putback")
             /\ UNCHANGED <<lockf, val, raw, gy, mine, seen, res, wlog>>
BrkPutback(c) == /\ pc[c] = "brk_putback"
                 /\ IF lockf = NOFILE THEN lockf' = gy[c] ELSE UNCHANGED lockf
                 /\ Go(c, "start") /\ UNCHANGED <<val, raw, gy, mine, seen, res, wlog>>
Rd(c) == /\ pc[c] = "rd" /\ seen' = [seen EXCEPT ![c] = val]
         /\ Go(c, IF Recheck THEN "rchk" ELSE "wr") /\ UNCHANGED <<lockf, val, raw, gy, mine, res, wlog>>
Rchk(c) == /\ pc[c] = "rchk"
           /\ IF lockf = c THEN Go(c, "wr") /\ UNCHANGED res
              ELSE Go(c, "rel_read") /\ res' = [res EXCEPT ![c] = "err"]       \* lost the lock: abort
           /\ UNCHANGED <<lockf, val, raw, gy, mine, seen, wlog>>
Wr(c) == /\ pc[c] = "wr"
         /\ IF seen[c] < 1 THEN val' = 1 /\ wlog' = Append(wlog, 1) /\ res' = [res EXCEPT ![c] = "T"]
            ELSE UNCHANGED <<val, wlog>> /\ res' = [res EXCEPT ![c] = "F"]
         /\ Go(c, "rel_read") /\ UNCHANGED <<lockf, raw, gy, mine, seen>>
RelRead(c) == /\ pc[c] = "rel_read" /\ mine' = [mine EXCEPT ![c] = (lockf = c)] /\ Go(c, "rel_unlink")
              /\ UNCHANGED <<lockf, val, raw, gy, seen, res, wlog>>
RelUnlink(c) == /\ pc[c] = "rel_unlink"
                /\ lockf' = IF mine[c] THEN NOFILE ELSE lockf
                /\ Go(c, "done") /\ UNCHANGED <<val, raw, gy, mine, seen, res, wlog>>
Die(c) == /\ Crash /\ pc[c] \notin {"done", "dead"} /\ Go(c, "dead")
          /\ UNCHANGED <<lockf, val, raw, gy, mine, seen, res, wlog>>

Next == \E c \in Clients : Start(c) \/ BrkRead(c) \/ BrkDecide(c) \/ BrkRename(c) \/ BrkCmp(c) \/ BrkPutback(c)
                           \/ Rd(c) \/ Rchk(c) \/ Wr(c) \/ RelRead(c) \/ RelUnlink(c) \/ Die(c)
Spec == Init /\ [][Next]_vars

MutualExclusion == Cardinality({c \in Clients : pc[c] \in Crit}) <= 1
WriteMono == \A i \in 1..(Len(wlog) - 1) : wlog[i] < wlog[i + 1]
AtMostOneTrue == Cardinality({c \in Clients : res[c] = "T"}) <= 1
Safe == MutualExclusion /\ WriteMono /\ AtMostOneTrue
=============================================================================
