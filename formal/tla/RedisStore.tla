------------------------------ MODULE RedisStore ------------------------------
(***************************************************************************
 Redis implementations of ReplayStore.consumeOnce / CounterStore.advance.
 One register = one key (consume: every client presents 1; counter: each
 presents its own value; value c stored as c+1, 0 = absent).

 Modes
   GOOD set_nx       SET key v NX PX ttl          (single-threaded, atomic)
   GOOD lua          EVAL: if tonumber(GET) < c then SET; return 1 end
   GOOD wait1        atomic write, then WAIT 1: TRUE only after the replica has it
   BAD  get_then_set GET in one command, SET in another (no script, no NX)
 Environment
   Failover   primary dies, the (async) replica is promoted: un-replicated writes are lost
   Restart    process restart; Persist decides what survives:
                "none"     nothing (RDB off / no persistence)
                "everysec" appendfsync everysec: writes since the last fsync lost
                "always"   appendfsync always: reply only after fsync
   Evict      maxmemory eviction of a live key (allkeys-lru)  [noeviction => FALSE]
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, Mode, MaxC, Consume, Failover, Restart, Persist, Evict

VARIABLES val, repl, dur, pc, cv, seen, res, wlog, maxEver
vars == <<val, repl, dur, pc, cv, seen, res, wlog, maxEver>>

Init ==
  /\ val = 0 /\ repl = 0 /\ dur = 0 /\ wlog = <<>> /\ maxEver = 0
  /\ pc = [c \in Clients |-> "start"] /\ seen = [c \in Clients |-> 0] /\ res = [c \in Clients |-> "none"]
  /\ cv \in IF Consume THEN {[c \in Clients |-> 1]} ELSE [Clients -> 1..MaxC]

Done(c, r) == /\ pc' = [pc EXCEPT ![c] = "done"] /\ res' = [res EXCEPT ![c] = r]
Put(v, w) == /\ val' = v /\ wlog' = Append(wlog, <<v, w>>) /\ maxEver' = IF v > maxEver THEN v ELSE maxEver
          /\ dur' = IF Persist = "always" THEN v ELSE dur

Start(c) ==
  /\ pc[c] = "start"
  /\ CASE Mode \in {"set_nx", "lua"} ->
            IF val < cv[c] THEN Put(cv[c], c) /\ Done(c, "T") /\ UNCHANGED <<repl, seen>>
                           ELSE Done(c, "F") /\ UNCHANGED <<val, repl, dur, seen, wlog, maxEver>>
       [] Mode = "wait1" ->
            IF val < cv[c] THEN Put(cv[c], c) /\ pc' = [pc EXCEPT ![c] = "wait"] /\ UNCHANGED <<repl, seen, res>>
                           ELSE Done(c, "F") /\ UNCHANGED <<val, repl, dur, seen, wlog, maxEver>>
       [] Mode = "get_then_set" ->
            /\ seen' = [seen EXCEPT ![c] = val]
            /\ IF val >= cv[c] THEN Done(c, "F") ELSE pc' = [pc EXCEPT ![c] = "wr"] /\ UNCHANGED res
            /\ UNCHANGED <<val, repl, dur, wlog, maxEver>>

Wr(c) == /\ pc[c] = "wr" /\ Put(cv[c], c) /\ Done(c, "T") /\ UNCHANGED <<repl, seen>>

\* WAIT 1 0 returned >= 1 : the replica acknowledged; otherwise the client errors (fail closed)
WaitOk(c)   == /\ pc[c] = "wait" /\ repl >= cv[c] /\ Done(c, "T") /\ UNCHANGED <<val, repl, dur, seen, wlog, maxEver>>
WaitFail(c) == /\ pc[c] = "wait" /\ Done(c, "err") /\ UNCHANGED <<val, repl, dur, seen, wlog, maxEver>>

Replicate == /\ repl < val /\ \E r \in (repl + 1)..val : repl' = r
             /\ UNCHANGED <<val, dur, pc, seen, res, wlog, maxEver>>
Fsync == /\ Persist = "everysec" /\ dur < val /\ dur' = val /\ UNCHANGED <<val, repl, pc, seen, res, wlog, maxEver>>

DoFailover ==
  /\ Failover
  /\ val' = repl /\ dur' = repl
  /\ pc' = [c \in Clients |-> IF pc[c] = "wait" THEN "done" ELSE pc[c]]
  /\ res' = [c \in Clients |-> IF pc[c] = "wait" THEN "err" ELSE res[c]]
  /\ UNCHANGED <<repl, seen, wlog, maxEver>>

DoRestart ==
  /\ Restart
  /\ val' = IF Persist = "none" THEN 0 ELSE dur
  /\ repl' = IF repl > val' THEN val' ELSE repl
  /\ pc' = [c \in Clients |-> IF pc[c] \in {"wait", "wr"} THEN "done" ELSE pc[c]]
  /\ res' = [c \in Clients |-> IF pc[c] \in {"wait"} THEN "err" ELSE res[c]]
  /\ UNCHANGED <<dur, seen, wlog, maxEver>>

DoEvict == /\ Evict /\ val > 0 /\ val' = 0 /\ repl' = 0 /\ dur' = 0 /\ UNCHANGED <<pc, seen, res, wlog, maxEver>>

Next == (
\/ \E c \in Clients : Start(c) \/ Wr(c) \/ WaitOk(c) \/ WaitFail(c)
        \/ Replicate \/ Fsync \/ DoFailover \/ DoRestart \/ DoEvict
        ) /\ UNCHANGED cv
Spec == Init /\ [][Next]_vars

WriteMono == \A i, j \in 1..Len(wlog) :
  (i < j /\ res[wlog[i][2]] = "T" /\ res[wlog[j][2]] = "T") => wlog[i][1] < wlog[j][1]
AckDurable == \A c \in Clients : res[c] = "T" => val >= cv[c]
AtMostOneTrue == \A c, d \in Clients : (c # d /\ res[c] = "T" /\ res[d] = "T") => cv[c] # cv[d]
FalseJustified == \A c \in Clients : res[c] = "F" => maxEver >= cv[c]
Safe == WriteMono /\ AckDurable /\ AtMostOneTrue /\ FalseJustified
=============================================================================
