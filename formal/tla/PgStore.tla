------------------------------- MODULE PgStore -------------------------------
(***************************************************************************
 Postgres (READ COMMITTED, the default) implementations of the replay
 contract, as interleavings of statement-level steps from concurrent
 clients (possibly on different API servers) plus crashes and restarts.

 One register models one key / stream:  val = committed value, 0 = no row /
 counter -1 ; a counter c is stored as c+1.  Consume-once is the special case
 where every client presents the same value 1 (Consume = TRUE): at most one
 client may ever be told TRUE.  For counters every client presents its own
 value cv[c] and TRUE must be returned only for a strict increase.

 Modes (Mode):
   GOOD  update_where      UPDATE .. SET counter=$c WHERE counter<$c RETURNING
                           (also INSERT .. ON CONFLICT DO NOTHING / DO UPDATE
                           .. WHERE .. RETURNING: row lock / unique-index wait,
                           re-evaluation after the wait)
   GOOD  for_update        BEGIN; SELECT .. FOR UPDATE; decide; UPDATE; COMMIT
                           (the reference server admission code Phase B)
   GOOD  advisory          pg_advisory_xact_lock; SELECT; decide; UPDATE; COMMIT
   GOOD  select_insert_unique  SELECT then INSERT with a UNIQUE index: the loser
                           gets unique_violation (error => fail closed)
   GOOD  replica_fastpath  Phase A: lagging read replica / unlocked read may only
                           DENY (seen <= val) then update_where on the primary
   BAD   read_then_write   SELECT in one statement, UPDATE .. SET counter=$c
                           (no WHERE) in another, no transaction
   BAD   no_txn_for_update SELECT .. FOR UPDATE in autocommit (lock gone at once)
   BAD   upsert_overwrite  SELECT then INSERT .. ON CONFLICT DO UPDATE SET (overwrite)
   BAD   for_update_noseed  SELECT .. FOR UPDATE on an absent row (no seed) locks nothing
   BAD   replica_decide    decision (allow) taken on a stale replica read
 Environment switches (BOOLEAN):
   Crash      a client may die at any step (tx rolls back, locks released)
   Restart    server crash-restart; if ~SyncCommit committed work can be lost
   LoseAck    commit succeeded but the ack is lost (client sees an error)
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, Mode, MaxC, Consume, Crash, Restart, SyncCommit, LoseAck

VARIABLES val, replica, lock, pend, pc, cv, seen, res, wlog, maxEver

NOLOCK == "none"
vars == <<val, replica, lock, pend, pc, cv, seen, res, wlog, maxEver>>

Init ==
  /\ val = 0 /\ replica = 0 /\ lock = NOLOCK /\ maxEver = 0 /\ wlog = <<>>
  /\ pend = [c \in Clients |-> 0]
  /\ pc = [c \in Clients |-> "start"]
  /\ seen = [c \in Clients |-> 0]
  /\ res = [c \in Clients |-> "none"]
  /\ cv \in IF Consume THEN {[c \in Clients |-> 1]} ELSE [Clients -> 1..MaxC]

Done(c, r) == /\ pc' = [pc EXCEPT ![c] = "done"] /\ res' = [res EXCEPT ![c] = r]
Release(c) == lock' = IF lock = c THEN NOLOCK ELSE lock
Write(v, w) == /\ val' = v /\ wlog' = Append(wlog, <<v, w>>) /\ maxEver' = IF v > maxEver THEN v ELSE maxEver

\* ------------------------------------------------------------------ first step
Start(c) ==
  /\ pc[c] = "start"
  /\ CASE Mode \in {"update_where"} ->
            \* single statement; blocks while another tx holds the row (re-evaluated after the wait)
            /\ lock = NOLOCK
            /\ IF val < cv[c]
                 THEN /\ lock' = c /\ pend' = [pend EXCEPT ![c] = cv[c]] /\ pc' = [pc EXCEPT ![c] = "commit"]
                      /\ UNCHANGED <<res, val, replica, seen, wlog, maxEver>>
                 ELSE /\ Done(c, "F") /\ UNCHANGED <<lock, pend, val, replica, seen, wlog, maxEver>>
       [] Mode \in {"for_update", "advisory"} ->
            /\ lock = NOLOCK
            /\ lock' = c /\ seen' = [seen EXCEPT ![c] = val] /\ pc' = [pc EXCEPT ![c] = "decide"]
            /\ UNCHANGED <<res, pend, val, replica, wlog, maxEver>>
       [] Mode = "for_update_noseed" ->
            \* SELECT .. FOR UPDATE on a row that does not exist yet locks NOTHING (the reference server seeds the row first)
            /\ IF val = 0
                 THEN /\ seen' = [seen EXCEPT ![c] = 0] /\ pc' = [pc EXCEPT ![c] = "decide"] /\ UNCHANGED lock
                 ELSE /\ lock = NOLOCK /\ lock' = c /\ seen' = [seen EXCEPT ![c] = val] /\ pc' = [pc EXCEPT ![c] = "decide"]
            /\ UNCHANGED <<res, pend, val, replica, wlog, maxEver>>
       [] Mode = "select_insert_unique" ->
            /\ seen' = [seen EXCEPT ![c] = val]
            /\ IF val >= cv[c] THEN Done(c, "F") ELSE pc' = [pc EXCEPT ![c] = "ins"] /\ UNCHANGED res
            /\ UNCHANGED <<lock, pend, val, replica, wlog, maxEver>>
       [] Mode \in {"read_then_write", "upsert_overwrite", "no_txn_for_update"} ->
            /\ seen' = [seen EXCEPT ![c] = val]
            /\ IF val >= cv[c] THEN Done(c, "F") ELSE pc' = [pc EXCEPT ![c] = "wr"] /\ UNCHANGED res
            /\ UNCHANGED <<lock, pend, val, replica, wlog, maxEver>>
       [] Mode \in {"replica_fastpath", "replica_decide"} ->
            \E r \in replica..val :   \* stale (but monotone) read
              /\ seen' = [seen EXCEPT ![c] = r]
              /\ IF r >= cv[c] THEN Done(c, "F") ELSE pc' = [pc EXCEPT ![c] = "wr"] /\ UNCHANGED res
              /\ UNCHANGED <<lock, pend, val, replica, wlog, maxEver>>

\* ------------------------------------------------------------ later statements
Decide(c) ==                       \* for_update / advisory, lock held, value read under the lock
  /\ pc[c] = "decide"
  /\ IF cv[c] > seen[c]
       THEN /\ pend' = [pend EXCEPT ![c] = cv[c]] /\ pc' = [pc EXCEPT ![c] = "commit"] /\ UNCHANGED <<res, lock>>
       ELSE /\ Done(c, "F") /\ Release(c) /\ UNCHANGED pend       \* ROLLBACK
  /\ UNCHANGED <<val, replica, seen, wlog, maxEver>>

Ins(c) ==                          \* INSERT into a UNIQUE index
  /\ pc[c] = "ins"
  /\ lock = NOLOCK
  /\ IF val >= cv[c]
       THEN /\ Done(c, "err") /\ UNCHANGED <<lock, pend>>           \* unique_violation: fail closed
       ELSE /\ lock' = c /\ pend' = [pend EXCEPT ![c] = cv[c]] /\ pc' = [pc EXCEPT ![c] = "commit"] /\ UNCHANGED res
  /\ UNCHANGED <<val, replica, seen, wlog, maxEver>>

Wr(c) ==                           \* second autocommit statement
  /\ pc[c] = "wr"
  /\ CASE Mode = "replica_fastpath" ->
            \* UPDATE .. WHERE counter < $c on the primary (single statement, lock + re-evaluate)
            /\ lock = NOLOCK
            /\ IF val < cv[c]
                 THEN lock' = c /\ pend' = [pend EXCEPT ![c] = cv[c]] /\ pc' = [pc EXCEPT ![c] = "commit"] /\ UNCHANGED <<res, val, wlog, maxEver>>
                 ELSE Done(c, "F") /\ UNCHANGED <<lock, pend, val, wlog, maxEver>>
       [] OTHER ->
            \* unconditional write of $c (atomic single statement, commits at once)
            /\ lock = NOLOCK
            /\ Write(cv[c], c) /\ Done(c, "T") /\ UNCHANGED <<lock, pend>>
  /\ UNCHANGED <<replica, seen>>

CommitDB(c) ==
  /\ pc[c] = "commit"
  /\ Write(pend[c], c) /\ Release(c) /\ pend' = [pend EXCEPT ![c] = 0]
  /\ pc' = [pc EXCEPT ![c] = "ack"] /\ UNCHANGED <<res, replica, seen>>

Ack(c) == /\ pc[c] = "ack" /\ Done(c, "T") /\ UNCHANGED <<val, replica, lock, pend, seen, wlog, maxEver>>

\* ------------------------------------------------------------------ failures
Fail(c) ==                         \* client crash / connection drop / ROLLBACK
  /\ Crash
  /\ pc[c] # "done"
  /\ IF pc[c] = "ack"
       THEN /\ LoseAck /\ Done(c, "err") /\ UNCHANGED <<val, replica, lock, pend, seen, wlog, maxEver>>
       ELSE /\ Done(c, "err") /\ Release(c) /\ pend' = [pend EXCEPT ![c] = 0]
            /\ UNCHANGED <<val, replica, seen, wlog, maxEver>>

DoRestart ==                       \* server crash + recovery: tx's roll back, locks gone
  /\ Restart
  /\ lock' = NOLOCK /\ pend' = [c \in Clients |-> 0]
  /\ pc' = [c \in Clients |-> IF pc[c] \in {"done", "ack"} THEN pc[c] ELSE "done"]
  /\ res' = [c \in Clients |-> IF pc[c] \in {"done", "ack"} THEN res[c] ELSE "err"]
  /\ val' \in IF SyncCommit THEN {val} ELSE 0..val         \* async commit: last commits may vanish
  /\ replica' = IF replica > val' THEN val' ELSE replica
  /\ UNCHANGED <<seen, wlog, maxEver>>

CatchUp == /\ replica < val /\ \E r \in (replica + 1)..val : replica' = r
           /\ UNCHANGED <<val, lock, pend, pc, seen, res, wlog, maxEver>>

Next == (
\/ \E c \in Clients : Start(c) \/ Decide(c) \/ Ins(c) \/ Wr(c) \/ CommitDB(c) \/ Ack(c) \/ Fail(c)
        \/ DoRestart \/ CatchUp
        ) /\ UNCHANGED cv
Spec == Init /\ [][Next]_vars

(*********************************** properties ***********************************)
\* (1) acknowledged writes, in commit order, are strictly increasing: no lost update, no regression, no double accept
WriteMono == \A i, j \in 1..Len(wlog) :
  (i < j /\ res[wlog[i][2]] = "T" /\ res[wlog[j][2]] = "T") => wlog[i][1] < wlog[j][1]
\* (2) a TRUE answer is for a value that is (still) durable
AckDurable == \A c \in Clients : res[c] = "T" => val >= cv[c]
\* (3) consume-once: at most one TRUE per key (pairwise: two TRUE need distinct, increasing values)
AtMostOneTrue == \A c, d \in Clients : (c # d /\ res[c] = "T" /\ res[d] = "T") => cv[c] # cv[d]
\* (4) a FALSE answer is justified by an earlier committed value >= the presented one
FalseJustified == \A c \in Clients : res[c] = "F" => maxEver >= cv[c]
Safe == WriteMono /\ AckDurable /\ AtMostOneTrue /\ FalseJustified
=============================================================================
