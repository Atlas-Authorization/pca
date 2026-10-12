---------------------------- MODULE ReplayContract ----------------------------
(***************************************************************************
 The ReplayStore / CounterStore CONTRACT of packages/pca/src/replay.ts, with
 real time, per-server clock offsets, retention and pruning.

   consumeOnce(key, retainUntil = exp + Skew, now)  : TRUE iff no live record
   prune(now)                                       : forget records with
                                                      retainUntil < now
   advance(stream, c)                               : TRUE iff c > last

 Servers have local clocks  local = t + off[s]  with pairwise skew <= Skew
 in the GOOD configuration.  A server accepts an action only while its LOCAL
 clock says  now <= exp  (guardPCActnReplay / replayPre: expired from exp+1).

 SAFETY (the contract):
   ExactlyOnce   a key is accepted at most once, ever (for one action)
   CounterMono   accepted counters of a stream strictly increase
 Known-bad variants (selected by constants) must VIOLATE these:
   MaxOff > Skew         clock skew exceeds the retention allowance
   PruneMode = "early"   horizon computed from exp (no skew term)
   PruneMode = "evict"   capacity eviction of a live record
   PruneMode = "ttl"     TTL store (Redis SET .. PX retainUntil-now): GOOD while pairwise skew <= Skew
   Durable = FALSE       restart loses the (in-memory) store
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Servers, Keys, ExpT, MaxT, Skew, MaxOff, PruneMode, Durable, MaxC

VARIABLES t, off, store, acc, last, clog

NONE == -1
vars == <<t, off, store, acc, last, clog>>

Init ==
  /\ t = 0
  /\ off \in [Servers -> 0..MaxOff]
  /\ store = [k \in Keys |-> NONE]
  /\ acc = [k \in Keys |-> 0]
  /\ last = -1
  /\ clog = <<>>

Tick == /\ t < MaxT /\ t' = t + 1 /\ UNCHANGED <<off, store, acc, last, clog>>

\* guardPCActnReplay on server s: expired (local) => deny before touching the store.
Consume(s, k) ==
  LET now == t + off[s] IN
  /\ now <= ExpT
  /\ IF store[k] >= (IF PruneMode = "ttl" THEN t ELSE now)   \* live record: replay ("ttl": the STORE'S clock decides)
       THEN UNCHANGED <<store, acc>>
       ELSE /\ store' = [store EXCEPT ![k] = IF PruneMode = "ttl" THEN t + (ExpT + Skew - now)   \* SET .. PX (retainUntil - callerNow)
                                                                  ELSE ExpT + Skew]
            /\ acc' = [acc EXCEPT ![k] = @ + 1]
  /\ UNCHANGED <<t, off, last, clog>>

Horizon(s) ==
  LET now == t + off[s] IN
  CASE PruneMode = "safe"  -> now            \* forget iff retainUntil < now
    [] PruneMode = "early" -> now + Skew      \* retainUntil - Skew < now  (exp-only horizon)
    [] PruneMode = "evict" -> 1000            \* any record (capacity eviction)
    [] PruneMode = "ttl"   -> t               \* Redis/Memcached TTL: expiry is judged by the store's own (real-time) clock

Prune(s) ==
  /\ store' = [k \in Keys |-> IF store[k] # NONE /\ store[k] < Horizon(s) THEN NONE ELSE store[k]]
  /\ UNCHANGED <<t, off, acc, last, clog>>

\* A volatile store loses everything when its process restarts.
Restart ==
  /\ ~Durable
  /\ store' = [k \in Keys |-> NONE]
  /\ UNCHANGED <<t, off, acc, last, clog>>

\* CounterStore.advance : atomic compare-and-advance, never pruned.
Advance(c) ==
  /\ IF c > last THEN /\ last' = c /\ clog' = Append(clog, c)
                 ELSE UNCHANGED <<last, clog>>
  /\ UNCHANGED <<t, off, store, acc>>

Next ==
  \/ Tick
  \/ \E s \in Servers, k \in Keys : Consume(s, k)
  \/ \E s \in Servers : Prune(s)
  \/ Restart
  \/ \E c \in 0..MaxC : Advance(c)

Spec == Init /\ [][Next]_vars

ExactlyOnce == \A k \in Keys : acc[k] <= 1
CounterMono == \A i \in 1..(Len(clog) - 1) : clog[i] < clog[i + 1]
SkewBound == \A a, b \in Servers : off[a] - off[b] <= Skew   \* environment assumption, used as a CONSTRAINT-free check

TypeOK == /\ t \in 0..MaxT /\ \A k \in Keys : acc[k] \in Nat
=============================================================================
