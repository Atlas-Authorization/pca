---------------------------- MODULE ApaContract ----------------------------
(***************************************************************************
 Apalache-typed twin of ReplayContract.tla, used for an UNBOUNDED-TIME proof.
 TLC explores t <= MaxT; here time is a mathematical integer and we prove that

     IndInv  /\  Next  =>  IndInv'          (one-step inductiveness, SMT)
     Init    =>  IndInv

 so ExactlyOnce holds in every reachable state at any time, for all clock
 offsets satisfying the pairwise bound.  With the bad constants (offset bound
 > Skew, or an early prune horizon) the same query yields a counterexample.

 Run (see formal/tla/run-apalache.sh):
   apalache-mc check --init=Init   --inv=IndInv --length=0 --cinit=CInitGood ApaContract.tla
   apalache-mc check --init=IndInit --inv=IndInv --length=1 --cinit=CInitGood ApaContract.tla
 ***************************************************************************)
EXTENDS Integers

CONSTANTS
  \* @type: Int;
  Skew,
  \* @type: Int;
  ExpT,
  \* @type: Int;
  MaxOff,
  \* @type: Int;
  PruneAdd

VARIABLES
  \* @type: Int;
  t,
  \* @type: Str -> Int;
  off,
  \* @type: Str -> Int;
  store,
  \* @type: Str -> Int;
  acc

Servers == {"s1", "s2", "s3"}
Keys == {"k1", "k2"}
NONE == -1

CInitGood == Skew = 1 /\ ExpT = 2 /\ MaxOff = 1 /\ PruneAdd = 0
CInitBadSkew == Skew = 1 /\ ExpT = 2 /\ MaxOff = 2 /\ PruneAdd = 0
CInitBadPrune == Skew = 1 /\ ExpT = 2 /\ MaxOff = 1 /\ PruneAdd = 1
\* any non-negative parameters (SMT chooses them): the proof for ALL skews / expiries
CInitGeneral == Skew \in Int /\ ExpT \in Int /\ MaxOff \in Int /\ PruneAdd \in Int
  /\ Skew >= 0 /\ ExpT >= 0 /\ MaxOff = Skew /\ PruneAdd = 0

Init ==
  /\ t = 0
  /\ off \in [Servers -> Int]
  /\ \A s \in Servers : off[s] >= 0 /\ off[s] <= MaxOff
  /\ store = [k \in Keys |-> NONE]
  /\ acc = [k \in Keys |-> 0]

Tick == /\ t' = t + 1 /\ UNCHANGED <<off, store, acc>>

Consume(s, k) ==
  LET now == t + off[s] IN
  /\ now <= ExpT
  /\ IF store[k] >= now
       THEN UNCHANGED <<store, acc>>
       ELSE /\ store' = [store EXCEPT ![k] = ExpT + Skew]
            /\ acc' = [acc EXCEPT ![k] = acc[k] + 1]
  /\ UNCHANGED <<t, off>>

Prune(s) ==
  /\ store' = [k \in Keys |-> IF store[k] /= NONE /\ store[k] < t + off[s] + PruneAdd THEN NONE ELSE store[k]]
  /\ UNCHANGED <<t, off, acc>>

Next == Tick \/ (\E s \in Servers, k \in Keys : Consume(s, k)) \/ (\E s \in Servers : Prune(s))

ExactlyOnce == \A k \in Keys : acc[k] <= 1

\* environment: any two local clocks differ by at most Skew (the guard's documented clockSkewMs ceiling)
PairwiseSkew == \A a \in Servers, b \in Servers : off[a] - off[b] <= MaxOff   \* MaxOff = Skew in the good configs
AllPastExp == \A s \in Servers : t + off[s] > ExpT

IndInv ==
  /\ PairwiseSkew
  /\ t >= 0
  /\ \A s \in Servers : off[s] >= 0
  /\ \A k \in Keys :
       /\ acc[k] >= 0 /\ acc[k] <= 1
       /\ (acc[k] = 0 => store[k] = NONE)
       /\ (acc[k] = 1 => (store[k] = ExpT + Skew \/ (store[k] = NONE /\ AllPastExp)))

IndInit ==
  /\ t \in Int /\ off \in [Servers -> Int] /\ store \in [Keys -> Int] /\ acc \in [Keys -> Int]
  /\ IndInv
=============================================================================
