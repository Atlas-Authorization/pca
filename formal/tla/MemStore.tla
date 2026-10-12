------------------------------- MODULE MemStore -------------------------------
(***************************************************************************
 InMemoryReplayStore (packages/pca/src/replay.ts).  Atomic inside ONE process
 (no await between check and set).  The contract nevertheless requires the
 key to be remembered across every verifier instance and across restarts, so
   Mode = "one_process"  Restart = FALSE  : holds   (the documented use)
   Mode = "one_process"  Restart = TRUE   : VIOLATED (state loss resurrects a nonce)
   Mode = "per_process"                   : VIOLATED (two instances, two maps)
 ***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Clients, Procs, Mode, Restart, MaxC, Consume

VARIABLES mem, proc, cv, res, pc, wlog
vars == <<mem, proc, cv, res, pc, wlog>>

Init ==
  /\ mem = [p \in Procs |-> 0] /\ wlog = <<>>
  /\ proc \in [Clients -> Procs]
  /\ cv \in IF Consume THEN {[c \in Clients |-> 1]} ELSE [Clients -> 1..MaxC]
  /\ res = [c \in Clients |-> "none"] /\ pc = [c \in Clients |-> "start"]

Home(c) == IF Mode = "one_process" THEN CHOOSE p \in Procs : TRUE ELSE proc[c]

Op(c) == /\ pc[c] = "start"
         /\ LET p == Home(c) IN
            IF mem[p] < cv[c]
              THEN /\ mem' = [mem EXCEPT ![p] = cv[c]] /\ wlog' = Append(wlog, cv[c]) /\ res' = [res EXCEPT ![c] = "T"]
              ELSE /\ UNCHANGED <<mem, wlog>> /\ res' = [res EXCEPT ![c] = "F"]
         /\ pc' = [pc EXCEPT ![c] = "done"] /\ UNCHANGED <<proc, cv>>

DoRestart == /\ Restart /\ mem' = [p \in Procs |-> 0] /\ UNCHANGED <<proc, cv, res, pc, wlog>>

Next == (\E c \in Clients : Op(c)) \/ DoRestart
Spec == Init /\ [][Next]_vars

WriteMono == \A i \in 1..(Len(wlog) - 1) : wlog[i] < wlog[i + 1]
AtMostOneTrue == \A c, d \in Clients : (c # d /\ res[c] = "T" /\ res[d] = "T") => cv[c] # cv[d]
Safe == WriteMono /\ AtMostOneTrue
=============================================================================
