----------------------------- MODULE Revocation -----------------------------
(***************************************************************************)
(* v2 §3.9 / T22: revocation exposure. A session is revoked at t_r. The     *)
(* epoch publisher publishes the revocation state from time to time (it may *)
(* stall; nothing forces it). A verifier at time `now` admits an action     *)
(* stamped ts (|ts - now| <= S, clock skew) only if the latest epoch is at   *)
(* most DRev old and does not list the session. ExposureBound: no action    *)
(* stamped after t_r + DRev + S is ever admitted.                          *)
(* CheckAge = FALSE drops the freshness check (expected fail).              *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxT, DRev, S, CheckAge

VARIABLES now, tr, pubTime, pubRevoked, bad
vars == <<now, tr, pubTime, pubRevoked, bad>>

None == MaxT + DRev + S + 100

Init == /\ now = 0 /\ tr = None /\ pubTime = 0 /\ pubRevoked = FALSE /\ bad = FALSE

Tick    == now < MaxT /\ now' = now + 1 /\ UNCHANGED <<tr, pubTime, pubRevoked, bad>>
Revoke  == tr = None /\ tr' = now /\ UNCHANGED <<now, pubTime, pubRevoked, bad>>
Publish == /\ pubTime' = now /\ pubRevoked' = (tr # None)
           /\ UNCHANGED <<now, tr, bad>>
Admit(ts) == /\ ts + S >= now /\ ts <= now + S
             /\ (CheckAge => now - pubTime <= DRev)
             /\ ~pubRevoked
             /\ bad' = (bad \/ (tr # None /\ ts > tr + DRev + S))
             /\ UNCHANGED <<now, tr, pubTime, pubRevoked>>

Next == Tick \/ Revoke \/ Publish \/ \E ts \in 0..(MaxT + S) : Admit(ts)
Spec == Init /\ [][Next]_vars

ExposureBound == ~bad
=============================================================================
