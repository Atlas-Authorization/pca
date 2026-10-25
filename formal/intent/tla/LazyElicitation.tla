--------------------------- MODULE LazyElicitation ---------------------------
(***************************************************************************)
(* v2 §3.3 / T13, T14: lazy just-in-time elicitation with delta grants.     *)
(* The agent chooses the visit order adversarially (any cell, any time).    *)
(* Visiting an uncertain cell (0 < p < 1, i.e. in the disagreement region)  *)
(* triggers one question; the principal's answer (noise-free unless Noisy)  *)
(* updates the version space and a principal-signed delta adds exactly the  *)
(* cells that became certain. The effective grant is G0 ∪ deltas.           *)
(* AgentSigned = TRUE lets the agent mint a delta (expected fail).          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS N, Noisy, MaxNoise, AgentSigned

Outcomes == 1..N
Hyps     == {{}} \cup {lo..hi : lo \in Outcomes, hi \in Outcomes}
Acc(V, w) == {t \in V : w \in t}
Rej(V, w) == {t \in V : w \notin t}
Dis(V)    == {w \in Outcomes : Acc(V, w) # {} /\ Rej(V, w) # {}}
G1(V)     == {w \in Outcomes : \A t \in V : w \in t}

VARIABLES truth, vs, eff, asked, nq, noise, visited, agentAdded
vars == <<truth, vs, eff, asked, nq, noise, visited, agentAdded>>

Init == /\ truth \in Hyps
        /\ vs = Hyps
        /\ eff = G1(Hyps)
        /\ asked = {} /\ nq = 0 /\ noise = 0 /\ visited = {} /\ agentAdded = FALSE

\* the agent visits w; if w is uncertain the principal is asked once, and the delta is signed by the principal
Visit(w) == /\ visited' = visited \cup {w}
            /\ IF w \in Dis(vs)
               THEN \E y \in BOOLEAN :
                      /\ (y = (w \in truth)) \/ (Noisy /\ noise < MaxNoise)
                      /\ noise' = IF y = (w \in truth) THEN noise ELSE noise + 1
                      /\ vs' = {t \in vs : (w \in t) = y}
                      /\ eff' = eff \cup (G1(vs') \ G1(vs))
                      /\ asked' = asked \cup {w}
                      /\ nq' = nq + 1
               ELSE UNCHANGED <<vs, eff, asked, nq, noise>>
            /\ UNCHANGED <<truth, agentAdded>>

AgentDelta(w) == /\ AgentSigned
                 /\ eff' = eff \cup {w}
                 /\ agentAdded' = TRUE
                 /\ UNCHANGED <<truth, vs, asked, nq, noise, visited>>

Next == \E w \in Outcomes : Visit(w) \/ AgentDelta(w)
Spec == Init /\ [][Next]_vars

EffectiveSound  == eff \subseteq truth
\* each cell is asked at most once (nq counts questions), only visited cells are asked, and
\* every question removes at least one hypothesis
QuestionsBound  == /\ asked \subseteq visited
                   /\ nq = Cardinality(asked)
                   /\ nq + Cardinality(vs) <= Cardinality(Hyps)
NoAgentWidening == ~agentAdded
UncertainShrinks == [][Dis(vs') \subseteq Dis(vs)]_vars
=============================================================================
