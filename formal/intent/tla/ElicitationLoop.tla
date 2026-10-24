--------------------------- MODULE ElicitationLoop ---------------------------
(***************************************************************************)
(* The PCA Intent Layer elicitation loop (docs/specs/pca-intent-layer.md   *)
(* §2.5), model-checked with TLC. Companion: docs/specs/pca-intent-formal.md*)
(*                                                                         *)
(*   ask -> update -> stop when the estimate <= Eps (or nothing to ask)    *)
(*                                                                         *)
(* One verb, one ordered numeric dimension with N cells. The hypothesis    *)
(* class is the spec's Theta_v for that verb: the deny-verb hypothesis {}  *)
(* plus every non-empty contiguous range of cells. The TRUE intent is any  *)
(* hypothesis (chosen non-deterministically in Init, so every truth is     *)
(* checked), and the questioner is ANY strategy that asks a point of the   *)
(* disagreement region (the choice of question is non-deterministic, so    *)
(* every strategy -- halving or not -- is covered).                        *)
(*                                                                         *)
(* Posterior: uniform over the version space (the noise-free posterior     *)
(* under a uniform prior). Workload and harm are 1 per cell, so the        *)
(* estimates are integers after multiplying by |VS|:                       *)
(*   p(w)       = |Acc(VS,w)| / |VS|                                       *)
(*   G_tau      = {w : p(w) >= TauNum/TauDen}                              *)
(*   R^ * |VS|  = sum_{w in G_tau}  |Rej(VS,w)|                            *)
(*   B^ * |VS|  = sum_{w notin G_tau} |Acc(VS,w)|                          *)
(* Stop when both are <= Eps*|VS| (spec: R^ <= eps_R and B^ <= eps_B), or  *)
(* when the disagreement region is empty. The emitted grant is G_tau.      *)
(*                                                                         *)
(* Noisy = TRUE lets up to MaxNoise answers be wrong (adversarially), to   *)
(* show that the noise-free assumption is load-bearing.                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS N, Eps, TauNum, TauDen, Noisy, MaxNoise

Outcomes == 1..N
Hyps     == {{}} \cup {lo..hi : lo \in Outcomes, hi \in Outcomes}

Acc(V, w) == {t \in V : w \in t}
Rej(V, w) == {t \in V : w \notin t}
Dis(V)    == {w \in Outcomes : Acc(V, w) # {} /\ Rej(V, w) # {}}

\* the high-confidence region at threshold tau = TauNum/TauDen
HighConf(V) == {w \in Outcomes : TauDen * Cardinality(Acc(V, w)) >= TauNum * Cardinality(V)}

RECURSIVE RejSum(_, _)
RejSum(V, S) == IF S = {} THEN 0
                ELSE LET w == CHOOSE x \in S : TRUE IN Cardinality(Rej(V, w)) + RejSum(V, S \ {w})
RECURSIVE AccSum(_, _)
AccSum(V, S) == IF S = {} THEN 0
                ELSE LET w == CHOOSE x \in S : TRUE IN Cardinality(Acc(V, w)) + AccSum(V, S \ {w})

RiskNum(V)   == RejSum(V, HighConf(V))               \* |VS| * R^(G_tau)
BurdenNum(V) == AccSum(V, Outcomes \ HighConf(V))    \* |VS| * B^(G_tau)
EstOK(V)     == RiskNum(V) <= Eps * Cardinality(V) /\ BurdenNum(V) <= Eps * Cardinality(V)

VARIABLES truth, vs, asked, noise, done, grant, vetoed
vars == <<truth, vs, asked, noise, done, grant, vetoed>>

TypeOK == /\ truth \in Hyps
          /\ vs \subseteq Hyps
          /\ asked \in Nat /\ noise \in Nat
          /\ done \in BOOLEAN
          /\ grant \subseteq Outcomes
          /\ vetoed \subseteq Outcomes

Init == /\ truth \in Hyps
        /\ vs = Hyps
        /\ asked = 0 /\ noise = 0
        /\ done = FALSE
        /\ grant = {}
        /\ vetoed = {}

\* ask w (any point of the disagreement region), receive answer y, update the version space
Ask(w) == /\ ~done
          /\ ~EstOK(vs)
          /\ w \in Dis(vs)
          /\ \E y \in BOOLEAN :
                /\ (y = (w \in truth)) \/ (Noisy /\ noise < MaxNoise)
                /\ vs' = {t \in vs : (w \in t) = y}
                /\ noise' = IF y = (w \in truth) THEN noise ELSE noise + 1
          /\ asked' = asked + 1
          /\ UNCHANGED <<truth, done, grant, vetoed>>

Stop == /\ ~done
        /\ EstOK(vs) \/ Dis(vs) = {}
        /\ done' = TRUE
        /\ grant' = HighConf(vs) \ vetoed
        /\ UNCHANGED <<truth, vs, asked, noise, vetoed>>

\* v2 §2.9 / T21: a runtime frame or postcondition divergence on an admitted cell vetoes it for good
FrameVeto(w) == /\ done
                /\ w \in grant
                /\ vetoed' = vetoed \cup {w}
                /\ grant' = grant \ {w}
                /\ UNCHANGED <<truth, vs, asked, noise, done>>

Halt == done /\ UNCHANGED vars

Next == (\E w \in Outcomes : Ask(w)) \/ Stop \/ (\E w \in Outcomes : FrameVeto(w)) \/ Halt

Spec == Init /\ [][Next]_vars /\ WF_vars((\E w \in Outcomes : Ask(w)) \/ Stop)

-----------------------------------------------------------------------------
\* Properties

\* the emitted grant is inside the high-confidence region of the final version space
GrantHighConf == done => grant \subseteq HighConf(vs)
\* noise-free answers keep the truth in the version space (T1/T2 precondition)
TruthInVS     == (noise = 0) => truth \in vs
\* soundness (T1): the emitted grant admits nothing the principal would reject
GrantSound    == done => grant \subseteq truth
\* every question removes at least one hypothesis (T3, assumption-free part)
QueryBound    == asked + Cardinality(vs) <= Cardinality(Hyps)
\* the version space only shrinks (T2)
VsShrinks     == [][vs' \subseteq vs]_vars
\* termination: the loop always stops
Termination   == <>done
\* v2 (extended ratchet): vetoes only accumulate and a vetoed cell is never in the grant again
VetoPermanent == [][vetoed \subseteq vetoed' /\ vetoed' \cap grant' = {}]_vars
VetoDisjoint  == vetoed \cap grant = {}
=============================================================================
