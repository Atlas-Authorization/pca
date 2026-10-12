---------------------------- MODULE TrustBudget ----------------------------
(***************************************************************************)
(* Formal, machine-checkable model of the PCA decaying trust-budget as a   *)
(* closed-loop admission controller.                                       *)
(*                                                                         *)
(* Source of truth:                                                        *)
(*   - docs/specs/agentic-auth-proof-carrying-authority.md,                *)
(*     "Deep Dive III - The decaying trust-budget as a control system"     *)
(*     (~lines 520-592).                                                   *)
(*   - packages/pca/src/risk.ts : requiredThreshold / cost / leak / debit  *)
(*     / recharge / rechargeFull / admit / safetyBound  (the SHIPPED model).*)
(*                                                                         *)
(* Discretisation.  Every quantity lives on an integer grid of size GRID.  *)
(* An actual risk r in [0,1] is the integer R in 0..GRID with r = R/GRID.   *)
(* Budget b in [0, bMax] is the integer B in 0..Bmax (units of 1/GRID).     *)
(* Under this scaling the per-action cost  c(A) = kappa * r(A)  is the      *)
(* integer  Kappa * R, and the spec's safety bound                         *)
(*                                                                         *)
(*        Sum r(A_i)  <=  bMax / kappa     (between human recharges)        *)
(*                                                                         *)
(* becomes the integer invariant   Kappa * sumRisk  <=  Bmax .              *)
(*                                                                         *)
(* The adversary is maximally free: at every step it chooses ANY risk      *)
(* level R and the timing of actions / leaks, trying to maximise the       *)
(* admitted risk between two human touchpoints.  The only thing standing   *)
(* in its way is the admission gate B >= c(A) -- exactly risk.ts admit().  *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    GRID,       \* risk discretisation; risk levels are 0..GRID (r = R/GRID)
    Bmax,       \* budget ceiling, in grid units (actual bMax = Bmax/GRID)
    Kappa,      \* cost scale kappa in c(A) = Kappa * R   (risk.ts cost)
    Theta1,     \* threshold theta1 as a risk level in 0..GRID
    Theta2,     \* threshold theta2 as a risk level in 0..GRID
    Lambda,     \* passive leak per tick, in grid units   (risk.ts leak)
    Rho,        \* human co-sign recharge amount, grid units (risk.ts recharge)
    RLCooldown  \* anti-windup: ticks a recharge must wait (rate limit)

ASSUME GRID \in Nat /\ GRID > 0
ASSUME Bmax \in Nat
ASSUME Kappa \in Nat /\ Kappa > 0
ASSUME Theta1 \in 0..GRID /\ Theta2 \in 0..GRID /\ Theta1 <= Theta2
ASSUME Lambda \in Nat /\ Rho \in Nat /\ RLCooldown \in Nat

VARIABLES
    B,           \* current budget (grid units)
    sumRisk,     \* sum of admitted (metered) risk levels since the last human recharge
    cooldown,    \* ticks remaining before a recharge is allowed again (anti-windup)
    last         \* record describing the most recent action, used by the assertions

vars == << B, sumRisk, cooldown, last >>

RiskLevels == 0..GRID

\* t(r): the piecewise required-threshold map (risk.ts requiredThreshold / spec section
\* "Admission controller").  r <= theta1 -> t=1 ; theta1 < r <= theta2 -> t=2 ; r > theta2 -> t=3.
ReqT(R) == IF R <= Theta1 THEN 1 ELSE IF R <= Theta2 THEN 2 ELSE 3

\* c(A) = kappa * r(A)                                             (risk.ts cost)
Cost(R) == Kappa * R

\* A deliberately generous finite type for sumRisk so that, were the invariant ever
\* violable, the violating state would be representable (the check is then non-vacuous).
SumCap == 2 * Bmax + GRID

Init ==
    /\ B = Bmax                      \* start fully charged (a goal re-confirmation)
    /\ sumRisk = 0
    /\ cooldown = 0
    /\ last = [r |-> 0, t |-> 1, cost |-> 0, covered |-> TRUE, outcome |-> "init"]

(***************************************************************************)
(* A machine-only action.  The adversary picks any risk level R; the        *)
(* controller routes it EXACTLY as risk.ts admit() does:                    *)
(*   t<3 and B>=c  -> metered machine path (t=1 auto-admit, or t=2 guardian  *)
(*                    auto-cosign): debit kappa*r and accrue the risk.       *)
(*   t<3 and B<c   -> depletion forces a human check-in even for low r.      *)
(*   t=3           -> a human step-up is cryptographically required; the     *)
(*                    action is never debited (it is itself the touchpoint). *)
(***************************************************************************)
MachineAction ==
    \E R \in RiskLevels :
        LET t       == ReqT(R)
            c       == Cost(R)
            covered == B >= c
        IN  /\ CASE (t < 3 /\ covered) ->
                        /\ B' = B - c
                        /\ sumRisk' = sumRisk + R
                        /\ last' = [r |-> R, t |-> t, cost |-> c, covered |-> TRUE,
                                    outcome |-> IF t = 1 THEN "auto" ELSE "guardian"]
                 [] (t < 3 /\ ~covered) ->
                        /\ UNCHANGED << B, sumRisk >>
                        /\ last' = [r |-> R, t |-> t, cost |-> c, covered |-> FALSE,
                                    outcome |-> "forced_human"]
                 [] OTHER ->
                        /\ UNCHANGED << B, sumRisk >>
                        /\ last' = [r |-> R, t |-> 3, cost |-> c, covered |-> covered,
                                    outcome |-> "human_required"]
            /\ UNCHANGED cooldown

\* Passive leak dB/dt = -lambda, discretised per tick (risk.ts leak); floors at 0.
\* Leak is NOT a human touch, so it never resets sumRisk.
Tick ==
    /\ B' = IF B > Lambda THEN B - Lambda ELSE 0
    /\ cooldown' = IF cooldown > 0 THEN cooldown - 1 ELSE 0
    /\ UNCHANGED << sumRisk, last >>

\* Human co-sign recharge: B <- min(Bmax, B + rho)   (risk.ts recharge).  The ONLY
\* way the budget increases, and the event that closes a checkpoint (sumRisk <- 0).
\* Rate-limited per the anti-windup note (cannot fire again until cooldown elapses).
RechargeHuman ==
    /\ cooldown = 0
    /\ B' = IF B + Rho < Bmax THEN B + Rho ELSE Bmax
    /\ sumRisk' = 0
    /\ cooldown' = RLCooldown
    /\ last' = [r |-> 0, t |-> 1, cost |-> 0, covered |-> TRUE, outcome |-> "recharge"]

\* Full goal re-confirmation: B <- Bmax             (risk.ts rechargeFull); human-sourced.
RechargeFull ==
    /\ cooldown = 0
    /\ B' = Bmax
    /\ sumRisk' = 0
    /\ cooldown' = RLCooldown
    /\ last' = [r |-> 0, t |-> 1, cost |-> 0, covered |-> TRUE, outcome |-> "recharge_full"]

Next == MachineAction \/ Tick \/ RechargeHuman \/ RechargeFull

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ B \in 0..Bmax
    /\ sumRisk \in 0..SumCap
    /\ cooldown \in 0..RLCooldown
    /\ last.outcome \in {"init","auto","guardian","forced_human",
                         "human_required","recharge","recharge_full"}

\* (1) THE CROWN.  Between two consecutive human recharges the risk-weighted
\* autonomous blast radius is bounded a priori by bMax/kappa:
\*        Kappa * sumRisk  <=  Bmax          (risk.ts safetyBound).
\* Holds even though the adversary freely chooses every risk level and the timing.
SafetyInvariant == Kappa * sumRisk <= Bmax

\* (2) Budget never negative on the auto path; a recharge never exceeds Bmax.
BudgetBounds == 0 <= B /\ B <= Bmax

\* (3) A metered (debited) machine action was admitted only with B >= c(A).
MeteredImpliesCovered ==
    (last.outcome \in {"auto","guardian"}) => last.covered

\* (4) A depleted budget forces a human touch even for a low-risk action: whenever
\* the controller routed an action to a forced human check-in, it was because the
\* budget could not cover the cost -- for ANY risk level, low r included.
DepletionForcesHuman ==
    (last.outcome = "forced_human") => (~last.covered /\ last.t < 3)

Invariant ==
    /\ TypeOK
    /\ SafetyInvariant
    /\ BudgetBounds
    /\ MeteredImpliesCovered
    /\ DepletionForcesHuman
=============================================================================
