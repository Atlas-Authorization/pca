// VerdictDecision.dfy - the ternary decision of a verifier verdict (goal-to-decision G-T4; contract C-50).
// STANDALONE. No assume / axiom / extern. Mirrors packages/pca/src/decision.ts `decisionOf`: a verdict that is not allowed is
// Escalate iff there is at least one failing check and EVERY failing check is escalate-class (its reasons all carry an
// escalate prefix, and it has at least one reason); otherwise Deny. A failing check with no reason of its own is hard.
module VerdictDecision {
  datatype Decision = Deny | Escalate | Allow
  // one failing check: does it have a reason, and are all its reasons escalate-class
  datatype Failing = Failing(hasReason: bool, allEscalateClass: bool)

  predicate EscalateClass(f: Failing) { f.hasReason && f.allEscalateClass }

  function AllEscalate(fs: seq<Failing>): bool decreases |fs| {
    if |fs| == 0 then true else EscalateClass(fs[0]) && AllEscalate(fs[1..])
  }

  function DecisionOf(allow: bool, fs: seq<Failing>): Decision {
    if allow then Allow else if |fs| > 0 && AllEscalate(fs) then Escalate else Deny
  }

  lemma AllEscalateIff(fs: seq<Failing>) ensures AllEscalate(fs) <==> (forall i :: 0 <= i < |fs| ==> EscalateClass(fs[i])) decreases |fs| {
    if |fs| > 0 { AllEscalateIff(fs[1..]); assert forall i :: 1 <= i < |fs| ==> fs[i] == fs[1..][i - 1]; }
  }
  // an allowed verdict is Allow; a not-allowed verdict is never Allow
  lemma NotAllowedNeverAllow(fs: seq<Failing>) ensures DecisionOf(false, fs) != Allow {}
  // escalate never yields allow: the verdict's allow flag is false whenever the decision is Escalate
  lemma EscalateImpliesNotAllow(allow: bool, fs: seq<Failing>) requires DecisionOf(allow, fs) == Escalate ensures !allow {}
  // any hard failure (no reason, or a non-escalate reason) makes the decision Deny
  lemma HardFailureDenies(fs: seq<Failing>, i: int) requires 0 <= i < |fs| && !EscalateClass(fs[i]) ensures DecisionOf(false, fs) == Deny {
    AllEscalateIff(fs);
  }
  // an unexplained failure never escalates
  lemma UnexplainedDenies(f: Failing) requires !f.hasReason ensures DecisionOf(false, [f]) == Deny {}
  // adding a failing check can only lower the decision (Allow stays only if there is no failure at all)
  lemma MoreFailuresNeverRaise(fs: seq<Failing>, f: Failing) ensures DecisionOf(false, fs + [f]) != Allow {}
  lemma AppendHardIsDeny(fs: seq<Failing>, f: Failing) requires !EscalateClass(f) ensures DecisionOf(false, fs + [f]) == Deny {
    AllEscalateIff(fs + [f]);
    assert (fs + [f])[|fs|] == f;
  }
}
