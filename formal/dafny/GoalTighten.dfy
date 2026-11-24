// GoalTighten.dfy - the ternary decision lattice and the tighten-only rule (goal-to-decision G-T4 and G-T9).
// STANDALONE (no includes). No assume / axiom / extern. Mirrors packages/pca/src/decision.ts (meet, tighten, pepDecision,
// decisionOf) and the Kleene fact that Unknown never yields Allow (PolicyVm.dfy Tri). Every model oracle is a function
// parameter, so each theorem holds for EVERY oracle, including an adversarial one.
module GoalTighten {
  datatype Decision = Deny | Escalate | Allow
  datatype Signal = Ok | EscalateS | DenyS
  datatype Tri = TT | TF | TU

  function Rank(d: Decision): int { match d case Deny => 0 case Escalate => 1 case Allow => 2 }
  function Meet(a: Decision, b: Decision): Decision { if Rank(a) <= Rank(b) then a else b }
  predicate Leq(a: Decision, b: Decision) { Rank(a) <= Rank(b) }

  function Ceiling(s: Signal): Decision { match s case Ok => Allow case EscalateS => Escalate case DenyS => Deny }
  function Tighten(base: Decision, s: Signal): Decision { Meet(base, Ceiling(s)) }

  // meet over a list; Allow is the neutral element
  function MeetAll(ds: seq<Decision>): Decision decreases |ds| {
    if |ds| == 0 then Allow else Meet(ds[0], MeetAll(ds[1..]))
  }
  // the final verdict with a model oracle M over some context C: the base decision tightened by every signal
  function Fold(base: Decision, sigs: seq<Signal>): Decision decreases |sigs| {
    if |sigs| == 0 then base else Fold(Tighten(base, sigs[0]), sigs[1..])
  }
  // the PEP: an escalate is admitted only with a valid bound answer; never a deny
  function Pep(d: Decision, answered: bool): Decision { if d.Escalate? && answered then Allow else d }
  // Kleene condition result to the decision a rule reads (true: the rule's cap, unknown: escalate, false: none)
  function RuleCap(fired: Tri, s: Signal): Decision {
    match fired case TT => Ceiling(s) case TU => Escalate case TF => Allow
  }

  lemma MeetComm(a: Decision, b: Decision) ensures Meet(a, b) == Meet(b, a) {}
  lemma MeetAssoc(a: Decision, b: Decision, c: Decision) ensures Meet(Meet(a, b), c) == Meet(a, Meet(b, c)) {}
  lemma MeetIdem(a: Decision) ensures Meet(a, a) == a {}
  lemma MeetLeq(a: Decision, b: Decision) ensures Leq(Meet(a, b), a) && Leq(Meet(a, b), b) {}
  lemma MeetGreatest(a: Decision, b: Decision, c: Decision) requires Leq(c, a) && Leq(c, b) ensures Leq(c, Meet(a, b)) {}

  // G-T4: Escalate is absorbing against Allow and never becomes Allow by composition
  lemma EscalateNeverAllow(d: Decision)
    ensures Meet(Escalate, d) != Allow
    ensures Meet(d, Escalate) != Allow
  {}
  lemma MeetAllowIff(a: Decision, b: Decision) ensures Meet(a, b) == Allow <==> (a == Allow && b == Allow) {}
  lemma MeetAllAllowIff(ds: seq<Decision>) ensures MeetAll(ds) == Allow <==> (forall i :: 0 <= i < |ds| ==> ds[i] == Allow) decreases |ds| {
    if |ds| > 0 { MeetAllAllowIff(ds[1..]); MeetAllowIff(ds[0], MeetAll(ds[1..])); assert forall i :: 1 <= i < |ds| ==> ds[i] == ds[1..][i - 1]; }
  }
  // Unknown never yields Allow
  lemma UnknownNeverAllow(s: Signal) ensures RuleCap(TU, s) != Allow {}

  // G-T9: no widening by any oracle.
  lemma TightenNoWiden(base: Decision, s: Signal) ensures Leq(Tighten(base, s), base) {}
  lemma TightenOkNeutral(base: Decision) ensures Tighten(base, Ok) == base {}
  lemma FoldNoWiden(base: Decision, sigs: seq<Signal>) ensures Leq(Fold(base, sigs), base) decreases |sigs| {
    if |sigs| > 0 { TightenNoWiden(base, sigs[0]); FoldNoWiden(Tighten(base, sigs[0]), sigs[1..]); }
  }
  // M absent (no signals, or only Ok) equals the base decision
  lemma FoldAbsent(base: Decision) ensures Fold(base, []) == base {}
  lemma FoldAllOk(base: Decision, sigs: seq<Signal>) requires forall i :: 0 <= i < |sigs| ==> sigs[i] == Ok ensures Fold(base, sigs) == base decreases |sigs| {
    if |sigs| > 0 { FoldAllOk(base, sigs[1..]); assert forall i :: 0 <= i < |sigs[1..]| ==> sigs[1..][i] == sigs[i + 1]; }
  }
  // for ANY oracle (any function from a context to signals) the verdict never exceeds the oracle-free one
  lemma OracleNeverWidens<C>(base: Decision, oracle: C -> seq<Signal>, c: C) ensures Leq(Fold(base, oracle(c)), base) { FoldNoWiden(base, oracle(c)); }
  // an Allow requires Allow from the base AND from every signal
  lemma FoldAllowImpliesBase(base: Decision, sigs: seq<Signal>) requires Fold(base, sigs) == Allow ensures base == Allow decreases |sigs| {
    FoldNoWiden(base, sigs);
  }
  lemma FoldAllowImpliesOk(base: Decision, sigs: seq<Signal>) requires Fold(base, sigs) == Allow ensures forall i :: 0 <= i < |sigs| ==> sigs[i] == Ok decreases |sigs| {
    if |sigs| > 0 {
      FoldNoWiden(Tighten(base, sigs[0]), sigs[1..]);
      assert Tighten(base, sigs[0]) == Allow;
      FoldAllowImpliesOk(Tighten(base, sigs[0]), sigs[1..]);
      assert forall i :: 1 <= i < |sigs| ==> sigs[i] == sigs[1..][i - 1];
    }
  }
  // order independence of the signals
  lemma FoldMeet(base: Decision, sigs: seq<Signal>) ensures Fold(base, sigs) == Meet(base, MeetAll(seq(|sigs|, i requires 0 <= i < |sigs| => Ceiling(sigs[i])))) decreases |sigs| {
    if |sigs| > 0 {
      var rest := seq(|sigs| - 1, i requires 0 <= i < |sigs| - 1 => Ceiling(sigs[1..][i]));
      var all := seq(|sigs|, i requires 0 <= i < |sigs| => Ceiling(sigs[i]));
      assert all[1..] == rest;
      FoldMeet(Tighten(base, sigs[0]), sigs[1..]);
      MeetAssoc(base, Ceiling(sigs[0]), MeetAll(rest));
    }
  }

  // PEP lemma: an admitted action was Allow, or Escalate with an answer; a deny is never admitted
  lemma PepSound(d: Decision, answered: bool) ensures Pep(d, answered) == Allow ==> (d == Allow || (d == Escalate && answered)) {}
  lemma PepNeverUpgradesDeny(answered: bool) ensures Pep(Deny, answered) == Deny {}
  lemma PepEscalateUnanswered() ensures Pep(Escalate, false) == Escalate {}
  // the whole chain: a model-tightened decision, then the PEP: Allow only if the oracle-free decision was Allow, or an answer exists
  lemma EndToEnd(base: Decision, sigs: seq<Signal>, answered: bool)
    ensures Pep(Fold(base, sigs), answered) == Allow ==> (base == Allow || (base == Escalate && answered) || (base == Allow && answered))
  {
    FoldNoWiden(base, sigs);
  }
}
