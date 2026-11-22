// GoalWitness.dfy - provenance of an Allow (G-T3), a separate small witness checker, and the PEP lemma of G-T4.
// No assume / axiom / extern.
include "GoalCompile.dfy"
module GoalWitness {
  import opened GoalIr
  import opened GoalCompile

  // the grant that admitted the action and the bounds that were checked for it
  datatype Wit = Wit(gid: string, bids: seq<string>)

  // ids of the ceilings that apply to an action admitted by `gid`
  function Applicable(cs: seq<LCeil>, gid: string, verb: string): seq<string> decreases cs {
    if |cs| == 0 then [] else (if AppliesL(cs[0].sel, gid, verb) then [cs[0].bid] else []) + Applicable(cs[1..], gid, verb)
  }
  // the first grant whose own decision is Allow
  function FindAllow(ps: seq<LPred>, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist): Option<LPred> decreases ps {
    if |ps| == 0 then None
    else if PredDec(ps[0], ceils, dg, a, h) == Allow then Some(ps[0])
    else FindAllow(ps[1..], ceils, dg, a, h)
  }
  lemma AllowHasWitness(ps: seq<LPred>, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist)
    requires PredsDecP(ps, ceils, dg, a, h) == Allow
    ensures FindAllow(ps, ceils, dg, a, h).Some?
    ensures FindAllow(ps, ceils, dg, a, h).v in ps
    ensures PredDec(FindAllow(ps, ceils, dg, a, h).v, ceils, dg, a, h) == Allow
    decreases ps
  {
    if PredDec(ps[0], ceils, dg, a, h) != Allow { AllowHasWitness(ps[1..], ceils, dg, a, h); }
  }

  // G-T3: the decision function returns the decision together with the witness of an Allow
  function DecideW(p: Pol, a: Act, h: Hist): (Dec, Wit) {
    var d := DP(p, a, h);
    if d == Allow then
      (match FindAllow(p.preds, p.ceils, p.deleg, a, h)
       case Some(pr) => (Allow, Wit(pr.gid, Applicable(p.ceils, pr.gid, a.verb)))
       case None => (Deny, Wit("", [])))
    else (d, Wit("", []))
  }
  lemma DecideWAgrees(p: Pol, a: Act, h: Hist)
    ensures DecideW(p, a, h).0 == DP(p, a, h)
  {
    if DP(p, a, h) == Allow { AllowHasWitness(p.preds, p.ceils, p.deleg, a, h); }
  }

  // the checker: it re-evaluates ONE grant (and the gates), never the whole policy
  predicate AnyPredAllows(ps: seq<LPred>, gid: string, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist) decreases ps {
    |ps| > 0 && ((ps[0].gid == gid && PredDec(ps[0], ceils, dg, a, h) == Allow) || AnyPredAllows(ps[1..], gid, ceils, dg, a, h))
  }
  function VerifyWitness(p: Pol, a: Act, h: Hist, w: Wit): bool {
    ValidityDec(p.validity, p.deleg, a, h) == Allow && ProhDecP(p.prohs, a, h) == Allow && EscDecP(p.escs, a, h) == Allow
    && AnyPredAllows(p.preds, w.gid, p.ceils, p.deleg, a, h)
    && w.bids == Applicable(p.ceils, w.gid, a.verb)
  }
  lemma PredAbove(ps: seq<LPred>, ceils: seq<LCeil>, dg: Delegation, gid: string, a: Act, h: Hist)
    requires AnyPredAllows(ps, gid, ceils, dg, a, h)
    ensures PredsDecP(ps, ceils, dg, a, h) == Allow
    decreases ps
  { if !(ps[0].gid == gid && PredDec(ps[0], ceils, dg, a, h) == Allow) { PredAbove(ps[1..], ceils, dg, gid, a, h); } }

  // the checker is sound: an accepted witness means the decision is Allow
  lemma VerifyWitnessSound(p: Pol, a: Act, h: Hist, w: Wit)
    requires VerifyWitness(p, a, h, w)
    ensures DP(p, a, h) == Allow
  { PredAbove(p.preds, p.ceils, p.deleg, w.gid, a, h); }
  // and complete for the witness the decision function produced
  lemma VerifyWitnessComplete(p: Pol, a: Act, h: Hist)
    requires DP(p, a, h) == Allow
    ensures VerifyWitness(p, a, h, DecideW(p, a, h).1)
  {
    AllowHasWitness(p.preds, p.ceils, p.deleg, a, h);
    var pr := FindAllow(p.preds, p.ceils, p.deleg, a, h).v;
    InPredsAllows(p.preds, pr, p.ceils, p.deleg, a, h);
  }
  lemma InPredsAllows(ps: seq<LPred>, pr: LPred, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist)
    requires pr in ps && PredDec(pr, ceils, dg, a, h) == Allow
    ensures AnyPredAllows(ps, pr.gid, ceils, dg, a, h)
    decreases ps
  { if ps[0] != pr { InTail(ps, pr); InPredsAllows(ps[1..], pr, ceils, dg, a, h); } }

  // G-T3 provenance: every Allow carries a witness naming a grant of the policy; that grant's condition, resource, delegation and every
  // ceiling that applies to it hold (PredDec == Allow), and so do the gates.
  lemma ProvenanceT3(p: Pol, a: Act, h: Hist)
    requires DecideW(p, a, h).0 == Allow
    ensures exists pr :: pr in p.preds && pr.gid == DecideW(p, a, h).1.gid && PredDec(pr, p.ceils, p.deleg, a, h) == Allow
    ensures DecideW(p, a, h).1.bids == Applicable(p.ceils, DecideW(p, a, h).1.gid, a.verb)
    ensures ValidityDec(p.validity, p.deleg, a, h) == Allow && ProhDecP(p.prohs, a, h) == Allow && EscDecP(p.escs, a, h) == Allow
  {
    DecideWAgrees(p, a, h);
    AllowHasWitness(p.preds, p.ceils, p.deleg, a, h);
    var pr := FindAllow(p.preds, p.ceils, p.deleg, a, h).v;
    assert pr in p.preds && pr.gid == DecideW(p, a, h).1.gid && PredDec(pr, p.ceils, p.deleg, a, h) == Allow;
  }
  lemma TailSub<T>(xs: seq<T>, x: T)
    requires |xs| > 0 && x in xs[1..]
    ensures x in xs
  { var i :| 0 <= i < |xs[1..]| && xs[1..][i] == x; assert xs[i + 1] == x; }
  // an Allow's grant is a grant of the goal (lowering keeps the ids)
  lemma LowerKeepsGids(ont: Ontology, gs: seq<Grant>, pr: LPred)
    requires pr in LowerGrants(ont, gs)
    ensures exists gr :: gr in gs && gr.gid == pr.gid
    decreases gs
  {
    if |gs| > 0 {
      if pr == LowerGrants(ont, gs)[0] {
        assert gs[0] in gs;
      } else {
        InTail(LowerGrants(ont, gs), pr);
        LowerKeepsGids(ont, gs[1..], pr);
        var gr :| gr in gs[1..] && gr.gid == pr.gid;
        TailSub(gs, gr);
      }
    }
  }
  lemma StripMember(hs: seq<Hole>, gs: seq<Grant>, gr: Grant)
    requires gr in StripGrants(hs, gs)
    ensures gr in gs
    decreases gs
  {
    if |gs| > 0 {
      if DependsOn(hs, gs[0].gid) {
        StripMember(hs, gs[1..], gr);
        TailSub(gs, gr);
      } else if gr == gs[0] {
        assert gr in gs;
      } else {
        InTail(StripGrants(hs, gs), gr);
        StripMember(hs, gs[1..], gr);
        TailSub(gs, gr);
      }
    }
  }
  lemma ProvenanceNamesAGrant(ont: Ontology, g: Goal, a: Act, h: Hist)
    requires Compile(ont, g).Compiled?
    requires DecideW(Compile(ont, g).p, a, h).0 == Allow
    ensures exists gr :: gr in g.grants && gr.gid == DecideW(Compile(ont, g).p, a, h).1.gid
  {
    var p := Compile(ont, g).p;
    ProvenanceT3(p, a, h);
    var pr :| pr in p.preds && pr.gid == DecideW(p, a, h).1.gid && PredDec(pr, p.ceils, p.deleg, a, h) == Allow;
    LowerKeepsGids(ont, StripGrants(g.holes, g.grants), pr);
    var gr :| gr in StripGrants(g.holes, g.grants) && gr.gid == pr.gid;
    StripMember(g.holes, g.grants, gr);
  }

  // ------------------------------------------------------------------ G-T4: the PEP rule
  // An escalation answer, as the enforcement point has already checked it: signature valid, and bound to (policy digest, action digest, history head).
  datatype Answer = Answer(sigOk: bool, policyDigest: string, actionDigest: string, histHead: string)
  function PepAllows(d: Dec, ans: Option<Answer>, pd: string, ad: string, hh: string): bool {
    d == Allow || (d == Escalate && ans.Some? && ans.v.sigOk && ans.v.policyDigest == pd && ans.v.actionDigest == ad && ans.v.histHead == hh)
  }
  lemma PepT4(d: Dec, ans: Option<Answer>, pd: string, ad: string, hh: string)
    ensures PepAllows(d, ans, pd, ad, hh) ==> d == Allow || (d == Escalate && ans.Some? && ans.v.sigOk && ans.v.policyDigest == pd
                                                          && ans.v.actionDigest == ad && ans.v.histHead == hh)
    ensures d == Deny ==> !PepAllows(d, ans, pd, ad, hh)
    ensures d == Escalate && ans.None? ==> !PepAllows(d, ans, pd, ad, hh)
  {}
  // a wrong-policy, wrong-action or wrong-history answer never turns an Escalate into an Allow (no replay onto another request)
  lemma NoAnswerReplay(ans: Answer, pd: string, ad: string, hh: string)
    requires ans.policyDigest != pd || ans.actionDigest != ad || ans.histHead != hh || !ans.sigOk
    ensures !PepAllows(Escalate, Some(ans), pd, ad, hh)
  {}
}
