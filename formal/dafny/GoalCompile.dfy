// GoalCompile.dfy - the deterministic compiler C : Goal -> Policy (+) Escalate(reasons) and its theorems G-T1, G-T2, G-T4, G-T5, G-T7.
// No assume / axiom / extern. The compiler is a pure total function: typecheck (units, currency, closed world, canonical order,
// wildcards, holes), strip the clauses that depend on a hole, lower (negation-normal conditions, ontology-resolved resource
// patterns, effect-class resolved verb lists, bound selections).
//
// The lowered policy `Pol` is the shape the verifier's predicate / caveat / accumulator machinery consumes (a list of
// `{verb, resource, where[]}` predicates with a Kleene condition, prohibitions, ceilings, escalation triggers). `DP` is the decision
// function of that target. G-T1 is proved as an EQUALITY, D_P(C(G)) = D_G(G), which is strictly stronger than "never allows more".
include "GoalIr.dfy"
module GoalCompile {
  import opened GoalIr

  // ------------------------------------------------------------------ negation-normal conditions
  datatype NC = NTrue | NFalse | NAtom(op: Op, l: Term, r: Term) | NAnd(a: NC, b: NC) | NOr(a: NC, b: NC)

  function EvalN(c: NC, a: Act, h: Hist): Tri decreases c {
    match c
    case NTrue => KT
    case NFalse => KF
    case NAtom(op, l, r) => CmpT(op, EvalT(l, a, h), EvalT(r, a, h))
    case NAnd(x, y) => AndK(EvalN(x, a, h), EvalN(y, a, h))
    case NOr(x, y) => OrK(EvalN(x, a, h), EvalN(y, a, h))
  }
  // `pos` = the polarity: Nnf(c, false) is the normal form of `not c`. Negation is pushed to the comparison operators (NegOp).
  function Nnf(c: Cond, pos: bool): NC decreases c {
    match c
    case CTrue => if pos then NTrue else NFalse
    case Cmp(op, l, r) => NAtom(if pos then op else NegOp(op), l, r)
    case And(x, y) => if pos then NAnd(Nnf(x, true), Nnf(y, true)) else NOr(Nnf(x, false), Nnf(y, false))
    case Or(x, y) => if pos then NOr(Nnf(x, true), Nnf(y, true)) else NAnd(Nnf(x, false), Nnf(y, false))
    case Not(x) => Nnf(x, !pos)
  }
  lemma NnfSound(c: Cond, pos: bool, a: Act, h: Hist)
    ensures EvalN(Nnf(c, pos), a, h) == (if pos then EvalC(c, a, h) else NotK(EvalC(c, a, h)))
    decreases c
  {
    match c
    case CTrue =>
    case Cmp(op, l, r) => NegOpSound(op, EvalT(l, a, h), EvalT(r, a, h));
    case And(x, y) => NnfSound(x, pos, a, h); NnfSound(y, pos, a, h);
    case Or(x, y) => NnfSound(x, pos, a, h); NnfSound(y, pos, a, h);
    case Not(x) => NnfSound(x, !pos, a, h);
  }

  // ------------------------------------------------------------------ the lowered policy
  datatype LPred = LPred(gid: string, verb: string, res: ResPat, cond: NC)
  datatype LProh = LProh(pid: string, verbs: seq<string>, res: ResPat, cond: NC)
  datatype LCeil = LCeil(bid: string, sel: LSel, core: BCore)
  datatype Pol = Pol(preds: seq<LPred>, prohs: seq<LProh>, ceils: seq<LCeil>, escs: seq<NC>, validity: Validity, deleg: Delegation)

  function ProhOneP(p: LProh, a: Act, h: Hist): Dec {
    var m := AndK(B2T(a.verb in p.verbs), AndK(B2T(ResOk(p.res, a.res)), EvalN(p.cond, a, h)));
    if m == KT then Deny else if m == KU then Escalate else Allow
  }
  function ProhDecP(ps: seq<LProh>, a: Act, h: Hist): Dec decreases ps {
    if |ps| == 0 then Allow else MeetD(ProhOneP(ps[0], a, h), ProhDecP(ps[1..], a, h))
  }
  function EscDecP(cs: seq<NC>, a: Act, h: Hist): Dec decreases cs {
    if |cs| == 0 then Allow else MeetD(EscOne(EvalN(cs[0], a, h)), EscDecP(cs[1..], a, h))
  }
  function CeilOne(c: LCeil, gid: string, a: Act, h: Hist): Dec {
    if AppliesL(c.sel, gid, a.verb) then BoundStat(c.core, c.sel, a, h) else Allow
  }
  function CeilsDecP(cs: seq<LCeil>, gid: string, a: Act, h: Hist): Dec decreases cs {
    if |cs| == 0 then Allow else MeetD(CeilOne(cs[0], gid, a, h), CeilsDecP(cs[1..], gid, a, h))
  }
  function PredMatch(p: LPred, dg: Delegation, a: Act, h: Hist): Tri {
    AndK(B2T(a.verb == p.verb && DelegOk(dg, p.gid, a)), AndK(B2T(ResOk(p.res, a.res)), EvalN(p.cond, a, h)))
  }
  function PredDec(p: LPred, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist): Dec {
    MeetD(DecOfTri(PredMatch(p, dg, a, h)), CeilsDecP(ceils, p.gid, a, h))
  }
  function PredsDecP(ps: seq<LPred>, ceils: seq<LCeil>, dg: Delegation, a: Act, h: Hist): Dec decreases ps {
    if |ps| == 0 then Deny else JoinD(PredDec(ps[0], ceils, dg, a, h), PredsDecP(ps[1..], ceils, dg, a, h))
  }
  // D_P: the decision of a lowered policy. Total and deterministic; Deny < Escalate < Allow; Unknown never yields Allow.
  function DP(p: Pol, a: Act, h: Hist): Dec {
    MeetD(ValidityDec(p.validity, p.deleg, a, h),
    MeetD(ProhDecP(p.prohs, a, h),
    MeetD(EscDecP(p.escs, a, h),
          PredsDecP(p.preds, p.ceils, p.deleg, a, h))))
  }

  // ------------------------------------------------------------------ lowering
  function LowerGrants(ont: Ontology, gs: seq<Grant>): seq<LPred> decreases gs {
    if |gs| == 0 then [] else [LPred(gs[0].gid, gs[0].verb, ResolveSel(ont, gs[0].res), Nnf(gs[0].cond, true))] + LowerGrants(ont, gs[1..])
  }
  function LowerProhs(ont: Ontology, ps: seq<Prohibit>): seq<LProh> decreases ps {
    if |ps| == 0 then []
    else [LProh(ps[0].pid, ProhVerbs(ont, ps[0].target), ResolveSel(ont, ps[0].res), Nnf(ps[0].cond, true))] + LowerProhs(ont, ps[1..])
  }
  function LowerBounds(ont: Ontology, bs: seq<Bound>): seq<LCeil> decreases bs {
    if |bs| == 0 then [] else [LCeil(bs[0].bid, ResolveBSel(ont, bs[0].sel), bs[0].core)] + LowerBounds(ont, bs[1..])
  }
  function LowerEscs(cs: seq<Cond>): seq<NC> decreases cs {
    if |cs| == 0 then [] else [Nnf(cs[0], true)] + LowerEscs(cs[1..])
  }
  function Lower(ont: Ontology, g: Goal): Pol {
    Pol(LowerGrants(ont, g.grants), LowerProhs(ont, g.prohibits), LowerBounds(ont, g.bounds), LowerEscs(g.escalateOn), g.validity, g.deleg)
  }

  lemma ProhEq(ont: Ontology, ps: seq<Prohibit>, a: Act, h: Hist)
    ensures ProhDecG(ont, ps, a, h) == ProhDecP(LowerProhs(ont, ps), a, h)
    decreases ps
  {
    if |ps| > 0 {
      NnfSound(ps[0].cond, true, a, h);
      ProhEq(ont, ps[1..], a, h);
    }
  }
  lemma EscEq(cs: seq<Cond>, a: Act, h: Hist)
    ensures EscDecG(cs, a, h) == EscDecP(LowerEscs(cs), a, h)
    decreases cs
  {
    if |cs| > 0 {
      NnfSound(cs[0], true, a, h);
      EscEq(cs[1..], a, h);
    }
  }
  lemma BoundsEq(ont: Ontology, bs: seq<Bound>, gid: string, a: Act, h: Hist)
    ensures BoundsDecG(ont, bs, gid, a, h) == CeilsDecP(LowerBounds(ont, bs), gid, a, h)
    decreases bs
  {
    if |bs| > 0 { BoundsEq(ont, bs[1..], gid, a, h); }
  }
  lemma GrantsEq(ont: Ontology, g: Goal, gs: seq<Grant>, a: Act, h: Hist)
    ensures GrantsDecG(ont, g, gs, a, h) == PredsDecP(LowerGrants(ont, gs), LowerBounds(ont, g.bounds), g.deleg, a, h)
    decreases gs
  {
    if |gs| > 0 {
      NnfSound(gs[0].cond, true, a, h);
      BoundsEq(ont, g.bounds, gs[0].gid, a, h);
      GrantsEq(ont, g, gs[1..], a, h);
    }
  }
  // the compiled policy decides exactly as the goal's reference semantics (G-T1 as an equality)
  lemma LowerEquiv(ont: Ontology, g: Goal, a: Act, h: Hist)
    ensures DP(Lower(ont, g), a, h) == DG(ont, g, a, h)
  {
    ProhEq(ont, g.prohibits, a, h);
    EscEq(g.escalateOn, a, h);
    GrantsEq(ont, g, g.grants, a, h);
  }

  // ------------------------------------------------------------------ holes: the most restrictive completion
  function DependsOn(hs: seq<Hole>, gid: string): bool decreases hs {
    |hs| > 0 && (hs[0].global || gid in hs[0].affects || DependsOn(hs[1..], gid))
  }
  function StripGrants(hs: seq<Hole>, gs: seq<Grant>): seq<Grant> decreases gs {
    if |gs| == 0 then [] else (if DependsOn(hs, gs[0].gid) then [] else [gs[0]]) + StripGrants(hs, gs[1..])
  }
  // drop every grant that depends on a hole; the other clauses stay (prohibitions and bounds only ever restrict)
  function Strip(g: Goal): Goal { g.(grants := StripGrants(g.holes, g.grants), holes := []) }
  lemma StripNoHoles(g: Goal)
    requires |g.holes| == 0
    ensures Strip(g) == g
  {
    StripGrantsId(g.holes, g.grants);
  }
  lemma StripGrantsId(hs: seq<Hole>, gs: seq<Grant>)
    requires |hs| == 0
    ensures StripGrants(hs, gs) == gs
    decreases gs
  {
    if |gs| > 0 { StripGrantsId(hs, gs[1..]); }
  }

  // ------------------------------------------------------------------ the compiler
  datatype CResult = Compiled(p: Pol) | CEscalate(reasons: seq<string>)

  // per-clause diagnostics: the ids of the clauses that fail their typing rule
  function BadGrants(ont: Ontology, g: Goal, gs: seq<Grant>): seq<string> decreases gs {
    if |gs| == 0 then [] else (if GrantOk(ont, g, gs[0]) then [] else [gs[0].gid]) + BadGrants(ont, g, gs[1..])
  }
  function BadProhibits(ont: Ontology, ps: seq<Prohibit>): seq<string> decreases ps {
    if |ps| == 0 then [] else (if ProhibitOk(ont, ps[0]) then [] else [ps[0].pid]) + BadProhibits(ont, ps[1..])
  }
  function BadBounds(ont: Ontology, g: Goal, bs: seq<Bound>): seq<string> decreases bs {
    if |bs| == 0 then [] else (if BoundOk(ont, g, bs[0]) then [] else [bs[0].bid]) + BadBounds(ont, g, bs[1..])
  }
  function BadHoles(g: Goal, hs: seq<Hole>): seq<string> decreases hs {
    if |hs| == 0 then [] else (if HoleOk(g, hs[0]) then [] else [hs[0].hid]) + BadHoles(g, hs[1..])
  }
  function TypeReasons(ont: Ontology, g: Goal): seq<string> {
    (if Sorted4(g) then [] else ["not_canonical_order"])
    + (if |BadGrants(ont, g, g.grants)| == 0 then [] else ["ill_typed_grant"])
    + (if |BadProhibits(ont, g.prohibits)| == 0 then [] else ["ill_typed_prohibit"])
    + (if |BadBounds(ont, g, g.bounds)| == 0 then [] else ["ill_typed_bound"])
    + (if EscsTyped(ont, g) then [] else ["ill_typed_escalation"])
    + (if ValidityOk(g.validity, g.deleg, g) then [] else ["bad_validity_or_delegation"])
    + (if |BadHoles(g, g.holes)| == 0 then [] else ["bad_hole"])
  }
  lemma BadGrantsEmpty(ont: Ontology, g: Goal, gs: seq<Grant>)
    ensures |BadGrants(ont, g, gs)| == 0 <==> (forall i :: 0 <= i < |gs| ==> GrantOk(ont, g, gs[i]))
    decreases gs
  { if |gs| > 0 { BadGrantsEmpty(ont, g, gs[1..]); assert forall i :: 1 <= i < |gs| ==> gs[i] == gs[1..][i - 1]; } }
  lemma BadProhibitsEmpty(ont: Ontology, ps: seq<Prohibit>)
    ensures |BadProhibits(ont, ps)| == 0 <==> (forall i :: 0 <= i < |ps| ==> ProhibitOk(ont, ps[i]))
    decreases ps
  { if |ps| > 0 { BadProhibitsEmpty(ont, ps[1..]); assert forall i :: 1 <= i < |ps| ==> ps[i] == ps[1..][i - 1]; } }
  lemma BadBoundsEmpty(ont: Ontology, g: Goal, bs: seq<Bound>)
    ensures |BadBounds(ont, g, bs)| == 0 <==> (forall i :: 0 <= i < |bs| ==> BoundOk(ont, g, bs[i]))
    decreases bs
  { if |bs| > 0 { BadBoundsEmpty(ont, g, bs[1..]); assert forall i :: 1 <= i < |bs| ==> bs[i] == bs[1..][i - 1]; } }
  lemma BadHolesEmpty(g: Goal, hs: seq<Hole>)
    ensures |BadHoles(g, hs)| == 0 <==> (forall i :: 0 <= i < |hs| ==> HoleOk(g, hs[i]))
    decreases hs
  { if |hs| > 0 { BadHolesEmpty(g, hs[1..]); assert forall i :: 1 <= i < |hs| ==> hs[i] == hs[1..][i - 1]; } }
  // no reason <=> well typed
  lemma ReasonsIffTyped(ont: Ontology, g: Goal)
    ensures |TypeReasons(ont, g)| == 0 <==> IsWellTyped(ont, g)
  {
    BadGrantsEmpty(ont, g, g.grants);
    BadProhibitsEmpty(ont, g.prohibits);
    BadBoundsEmpty(ont, g, g.bounds);
    BadHolesEmpty(g, g.holes);
  }

  // C: ill-typed goals are rejected with reasons (no coercion, no guess); a goal with holes compiles to its most restrictive completion
  function Compile(ont: Ontology, g: Goal): CResult {
    var rs := TypeReasons(ont, g);
    if |rs| > 0 then CEscalate(rs) else Compiled(Lower(ont, Strip(g)))
  }

  // ------------------------------------------------------------------ G-T1 soundness
  // A signable goal's compiled policy decides exactly as the goal; in particular it never allows more.
  lemma SoundnessT1(ont: Ontology, g: Goal, a: Act, h: Hist)
    requires Compile(ont, g).Compiled? && |g.holes| == 0
    ensures DP(Compile(ont, g).p, a, h) == DG(ont, g, a, h)
    ensures DP(Compile(ont, g).p, a, h) == Allow ==> DG(ont, g, a, h) == Allow
  {
    StripNoHoles(g);
    LowerEquiv(ont, g, a, h);
  }
  // for a draft, the compiled policy is the reference semantics of the stripped goal
  lemma DraftSemantics(ont: Ontology, g: Goal, a: Act, h: Hist)
    requires Compile(ont, g).Compiled?
    ensures DP(Compile(ont, g).p, a, h) == DG(ont, Strip(g), a, h)
  {
    LowerEquiv(ont, Strip(g), a, h);
  }

  // ------------------------------------------------------------------ G-T2 monotonicity
  predicate ResNarrows(p2: ResPat, p1: ResPat) {
    p1.PStar? || (p2.PSet? && p1.PSet? && forall i :: 0 <= i < |p2.ids| ==> p2.ids[i] in p1.ids)
  }
  predicate CondNarrows(c2: Cond, c1: Cond) { c2 == c1 || (c2.And? && (c2.a == c1 || c2.b == c1)) }
  predicate GrantNarrows(ont: Ontology, g2: Grant, g1: Grant) {
    g2.gid == g1.gid && g2.verb == g1.verb && ResNarrows(ResolveSel(ont, g2.res), ResolveSel(ont, g1.res)) && CondNarrows(g2.cond, g1.cond)
  }
  predicate SubsetOf<T(==)>(xs: seq<T>, ys: seq<T>) { forall i :: 0 <= i < |xs| ==> xs[i] in ys }
  // G' refines G: grants narrowed, prohibitions / bounds / escalation triggers only added, validity and delegation only tightened
  predicate Refines(ont: Ontology, g2: Goal, g1: Goal) {
    (forall i :: 0 <= i < |g2.grants| ==> (exists j :: 0 <= j < |g1.grants| && GrantNarrows(ont, g2.grants[i], g1.grants[j])))
    && SubsetOf(g1.prohibits, g2.prohibits) && SubsetOf(g1.bounds, g2.bounds) && SubsetOf(g1.escalateOn, g2.escalateOn)
    && g2.validity.notBefore >= g1.validity.notBefore && g2.validity.notAfter <= g1.validity.notAfter
    && (g1.validity.maxIdle <= 0 || (0 < g2.validity.maxIdle <= g1.validity.maxIdle))
    && g2.deleg.maxDepth <= g1.deleg.maxDepth && SubsetOf(g2.deleg.mayTouch, g1.deleg.mayTouch)
  }

  lemma InTail<T>(xs: seq<T>, x: T)
    requires x in xs && xs[0] != x
    ensures x in xs[1..]
  {
    var i :| 0 <= i < |xs| && xs[i] == x;
    assert i >= 1;
    assert xs[1..][i - 1] == x;
  }
  lemma SubsetTail<T>(xs: seq<T>, ys: seq<T>)
    requires SubsetOf(xs, ys) && |xs| > 0
    ensures SubsetOf(xs[1..], ys) && xs[0] in ys
  {
    assert xs[0] in ys;
    forall i | 0 <= i < |xs[1..]| ensures xs[1..][i] in ys { assert xs[1..][i] == xs[i + 1]; }
  }
  lemma SubsetMem<T>(xs: seq<T>, ys: seq<T>, x: T)
    requires SubsetOf(xs, ys) && x in xs
    ensures x in ys
  { var i :| 0 <= i < |xs| && xs[i] == x; }
  lemma SubsetRefl<T>(xs: seq<T>) ensures SubsetOf(xs, xs) {}
  // a fold of Meet over a list is below every element, and below the fold over any sub-list
  lemma ProhBelow(ont: Ontology, ps: seq<Prohibit>, p: Prohibit, a: Act, h: Hist)
    requires p in ps
    ensures ProhDecG(ont, ps, a, h) <= ProhOne(ProhVerbs(ont, p.target), ResolveSel(ont, p.res), p.cond, a, h)
    decreases ps
  { if ps[0] != p { InTail(ps, p); ProhBelow(ont, ps[1..], p, a, h); } }
  lemma ProhSuper(ont: Ontology, ps1: seq<Prohibit>, ps2: seq<Prohibit>, a: Act, h: Hist)
    requires SubsetOf(ps1, ps2)
    ensures ProhDecG(ont, ps2, a, h) <= ProhDecG(ont, ps1, a, h)
    decreases ps1
  {
    if |ps1| > 0 {
      ProhBelow(ont, ps2, ps1[0], a, h);
      SubsetTail(ps1, ps2);
      ProhSuper(ont, ps1[1..], ps2, a, h);
    }
  }
  lemma EscBelow(cs: seq<Cond>, c: Cond, a: Act, h: Hist)
    requires c in cs
    ensures EscDecG(cs, a, h) <= EscOne(EvalC(c, a, h))
    decreases cs
  { if cs[0] != c { InTail(cs, c); EscBelow(cs[1..], c, a, h); } }
  lemma EscSuper(cs1: seq<Cond>, cs2: seq<Cond>, a: Act, h: Hist)
    requires SubsetOf(cs1, cs2)
    ensures EscDecG(cs2, a, h) <= EscDecG(cs1, a, h)
    decreases cs1
  {
    if |cs1| > 0 {
      EscBelow(cs2, cs1[0], a, h);
      SubsetTail(cs1, cs2);
      EscSuper(cs1[1..], cs2, a, h);
    }
  }
  function BoundOne(ont: Ontology, b: Bound, gid: string, a: Act, h: Hist): Dec {
    var s := ResolveBSel(ont, b.sel);
    if AppliesL(s, gid, a.verb) then BoundStat(b.core, s, a, h) else Allow
  }
  lemma BoundBelow(ont: Ontology, bs: seq<Bound>, b: Bound, gid: string, a: Act, h: Hist)
    requires b in bs
    ensures BoundsDecG(ont, bs, gid, a, h) <= BoundOne(ont, b, gid, a, h)
    decreases bs
  { if bs[0] != b { InTail(bs, b); BoundBelow(ont, bs[1..], b, gid, a, h); } }
  lemma BoundSuper(ont: Ontology, bs1: seq<Bound>, bs2: seq<Bound>, gid: string, a: Act, h: Hist)
    requires SubsetOf(bs1, bs2)
    ensures BoundsDecG(ont, bs2, gid, a, h) <= BoundsDecG(ont, bs1, gid, a, h)
    decreases bs1
  {
    if |bs1| > 0 {
      BoundBelow(ont, bs2, bs1[0], gid, a, h);
      SubsetTail(bs1, bs2);
      BoundSuper(ont, bs1[1..], bs2, gid, a, h);
    }
  }
  lemma GrantAbove(ont: Ontology, g: Goal, gs: seq<Grant>, gr: Grant, a: Act, h: Hist)
    requires gr in gs
    ensures GrantDecG(ont, g, gr, a, h) <= GrantsDecG(ont, g, gs, a, h)
    decreases gs
  { if gs[0] != gr { InTail(gs, gr); GrantAbove(ont, g, gs[1..], gr, a, h); } }
  lemma NarrowEval(c2: Cond, c1: Cond, a: Act, h: Hist)
    requires CondNarrows(c2, c1)
    ensures EvalC(c2, a, h) <= EvalC(c1, a, h)
  { if c2 != c1 { match c2 case And(_, _) => {} } }
  lemma ValidityMono(g1: Goal, g2: Goal, a: Act, h: Hist)
    requires Refines2V(g2, g1)
    ensures ValidityDec(g2.validity, g2.deleg, a, h) <= ValidityDec(g1.validity, g1.deleg, a, h)
  {}
  predicate Refines2V(g2: Goal, g1: Goal) {
    g2.validity.notBefore >= g1.validity.notBefore && g2.validity.notAfter <= g1.validity.notAfter
    && (g1.validity.maxIdle <= 0 || (0 < g2.validity.maxIdle <= g1.validity.maxIdle))
    && g2.deleg.maxDepth <= g1.deleg.maxDepth
  }
  // one narrowed grant decides no higher than the grant it narrows
  lemma GrantDecMono(ont: Ontology, g1: Goal, g2: Goal, gr1: Grant, gr2: Grant, a: Act, h: Hist)
    requires Refines(ont, g2, g1) && GrantNarrows(ont, gr2, gr1)
    ensures GrantDecG(ont, g2, gr2, a, h) <= GrantDecG(ont, g1, gr1, a, h)
  {
    BoundSuper(ont, g1.bounds, g2.bounds, gr2.gid, a, h);
    NarrowEval(gr2.cond, gr1.cond, a, h);
    if DelegOk(g2.deleg, gr2.gid, a) && a.depth != 0 { SubsetMem(g2.deleg.mayTouch, g1.deleg.mayTouch, gr2.gid); }
    assert DelegOk(g2.deleg, gr2.gid, a) ==> DelegOk(g1.deleg, gr2.gid, a);
    assert ResOk(ResolveSel(ont, gr2.res), a.res) ==> ResOk(ResolveSel(ont, gr1.res), a.res);
    assert GrantMatch(ont, gr2, g2.deleg, a, h) <= GrantMatch(ont, gr1, g1.deleg, a, h);
  }
  // the join over g2's grants is below the join over g1's when every g2 grant is below some g1 grant
  lemma GrantsLeast(ont: Ontology, g1: Goal, g2: Goal, gs2: seq<Grant>, a: Act, h: Hist)
    requires Refines(ont, g2, g1)
    requires forall i :: 0 <= i < |gs2| ==> gs2[i] in g2.grants
    ensures GrantsDecG(ont, g2, gs2, a, h) <= GrantsDecG(ont, g1, g1.grants, a, h)
    decreases gs2
  {
    if |gs2| > 0 {
      var gr2 := gs2[0];
      assert gr2 in g2.grants;
      var i :| 0 <= i < |g2.grants| && g2.grants[i] == gr2;
      var j :| 0 <= j < |g1.grants| && GrantNarrows(ont, gr2, g1.grants[j]);
      var gr1 := g1.grants[j];
      GrantAbove(ont, g1, g1.grants, gr1, a, h);
      GrantDecMono(ont, g1, g2, gr1, gr2, a, h);
      assert forall k :: 0 <= k < |gs2[1..]| ==> gs2[1..][k] in g2.grants by {
        forall k | 0 <= k < |gs2[1..]| ensures gs2[1..][k] in g2.grants { assert gs2[1..][k] == gs2[k + 1]; }
      }
      GrantsLeast(ont, g1, g2, gs2[1..], a, h);
    }
  }
  // G-T2: if G' refines G then D_G'(a, H) <= D_G(a, H): adding a constraint, or narrowing a clause, never grows the allow set.
  lemma Monotonicity(ont: Ontology, g1: Goal, g2: Goal, a: Act, h: Hist)
    requires Refines(ont, g2, g1)
    ensures DG(ont, g2, a, h) <= DG(ont, g1, a, h)
  {
    ProhSuper(ont, g1.prohibits, g2.prohibits, a, h);
    EscSuper(g1.escalateOn, g2.escalateOn, a, h);
    assert forall i :: 0 <= i < |g2.grants| ==> g2.grants[i] in g2.grants;
    GrantsLeast(ont, g1, g2, g2.grants, a, h);
    ValidityMono(g1, g2, a, h);
  }
  // the same, stated on the compiled policies
  lemma MonotonicityCompiled(ont: Ontology, g1: Goal, g2: Goal, a: Act, h: Hist)
    requires Refines(ont, g2, g1)
    ensures DP(Lower(ont, g2), a, h) <= DP(Lower(ont, g1), a, h)
  {
    LowerEquiv(ont, g1, a, h);
    LowerEquiv(ont, g2, a, h);
    Monotonicity(ont, g1, g2, a, h);
  }

  // ------------------------------------------------------------------ G-T7 hole safety
  lemma NarrowReflexive(ont: Ontology, gr: Grant) ensures GrantNarrows(ont, gr, gr) {
    var p := ResolveSel(ont, gr.res);
    assert ResNarrows(p, p) by {
      match p
      case PStar =>
      case PSet(ids) => assert forall i :: 0 <= i < |ids| ==> ids[i] in ids;
    }
  }
  // a draft's compiled policy is no wider than ANY completion that keeps the other clauses and adds grants for the holes
  lemma HoleSafety(ont: Ontology, g: Goal, g2: Goal, a: Act, h: Hist)
    requires Compile(ont, g).Compiled?
    requires |g2.holes| == 0 && g2.prohibits == g.prohibits && g2.bounds == g.bounds && g2.validity == g.validity
    requires g2.deleg == g.deleg && g2.escalateOn == g.escalateOn
    requires forall i :: 0 <= i < |StripGrants(g.holes, g.grants)| ==> StripGrants(g.holes, g.grants)[i] in g2.grants
    ensures DP(Compile(ont, g).p, a, h) <= DG(ont, g2, a, h)
  {
    DraftSemantics(ont, g, a, h);
    var s := Strip(g);
    forall i | 0 <= i < |s.grants| ensures exists j :: 0 <= j < |g2.grants| && GrantNarrows(ont, s.grants[i], g2.grants[j]) {
      assert s.grants[i] in g2.grants;
      var j :| 0 <= j < |g2.grants| && g2.grants[j] == s.grants[i];
      NarrowReflexive(ont, s.grants[i]);
    }
    SubsetRefl(g.prohibits);
    SubsetRefl(g.bounds);
    SubsetRefl(g.escalateOn);
    SubsetRefl(g.deleg.mayTouch);
    assert Refines(ont, s, g2);
    Monotonicity(ont, g2, s, a, h);
  }

  // ------------------------------------------------------------------ G-T4 (the compiler's half): the ternary result, escalation absorbs
  lemma EscalateNeverAllow(x: Dec, y: Dec)
    ensures x != Allow ==> MeetD(x, y) != Allow
    ensures MeetD(Escalate, y) != Allow
    ensures MeetD(Deny, y) == Deny
  {}
  // a clause that evaluates to Unknown can never make a decision Allow
  lemma UnknownNeverAllows(ont: Ontology, g: Goal, gr: Grant, a: Act, h: Hist)
    requires GrantMatch(ont, gr, g.deleg, a, h) != KT
    ensures GrantDecG(ont, g, gr, a, h) != Allow
  {}

  // ------------------------------------------------------------------ G-T5 canonicity
  // The compiler is a function of the goal's value: equal goals (hence equal canonical bytes, GoalRender.dfy) give the same policy.
  // The policy digest is then a hash of the policy's canonical encoding; the clause order is canonical because typing demands
  // strictly increasing ids, so semantically equal goals that differ only in clause order are not both well typed.
  lemma Canonicity(ont: Ontology, g1: Goal, g2: Goal)
    requires g1 == g2
    ensures Compile(ont, g1) == Compile(ont, g2)
  {}
}
