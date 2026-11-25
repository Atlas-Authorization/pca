// Goal.dfy - the entry module of the extracted goal compiler (compiled to packages/pca-verified-core/generated/pca_goal.js).
// The TypeScript bridge talks to it ONLY through token tapes (GoalRender.Tok: keywords, exact integers, exact strings), so no Dafny
// datatype crosses the language boundary; the same tapes drive the differential harness (difftargets/GoalHarness.dfy).
// No assume / axiom / extern. Everything proved lives in GoalIr / GoalCompile / GoalWitness / GoalRender; this file is decoders for the
// non-goal inputs (ontology, action, history), encoders for the compiled policy, and total entry points with no logic of their own.
include "GoalIr.dfy"
include "GoalCompile.dfy"
include "GoalWitness.dfy"
include "GoalRender.dfy"
module GoalApi {
  import opened GoalIr
  import opened GoalCompile
  import opened GoalWitness
  import opened GoalRender

  // ------------------------------------------------------------------ decoders: ontology, action, history
  function DecParamDecl(ts: seq<Tok>): PR<ParamDecl> {
    if |ts| == 0 || ts[0] != TKw(500) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(p, r1) =>
      (match DecTy(r1) case Fail => Fail case Ok(ty, r2) => Ok(ParamDecl(p, ty), r2))
  }
  function DecParamDeclsElems(ts: seq<Tok>, n: nat): PR<seq<ParamDecl>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecParamDecl(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecParamDeclsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecParamDecls(ts: seq<Tok>): PR<seq<ParamDecl>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecParamDeclsElems(ts[1..], ts[0].i) else Fail
  }
  function DecVerbDecl(ts: seq<Tok>): PR<VerbDecl> {
    if |ts| == 0 || ts[0] != TKw(501) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(v, r1) =>
      (match DecStr(r1) case Fail => Fail case Ok(c, r2) =>
       (match DecParamDecls(r2) case Fail => Fail case Ok(ps, r3) => Ok(VerbDecl(v, c, ps), r3)))
  }
  function DecRelDecl(ts: seq<Tok>): PR<RelDecl> {
    if |ts| == 0 || ts[0] != TKw(502) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(rel, r1) =>
      (match DecStr(r1) case Fail => Fail case Ok(an, r2) =>
       (match DecStrs(r2) case Fail => Fail case Ok(ms, r3) => Ok(RelDecl(rel, an, ms), r3)))
  }
  function DecVerbDeclsElems(ts: seq<Tok>, n: nat): PR<seq<VerbDecl>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecVerbDecl(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecVerbDeclsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecVerbDecls(ts: seq<Tok>): PR<seq<VerbDecl>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecVerbDeclsElems(ts[1..], ts[0].i) else Fail
  }
  function DecRelDeclsElems(ts: seq<Tok>, n: nat): PR<seq<RelDecl>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecRelDecl(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecRelDeclsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecRelDecls(ts: seq<Tok>): PR<seq<RelDecl>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecRelDeclsElems(ts[1..], ts[0].i) else Fail
  }
  function DecOntology(ts: seq<Tok>): PR<Ontology> {
    if |ts| == 0 || ts[0] != TKw(510) then Fail
    else
      match DecVerbDecls(ts[1..]) case Fail => Fail case Ok(vs, r1) =>
      (match DecRelDecls(r1) case Fail => Fail case Ok(rs, r2) => Ok(Ontology(vs, rs), r2))
  }
  // a parameter map: n entries (key, value); a later entry for the same key replaces an earlier one
  function DecParamEntries(ts: seq<Tok>, n: nat): PR<map<string, V>> decreases n {
    if n == 0 then Ok(map[], ts)
    else if |ts| == 0 || ts[0] != TKw(520) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(k, r1) =>
      (match DecV(r1) case Fail => Fail case Ok(v, r2) =>
       (match DecParamEntries(r2, n - 1) case Fail => Fail case Ok(m, r3) => Ok(m[k := v], r3)))
  }
  function DecParams(ts: seq<Tok>): PR<map<string, V>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecParamEntries(ts[1..], ts[0].i) else Fail
  }
  function DecAct(ts: seq<Tok>): PR<Act> {
    if |ts| == 0 || ts[0] != TKw(530) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(verb, r1) =>
      (match DecStr(r1) case Fail => Fail case Ok(res, r2) =>
       (match DecParams(r2) case Fail => Fail case Ok(ps, r3) =>
        (match DecInt(r3) case Fail => Fail case Ok(t, r4) =>
         (match DecStr(r4) case Fail => Fail case Ok(sess, r5) =>
          (match DecStr(r5) case Fail => Fail case Ok(prin, r6) =>
           (match DecStr(r6) case Fail => Fail case Ok(org, r7) =>
            (match DecStr(r7) case Fail => Fail case Ok(agent, r8) =>
             (match DecInt(r8) case Fail => Fail case Ok(depth, r9) => Ok(Act(verb, res, ps, t, sess, prin, org, agent, depth), r9)))))))))
  }
  function DecAdm(ts: seq<Tok>): PR<Adm> {
    if |ts| == 0 || ts[0] != TKw(531) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(gid, r1) =>
      (match DecAct(r1) case Fail => Fail case Ok(a, r2) => Ok(Adm(gid, a), r2))
  }
  function DecAdmsElems(ts: seq<Tok>, n: nat): PR<seq<Adm>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecAdm(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecAdmsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecAdms(ts: seq<Tok>): PR<seq<Adm>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecAdmsElems(ts[1..], ts[0].i) else Fail
  }
  function DecAggEntries(ts: seq<Tok>, n: nat): PR<map<string, Q>> decreases n {
    if n == 0 then Ok(map[], ts)
    else if |ts| == 0 || ts[0] != TKw(540) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(k, r1) =>
      (match DecQ(r1) case Fail => Fail case Ok(q, r2) =>
       (match DecAggEntries(r2, n - 1) case Fail => Fail case Ok(m, r3) => Ok(m[k := q], r3)))
  }
  function DecAggs(ts: seq<Tok>): PR<map<string, Q>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecAggEntries(ts[1..], ts[0].i) else Fail
  }
  function DecHist(ts: seq<Tok>): PR<Hist> {
    if |ts| == 0 || ts[0] != TKw(541) then Fail
    else
      match DecAdms(ts[1..]) case Fail => Fail case Ok(adms, r1) =>
      (match DecInt(r1) case Fail => Fail case Ok(last, r2) =>
       (match DecAggs(r2) case Fail => Fail case Ok(aggs, r3) => Ok(Hist(adms, last, aggs), r3)))
  }
  // a whole-tape parse: the value, and nothing left over
  function Whole<T>(r: PR<T>): Option<T> { match r case Ok(v, rest) => (if |rest| == 0 then Some(v) else None) case Fail => None }

  // ------------------------------------------------------------------ encoders: the compiled policy
  function EncResPat(p: ResPat): seq<Tok> { match p case PStar => [TKw(630)] case PSet(ids) => [TKw(631)] + EncStrs(ids) }
  function EncNC(c: NC): seq<Tok> decreases c {
    match c
    case NTrue => [TKw(600)]
    case NFalse => [TKw(601)]
    case NAtom(op, l, r) => [TKw(602)] + (EncOp(op) + (EncTerm(l) + EncTerm(r)))
    case NAnd(x, y) => [TKw(603)] + (EncNC(x) + EncNC(y))
    case NOr(x, y) => [TKw(604)] + (EncNC(x) + EncNC(y))
  }
  function EncLPred(p: LPred): seq<Tok> { [TKw(620)] + (EncStr(p.gid) + (EncStr(p.verb) + (EncResPat(p.res) + EncNC(p.cond)))) }
  function EncLProh(p: LProh): seq<Tok> { [TKw(640)] + (EncStr(p.pid) + (EncStrs(p.verbs) + (EncResPat(p.res) + EncNC(p.cond)))) }
  function EncLCeil(c: LCeil): seq<Tok> { [TKw(610)] + (EncStr(c.bid) + (EncStrs(c.sel.gids) + (EncStrs(c.sel.verbs) + EncBCore(c.core)))) }
  function EncLPredsElems(xs: seq<LPred>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncLPred(xs[0]) + EncLPredsElems(xs[1..])
  }
  function EncLPreds(xs: seq<LPred>): seq<Tok> { [TI(|xs|)] + EncLPredsElems(xs) }
  function EncLProhsElems(xs: seq<LProh>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncLProh(xs[0]) + EncLProhsElems(xs[1..])
  }
  function EncLProhs(xs: seq<LProh>): seq<Tok> { [TI(|xs|)] + EncLProhsElems(xs) }
  function EncLCeilsElems(xs: seq<LCeil>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncLCeil(xs[0]) + EncLCeilsElems(xs[1..])
  }
  function EncLCeils(xs: seq<LCeil>): seq<Tok> { [TI(|xs|)] + EncLCeilsElems(xs) }
  function EncNCsElems(xs: seq<NC>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncNC(xs[0]) + EncNCsElems(xs[1..])
  }
  function EncNCs(xs: seq<NC>): seq<Tok> { [TI(|xs|)] + EncNCsElems(xs) }
  function EncPol(p: Pol): seq<Tok> {
    [TKw(650)] + (EncLPreds(p.preds) + (EncLProhs(p.prohs) + (EncLCeils(p.ceils) + (EncNCs(p.escs) + (EncValidity(p.validity) + EncDeleg(p.deleg))))))
  }

  // ------------------------------------------------------------------ tape construction / reading for the JS bridge (no Dafny datatype crosses the boundary)
  function MkKw(k: int): Tok { TKw(k) }
  function MkI(i: int): Tok { TI(i) }
  function MkS(s: string): Tok { TS(s) }
  function TokKind(t: Tok): int { match t case TKw(_) => 0 case TI(_) => 1 case TS(_) => 2 }
  function TokKw(t: Tok): int { match t case TKw(k) => k case _ => 0 }
  function TokInt(t: Tok): int { match t case TI(i) => i case _ => 0 }
  function TokStr(t: Tok): string { match t case TS(s) => s case _ => "" }

  // ------------------------------------------------------------------ entry points (tapes in, tapes out). First token: 0 ok, 1 rejected with reasons, 9 malformed input
  function Bad(): seq<Tok> { [TI(9)] }
  function ParseG(ts: seq<Tok>): Option<Goal> { Parse(ts) }
  // the type reasons of a goal against an ontology (empty list = well typed)
  function TypecheckT(gt: seq<Tok>, ot: seq<Tok>): seq<Tok> {
    match (ParseG(gt), Whole(DecOntology(ot)))
    case (Some(g), Some(o)) => (var rs := TypeReasons(o, g); if |rs| == 0 then [TI(0)] else [TI(1)] + EncStrs(rs))
    case _ => Bad()
  }
  function CompileT(gt: seq<Tok>, ot: seq<Tok>): seq<Tok> {
    match (ParseG(gt), Whole(DecOntology(ot)))
    case (Some(g), Some(o)) =>
      (match Compile(o, g) case Compiled(p) => [TI(0)] + EncPol(p) case CEscalate(rs) => [TI(1)] + EncStrs(rs))
    case _ => Bad()
  }
  // the reference semantics D_G
  function DecideGoalT(gt: seq<Tok>, ot: seq<Tok>, at: seq<Tok>, ht: seq<Tok>): seq<Tok> {
    match (ParseG(gt), Whole(DecOntology(ot)), Whole(DecAct(at)), Whole(DecHist(ht)))
    case (Some(g), Some(o), Some(a), Some(h)) => [TI(0), TI(DG(o, g, a, h))]
    case _ => Bad()
  }
  // the compiled policy's decision with its witness and the witness checker's verdict
  function DecidePolicyT(gt: seq<Tok>, ot: seq<Tok>, at: seq<Tok>, ht: seq<Tok>): seq<Tok> {
    match (ParseG(gt), Whole(DecOntology(ot)), Whole(DecAct(at)), Whole(DecHist(ht)))
    case (Some(g), Some(o), Some(a), Some(h)) =>
      (match Compile(o, g)
       case CEscalate(rs) => [TI(1)] + EncStrs(rs)
       case Compiled(p) =>
         (var r := DecideW(p, a, h);
          [TI(0), TI(r.0), TS(r.1.gid)] + EncStrs(r.1.bids) + [TI(if r.0 == Allow && VerifyWitness(p, a, h, r.1) then 1 else 0)]))
    case _ => Bad()
  }
  // the card: parse and render again (the identity on every parsable tape)
  function RenderT(gt: seq<Tok>): seq<Tok> {
    match ParseG(gt) case Some(g) => [TI(0)] + Render(g) case None => Bad()
  }
}

