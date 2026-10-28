// GoalSelect.dfy - trait selectors and role-addressed parameters for the Goal IR (docs/pca/specs/action-kit.md section 8).
// No assume / axiom / extern. The goal gains two generalizations of the signed IR in GoalIr.dfy:
//   (i)  a grant names a VerbSel (one verb, or Class(all_of, none_of): every verb of the pinned catalog whose trait closure has
//        every all_of trait and none of the none_of traits); a prohibition may target a trait selector; a bound may select by trait;
//   (ii) a term may be addressed by ROLE (`ParamRole(money.amount)`): the one parameter of the verb that carries the role.
// A selector goal is lowered by Expand into an ordinary GoalIr.Goal (per-verb grants, prohibitions and bounds, each with the
// verb's own parameter path), then compiled by the unchanged, already proved compiler. So everything GoalCompile proves
// (G-T1 equality with the reference semantics, monotonicity, hole safety, canonicity) holds for selector goals by composition;
// this file proves the extra obligations of the expansion itself:
//   G-A4  the verb list of a Class selector is exactly the set comprehension over the pinned catalog (ClassVerbsSpec);
//   T6a   a prohibition that floats covers more when the catalog grows (ClassVerbsGrow, FloatClassVerbsGrow, ProhOneVerbsMono);
//   UNCONFIRMED  a verb whose def has no valid signed review carries the marker `pca.unreviewed` in its closure (it is the top of
//         the registry). A class ALLOW never covers it (AllowExcludesUnrev: the allow list is ClassVerbs with `pca.unreviewed` added to
//         none_of); a class PROHIBITION or bound ALWAYS covers it, whatever its all_of and none_of say (FloatCoversUnrev), so no
//         carve-out can rescue an unreviewed verb;
//   T6b   an expanded grant exists only for a verb of the pinned catalog, so an action outside it is Deny (GrantsOnlyPinned,
//         NoGrantVerbDeny, NewVerbDenied);
//   the compile result is the reference semantics of the expansion (CompileXSound).
// The pin itself (the catalog digest the goal names) is checked by the caller before Expand; this module is the function of the
// pinned catalog it is given.
include "GoalCompile.dfy"
include "GoalRender.dfy"
include "Goal.dfy"
module GoalSelect {
  import opened GoalIr
  import opened GoalCompile
  import opened GoalRender

  // ------------------------------------------------------------------ the pinned catalog
  // role -> parameter path (a verb may carry a role on several paths: then the role is ambiguous and unresolvable)
  datatype RoleDecl = RoleDecl(role: string, path: string)
  // a verb of the catalog with the trait ids of its closure
  datatype VerbInfo = VerbInfo(verb: string, traits: seq<string>, roles: seq<RoleDecl>)
  // `known` = every trait id of the registry the catalog was built from (a selector naming another is ill typed)
  datatype Catalog = Catalog(known: seq<string>, verbs: seq<VerbInfo>)

  // ------------------------------------------------------------------ the selector-extended IR
  datatype VerbSel = SVerb(verb: string) | SClass(allOf: seq<string>, noneOf: seq<string>)
  datatype TermX = XParam(path: string, ty: Ty) | XRole(role: string) | XLit(v: V) | XHist(bid: string, u: Unit)
  datatype CondX = XTrue | XCmp(op: Op, l: TermX, r: TermX) | XAnd(a: CondX, b: CondX) | XOr(a: CondX, b: CondX) | XNot(c: CondX)
  datatype GrantX = GrantX(gid: string, vsel: VerbSel, res: ResSel, cond: CondX)
  datatype ProhTargetX = XPVerb(verb: string) | XPEffect(cls: string) | XPTrait(allOf: seq<string>, noneOf: seq<string>)
  datatype ProhibitX = ProhibitX(pid: string, target: ProhTargetX, res: ResSel, cond: CondX)
  datatype SelX = XGids(gids: seq<string>) | XEffect(cls: string) | XTrait(allOf: seq<string>, noneOf: seq<string>)
  datatype BoundX = BoundX(bid: string, sel: SelX, agg: Agg, value: TermX, key: string, window: Window, scope: Scope, cap: Q, onExceed: OnExceed)
  // `core` carries every other member (validity, delegation, escalation triggers, wildcard acknowledgements, holes); its own
  // grants / prohibits / bounds are ignored and replaced by the expansion of the three selector lists
  datatype GoalX = GoalX(core: Goal, grants: seq<GrantX>, prohibits: seq<ProhibitX>, bounds: seq<BoundX>)

  // ------------------------------------------------------------------ G-A4: the verbs of a Class selector
  function HasAll(ts: seq<string>, req: seq<string>): bool decreases req {
    |req| == 0 || (req[0] in ts && HasAll(ts, req[1..]))
  }
  function HasNone(ts: seq<string>, ex: seq<string>): bool decreases ex {
    |ex| == 0 || (!(ex[0] in ts) && HasNone(ts, ex[1..]))
  }
  function ClassVerbs(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>): seq<string> decreases vs {
    if |vs| == 0 then []
    else (if HasAll(vs[0].traits, allOf) && HasNone(vs[0].traits, noneOf) then [vs[0].verb] else []) + ClassVerbs(vs[1..], allOf, noneOf)
  }
  // the marker every unconfirmed verb carries in its closure (a confirmed verb never has it)
  const Unrev: string := "pca.unreviewed"
  // a floating selector (prohibition, bound) covers the class AND every unconfirmed verb, whatever all_of / none_of say
  predicate Cov(t: VerbInfo, allOf: seq<string>, noneOf: seq<string>) {
    Unrev in t.traits || (HasAll(t.traits, allOf) && HasNone(t.traits, noneOf))
  }
  function FloatClassVerbs(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>): seq<string> decreases vs {
    if |vs| == 0 then []
    else (if Cov(vs[0], allOf, noneOf) then [vs[0].verb] else []) + FloatClassVerbs(vs[1..], allOf, noneOf)
  }
  lemma HasAllSpec(ts: seq<string>, req: seq<string>)
    ensures HasAll(ts, req) <==> (forall j :: 0 <= j < |req| ==> req[j] in ts)
    decreases req
  {
    if |req| > 0 {
      HasAllSpec(ts, req[1..]);
      assert forall j :: 1 <= j < |req| ==> req[j] == req[1..][j - 1];
    }
  }
  lemma HasNoneSpec(ts: seq<string>, ex: seq<string>)
    ensures HasNone(ts, ex) <==> (forall j :: 0 <= j < |ex| ==> !(ex[j] in ts))
    decreases ex
  {
    if |ex| > 0 {
      HasNoneSpec(ts, ex[1..]);
      assert forall j :: 1 <= j < |ex| ==> ex[j] == ex[1..][j - 1];
    }
  }
  // the compiler's verb list equals the oracle's set comprehension over the pinned catalog
  lemma ClassVerbsSpec(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, v: string)
    ensures v in ClassVerbs(vs, allOf, noneOf) <==>
      (exists i :: 0 <= i < |vs| && vs[i].verb == v
        && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[i].traits)
        && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in vs[i].traits)))
    decreases vs
  {
    if |vs| > 0 {
      HasAllSpec(vs[0].traits, allOf);
      HasNoneSpec(vs[0].traits, noneOf);
      ClassVerbsSpec(vs[1..], allOf, noneOf, v);
      if v in ClassVerbs(vs, allOf, noneOf) {
        if HasAll(vs[0].traits, allOf) && HasNone(vs[0].traits, noneOf) && vs[0].verb == v {
          assert 0 <= 0 < |vs| && vs[0].verb == v
            && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[0].traits)
            && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in vs[0].traits));
        } else {
          assert v in ClassVerbs(vs[1..], allOf, noneOf);
          var k :| 0 <= k < |vs[1..]| && vs[1..][k].verb == v
            && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[1..][k].traits)
            && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in vs[1..][k].traits));
          assert vs[1..][k] == vs[k + 1];
          assert 0 <= k + 1 < |vs| && vs[k + 1].verb == v;
        }
      }
      if exists i :: 0 <= i < |vs| && vs[i].verb == v
          && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[i].traits)
          && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in vs[i].traits)) {
        var i :| 0 <= i < |vs| && vs[i].verb == v
          && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[i].traits)
          && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in vs[i].traits));
        if i == 0 {
          assert HasAll(vs[0].traits, allOf) && HasNone(vs[0].traits, noneOf);
        } else {
          assert vs[1..][i - 1] == vs[i];
          assert 0 <= i - 1 < |vs[1..]| && vs[1..][i - 1].verb == v;
        }
      }
    }
  }

  lemma FloatClassVerbsSpec(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, v: string)
    ensures v in FloatClassVerbs(vs, allOf, noneOf) <==> (exists i :: 0 <= i < |vs| && vs[i].verb == v && Cov(vs[i], allOf, noneOf))
    decreases vs
  {
    if |vs| > 0 {
      FloatClassVerbsSpec(vs[1..], allOf, noneOf, v);
      if v in FloatClassVerbs(vs, allOf, noneOf) {
        if Cov(vs[0], allOf, noneOf) && vs[0].verb == v {
          assert 0 <= 0 < |vs| && vs[0].verb == v && Cov(vs[0], allOf, noneOf);
        } else {
          assert v in FloatClassVerbs(vs[1..], allOf, noneOf);
          var k :| 0 <= k < |vs[1..]| && vs[1..][k].verb == v && Cov(vs[1..][k], allOf, noneOf);
          assert vs[1..][k] == vs[k + 1];
          assert 0 <= k + 1 < |vs| && vs[k + 1].verb == v && Cov(vs[k + 1], allOf, noneOf);
        }
      }
      if exists i :: 0 <= i < |vs| && vs[i].verb == v && Cov(vs[i], allOf, noneOf) {
        var i :| 0 <= i < |vs| && vs[i].verb == v && Cov(vs[i], allOf, noneOf);
        if i == 0 {
          assert Cov(vs[0], allOf, noneOf) && vs[0].verb == v;
        } else {
          assert vs[1..][i - 1] == vs[i];
          assert 0 <= i - 1 < |vs[1..]| && vs[1..][i - 1].verb == v && Cov(vs[1..][i - 1], allOf, noneOf);
        }
      }
    }
  }
  // an unconfirmed verb is covered by EVERY floating selector: a classifier miss, or a carve-out, can never exempt it
  lemma FloatCoversUnrev(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, i: int)
    requires 0 <= i < |vs|
    requires Unrev in vs[i].traits
    ensures vs[i].verb in FloatClassVerbs(vs, allOf, noneOf)
  {
    FloatClassVerbsSpec(vs, allOf, noneOf, vs[i].verb);
    assert 0 <= i < |vs| && vs[i].verb == vs[i].verb && Cov(vs[i], allOf, noneOf);
  }
  // a class ALLOW is the class with `pca.unreviewed` added to none_of: it never covers an unconfirmed verb
  lemma AllowExcludesUnrev(vs: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, v: string)
    requires v in ClassVerbs(vs, allOf, noneOf + [Unrev])
    ensures exists i :: 0 <= i < |vs| && vs[i].verb == v && !(Unrev in vs[i].traits)
  {
    ClassVerbsSpec(vs, allOf, noneOf + [Unrev], v);
    var i :| 0 <= i < |vs| && vs[i].verb == v
      && (forall j :: 0 <= j < |allOf| ==> allOf[j] in vs[i].traits)
      && (forall j :: 0 <= j < |noneOf + [Unrev]| ==> !((noneOf + [Unrev])[j] in vs[i].traits));
    assert (noneOf + [Unrev])[|noneOf|] == Unrev;
    assert !(Unrev in vs[i].traits);
  }

  // ------------------------------------------------------------------ T6a: a floating selector covers more when the catalog grows
  predicate CatSub(a: seq<VerbInfo>, b: seq<VerbInfo>) { forall i :: 0 <= i < |a| ==> a[i] in b }
  lemma ClassVerbsGrow(a: seq<VerbInfo>, b: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, v: string)
    requires CatSub(a, b)
    requires v in ClassVerbs(a, allOf, noneOf)
    ensures v in ClassVerbs(b, allOf, noneOf)
  {
    ClassVerbsSpec(a, allOf, noneOf, v);
    ClassVerbsSpec(b, allOf, noneOf, v);
    var i :| 0 <= i < |a| && a[i].verb == v
      && (forall j :: 0 <= j < |allOf| ==> allOf[j] in a[i].traits)
      && (forall j :: 0 <= j < |noneOf| ==> !(noneOf[j] in a[i].traits));
    assert a[i] in b;
    var k :| 0 <= k < |b| && b[k] == a[i];
    assert 0 <= k < |b| && b[k].verb == v;
  }
  lemma FloatClassVerbsGrow(a: seq<VerbInfo>, b: seq<VerbInfo>, allOf: seq<string>, noneOf: seq<string>, v: string)
    requires CatSub(a, b)
    requires v in FloatClassVerbs(a, allOf, noneOf)
    ensures v in FloatClassVerbs(b, allOf, noneOf)
  {
    FloatClassVerbsSpec(a, allOf, noneOf, v);
    FloatClassVerbsSpec(b, allOf, noneOf, v);
    var i :| 0 <= i < |a| && a[i].verb == v && Cov(a[i], allOf, noneOf);
    assert a[i] in b;
    var k :| 0 <= k < |b| && b[k] == a[i];
    assert 0 <= k < |b| && b[k].verb == v && Cov(b[k], allOf, noneOf);
  }
  // a prohibition over more verbs decides no higher (Deny < Escalate < Allow): floating coverage can only drop a decision
  lemma ProhOneVerbsMono(vs: seq<string>, vs2: seq<string>, res: ResPat, c: Cond, a: Act, h: Hist)
    requires forall x :: x in vs ==> x in vs2
    ensures ProhOne(vs2, res, c, a, h) <= ProhOne(vs, res, c, a, h)
  {
    var m1 := AndK(B2T(a.verb in vs), AndK(B2T(ResOk(res, a.res)), EvalC(c, a, h)));
    var m2 := AndK(B2T(a.verb in vs2), AndK(B2T(ResOk(res, a.res)), EvalC(c, a, h)));
    assert m1 <= m2;
  }

  // ------------------------------------------------------------------ role resolution
  datatype Res = Res(path: string, ty: Ty)
  function FindInfo(vs: seq<VerbInfo>, verb: string): Option<VerbInfo> decreases vs {
    if |vs| == 0 then None else if vs[0].verb == verb then Some(vs[0]) else FindInfo(vs[1..], verb)
  }
  function RolePaths(rs: seq<RoleDecl>, role: string): seq<string> decreases rs {
    if |rs| == 0 then [] else (if rs[0].role == role then [rs[0].path] else []) + RolePaths(rs[1..], role)
  }
  function FindParamTy(ps: seq<ParamDecl>, path: string): Option<Ty> decreases ps {
    if |ps| == 0 then None else if ps[0].path == path then Some(ps[0].ty) else FindParamTy(ps[1..], path)
  }
  // the unique parameter of the verb carrying the role, with its declared type; none or several: unresolved
  function ResolveRoleIn(d: VerbDecl, info: VerbInfo, role: string): Option<Res> {
    var ps := RolePaths(info.roles, role);
    if |ps| != 1 then None
    else (match FindParamTy(d.params, ps[0]) case None => None case Some(ty) => Some(Res(ps[0], ty)))
  }
  function ResolveRole(ont: Ontology, cat: Catalog, verb: string, role: string): Option<Res> {
    var oi := FindInfo(cat.verbs, verb);
    var od := FindDecl(ont.verbs, verb);
    if oi.None? || od.None? then None else ResolveRoleIn(od.v, oi.v, role)
  }
  function ResolveTerm(ont: Ontology, cat: Catalog, verb: string, t: TermX): Option<Term> {
    match t
    case XParam(p, ty) => Some(Param(p, ty))
    case XLit(v) => Some(Lit(v))
    case XHist(b, u) => Some(HistAgg(b, u))
    case XRole(r) => (match ResolveRole(ont, cat, verb, r) case Some(x) => Some(Param(x.path, x.ty)) case None => None)
  }
  // None as soon as one role term is unresolved for the verb
  function ResolveCond(ont: Ontology, cat: Catalog, verb: string, c: CondX): Option<Cond> decreases c {
    match c
    case XTrue => Some(CTrue)
    case XCmp(op, l, r) =>
      (match ResolveTerm(ont, cat, verb, l)
       case None => None
       case Some(a) => (match ResolveTerm(ont, cat, verb, r) case None => None case Some(b) => Some(Cmp(op, a, b))))
    case XAnd(x, y) =>
      (match ResolveCond(ont, cat, verb, x)
       case None => None
       case Some(a) => (match ResolveCond(ont, cat, verb, y) case None => None case Some(b) => Some(And(a, b))))
    case XOr(x, y) =>
      (match ResolveCond(ont, cat, verb, x)
       case None => None
       case Some(a) => (match ResolveCond(ont, cat, verb, y) case None => None case Some(b) => Some(Or(a, b))))
    case XNot(x) => (match ResolveCond(ont, cat, verb, x) case None => None case Some(a) => Some(Not(a)))
  }
  // a prohibition whose condition cannot be resolved for a verb applies to that verb unconditionally (more restrictive, never less)
  function ResolveCondProh(ont: Ontology, cat: Catalog, verb: string, c: CondX): Cond {
    match ResolveCond(ont, cat, verb, c) case Some(x) => x case None => CTrue
  }

  // ------------------------------------------------------------------ expansion of grants
  datatype EG = EG(src: string, g: Grant)
  function GrantVerbsX(cat: Catalog, s: VerbSel): seq<string> {
    match s case SVerb(v) => [v] case SClass(a, n) => ClassVerbs(cat.verbs, a, n + [Unrev])
  }
  // a Class grant yields one grant per verb, named `<gid>.<verb>` (so ids stay unique); a single-verb grant keeps its id
  function ExpandGrantVerbs(ont: Ontology, cat: Catalog, gr: GrantX, vs: seq<string>): seq<EG> decreases vs {
    if |vs| == 0 then []
    else
      (match ResolveCond(ont, cat, vs[0], gr.cond)
       case Some(c) => [EG(gr.gid, Grant(if gr.vsel.SClass? then gr.gid + "." + vs[0] else gr.gid, vs[0], gr.res, c))]
       case None => [])
      + ExpandGrantVerbs(ont, cat, gr, vs[1..])
  }
  function ExpandGrantsX(ont: Ontology, cat: Catalog, gs: seq<GrantX>): seq<EG> decreases gs {
    if |gs| == 0 then [] else ExpandGrantVerbs(ont, cat, gs[0], GrantVerbsX(cat, gs[0].vsel)) + ExpandGrantsX(ont, cat, gs[1..])
  }
  function EGGrants(es: seq<EG>): seq<Grant> decreases es {
    if |es| == 0 then [] else [es[0].g] + EGGrants(es[1..])
  }
  function AllGrantVerbs(cat: Catalog, gs: seq<GrantX>): seq<string> decreases gs {
    if |gs| == 0 then [] else GrantVerbsX(cat, gs[0].vsel) + AllGrantVerbs(cat, gs[1..])
  }

  // ------------------------------------------------------------------ expansion of prohibitions
  function ProhVerbsX(ont: Ontology, cat: Catalog, t: ProhTargetX): seq<string> {
    match t
    case XPVerb(v) => [v]
    case XPEffect(c) => VerbsOfClass(ont.verbs, c)
    case XPTrait(a, n) => FloatClassVerbs(cat.verbs, a, n)
  }
  function ExpandProhVerbs(ont: Ontology, cat: Catalog, p: ProhibitX, vs: seq<string>): seq<Prohibit> decreases vs {
    if |vs| == 0 then []
    else
      [Prohibit(if p.target.XPVerb? then p.pid else p.pid + "." + vs[0], PVerb(vs[0]), p.res, ResolveCondProh(ont, cat, vs[0], p.cond))]
      + ExpandProhVerbs(ont, cat, p, vs[1..])
  }
  function ExpandProhsX(ont: Ontology, cat: Catalog, ps: seq<ProhibitX>): seq<Prohibit> decreases ps {
    if |ps| == 0 then [] else ExpandProhVerbs(ont, cat, ps[0], ProhVerbsX(ont, cat, ps[0].target)) + ExpandProhsX(ont, cat, ps[1..])
  }

  // ------------------------------------------------------------------ expansion of bounds
  // ids of the expanded grants that came from one of the source grants
  function IdsOf(es: seq<EG>, srcs: seq<string>): seq<string> decreases es {
    if |es| == 0 then [] else (if es[0].src in srcs then [es[0].g.gid] else []) + IdsOf(es[1..], srcs)
  }
  // ids of the expanded grants whose verb is in the list: an action of such a verb can only be admitted by one of them
  function GidsOfVerbs(es: seq<EG>, vs: seq<string>): seq<string> decreases es {
    if |es| == 0 then [] else (if es[0].g.verb in vs then [es[0].g.gid] else []) + GidsOfVerbs(es[1..], vs)
  }
  function VerbsOfGids(es: seq<EG>, gids: seq<string>): seq<string> decreases es {
    if |es| == 0 then [] else (if es[0].g.gid in gids then [es[0].g.verb] else []) + VerbsOfGids(es[1..], gids)
  }
  // the verbs a bound's role-addressed value must resolve for
  function BoundRoleVerbs(ont: Ontology, cat: Catalog, es: seq<EG>, s: SelX): seq<string> {
    match s
    case XGids(gs) => VerbsOfGids(es, IdsOf(es, gs))
    case XEffect(c) => VerbsOfClass(ont.verbs, c)
    case XTrait(a, n) => VerbsOfGids(es, GidsOfVerbs(es, FloatClassVerbs(cat.verbs, a, n)))
  }
  function ResolveAll(ont: Ontology, cat: Catalog, vs: seq<string>, role: string): Option<seq<Res>> decreases vs {
    if |vs| == 0 then Some([])
    else
      (match ResolveRole(ont, cat, vs[0], role)
       case None => None
       case Some(x) => (match ResolveAll(ont, cat, vs[1..], role) case None => None case Some(rest) => Some([x] + rest)))
  }
  predicate AllSameRes(rs: seq<Res>) { forall i :: 0 <= i < |rs| ==> rs[i] == rs[0] }
  predicate AllSameTy(rs: seq<Res>) { forall i :: 0 <= i < |rs| ==> rs[i].ty == rs[0].ty }
  // one value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` (the caller supplies it on the
  // action) when the paths differ but the type is one; unresolved otherwise (the goal is then rejected, never weakened)
  function BoundValue(ont: Ontology, cat: Catalog, vs: seq<string>, t: TermX): Option<Term> {
    match t
    case XParam(p, ty) => Some(Param(p, ty))
    case XLit(v) => Some(Lit(v))
    case XHist(b, u) => Some(HistAgg(b, u))
    case XRole(r) =>
      (match ResolveAll(ont, cat, vs, r)
       case None => None
       case Some(rs) =>
         if |rs| == 0 then None
         else if AllSameRes(rs) then Some(Param(rs[0].path, rs[0].ty))
         else if AllSameTy(rs) then Some(Param("@" + r, rs[0].ty))
         else None)
  }
  function MkBound(b: BoundX, sel: Sel, tv: Term): Bound {
    Bound(b.bid, sel, BCore(b.agg, tv, b.key, b.window, b.scope, b.cap, b.onExceed))
  }
  // a bound that selects no expanded grant bounds nothing and is dropped
  function ExpandBound(ont: Ontology, cat: Catalog, es: seq<EG>, b: BoundX): seq<Bound> {
    match BoundValue(ont, cat, BoundRoleVerbs(ont, cat, es, b.sel), b.value)
    case None => []
    case Some(tv) =>
      (match b.sel
       case XGids(gs) => (if |IdsOf(es, gs)| == 0 then [] else [MkBound(b, SelGids(IdsOf(es, gs)), tv)])
       case XEffect(c) => [MkBound(b, SelEffect(c), tv)]
       case XTrait(a, n) =>
         (if |GidsOfVerbs(es, FloatClassVerbs(cat.verbs, a, n))| == 0 then []
          else [MkBound(b, SelGids(GidsOfVerbs(es, FloatClassVerbs(cat.verbs, a, n))), tv)]))
  }
  function ExpandBoundsX(ont: Ontology, cat: Catalog, es: seq<EG>, bs: seq<BoundX>): seq<Bound> decreases bs {
    if |bs| == 0 then [] else ExpandBound(ont, cat, es, bs[0]) + ExpandBoundsX(ont, cat, es, bs[1..])
  }

  // ------------------------------------------------------------------ the expanded goal
  function ExpandHoles(es: seq<EG>, hs: seq<Hole>): seq<Hole> decreases hs {
    if |hs| == 0 then [] else [hs[0].(affects := IdsOf(es, hs[0].affects))] + ExpandHoles(es, hs[1..])
  }
  function ExpandGoal(ont: Ontology, cat: Catalog, gx: GoalX): Goal {
    var es := ExpandGrantsX(ont, cat, gx.grants);
    gx.core.(grants := EGGrants(es),
             prohibits := ExpandProhsX(ont, cat, gx.prohibits),
             bounds := ExpandBoundsX(ont, cat, es, gx.bounds),
             deleg := gx.core.deleg.(mayTouch := IdsOf(es, gx.core.deleg.mayTouch)),
             wildcardAck := IdsOf(es, gx.core.wildcardAck),
             holes := ExpandHoles(es, gx.core.holes))
  }

  // ------------------------------------------------------------------ typing of the selector layer (reasons, fail closed)
  predicate AllKnown(known: seq<string>, ids: seq<string>) decreases ids {
    |ids| == 0 || (|ids[0]| > 0 && ids[0] in known && AllKnown(known, ids[1..]))
  }
  // a grant selector is positive and non-empty: no none_of (T7), at least one trait, every trait in the registry
  predicate GrantSelOk(cat: Catalog, g: GrantX) {
    match g.vsel case SVerb(_) => true case SClass(a, n) => |a| > 0 && |n| == 0 && AllKnown(cat.known, a)
  }
  predicate AllGrantSelOk(cat: Catalog, gs: seq<GrantX>) decreases gs {
    |gs| == 0 || (GrantSelOk(cat, gs[0]) && AllGrantSelOk(cat, gs[1..]))
  }
  predicate ProhSelOk(cat: Catalog, p: ProhibitX) {
    match p.target case XPTrait(a, n) => AllKnown(cat.known, a) && AllKnown(cat.known, n) case _ => true
  }
  predicate AllProhSelOk(cat: Catalog, ps: seq<ProhibitX>) decreases ps {
    |ps| == 0 || (ProhSelOk(cat, ps[0]) && AllProhSelOk(cat, ps[1..]))
  }
  predicate SrcGid(gs: seq<GrantX>, gid: string) decreases gs { |gs| > 0 && (gs[0].gid == gid || SrcGid(gs[1..], gid)) }
  predicate AllSrcGids(gs: seq<GrantX>, ids: seq<string>) decreases ids { |ids| == 0 || (SrcGid(gs, ids[0]) && AllSrcGids(gs, ids[1..])) }
  predicate BoundSelOk(cat: Catalog, gs: seq<GrantX>, b: BoundX) {
    match b.sel
    case XGids(ids) => AllSrcGids(gs, ids)
    case XEffect(_) => true
    case XTrait(a, n) => AllKnown(cat.known, a) && AllKnown(cat.known, n)
  }
  predicate AllBoundSelOk(cat: Catalog, gs: seq<GrantX>, bs: seq<BoundX>) decreases bs {
    |bs| == 0 || (BoundSelOk(cat, gs, bs[0]) && AllBoundSelOk(cat, gs, bs[1..]))
  }
  predicate AllBoundValuesOk(ont: Ontology, cat: Catalog, es: seq<EG>, bs: seq<BoundX>) decreases bs {
    |bs| == 0 || (BoundValue(ont, cat, BoundRoleVerbs(ont, cat, es, bs[0].sel), bs[0].value).Some? && AllBoundValuesOk(ont, cat, es, bs[1..]))
  }
  // every verb the catalog names is declared by the ontology (the catalog is built from the same definitions)
  predicate CatVerbsDeclared(ont: Ontology, vs: seq<VerbInfo>) decreases vs {
    |vs| == 0 || (FindDecl(ont.verbs, vs[0].verb).Some? && CatVerbsDeclared(ont, vs[1..]))
  }
  function XReasons(ont: Ontology, cat: Catalog, gx: GoalX): seq<string> {
    var es := ExpandGrantsX(ont, cat, gx.grants);
    (if CatVerbsDeclared(ont, cat.verbs) then [] else ["catalog_mismatch"])
    + (if AllGrantSelOk(cat, gx.grants) then [] else ["bad_grant_selector"])
    + (if AllProhSelOk(cat, gx.prohibits) then [] else ["bad_prohibit_selector"])
    + (if AllBoundSelOk(cat, gx.grants, gx.bounds) then [] else ["bad_bound_selector"])
    + (if AllBoundValuesOk(ont, cat, es, gx.bounds) then [] else ["unresolved_role_bound"])
  }

  // ------------------------------------------------------------------ the compiler for selector goals
  function CompileX(ont: Ontology, cat: Catalog, gx: GoalX): CResult {
    var rs := XReasons(ont, cat, gx);
    if |rs| > 0 then CEscalate(rs) else Compile(ont, ExpandGoal(ont, cat, gx))
  }
  // the compiled policy decides exactly as the reference semantics of the expansion (G-T1 for selector goals)
  lemma CompileXSound(ont: Ontology, cat: Catalog, gx: GoalX, a: Act, h: Hist)
    requires CompileX(ont, cat, gx).Compiled? && |gx.core.holes| == 0
    ensures DP(CompileX(ont, cat, gx).p, a, h) == DG(ont, ExpandGoal(ont, cat, gx), a, h)
  {
    var g := ExpandGoal(ont, cat, gx);
    assert CompileX(ont, cat, gx) == Compile(ont, g);
    assert Compile(ont, g).Compiled?;
    assert |g.holes| == 0 by {
      ExpandHolesLen(ExpandGrantsX(ont, cat, gx.grants), gx.core.holes);
    }
    SoundnessT1(ont, g, a, h);
  }
  lemma ExpandHolesLen(es: seq<EG>, hs: seq<Hole>)
    ensures |ExpandHoles(es, hs)| == |hs|
    decreases hs
  {
    if |hs| > 0 { ExpandHolesLen(es, hs[1..]); }
  }

  // ------------------------------------------------------------------ T6b: expanded grants exist only for verbs of the pinned catalog
  lemma EGGrantsConcat(a: seq<EG>, b: seq<EG>)
    ensures EGGrants(a + b) == EGGrants(a) + EGGrants(b)
    decreases a
  {
    if |a| > 0 {
      assert a + b == [a[0]] + (a[1..] + b);
      EGGrantsConcat(a[1..], b);
    }
  }
  lemma GrantVerbsIn(ont: Ontology, cat: Catalog, gr: GrantX, vs: seq<string>, x: Grant)
    requires x in EGGrants(ExpandGrantVerbs(ont, cat, gr, vs))
    ensures x.verb in vs
    decreases vs
  {
    if |vs| > 0 {
      assert vs == [vs[0]] + vs[1..];
      var tail := ExpandGrantVerbs(ont, cat, gr, vs[1..]);
      match ResolveCond(ont, cat, vs[0], gr.cond) {
        case Some(c) =>
          var e := EG(gr.gid, Grant(if gr.vsel.SClass? then gr.gid + "." + vs[0] else gr.gid, vs[0], gr.res, c));
          assert ExpandGrantVerbs(ont, cat, gr, vs) == [e] + tail;
          EGGrantsConcat([e], tail);
          assert EGGrants([e]) == [e.g];
          if x in EGGrants(tail) {
            GrantVerbsIn(ont, cat, gr, vs[1..], x);
          } else {
            assert x in EGGrants([e]);
            assert x == e.g;
          }
        case None =>
          assert ExpandGrantVerbs(ont, cat, gr, vs) == tail;
          GrantVerbsIn(ont, cat, gr, vs[1..], x);
      }
    }
  }
  lemma GrantsOnlyPinned(ont: Ontology, cat: Catalog, gs: seq<GrantX>, x: Grant)
    requires x in EGGrants(ExpandGrantsX(ont, cat, gs))
    ensures x.verb in AllGrantVerbs(cat, gs)
    decreases gs
  {
    if |gs| > 0 {
      var head := ExpandGrantVerbs(ont, cat, gs[0], GrantVerbsX(cat, gs[0].vsel));
      var tail := ExpandGrantsX(ont, cat, gs[1..]);
      assert ExpandGrantsX(ont, cat, gs) == head + tail;
      EGGrantsConcat(head, tail);
      if x in EGGrants(head) {
        GrantVerbsIn(ont, cat, gs[0], GrantVerbsX(cat, gs[0].vsel), x);
      } else {
        assert x in EGGrants(tail);
        GrantsOnlyPinned(ont, cat, gs[1..], x);
      }
    }
  }
  // a set of grants none of which names the action's verb never allows the action
  lemma NoGrantVerbDeny(ont: Ontology, g: Goal, gs: seq<Grant>, a: Act, h: Hist)
    requires forall i :: 0 <= i < |gs| ==> gs[i].verb != a.verb
    ensures GrantsDecG(ont, g, gs, a, h) == Deny
    decreases gs
  {
    if |gs| > 0 {
      assert forall i :: 1 <= i < |gs| ==> gs[i] == gs[1..][i - 1];
      NoGrantVerbDeny(ont, g, gs[1..], a, h);
      assert GrantMatch(ont, gs[0], g.deleg, a, h) == KF;
    }
  }
  // an action whose verb is outside the verbs the (pinned) catalog gave the goal's grants is Deny, whatever else the catalog holds
  lemma NewVerbDenied(ont: Ontology, cat: Catalog, gx: GoalX, a: Act, h: Hist)
    requires !(a.verb in AllGrantVerbs(cat, gx.grants))
    ensures GrantsDecG(ont, ExpandGoal(ont, cat, gx), EGGrants(ExpandGrantsX(ont, cat, gx.grants)), a, h) == Deny
  {
    var gs := EGGrants(ExpandGrantsX(ont, cat, gx.grants));
    forall i | 0 <= i < |gs| ensures gs[i].verb != a.verb {
      assert gs[i] in gs;
      GrantsOnlyPinned(ont, cat, gx.grants, gs[i]);
    }
    NoGrantVerbDeny(ont, ExpandGoal(ont, cat, gx), gs, a, h);
  }

  // ------------------------------------------------------------------ string-only entry points for the differential harness
  // `entries[i]` = [verb, trait, trait, ...] (the trait closure); `roles[i]` = [verb, role, path, role, path, ...]
  function EntriesToInfo(entries: seq<seq<string>>): seq<VerbInfo> decreases entries {
    if |entries| == 0 then []
    else (if |entries[0]| == 0 then [] else [VerbInfo(entries[0][0], entries[0][1..], [])]) + EntriesToInfo(entries[1..])
  }
  function ClassVerbsT(entries: seq<seq<string>>, allOf: seq<string>, noneOf: seq<string>): seq<string> {
    ClassVerbs(EntriesToInfo(entries), allOf, noneOf)
  }
  function FloatClassVerbsT(entries: seq<seq<string>>, allOf: seq<string>, noneOf: seq<string>): seq<string> {
    FloatClassVerbs(EntriesToInfo(entries), allOf, noneOf)
  }
  function AllowClassVerbsT(entries: seq<seq<string>>, allOf: seq<string>, noneOf: seq<string>): seq<string> {
    ClassVerbs(EntriesToInfo(entries), allOf, noneOf + [Unrev])
  }
  function PairsToRoles(xs: seq<string>): seq<RoleDecl> decreases |xs| {
    if |xs| < 2 then [] else [RoleDecl(xs[0], xs[1])] + PairsToRoles(xs[2..])
  }
  // the unique path carrying `role` on `verb` in the role table, or "" (none, several, or unknown verb): ResolveRole without the types
  function RolePathT(roles: seq<seq<string>>, verb: string, role: string): string decreases roles {
    if |roles| == 0 then ""
    else if |roles[0]| >= 1 && roles[0][0] == verb then
      (var ps := RolePaths(PairsToRoles(roles[0][1..]), role); if |ps| == 1 then ps[0] else "")
    else RolePathT(roles[1..], verb, role)
  }

  // ------------------------------------------------------------------ whole-expansion entry point (the differential harness)
  // The selector goal travels as an ordinary Goal tape (the "carrier"); the selector parts ride in strings and in role-marked params:
  //   grant.verb   = "V\u0001<verb>"  |  "C\u0001<all_of joined by \u0002>\u0001<none_of joined by \u0002>"
  //   prohibit     = PVerb("V\u0001<verb>") | PVerb("E\u0001<cls>") | PVerb("T\u0001<all>\u0001<none>")
  //   bound.sel    = SelGids(gids) | SelEffect("<cls>") | SelEffect("T\u0001<all>\u0001<none>")
  //   role term    = Param("\u0001role:<role>", TyS) anywhere a term may stand
  // The catalog travels as: known (strings), then per verb: verb, traits, n roles, (role, paths)*.
  function SplitSep(s: string, c: char): seq<string> decreases |s| {
    if |s| == 0 then [] else SplitFrom(s, c, 0)
  }
  function SplitFrom(s: string, c: char, start: nat): seq<string> requires start <= |s| decreases |s| - start {
    var i := IndexOf(s, c, start);
    if i == |s| then [s[start..]] else [s[start..i]] + SplitFrom(s, c, i + 1)
  }
  function IndexOf(s: string, c: char, from: nat): (r: nat) requires from <= |s| ensures from <= r <= |s| decreases |s| - from {
    if from == |s| then from else if s[from] == c then from else IndexOf(s, c, from + 1)
  }
  const RoleMark: string := "\u0001role:"
  function IsRoleParam(p: string): bool { |p| > |RoleMark| && p[..|RoleMark|] == RoleMark }
  function TermToX(t: Term): TermX {
    match t
    case Param(p, ty) => if IsRoleParam(p) then XRole(p[|RoleMark|..]) else XParam(p, ty)
    case Lit(v) => XLit(v)
    case HistAgg(b, u) => XHist(b, u)
  }
  function CondToX(c: Cond): CondX decreases c {
    match c
    case CTrue => XTrue
    case Cmp(op, l, r) => XCmp(op, TermToX(l), TermToX(r))
    case And(x, y) => XAnd(CondToX(x), CondToX(y))
    case Or(x, y) => XOr(CondToX(x), CondToX(y))
    case Not(x) => XNot(CondToX(x))
  }
  function SelOfString(s: string): VerbSel {
    var ps := SplitSep(s, '\u0001');
    if |ps| == 2 && ps[0] == "V" then SVerb(ps[1])
    else if |ps| == 3 && ps[0] == "C" then SClass(SplitSep(ps[1], '\u0002'), SplitSep(ps[2], '\u0002'))
    else SClass([], ["\u0000malformed"])
  }
  function GrantToX(g: Grant): GrantX { GrantX(g.gid, SelOfString(g.verb), g.res, CondToX(g.cond)) }
  function TargetOfString(s: string): ProhTargetX {
    var ps := SplitSep(s, '\u0001');
    if |ps| == 2 && ps[0] == "V" then XPVerb(ps[1])
    else if |ps| == 2 && ps[0] == "E" then XPEffect(ps[1])
    else if |ps| == 3 && ps[0] == "T" then XPTrait(SplitSep(ps[1], '\u0002'), SplitSep(ps[2], '\u0002'))
    else XPTrait([], ["\u0000malformed"])
  }
  function ProhToX(p: Prohibit): ProhibitX {
    ProhibitX(p.pid, (match p.target case PVerb(v) => TargetOfString(v) case PEffect(c) => XPEffect(c)), p.res, CondToX(p.cond))
  }
  function SelToX(s: Sel): SelX {
    match s
    case SelGids(g) => XGids(g)
    case SelEffect(c) =>
      (var ps := SplitSep(c, '\u0001');
       if |ps| == 3 && ps[0] == "T" then XTrait(SplitSep(ps[1], '\u0002'), SplitSep(ps[2], '\u0002')) else XEffect(c))
  }
  function BoundToX(b: Bound): BoundX {
    BoundX(b.bid, SelToX(b.sel), b.core.agg, TermToX(b.core.value), b.core.key, b.core.window, b.core.scope, b.core.cap, b.core.onExceed)
  }
  function MapSeq<A, B>(f: A -> B, xs: seq<A>): seq<B> decreases xs { if |xs| == 0 then [] else [f(xs[0])] + MapSeq(f, xs[1..]) }
  function CarrierToX(g: Goal): GoalX {
    GoalX(g, MapSeq(GrantToX, g.grants), MapSeq(ProhToX, g.prohibits), MapSeq(BoundToX, g.bounds))
  }

  function DecRoleDecls(ts: seq<Tok>, n: nat): PR<seq<RoleDecl>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecStr(ts)
      case Fail => Fail
      case Ok(role, r1) =>
        (match DecStrs(r1)
         case Fail => Fail
         case Ok(paths, r2) =>
           (match DecRoleDecls(r2, n - 1)
            case Fail => Fail
            case Ok(rest, r3) => Ok(MapSeq((p: string) => RoleDecl(role, p), paths) + rest, r3)))
  }
  function DecCatVerbs(ts: seq<Tok>, n: nat): PR<seq<VerbInfo>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecStr(ts)
      case Fail => Fail
      case Ok(verb, r1) =>
        (match DecStrs(r1)
         case Fail => Fail
         case Ok(traits, r2) =>
           (match DecInt(r2)
            case Fail => Fail
            case Ok(nr, r3) =>
              if nr < 0 then Fail
              else
                (match DecRoleDecls(r3, nr)
                 case Fail => Fail
                 case Ok(roles, r4) =>
                   (match DecCatVerbs(r4, n - 1)
                    case Fail => Fail
                    case Ok(rest, r5) => Ok([VerbInfo(verb, traits, roles)] + rest, r5)))))
  }
  function DecCatalog(ts: seq<Tok>): PR<Catalog> {
    match DecStrs(ts)
    case Fail => Fail
    case Ok(known, r1) =>
      (match DecInt(r1)
       case Fail => Fail
       case Ok(n, r2) =>
         if n < 0 then Fail
         else (match DecCatVerbs(r2, n) case Fail => Fail case Ok(vs, r3) => if |r3| == 0 then Ok(Catalog(known, vs), r3) else Fail))
  }
  // [0, <expanded goal tape>] | [1, n, reason...] (selector-layer type reasons, the core typechecker's are not run) | [2] (undecodable input)
  function ExpandT(goal: seq<Tok>, ont: seq<Tok>, cat: seq<Tok>): seq<Tok> {
    match DecGoal(goal)
    case Fail => [TI(2)]
    case Ok(g, rg) =>
      if |rg| != 0 then [TI(2)]
      else
        match GoalApi.DecOntology(ont)
        case Fail => [TI(2)]
        case Ok(o, ro) =>
          if |ro| != 0 then [TI(2)]
          else
            match DecCatalog(cat)
            case Fail => [TI(2)]
            case Ok(c, _) =>
              var gx := CarrierToX(g);
              var rs := XReasons(o, c, gx);
              if |rs| > 0 then [TI(1), TI(|rs|)] + MapSeq((r: string) => TS(r), rs)
              else [TI(0)] + EncGoal(ExpandGoal(o, c, gx))
  }
}
