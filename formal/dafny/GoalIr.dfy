// GoalIr.dfy - the Goal IR of goal-to-decision (types, ontology, reference semantics Allow_G / D_G, typing rules, unit safety G-T6).
// STANDALONE (no includes). No assume / axiom / extern. The IR is the contract between the human-reviewed goal and the compiled
// policy: everything below the signed Goal is a theorem (GoalCompile.dfy, GoalWitness.dfy, GoalRender.dfy), everything above it
// (text to IR) is measured, not proved.
//
// Numbers are exact integers (no floats). A Quantity is a unit tag plus an integer in the unit's minor scale (Money: minor units of a
// currency; Ratio: parts per million); there is no implicit conversion between units or currencies (typing rule T-unit).
// Decisions and Kleene truth values are small ranked integers so that meet / join are `min` / `max` (Deny < Escalate < Allow and
// false < unknown < true); GoalPvmTie.dfy proves these Kleene operators agree with the PolicyVm `Tri` operators.
module GoalIr {
  // ------------------------------------------------------------------ decisions and three-valued truth
  type Dec = d: int | 0 <= d <= 2
  const Deny: Dec := 0
  const Escalate: Dec := 1
  const Allow: Dec := 2
  function MeetD(a: Dec, b: Dec): Dec { if a <= b then a else b }
  function JoinD(a: Dec, b: Dec): Dec { if a >= b then a else b }

  type Tri = t: int | 0 <= t <= 2    // 0 false, 1 unknown, 2 true (Kleene strong logic, as PolicyVm.Tri)
  const KF: Tri := 0
  const KU: Tri := 1
  const KT: Tri := 2
  function AndK(a: Tri, b: Tri): Tri { if a <= b then a else b }
  function OrK(a: Tri, b: Tri): Tri { if a >= b then a else b }
  function NotK(a: Tri): Tri { 2 - a }
  function B2T(b: bool): Tri { if b then KT else KF }
  // false -> Deny, unknown -> Escalate, true -> Allow: Unknown never yields Allow.
  function DecOfTri(t: Tri): Dec { t }

  // ------------------------------------------------------------------ quantities, values, types
  datatype Unit = UMoney(ccy: string) | UCount | UDuration | UInstant | UBytes | URatio
  datatype Q = Q(u: Unit, n: int)
  // set members are atoms (never nested sets), so the value language is finite-depth
  datatype Atom = AQ(q: Q) | AS(s: string)
  datatype V = VQ(q: Q) | VS(s: string) | VSet(items: seq<Atom>)
  datatype Ty = TyQ(u: Unit) | TyS
  function AtomV(a: Atom): V { match a case AQ(q) => VQ(q) case AS(s) => VS(s) }
  function TypeOfV(v: V): Option<Ty> {
    match v case VQ(q) => Some(TyQ(q.u)) case VS(_) => Some(TyS) case VSet(_) => None
  }
  datatype Option<T> = None | Some(v: T)

  // ------------------------------------------------------------------ terms and conditions
  datatype Term = Param(path: string, ty: Ty) | Lit(v: V) | HistAgg(bid: string, u: Unit)
  datatype Op = Eq | Ne | Lt | Lte | Gt | Gte | In | Nin
  datatype Cond = CTrue | Cmp(op: Op, l: Term, r: Term) | And(a: Cond, b: Cond) | Or(a: Cond, b: Cond) | Not(c: Cond)

  // ------------------------------------------------------------------ clauses
  // a conjunct of an `AllOf` selector: AllOf is flat (parts are never wildcards and never AllOf themselves), so the intersection needs no recursion
  datatype ResPart = PartExact(id: string) | PartOneOf(ids: seq<string>) | PartRelated(rel: string, anchor: string)
  // `AllOf(parts)`: the resource must satisfy EVERY part (the meet of two readings of one goal; it can only narrow)
  datatype ResSel = Exact(id: string) | OneOf(ids: seq<string>) | Related(rel: string, anchor: string) | AnyRes(reason: string)
                  | AllOf(parts: seq<ResPart>)
  datatype Grant = Grant(gid: string, verb: string, res: ResSel, cond: Cond)
  datatype ProhTarget = PVerb(verb: string) | PEffect(cls: string)
  datatype Prohibit = Prohibit(pid: string, target: ProhTarget, res: ResSel, cond: Cond)
  datatype Agg = ACount | ASum | AMax | ADistinct
  datatype Sel = SelGids(gids: seq<string>) | SelEffect(cls: string)
  datatype Window = WTask | WSliding(ms: int) | WPeriod(ms: int, t0: int) | WLifetime
  datatype Scope = SSession | SPrincipal | SOrg | SFleet(agents: seq<string>)
  datatype OnExceed = OnDeny | OnEscalate
  // the part of a bound that is the same before and after lowering
  datatype BCore = BCore(agg: Agg, value: Term, key: string, window: Window, scope: Scope, cap: Q, onExceed: OnExceed)
  datatype Bound = Bound(bid: string, sel: Sel, core: BCore)
  datatype Validity = Validity(notBefore: int, notAfter: int, maxIdle: int)
  datatype Delegation = Delegation(maxDepth: int, narrowOnly: bool, mayTouch: seq<string>)
  // an unresolved ambiguity; `affects` names the grants that depend on it, `global` means every grant does
  datatype Hole = Hole(hid: string, q: string, domain: seq<string>, affects: seq<string>, global: bool)
  datatype Goal = Goal(v: int, principal: string, ontDigest: string, nlDigest: string, sources: seq<string>,
                       grants: seq<Grant>, prohibits: seq<Prohibit>, bounds: seq<Bound>, validity: Validity,
                       deleg: Delegation, escalateOn: seq<Cond>, wildcardAck: seq<string>, holes: seq<Hole>)

  // ------------------------------------------------------------------ ontology (the signed vocabulary the goal is typed against)
  datatype ParamDecl = ParamDecl(path: string, ty: Ty)
  datatype VerbDecl = VerbDecl(verb: string, cls: string, params: seq<ParamDecl>)
  datatype RelDecl = RelDecl(rel: string, anchor: string, members: seq<string>)
  datatype Ontology = Ontology(verbs: seq<VerbDecl>, rels: seq<RelDecl>)

  // ------------------------------------------------------------------ actions and history
  datatype Act = Act(verb: string, res: string, params: map<string, V>, t: int,
                     sess: string, prin: string, org: string, agent: string, depth: int)
  datatype Adm = Adm(gid: string, act: Act)
  // history of admitted actions (already restricted to what the caller can see), the time of the last admitted action (-1 if none),
  // and the aggregate values the durable store supplies for `HistAgg` terms
  datatype Hist = Hist(adms: seq<Adm>, last: int, aggs: map<string, Q>)

  // ------------------------------------------------------------------ resolved clause parts (shared by the semantics and the compiler)
  datatype ResPat = PStar | PSet(ids: seq<string>)
  datatype LSel = LSel(gids: seq<string>, verbs: seq<string>)

  function ResOk(p: ResPat, r: string): bool { match p case PStar => true case PSet(ids) => r in ids }

  function RelMembers(rels: seq<RelDecl>, rel: string, anchor: string): seq<string> decreases rels {
    if |rels| == 0 then [] else if rels[0].rel == rel && rels[0].anchor == anchor then rels[0].members else RelMembers(rels[1..], rel, anchor)
  }
  function ResolveSel(ont: Ontology, s: ResSel): ResPat {
    match s
    case Exact(id) => PSet([id])
    case OneOf(ids) => PSet(ids)
    case Related(rel, anchor) => PSet(RelMembers(ont.rels, rel, anchor))
    case AnyRes(_) => PStar
    case AllOf(ps) => ResolveParts(ont, ps)
  }
  function ResolvePart(ont: Ontology, p: ResPart): ResPat {
    match p
    case PartExact(id) => PSet([id])
    case PartOneOf(ids) => PSet(ids)
    case PartRelated(rel, anchor) => PSet(RelMembers(ont.rels, rel, anchor))
  }
  function FilterIn(a: seq<string>, b: seq<string>): seq<string> decreases a {
    if |a| == 0 then [] else (if a[0] in b then [a[0]] else []) + FilterIn(a[1..], b)
  }
  function InterPat(x: ResPat, y: ResPat): ResPat {
    match x
    case PStar => y
    case PSet(a) => (match y case PStar => x case PSet(b) => PSet(FilterIn(a, b)))
  }
  function ResolveParts(ont: Ontology, ps: seq<ResPart>): ResPat decreases ps {
    if |ps| == 0 then PStar else InterPat(ResolvePart(ont, ps[0]), ResolveParts(ont, ps[1..]))
  }
  lemma FilterInMem(a: seq<string>, b: seq<string>, r: string)
    ensures r in FilterIn(a, b) <==> (r in a && r in b)
    decreases a
  {
    if |a| > 0 {
      assert a == [a[0]] + a[1..];
      FilterInMem(a[1..], b, r);
    }
  }
  lemma InterOk(x: ResPat, y: ResPat, r: string)
    ensures ResOk(InterPat(x, y), r) <==> (ResOk(x, r) && ResOk(y, r))
  {
    if x.PSet? && y.PSet? { FilterInMem(x.ids, y.ids, r); }
  }
  // the all_of selector is exactly the conjunction of its parts
  lemma PartsSound(ont: Ontology, ps: seq<ResPart>, r: string)
    ensures ResOk(ResolveParts(ont, ps), r) <==> (forall i :: 0 <= i < |ps| ==> ResOk(ResolvePart(ont, ps[i]), r))
    decreases ps
  {
    if |ps| > 0 {
      PartsSound(ont, ps[1..], r);
      InterOk(ResolvePart(ont, ps[0]), ResolveParts(ont, ps[1..]), r);
      assert forall i :: 1 <= i < |ps| ==> ps[i] == ps[1..][i - 1];
    }
  }
  lemma AllOfSound(ont: Ontology, ps: seq<ResPart>, r: string)
    ensures ResOk(ResolveSel(ont, AllOf(ps)), r) <==> (forall i :: 0 <= i < |ps| ==> ResOk(ResolvePart(ont, ps[i]), r))
  { PartsSound(ont, ps, r); }
  // every verb the ontology declares with this effect class (W13: a prohibition names the CLASS, not one spelling)
  function VerbsOfClass(vs: seq<VerbDecl>, cls: string): seq<string> decreases vs {
    if |vs| == 0 then [] else (if vs[0].cls == cls then [vs[0].verb] else []) + VerbsOfClass(vs[1..], cls)
  }
  function ResolveBSel(ont: Ontology, s: Sel): LSel {
    match s case SelGids(g) => LSel(g, []) case SelEffect(c) => LSel([], VerbsOfClass(ont.verbs, c))
  }
  function ProhVerbs(ont: Ontology, t: ProhTarget): seq<string> {
    match t case PVerb(v) => [v] case PEffect(c) => VerbsOfClass(ont.verbs, c)
  }

  // ------------------------------------------------------------------ evaluation of terms and conditions (Kleene, as PolicyVm Tri)
  function EqT(x: V, y: V): Tri {
    match x
    case VQ(p) => (match y case VQ(q) => (if p.u == q.u then B2T(p.n == q.n) else KU) case _ => KU)
    case VS(s) => (match y case VS(t) => B2T(s == t) case _ => KU)
    case VSet(_) => KU
  }
  function LtT(x: V, y: V): Tri {
    match x
    case VQ(p) => (match y case VQ(q) => (if p.u == q.u then B2T(p.n < q.n) else KU) case _ => KU)
    case _ => KU
  }
  function InT(x: V, items: seq<Atom>): Tri decreases items {
    if |items| == 0 then KF else OrK(EqT(x, AtomV(items[0])), InT(x, items[1..]))
  }
  function CmpT(op: Op, x: Option<V>, y: Option<V>): Tri {
    if x.None? || y.None? then KU
    else
      match op
      case Eq => EqT(x.v, y.v)
      case Ne => NotK(EqT(x.v, y.v))
      case Lt => LtT(x.v, y.v)
      case Gte => NotK(LtT(x.v, y.v))
      case Gt => LtT(y.v, x.v)
      case Lte => NotK(LtT(y.v, x.v))
      case In => (match y.v case VSet(items) => InT(x.v, items) case _ => KU)
      case Nin => NotK((match y.v case VSet(items) => InT(x.v, items) case _ => KU))
  }
  function NegOp(op: Op): Op {
    match op case Eq => Ne case Ne => Eq case Lt => Gte case Gte => Lt case Gt => Lte case Lte => Gt case In => Nin case Nin => In
  }
  lemma NegOpSound(op: Op, x: Option<V>, y: Option<V>)
    ensures CmpT(NegOp(op), x, y) == NotK(CmpT(op, x, y))
  {}

  function EvalT(t: Term, a: Act, h: Hist): Option<V> {
    match t
    case Param(p, _) => if p in a.params then Some(a.params[p]) else None
    case Lit(v) => Some(v)
    case HistAgg(b, _) => if b in h.aggs then Some(VQ(h.aggs[b])) else None
  }
  function EvalC(c: Cond, a: Act, h: Hist): Tri decreases c {
    match c
    case CTrue => KT
    case Cmp(op, l, r) => CmpT(op, EvalT(l, a, h), EvalT(r, a, h))
    case And(x, y) => AndK(EvalC(x, a, h), EvalC(y, a, h))
    case Or(x, y) => OrK(EvalC(x, a, h), EvalC(y, a, h))
    case Not(x) => NotK(EvalC(x, a, h))
  }

  // ------------------------------------------------------------------ bounds (aggregates over the history plus the candidate action)
  function StrIn(x: string, s: seq<string>): bool { x in s }
  function AppliesL(s: LSel, gid: string, verb: string): bool { gid in s.gids || verb in s.verbs }
  function InScope(sc: Scope, a: Act, x: Act): bool {
    match sc
    case SSession => a.sess == x.sess
    case SPrincipal => a.prin == x.prin
    case SOrg => a.org == x.org
    case SFleet(ag) => a.agent in ag && x.agent in ag
  }
  function InWindow(w: Window, a: Act, x: Act): bool {
    match w
    case WTask => true
    case WLifetime => true
    case WSliding(ms) => x.t > a.t - ms && x.t <= a.t
    case WPeriod(ms, t0) => ms > 0 && (a.t - t0) / ms == (x.t - t0) / ms
  }
  // the admitted actions this bound counts, followed by the candidate itself
  function SelItems(core: BCore, s: LSel, adms: seq<Adm>, a: Act): seq<Act> decreases adms {
    if |adms| == 0 then [a]
    else
      (if AppliesL(s, adms[0].gid, adms[0].act.verb) && InScope(core.scope, a, adms[0].act) && InWindow(core.window, a, adms[0].act)
       then [adms[0].act] else []) + SelItems(core, s, adms[1..], a)
  }
  // numeric values of the bound's value term over the items; None as soon as one is unreadable or of another unit
  function ItemVals(core: BCore, items: seq<Act>, h: Hist): Option<seq<int>> decreases items {
    if |items| == 0 then Some([])
    else
      match EvalT(core.value, items[0], h)
      case Some(VQ(q)) =>
        if q.u != core.cap.u then None
        else (match ItemVals(core, items[1..], h) case Some(r) => Some([q.n] + r) case None => None)
      case _ => None
  }
  function SumI(xs: seq<int>): int decreases xs { if |xs| == 0 then 0 else xs[0] + SumI(xs[1..]) }
  function MaxI(xs: seq<int>): int requires |xs| > 0 decreases xs {
    if |xs| == 1 then xs[0] else (var m := MaxI(xs[1..]); if xs[0] >= m then xs[0] else m)
  }
  function KeyVals(core: BCore, items: seq<Act>): Option<seq<V>> decreases items {
    if |items| == 0 then Some([])
    else if core.key !in items[0].params then None
    else (match KeyVals(core, items[1..]) case Some(r) => Some([items[0].params[core.key]] + r) case None => None)
  }
  function Dedup(vs: seq<V>): seq<V> decreases vs {
    if |vs| == 0 then [] else if vs[0] in vs[1..] then Dedup(vs[1..]) else [vs[0]] + Dedup(vs[1..])
  }
  // the aggregate of the selected items, compared with the cap: true / unknown / false = exceeded / unreadable / within
  function Exceeded(core: BCore, items: seq<Act>, h: Hist): Tri {
    match core.agg
    case ACount => B2T(|items| > core.cap.n)
    case ASum => (match ItemVals(core, items, h) case Some(xs) => B2T(SumI(xs) > core.cap.n) case None => KU)
    case AMax => (match ItemVals(core, items, h)
                  case Some(xs) => (if |xs| == 0 then KU else B2T(MaxI(xs) > core.cap.n))
                  case None => KU)
    case ADistinct => (match KeyVals(core, items) case Some(vs) => B2T(|Dedup(vs)| > core.cap.n) case None => KU)
  }
  // the decision a bound imposes on a candidate admitted by a grant it applies to
  function BoundStat(core: BCore, s: LSel, a: Act, h: Hist): Dec {
    var e := Exceeded(core, SelItems(core, s, h.adms, a), h);
    if e == KT then (match core.onExceed case OnDeny => Deny case OnEscalate => Escalate)
    else if e == KU then Escalate else Allow
  }

  // ------------------------------------------------------------------ the decision D_G(a, H): validity, prohibitions, escalation triggers, grants with their bounds
  function ValidityDec(v: Validity, dg: Delegation, a: Act, h: Hist): Dec {
    if a.t < v.notBefore || a.t > v.notAfter then Deny
    else if v.maxIdle > 0 && h.last >= 0 && a.t - h.last > v.maxIdle then Deny
    else if a.depth < 0 || a.depth > dg.maxDepth then Deny
    else Allow
  }
  function DelegOk(dg: Delegation, gid: string, a: Act): bool { a.depth == 0 || gid in dg.mayTouch }

  function ProhOne(verbs: seq<string>, res: ResPat, c: Cond, a: Act, h: Hist): Dec {
    var m := AndK(B2T(a.verb in verbs), AndK(B2T(ResOk(res, a.res)), EvalC(c, a, h)));
    if m == KT then Deny else if m == KU then Escalate else Allow
  }
  function ProhDecG(ont: Ontology, ps: seq<Prohibit>, a: Act, h: Hist): Dec decreases ps {
    if |ps| == 0 then Allow
    else MeetD(ProhOne(ProhVerbs(ont, ps[0].target), ResolveSel(ont, ps[0].res), ps[0].cond, a, h), ProhDecG(ont, ps[1..], a, h))
  }
  function EscOne(m: Tri): Dec { if m == KF then Allow else Escalate }
  function EscDecG(cs: seq<Cond>, a: Act, h: Hist): Dec decreases cs {
    if |cs| == 0 then Allow else MeetD(EscOne(EvalC(cs[0], a, h)), EscDecG(cs[1..], a, h))
  }
  function BoundsDecG(ont: Ontology, bs: seq<Bound>, gid: string, a: Act, h: Hist): Dec decreases bs {
    if |bs| == 0 then Allow
    else
      var s := ResolveBSel(ont, bs[0].sel);
      MeetD(if AppliesL(s, gid, a.verb) then BoundStat(bs[0].core, s, a, h) else Allow, BoundsDecG(ont, bs[1..], gid, a, h))
  }
  function GrantMatch(ont: Ontology, g: Grant, dg: Delegation, a: Act, h: Hist): Tri {
    AndK(B2T(a.verb == g.verb && DelegOk(dg, g.gid, a)), AndK(B2T(ResOk(ResolveSel(ont, g.res), a.res)), EvalC(g.cond, a, h)))
  }
  function GrantDecG(ont: Ontology, g: Goal, gr: Grant, a: Act, h: Hist): Dec {
    MeetD(DecOfTri(GrantMatch(ont, gr, g.deleg, a, h)), BoundsDecG(ont, g.bounds, gr.gid, a, h))
  }
  function GrantsDecG(ont: Ontology, g: Goal, gs: seq<Grant>, a: Act, h: Hist): Dec decreases gs {
    if |gs| == 0 then Deny else JoinD(GrantDecG(ont, g, gs[0], a, h), GrantsDecG(ont, g, gs[1..], a, h))
  }
  // Allow_G / Escalate_G / Deny_G of the spec, as one total function. Closed world: a verb no grant names is Deny.
  function DG(ont: Ontology, g: Goal, a: Act, h: Hist): Dec {
    MeetD(ValidityDec(g.validity, g.deleg, a, h),
    MeetD(ProhDecG(ont, g.prohibits, a, h),
    MeetD(EscDecG(g.escalateOn, a, h),
          GrantsDecG(ont, g, g.grants, a, h))))
  }

  // ------------------------------------------------------------------ typing (units, currency, closed world, canonical order, wildcards, holes)
  function StrLt(a: string, b: string): bool decreases |a| + |b| {
    if |b| == 0 then false else if |a| == 0 then true
    else if a[0] != b[0] then (a[0] as int) < (b[0] as int) else StrLt(a[1..], b[1..])
  }
  // strictly increasing in code-unit order (adjacent pairs; the order is a strict total order, so ids are unique)
  predicate StrictlySorted(xs: seq<string>) decreases xs {
    |xs| <= 1 || (StrLt(xs[0], xs[1]) && StrictlySorted(xs[1..]))
  }
  predicate UnitOk(u: Unit) { match u case UMoney(c) => |c| > 0 case _ => true }
  predicate TyOk(t: Ty) { match t case TyQ(u) => UnitOk(u) case TyS => true }
  predicate VOk(v: V) {
    match v case VQ(q) => UnitOk(q.u) case VS(_) => true
            case VSet(items) => forall i :: 0 <= i < |items| ==> (match items[i] case AQ(q) => UnitOk(q.u) case AS(_) => true)
  }
  function TypeOfTerm(t: Term): Option<Ty> {
    match t case Param(_, ty) => Some(ty) case Lit(v) => TypeOfV(v) case HistAgg(_, u) => Some(TyQ(u))
  }
  predicate TermOk(t: Term) {
    match t case Param(p, ty) => |p| > 0 && TyOk(ty) case Lit(v) => VOk(v) case HistAgg(b, u) => |b| > 0 && UnitOk(u)
  }
  predicate AllOfTy(items: seq<Atom>, ty: Ty) {
    forall i :: 0 <= i < |items| ==> TypeOfV(AtomV(items[i])) == Some(ty)
  }
  // a comparison is typed when both sides have a type; ordering needs a quantity of one unit; `in` needs a literal set of that type
  predicate CmpTyped(op: Op, l: Term, r: Term) {
    TermOk(l) && TermOk(r) && TypeOfTerm(l).Some? &&
    (match op
     case Eq => TypeOfTerm(l) == TypeOfTerm(r)
     case Ne => TypeOfTerm(l) == TypeOfTerm(r)
     case Lt => TypeOfTerm(l) == TypeOfTerm(r) && TypeOfTerm(l).v.TyQ?
     case Lte => TypeOfTerm(l) == TypeOfTerm(r) && TypeOfTerm(l).v.TyQ?
     case Gt => TypeOfTerm(l) == TypeOfTerm(r) && TypeOfTerm(l).v.TyQ?
     case Gte => TypeOfTerm(l) == TypeOfTerm(r) && TypeOfTerm(l).v.TyQ?
     case In => r.Lit? && r.v.VSet? && AllOfTy(r.v.items, TypeOfTerm(l).v)
     case Nin => r.Lit? && r.v.VSet? && AllOfTy(r.v.items, TypeOfTerm(l).v))
  }
  // `ok` is the parameter-declaration check: every Param(p, ty) must be declared (or merely not contradicted) by the verbs in question
  predicate CondTyped(c: Cond, ok: (string, Ty) -> bool) decreases c {
    match c
    case CTrue => true
    case Cmp(op, l, r) => CmpTyped(op, l, r) && ParamsOk(l, ok) && ParamsOk(r, ok)
    case And(x, y) => CondTyped(x, ok) && CondTyped(y, ok)
    case Or(x, y) => CondTyped(x, ok) && CondTyped(y, ok)
    case Not(x) => CondTyped(x, ok)
  }
  predicate ParamsOk(t: Term, ok: (string, Ty) -> bool) { match t case Param(p, ty) => ok(p, ty) case _ => true }

  function FindDecl(vs: seq<VerbDecl>, verb: string): Option<VerbDecl> decreases vs {
    if |vs| == 0 then None else if vs[0].verb == verb then Some(vs[0]) else FindDecl(vs[1..], verb)
  }
  predicate HasParam(ps: seq<ParamDecl>, p: string, ty: Ty) { ParamDecl(p, ty) in ps }
  // declared: the verb declares exactly this parameter with exactly this type
  predicate DeclaredFor(ont: Ontology, verbs: seq<string>, p: string, ty: Ty) {
    forall i :: 0 <= i < |verbs| ==> (FindDecl(ont.verbs, verbs[i]).Some? && HasParam(FindDecl(ont.verbs, verbs[i]).v.params, p, ty))
  }
  // not contradicted: no verb declares this path with another type
  predicate NoConflictP(ps: seq<ParamDecl>, p: string, ty: Ty) decreases ps {
    |ps| == 0 || ((ps[0].path != p || ps[0].ty == ty) && NoConflictP(ps[1..], p, ty))
  }
  predicate NoConflict(vs: seq<VerbDecl>, p: string, ty: Ty) decreases vs {
    |vs| == 0 || (NoConflictP(vs[0].params, p, ty) && NoConflict(vs[1..], p, ty))
  }

  predicate ResSelOk(ont: Ontology, s: ResSel) {
    match s
    case Exact(id) => |id| > 0
    case OneOf(ids) => |ids| > 0
    case Related(rel, anchor) => exists i :: 0 <= i < |ont.rels| && ont.rels[i].rel == rel && ont.rels[i].anchor == anchor
    case AnyRes(_) => true
    case AllOf(ps) => |ps| >= 2 && forall i :: 0 <= i < |ps| ==> PartOk(ont, ps[i])
  }
  predicate PartOk(ont: Ontology, p: ResPart) {
    match p
    case PartExact(id) => |id| > 0
    case PartOneOf(ids) => |ids| > 0
    case PartRelated(rel, anchor) => exists i :: 0 <= i < |ont.rels| && ont.rels[i].rel == rel && ont.rels[i].anchor == anchor
  }
  predicate GrantOk(ont: Ontology, g: Goal, gr: Grant) {
    |gr.gid| > 0 && FindDecl(ont.verbs, gr.verb).Some? && ResSelOk(ont, gr.res)
    && (gr.res.AnyRes? ==> gr.gid in g.wildcardAck)
    && CondTyped(gr.cond, (p: string, ty: Ty) => DeclaredFor(ont, [gr.verb], p, ty))
  }
  predicate ProhibitOk(ont: Ontology, p: Prohibit) {
    |p.pid| > 0 && ResSelOk(ont, p.res)
    && (match p.target case PVerb(v) => FindDecl(ont.verbs, v).Some? case PEffect(c) => |c| > 0 && |VerbsOfClass(ont.verbs, c)| > 0)
    && CondTyped(p.cond, (q: string, ty: Ty) => DeclaredFor(ont, ProhVerbs(ont, p.target), q, ty))
  }
  predicate WindowOk(w: Window) { match w case WSliding(ms) => ms > 0 case WPeriod(ms, _) => ms > 0 case _ => true }
  predicate ScopeOk(s: Scope) { match s case SFleet(ag) => |ag| > 0 case _ => true }
  predicate BoundOk(ont: Ontology, g: Goal, b: Bound) {
    |b.bid| > 0 && TermOk(b.core.value) && UnitOk(b.core.cap.u) && b.core.cap.n >= 0
    && WindowOk(b.core.window) && ScopeOk(b.core.scope)
    && (match b.sel
        case SelGids(gids) => |gids| > 0 && forall i :: 0 <= i < |gids| ==> exists j :: 0 <= j < |g.grants| && g.grants[j].gid == gids[i]
        case SelEffect(c) => |c| > 0)
    && (match b.core.agg
        case ACount => b.core.cap.u == UCount
        case ASum => TypeOfTerm(b.core.value) == Some(TyQ(b.core.cap.u))
        case AMax => TypeOfTerm(b.core.value) == Some(TyQ(b.core.cap.u))
        case ADistinct => b.core.cap.u == UCount && |b.core.key| > 0)
  }
  predicate ValidityOk(v: Validity, dg: Delegation, g: Goal) {
    v.notBefore <= v.notAfter && v.maxIdle >= 0
    && 0 <= dg.maxDepth <= 16 && dg.narrowOnly
    && forall i :: 0 <= i < |dg.mayTouch| ==> exists j :: 0 <= j < |g.grants| && g.grants[j].gid == dg.mayTouch[i]
  }
  predicate HoleOk(g: Goal, h: Hole) {
    |h.hid| > 0 && forall i :: 0 <= i < |h.affects| ==> exists j :: 0 <= j < |g.grants| && g.grants[j].gid == h.affects[i]
  }
  function Gids(gs: seq<Grant>): seq<string> { seq(|gs|, i requires 0 <= i < |gs| => gs[i].gid) }
  function Pids(ps: seq<Prohibit>): seq<string> { seq(|ps|, i requires 0 <= i < |ps| => ps[i].pid) }
  function Bids(bs: seq<Bound>): seq<string> { seq(|bs|, i requires 0 <= i < |bs| => bs[i].bid) }
  function Hids(hs: seq<Hole>): seq<string> { seq(|hs|, i requires 0 <= i < |hs| => hs[i].hid) }

  predicate EscsTyped(ont: Ontology, g: Goal) {
    forall i :: 0 <= i < |g.escalateOn| ==> CondTyped(g.escalateOn[i], (p: string, ty: Ty) => NoConflict(ont.verbs, p, ty))
  }
  predicate Sorted4(g: Goal) {
    StrictlySorted(Gids(g.grants)) && StrictlySorted(Pids(g.prohibits)) && StrictlySorted(Bids(g.bounds)) && StrictlySorted(Hids(g.holes))
  }
  // the whole typing judgement; ill-typed goals are rejected, never coerced
  predicate IsWellTyped(ont: Ontology, g: Goal) {
    Sorted4(g)
    && (forall i :: 0 <= i < |g.grants| ==> GrantOk(ont, g, g.grants[i]))
    && (forall i :: 0 <= i < |g.prohibits| ==> ProhibitOk(ont, g.prohibits[i]))
    && (forall i :: 0 <= i < |g.bounds| ==> BoundOk(ont, g, g.bounds[i]))
    && EscsTyped(ont, g)
    && ValidityOk(g.validity, g.deleg, g)
    && (forall i :: 0 <= i < |g.holes| ==> HoleOk(g, g.holes[i]))
  }
  // a goal may be signed only when it is well typed and has no unresolved hole (G-T7)
  predicate Signable(ont: Ontology, g: Goal) { IsWellTyped(ont, g) && |g.holes| == 0 }

  // ------------------------------------------------------------------ G-T6 unit safety
  // the action conforms to the ontology when every declared parameter it carries has the declared type, and the supplied aggregates
  // have the unit the goal's HistAgg term declares
  ghost predicate ActConforms(ont: Ontology, a: Act) {
    FindDecl(ont.verbs, a.verb).Some? ==>
      forall i :: 0 <= i < |FindDecl(ont.verbs, a.verb).v.params| ==>
        (var pd := FindDecl(ont.verbs, a.verb).v.params[i]; pd.path in a.params ==> TypeOfV(a.params[pd.path]) == Some(pd.ty))
  }
  ghost predicate TermConforms(t: Term, a: Act, h: Hist) {
    match t
    case Param(p, ty) => p in a.params ==> TypeOfV(a.params[p]) == Some(ty)
    case Lit(_) => true
    case HistAgg(b, u) => b in h.aggs ==> h.aggs[b].u == u
  }
  // an evaluation of a comparison "mixes" when both operands are readable but of different kinds or units
  ghost predicate Mix(op: Op, x: Option<V>, y: Option<V>) {
    x.Some? && y.Some? &&
    (match op
     case In => !(y.v.VSet? && forall i :: 0 <= i < |y.v.items| ==> TypeOfV(x.v).Some? && TypeOfV(AtomV(y.v.items[i])) == TypeOfV(x.v))
     case Nin => !(y.v.VSet? && forall i :: 0 <= i < |y.v.items| ==> TypeOfV(x.v).Some? && TypeOfV(AtomV(y.v.items[i])) == TypeOfV(x.v))
     case _ => !(TypeOfV(x.v).Some? && TypeOfV(x.v) == TypeOfV(y.v)))
  }
  ghost predicate NoMix(c: Cond, a: Act, h: Hist) decreases c {
    match c
    case CTrue => true
    case Cmp(op, l, r) => !Mix(op, EvalT(l, a, h), EvalT(r, a, h))
    case And(x, y) => NoMix(x, a, h) && NoMix(y, a, h)
    case Or(x, y) => NoMix(x, a, h) && NoMix(y, a, h)
    case Not(x) => NoMix(x, a, h)
  }
  ghost predicate CondConforms(c: Cond, a: Act, h: Hist) decreases c {
    match c
    case CTrue => true
    case Cmp(_, l, r) => TermConforms(l, a, h) && TermConforms(r, a, h)
    case And(x, y) => CondConforms(x, a, h) && CondConforms(y, a, h)
    case Or(x, y) => CondConforms(x, a, h) && CondConforms(y, a, h)
    case Not(x) => CondConforms(x, a, h)
  }
  lemma TermTy(t: Term, a: Act, h: Hist)
    requires TermConforms(t, a, h)
    ensures EvalT(t, a, h).Some? ==> TypeOfV(EvalT(t, a, h).v) == TypeOfTerm(t)
  {
    match t
    case Param(_, _) =>
    case Lit(_) =>
    case HistAgg(_, _) =>
  }
  // G-T6: a typed condition evaluated on a conforming action never compares two different units or kinds (no coercion, no FX).
  lemma UnitSafety(c: Cond, ok: (string, Ty) -> bool, a: Act, h: Hist)
    requires CondTyped(c, ok) && CondConforms(c, a, h)
    ensures NoMix(c, a, h)
    decreases c
  {
    match c
    case CTrue =>
    case Cmp(op, l, r) =>
      assert CmpTyped(op, l, r);
      TermTy(l, a, h);
      TermTy(r, a, h);
      var x := EvalT(l, a, h);
      var y := EvalT(r, a, h);
      if x.Some? && y.Some? && (op == In || op == Nin) {
        assert r.Lit? && r.v.VSet?;
        assert y == Some(r.v);
        assert AllOfTy(r.v.items, TypeOfTerm(l).v);
      }
    case And(x, y) => UnitSafety(x, ok, a, h); UnitSafety(y, ok, a, h);
    case Or(x, y) => UnitSafety(x, ok, a, h); UnitSafety(y, ok, a, h);
    case Not(x) => UnitSafety(x, ok, a, h);
  }
}
