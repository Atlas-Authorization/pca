// GoalRender.dfy - the lossless card: a deterministic injective encoding of the Goal IR into a token stream (G-T10), the codec the
// TypeScript glue uses to talk to the extracted code, and the encoders of the compiled policy.
// No assume / axiom / extern.
//
// `Render(g)` is the PolicyCard as a sequence of tokens: structural keywords (TKw), exact integers (TI: quantities, times, limits,
// counts) and exact strings (TS: ids, currencies, verbs, resource names). Every clause of the goal appears, in order, with its exact
// numbers; nothing the goal says is summarised or omitted. G-T10 (`RenderParse`): Parse(Render(g)) == Some(g) for EVERY goal value, so
// Render is injective and anything the policy permits is visible on the card. The glue turns the token stream into text with a fixed
// phrase table per keyword (decimal digits for TI, JSON-quoted text for TS); that last step is trusted glue, listed in trusted-base.md.
include "GoalIr.dfy"
module GoalRender {
  import opened GoalIr

  datatype Tok = TKw(k: int) | TI(i: int) | TS(s: string)
  datatype PR<T> = Fail | Ok(v: T, rest: seq<Tok>)

  // ------------------------------------------------------------------ scalars
  function EncStr(s: string): seq<Tok> { [TS(s)] }
  function DecStr(ts: seq<Tok>): PR<string> { if |ts| > 0 && ts[0].TS? then Ok(ts[0].s, ts[1..]) else Fail }
  lemma StrRT(s: string, m: seq<Tok>) ensures DecStr(EncStr(s) + m) == Ok(s, m) {}
  function EncInt(i: int): seq<Tok> { [TI(i)] }
  function DecInt(ts: seq<Tok>): PR<int> { if |ts| > 0 && ts[0].TI? then Ok(ts[0].i, ts[1..]) else Fail }
  lemma IntRT(i: int, m: seq<Tok>) ensures DecInt(EncInt(i) + m) == Ok(i, m) {}
  function EncBool(b: bool): seq<Tok> { [TI(if b then 1 else 0)] }
  function DecBool(ts: seq<Tok>): PR<bool> {
    if |ts| > 0 && ts[0].TI? && (ts[0].i == 0 || ts[0].i == 1) then Ok(ts[0].i == 1, ts[1..]) else Fail
  }
  lemma BoolRT(b: bool, m: seq<Tok>) ensures DecBool(EncBool(b) + m) == Ok(b, m) {}

  // ------------------------------------------------------------------ units, quantities, values, types
  function EncUnit(u: Unit): seq<Tok> {
    match u
    case UMoney(c) => [TKw(300)] + EncStr(c)
    case UCount => [TKw(301)]
    case UDuration => [TKw(302)]
    case UInstant => [TKw(303)]
    case UBytes => [TKw(304)]
    case URatio => [TKw(305)]
  }
  function DecUnit(ts: seq<Tok>): PR<Unit> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 300 then (match DecStr(ts[1..]) case Ok(c, r) => Ok(UMoney(c), r) case Fail => Fail)
    else if ts[0].k == 301 then Ok(UCount, ts[1..])
    else if ts[0].k == 302 then Ok(UDuration, ts[1..])
    else if ts[0].k == 303 then Ok(UInstant, ts[1..])
    else if ts[0].k == 304 then Ok(UBytes, ts[1..])
    else if ts[0].k == 305 then Ok(URatio, ts[1..])
    else Fail
  }
  lemma UnitRT(u: Unit, m: seq<Tok>) ensures DecUnit(EncUnit(u) + m) == Ok(u, m) {
    match u
    case UMoney(c) =>
      assert EncUnit(u) + m == [TKw(300)] + (EncStr(c) + m);
      StrRT(c, m);
    case UCount =>
    case UDuration =>
    case UInstant =>
    case UBytes =>
    case URatio =>
  }

  function EncQ(q: Q): seq<Tok> { EncUnit(q.u) + EncInt(q.n) }
  function DecQ(ts: seq<Tok>): PR<Q> {
    match DecUnit(ts) case Fail => Fail case Ok(u, r) => (match DecInt(r) case Fail => Fail case Ok(n, r2) => Ok(Q(u, n), r2))
  }
  lemma QRT(q: Q, m: seq<Tok>) ensures DecQ(EncQ(q) + m) == Ok(q, m) {
    assert EncQ(q) + m == EncUnit(q.u) + (EncInt(q.n) + m);
    UnitRT(q.u, EncInt(q.n) + m);
    IntRT(q.n, m);
  }

  function EncTy(t: Ty): seq<Tok> { match t case TyQ(u) => [TKw(310)] + EncUnit(u) case TyS => [TKw(311)] }
  function DecTy(ts: seq<Tok>): PR<Ty> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 310 then (match DecUnit(ts[1..]) case Ok(u, r) => Ok(TyQ(u), r) case Fail => Fail)
    else if ts[0].k == 311 then Ok(TyS, ts[1..])
    else Fail
  }
  lemma TyRT(t: Ty, m: seq<Tok>) ensures DecTy(EncTy(t) + m) == Ok(t, m) {
    match t
    case TyQ(u) => assert EncTy(t) + m == [TKw(310)] + (EncUnit(u) + m); UnitRT(u, m);
    case TyS =>
  }

  function EncAtom(a: Atom): seq<Tok> { match a case AQ(q) => [TKw(320)] + EncQ(q) case AS(s) => [TKw(321)] + EncStr(s) }
  function DecAtom(ts: seq<Tok>): PR<Atom> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 320 then (match DecQ(ts[1..]) case Ok(q, r) => Ok(AQ(q), r) case Fail => Fail)
    else if ts[0].k == 321 then (match DecStr(ts[1..]) case Ok(s, r) => Ok(AS(s), r) case Fail => Fail)
    else Fail
  }
  lemma AtomRT(a: Atom, m: seq<Tok>) ensures DecAtom(EncAtom(a) + m) == Ok(a, m) {
    match a
    case AQ(q) => assert EncAtom(a) + m == [TKw(320)] + (EncQ(q) + m); QRT(q, m);
    case AS(s) => assert EncAtom(a) + m == [TKw(321)] + (EncStr(s) + m); StrRT(s, m);
  }

  function EncAtomsElems(xs: seq<Atom>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncAtom(xs[0]) + EncAtomsElems(xs[1..])
  }
  function EncAtoms(xs: seq<Atom>): seq<Tok> { [TI(|xs|)] + EncAtomsElems(xs) }
  function DecAtomsElems(ts: seq<Tok>, n: nat): PR<seq<Atom>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecAtom(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecAtomsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecAtoms(ts: seq<Tok>): PR<seq<Atom>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecAtomsElems(ts[1..], ts[0].i) else Fail
  }
  lemma AtomsElemsRT(xs: seq<Atom>, m: seq<Tok>)
    ensures DecAtomsElems(EncAtomsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncAtomsElems(xs[1..]);
      assert EncAtomsElems(xs) + m == EncAtom(xs[0]) + (rest + m);
      AtomRT(xs[0], rest + m);
      AtomsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecAtom(EncAtom(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecAtomsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncAtomsElems(xs) == [];
      assert EncAtomsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecAtomsElems(m, 0) == Ok([], m);
    }
  }
  lemma AtomsRT(xs: seq<Atom>, m: seq<Tok>)
    ensures DecAtoms(EncAtoms(xs) + m) == Ok(xs, m)
  {
    AtomsElemsRT(xs, m);
    assert EncAtoms(xs) + m == [TI(|xs|)] + (EncAtomsElems(xs) + m);
  }

  function EncV(v: V): seq<Tok> {
    match v
    case VQ(q) => [TKw(330)] + EncQ(q)
    case VS(s) => [TKw(331)] + EncStr(s)
    case VSet(items) => [TKw(332)] + EncAtoms(items)
  }
  function DecV(ts: seq<Tok>): PR<V> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 330 then (match DecQ(ts[1..]) case Ok(q, r) => Ok(VQ(q), r) case Fail => Fail)
    else if ts[0].k == 331 then (match DecStr(ts[1..]) case Ok(s, r) => Ok(VS(s), r) case Fail => Fail)
    else if ts[0].k == 332 then (match DecAtoms(ts[1..]) case Ok(xs, r) => Ok(VSet(xs), r) case Fail => Fail)
    else Fail
  }
  lemma VRT(v: V, m: seq<Tok>) ensures DecV(EncV(v) + m) == Ok(v, m) {
    match v
    case VQ(q) => assert EncV(v) + m == [TKw(330)] + (EncQ(q) + m); QRT(q, m);
    case VS(s) => assert EncV(v) + m == [TKw(331)] + (EncStr(s) + m); StrRT(s, m);
    case VSet(items) => assert EncV(v) + m == [TKw(332)] + (EncAtoms(items) + m); AtomsRT(items, m);
  }

  // ------------------------------------------------------------------ terms, operators, conditions
  function EncTerm(t: Term): seq<Tok> {
    match t
    case Param(p, ty) => [TKw(340)] + (EncStr(p) + EncTy(ty))
    case Lit(v) => [TKw(341)] + EncV(v)
    case HistAgg(b, u) => [TKw(342)] + (EncStr(b) + EncUnit(u))
  }
  function DecTerm(ts: seq<Tok>): PR<Term> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 340 then
      (match DecStr(ts[1..]) case Fail => Fail case Ok(p, r1) =>
        (match DecTy(r1) case Fail => Fail case Ok(ty, r2) => Ok(Param(p, ty), r2)))
    else if ts[0].k == 341 then (match DecV(ts[1..]) case Ok(v, r) => Ok(Lit(v), r) case Fail => Fail)
    else if ts[0].k == 342 then
      (match DecStr(ts[1..]) case Fail => Fail case Ok(b, r1) =>
        (match DecUnit(r1) case Fail => Fail case Ok(u, r2) => Ok(HistAgg(b, u), r2)))
    else Fail
  }
  lemma TermRT(t: Term, m: seq<Tok>) ensures DecTerm(EncTerm(t) + m) == Ok(t, m) {
    match t
    case Param(p, ty) =>
      assert EncTerm(t) + m == [TKw(340)] + (EncStr(p) + (EncTy(ty) + m));
      StrRT(p, EncTy(ty) + m); TyRT(ty, m);
    case Lit(v) => assert EncTerm(t) + m == [TKw(341)] + (EncV(v) + m); VRT(v, m);
    case HistAgg(b, u) =>
      assert EncTerm(t) + m == [TKw(342)] + (EncStr(b) + (EncUnit(u) + m));
      StrRT(b, EncUnit(u) + m); UnitRT(u, m);
  }

  function OpIdx(op: Op): int {
    match op case Eq => 0 case Ne => 1 case Lt => 2 case Lte => 3 case Gt => 4 case Gte => 5 case In => 6 case Nin => 7
  }
  function EncOp(op: Op): seq<Tok> { [TKw(350 + OpIdx(op))] }
  function DecOp(ts: seq<Tok>): PR<Op> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 350 then Ok(Eq, ts[1..])
    else if ts[0].k == 351 then Ok(Ne, ts[1..])
    else if ts[0].k == 352 then Ok(Lt, ts[1..])
    else if ts[0].k == 353 then Ok(Lte, ts[1..])
    else if ts[0].k == 354 then Ok(Gt, ts[1..])
    else if ts[0].k == 355 then Ok(Gte, ts[1..])
    else if ts[0].k == 356 then Ok(In, ts[1..])
    else if ts[0].k == 357 then Ok(Nin, ts[1..])
    else Fail
  }
  lemma OpRT(op: Op, m: seq<Tok>) ensures DecOp(EncOp(op) + m) == Ok(op, m) {
    match op
    case Eq =>
    case Ne =>
    case Lt =>
    case Lte =>
    case Gt =>
    case Gte =>
    case In =>
    case Nin =>
  }

  function EncCond(c: Cond): seq<Tok> decreases c {
    match c
    case CTrue => [TKw(360)]
    case Cmp(op, l, r) => [TKw(361)] + (EncOp(op) + (EncTerm(l) + EncTerm(r)))
    case And(x, y) => [TKw(362)] + (EncCond(x) + EncCond(y))
    case Or(x, y) => [TKw(363)] + (EncCond(x) + EncCond(y))
    case Not(x) => [TKw(364)] + EncCond(x)
  }
  // fuel = the remaining token count: every node consumes at least one token, so the depth of a condition never exceeds it
  function DecCond(ts: seq<Tok>, fuel: nat): PR<Cond> decreases fuel {
    if fuel == 0 || |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 360 then Ok(CTrue, ts[1..])
    else if ts[0].k == 361 then
      (match DecOp(ts[1..]) case Fail => Fail case Ok(op, r1) =>
        (match DecTerm(r1) case Fail => Fail case Ok(l, r2) =>
          (match DecTerm(r2) case Fail => Fail case Ok(r, r3) => Ok(Cmp(op, l, r), r3))))
    else if ts[0].k == 362 then
      (match DecCond(ts[1..], fuel - 1) case Fail => Fail case Ok(x, r1) =>
        (match DecCond(r1, fuel - 1) case Fail => Fail case Ok(y, r2) => Ok(And(x, y), r2)))
    else if ts[0].k == 363 then
      (match DecCond(ts[1..], fuel - 1) case Fail => Fail case Ok(x, r1) =>
        (match DecCond(r1, fuel - 1) case Fail => Fail case Ok(y, r2) => Ok(Or(x, y), r2)))
    else if ts[0].k == 364 then (match DecCond(ts[1..], fuel - 1) case Ok(x, r) => Ok(Not(x), r) case Fail => Fail)
    else Fail
  }
  function DecCondTop(ts: seq<Tok>): PR<Cond> { DecCond(ts, |ts|) }
  function Depth(c: Cond): nat decreases c {
    match c
    case CTrue => 1
    case Cmp(_, _, _) => 1
    case And(x, y) => 1 + (if Depth(x) >= Depth(y) then Depth(x) else Depth(y))
    case Or(x, y) => 1 + (if Depth(x) >= Depth(y) then Depth(x) else Depth(y))
    case Not(x) => 1 + Depth(x)
  }
  lemma LenGeDepth(c: Cond) ensures |EncCond(c)| >= Depth(c) decreases c {
    match c
    case CTrue =>
    case Cmp(_, _, _) =>
    case And(x, y) => LenGeDepth(x); LenGeDepth(y);
    case Or(x, y) => LenGeDepth(x); LenGeDepth(y);
    case Not(x) => LenGeDepth(x);
  }
  lemma CondRT(c: Cond, m: seq<Tok>, fuel: nat)
    requires fuel >= Depth(c)
    ensures DecCond(EncCond(c) + m, fuel) == Ok(c, m)
    decreases c
  {
    match c
    case CTrue =>
    case Cmp(op, l, r) =>
      assert EncCond(c) + m == [TKw(361)] + (EncOp(op) + (EncTerm(l) + (EncTerm(r) + m)));
      OpRT(op, EncTerm(l) + (EncTerm(r) + m));
      TermRT(l, EncTerm(r) + m);
      TermRT(r, m);
    case And(x, y) =>
      assert EncCond(c) + m == [TKw(362)] + (EncCond(x) + (EncCond(y) + m));
      CondRT(x, EncCond(y) + m, fuel - 1);
      CondRT(y, m, fuel - 1);
    case Or(x, y) =>
      assert EncCond(c) + m == [TKw(363)] + (EncCond(x) + (EncCond(y) + m));
      CondRT(x, EncCond(y) + m, fuel - 1);
      CondRT(y, m, fuel - 1);
    case Not(x) =>
      assert EncCond(c) + m == [TKw(364)] + (EncCond(x) + m);
      CondRT(x, m, fuel - 1);
  }
  lemma CondTopRT(c: Cond, m: seq<Tok>) ensures DecCondTop(EncCond(c) + m) == Ok(c, m) {
    LenGeDepth(c);
    CondRT(c, m, |EncCond(c) + m|);
  }

  // ------------------------------------------------------------------ clauses
  function EncPart(p: ResPart): seq<Tok> {
    match p
    case PartExact(id) => [TKw(375)] + EncStr(id)
    case PartOneOf(ids) => [TKw(376)] + EncStrs(ids)
    case PartRelated(rel, anchor) => [TKw(377)] + (EncStr(rel) + EncStr(anchor))
  }
  function DecPart(ts: seq<Tok>): PR<ResPart> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 375 then (match DecStr(ts[1..]) case Ok(id, r) => Ok(PartExact(id), r) case Fail => Fail)
    else if ts[0].k == 376 then (match DecStrs(ts[1..]) case Ok(ids, r) => Ok(PartOneOf(ids), r) case Fail => Fail)
    else if ts[0].k == 377 then
      (match DecStr(ts[1..]) case Fail => Fail case Ok(rel, r1) =>
        (match DecStr(r1) case Fail => Fail case Ok(anchor, r2) => Ok(PartRelated(rel, anchor), r2)))
    else Fail
  }
  lemma PartRT(p: ResPart, m: seq<Tok>) ensures DecPart(EncPart(p) + m) == Ok(p, m) {
    match p
    case PartExact(id) => assert EncPart(p) + m == [TKw(375)] + (EncStr(id) + m); StrRT(id, m);
    case PartOneOf(ids) => assert EncPart(p) + m == [TKw(376)] + (EncStrs(ids) + m); StrsRT(ids, m);
    case PartRelated(rel, anchor) =>
      assert EncPart(p) + m == [TKw(377)] + (EncStr(rel) + (EncStr(anchor) + m));
      StrRT(rel, EncStr(anchor) + m); StrRT(anchor, m);
  }
  function EncPartsElems(xs: seq<ResPart>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncPart(xs[0]) + EncPartsElems(xs[1..])
  }
  function EncParts(xs: seq<ResPart>): seq<Tok> { [TI(|xs|)] + EncPartsElems(xs) }
  function DecPartsElems(ts: seq<Tok>, n: nat): PR<seq<ResPart>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecPart(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecPartsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecParts(ts: seq<Tok>): PR<seq<ResPart>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecPartsElems(ts[1..], ts[0].i) else Fail
  }
  lemma PartsElemsRT(xs: seq<ResPart>, m: seq<Tok>)
    ensures DecPartsElems(EncPartsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncPartsElems(xs[1..]);
      assert EncPartsElems(xs) + m == EncPart(xs[0]) + (rest + m);
      PartRT(xs[0], rest + m);
      PartsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecPart(EncPart(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecPartsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncPartsElems(xs) == [];
      assert EncPartsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecPartsElems(m, 0) == Ok([], m);
    }
  }
  lemma PartsRT(xs: seq<ResPart>, m: seq<Tok>)
    ensures DecParts(EncParts(xs) + m) == Ok(xs, m)
  {
    PartsElemsRT(xs, m);
    assert EncParts(xs) + m == [TI(|xs|)] + (EncPartsElems(xs) + m);
  }

  function EncResSel(s: ResSel): seq<Tok> {
    match s
    case Exact(id) => [TKw(370)] + EncStr(id)
    case OneOf(ids) => [TKw(371)] + EncStrs(ids)
    case Related(rel, anchor) => [TKw(372)] + (EncStr(rel) + EncStr(anchor))
    case AnyRes(reason) => [TKw(373)] + EncStr(reason)
    case AllOf(ps) => [TKw(374)] + EncParts(ps)
  }
  function DecResSel(ts: seq<Tok>): PR<ResSel> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 370 then (match DecStr(ts[1..]) case Ok(id, r) => Ok(Exact(id), r) case Fail => Fail)
    else if ts[0].k == 371 then (match DecStrs(ts[1..]) case Ok(ids, r) => Ok(OneOf(ids), r) case Fail => Fail)
    else if ts[0].k == 372 then
      (match DecStr(ts[1..]) case Fail => Fail case Ok(rel, r1) =>
        (match DecStr(r1) case Fail => Fail case Ok(anchor, r2) => Ok(Related(rel, anchor), r2)))
    else if ts[0].k == 373 then (match DecStr(ts[1..]) case Ok(reason, r) => Ok(AnyRes(reason), r) case Fail => Fail)
    else if ts[0].k == 374 then (match DecParts(ts[1..]) case Ok(ps, r) => Ok(AllOf(ps), r) case Fail => Fail)
    else Fail
  }
  lemma ResSelRT(s: ResSel, m: seq<Tok>) ensures DecResSel(EncResSel(s) + m) == Ok(s, m) {
    match s
    case Exact(id) => assert EncResSel(s) + m == [TKw(370)] + (EncStr(id) + m); StrRT(id, m);
    case OneOf(ids) => assert EncResSel(s) + m == [TKw(371)] + (EncStrs(ids) + m); StrsRT(ids, m);
    case Related(rel, anchor) =>
      assert EncResSel(s) + m == [TKw(372)] + (EncStr(rel) + (EncStr(anchor) + m));
      StrRT(rel, EncStr(anchor) + m); StrRT(anchor, m);
    case AnyRes(reason) => assert EncResSel(s) + m == [TKw(373)] + (EncStr(reason) + m); StrRT(reason, m);
    case AllOf(ps) => assert EncResSel(s) + m == [TKw(374)] + (EncParts(ps) + m); PartsRT(ps, m);
  }

  function EncGrant(g: Grant): seq<Tok> {
    [TKw(380)] + (EncStr(g.gid) + (EncStr(g.verb) + (EncResSel(g.res) + EncCond(g.cond))))
  }
  function DecGrant(ts: seq<Tok>): PR<Grant> {
    if |ts| == 0 || ts[0] != TKw(380) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(gid, r1) =>
      (match DecStr(r1) case Fail => Fail case Ok(verb, r2) =>
       (match DecResSel(r2) case Fail => Fail case Ok(res, r3) =>
        (match DecCondTop(r3) case Fail => Fail case Ok(c, r4) => Ok(Grant(gid, verb, res, c), r4))))
  }
  lemma GrantRT(g: Grant, m: seq<Tok>) ensures DecGrant(EncGrant(g) + m) == Ok(g, m) {
    assert EncGrant(g) + m == [TKw(380)] + (EncStr(g.gid) + (EncStr(g.verb) + (EncResSel(g.res) + (EncCond(g.cond) + m))));
    StrRT(g.gid, EncStr(g.verb) + (EncResSel(g.res) + (EncCond(g.cond) + m)));
    StrRT(g.verb, EncResSel(g.res) + (EncCond(g.cond) + m));
    ResSelRT(g.res, EncCond(g.cond) + m);
    CondTopRT(g.cond, m);
  }

  function EncProhTarget(t: ProhTarget): seq<Tok> {
    match t case PVerb(v) => [TKw(390)] + EncStr(v) case PEffect(c) => [TKw(391)] + EncStr(c)
  }
  function DecProhTarget(ts: seq<Tok>): PR<ProhTarget> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 390 then (match DecStr(ts[1..]) case Ok(v, r) => Ok(PVerb(v), r) case Fail => Fail)
    else if ts[0].k == 391 then (match DecStr(ts[1..]) case Ok(c, r) => Ok(PEffect(c), r) case Fail => Fail)
    else Fail
  }
  lemma ProhTargetRT(t: ProhTarget, m: seq<Tok>) ensures DecProhTarget(EncProhTarget(t) + m) == Ok(t, m) {
    match t
    case PVerb(v) => assert EncProhTarget(t) + m == [TKw(390)] + (EncStr(v) + m); StrRT(v, m);
    case PEffect(c) => assert EncProhTarget(t) + m == [TKw(391)] + (EncStr(c) + m); StrRT(c, m);
  }
  function EncProhibit(p: Prohibit): seq<Tok> {
    [TKw(392)] + (EncStr(p.pid) + (EncProhTarget(p.target) + (EncResSel(p.res) + EncCond(p.cond))))
  }
  function DecProhibit(ts: seq<Tok>): PR<Prohibit> {
    if |ts| == 0 || ts[0] != TKw(392) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(pid, r1) =>
      (match DecProhTarget(r1) case Fail => Fail case Ok(tg, r2) =>
       (match DecResSel(r2) case Fail => Fail case Ok(res, r3) =>
        (match DecCondTop(r3) case Fail => Fail case Ok(c, r4) => Ok(Prohibit(pid, tg, res, c), r4))))
  }
  lemma ProhibitRT(p: Prohibit, m: seq<Tok>) ensures DecProhibit(EncProhibit(p) + m) == Ok(p, m) {
    assert EncProhibit(p) + m == [TKw(392)] + (EncStr(p.pid) + (EncProhTarget(p.target) + (EncResSel(p.res) + (EncCond(p.cond) + m))));
    StrRT(p.pid, EncProhTarget(p.target) + (EncResSel(p.res) + (EncCond(p.cond) + m)));
    ProhTargetRT(p.target, EncResSel(p.res) + (EncCond(p.cond) + m));
    ResSelRT(p.res, EncCond(p.cond) + m);
    CondTopRT(p.cond, m);
  }

  // aggregates, selections, windows, scopes, exceed actions
  function EncAgg(a: Agg): seq<Tok> { match a case ACount => [TKw(400)] case ASum => [TKw(401)] case AMax => [TKw(402)] case ADistinct => [TKw(403)] }
  function DecAgg(ts: seq<Tok>): PR<Agg> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 400 then Ok(ACount, ts[1..])
    else if ts[0].k == 401 then Ok(ASum, ts[1..])
    else if ts[0].k == 402 then Ok(AMax, ts[1..])
    else if ts[0].k == 403 then Ok(ADistinct, ts[1..])
    else Fail
  }
  lemma AggRT(a: Agg, m: seq<Tok>) ensures DecAgg(EncAgg(a) + m) == Ok(a, m) {
    match a
    case ACount =>
    case ASum =>
    case AMax =>
    case ADistinct =>
  }
  function EncSel(s: Sel): seq<Tok> { match s case SelGids(g) => [TKw(410)] + EncStrs(g) case SelEffect(c) => [TKw(411)] + EncStr(c) }
  function DecSel(ts: seq<Tok>): PR<Sel> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 410 then (match DecStrs(ts[1..]) case Ok(g, r) => Ok(SelGids(g), r) case Fail => Fail)
    else if ts[0].k == 411 then (match DecStr(ts[1..]) case Ok(c, r) => Ok(SelEffect(c), r) case Fail => Fail)
    else Fail
  }
  lemma SelRT(s: Sel, m: seq<Tok>) ensures DecSel(EncSel(s) + m) == Ok(s, m) {
    match s
    case SelGids(g) => assert EncSel(s) + m == [TKw(410)] + (EncStrs(g) + m); StrsRT(g, m);
    case SelEffect(c) => assert EncSel(s) + m == [TKw(411)] + (EncStr(c) + m); StrRT(c, m);
  }
  function EncWindow(w: Window): seq<Tok> {
    match w
    case WTask => [TKw(420)]
    case WSliding(ms) => [TKw(421)] + EncInt(ms)
    case WPeriod(ms, t0) => [TKw(422)] + (EncInt(ms) + EncInt(t0))
    case WLifetime => [TKw(423)]
  }
  function DecWindow(ts: seq<Tok>): PR<Window> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 420 then Ok(WTask, ts[1..])
    else if ts[0].k == 421 then (match DecInt(ts[1..]) case Ok(ms, r) => Ok(WSliding(ms), r) case Fail => Fail)
    else if ts[0].k == 422 then
      (match DecInt(ts[1..]) case Fail => Fail case Ok(ms, r1) =>
        (match DecInt(r1) case Fail => Fail case Ok(t0, r2) => Ok(WPeriod(ms, t0), r2)))
    else if ts[0].k == 423 then Ok(WLifetime, ts[1..])
    else Fail
  }
  lemma WindowRT(w: Window, m: seq<Tok>) ensures DecWindow(EncWindow(w) + m) == Ok(w, m) {
    match w
    case WTask =>
    case WSliding(ms) => assert EncWindow(w) + m == [TKw(421)] + (EncInt(ms) + m); IntRT(ms, m);
    case WPeriod(ms, t0) =>
      assert EncWindow(w) + m == [TKw(422)] + (EncInt(ms) + (EncInt(t0) + m));
      IntRT(ms, EncInt(t0) + m); IntRT(t0, m);
    case WLifetime =>
  }
  function EncScope(s: Scope): seq<Tok> {
    match s case SSession => [TKw(430)] case SPrincipal => [TKw(431)] case SOrg => [TKw(432)] case SFleet(a) => [TKw(433)] + EncStrs(a)
  }
  function DecScope(ts: seq<Tok>): PR<Scope> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 430 then Ok(SSession, ts[1..])
    else if ts[0].k == 431 then Ok(SPrincipal, ts[1..])
    else if ts[0].k == 432 then Ok(SOrg, ts[1..])
    else if ts[0].k == 433 then (match DecStrs(ts[1..]) case Ok(a, r) => Ok(SFleet(a), r) case Fail => Fail)
    else Fail
  }
  lemma ScopeRT(s: Scope, m: seq<Tok>) ensures DecScope(EncScope(s) + m) == Ok(s, m) {
    match s
    case SSession =>
    case SPrincipal =>
    case SOrg =>
    case SFleet(a) => assert EncScope(s) + m == [TKw(433)] + (EncStrs(a) + m); StrsRT(a, m);
  }
  function EncOnExceed(o: OnExceed): seq<Tok> { match o case OnDeny => [TKw(440)] case OnEscalate => [TKw(441)] }
  function DecOnExceed(ts: seq<Tok>): PR<OnExceed> {
    if |ts| == 0 || !ts[0].TKw? then Fail
    else if ts[0].k == 440 then Ok(OnDeny, ts[1..])
    else if ts[0].k == 441 then Ok(OnEscalate, ts[1..])
    else Fail
  }
  lemma OnExceedRT(o: OnExceed, m: seq<Tok>) ensures DecOnExceed(EncOnExceed(o) + m) == Ok(o, m) {
    match o
    case OnDeny =>
    case OnEscalate =>
  }

  function EncBCore(b: BCore): seq<Tok> {
    [TKw(450)] + (EncAgg(b.agg) + (EncTerm(b.value) + (EncStr(b.key) + (EncWindow(b.window) + (EncScope(b.scope) + (EncQ(b.cap) + EncOnExceed(b.onExceed)))))))
  }
  function DecBCore(ts: seq<Tok>): PR<BCore> {
    if |ts| == 0 || ts[0] != TKw(450) then Fail
    else
      match DecAgg(ts[1..]) case Fail => Fail case Ok(agg, r1) =>
      (match DecTerm(r1) case Fail => Fail case Ok(value, r2) =>
       (match DecStr(r2) case Fail => Fail case Ok(key, r3) =>
        (match DecWindow(r3) case Fail => Fail case Ok(window, r4) =>
         (match DecScope(r4) case Fail => Fail case Ok(scope, r5) =>
          (match DecQ(r5) case Fail => Fail case Ok(cap, r6) =>
           (match DecOnExceed(r6) case Fail => Fail case Ok(oe, r7) => Ok(BCore(agg, value, key, window, scope, cap, oe), r7)))))))
  }
  lemma BCoreRT(b: BCore, m: seq<Tok>) ensures DecBCore(EncBCore(b) + m) == Ok(b, m) {
    assert EncBCore(b) + m == [TKw(450)] + (EncAgg(b.agg) + (EncTerm(b.value) + (EncStr(b.key) + (EncWindow(b.window) + (EncScope(b.scope) + (EncQ(b.cap) + (EncOnExceed(b.onExceed) + m)))))));
    AggRT(b.agg, EncTerm(b.value) + (EncStr(b.key) + (EncWindow(b.window) + (EncScope(b.scope) + (EncQ(b.cap) + (EncOnExceed(b.onExceed) + m))))));
    TermRT(b.value, EncStr(b.key) + (EncWindow(b.window) + (EncScope(b.scope) + (EncQ(b.cap) + (EncOnExceed(b.onExceed) + m)))));
    StrRT(b.key, EncWindow(b.window) + (EncScope(b.scope) + (EncQ(b.cap) + (EncOnExceed(b.onExceed) + m))));
    WindowRT(b.window, EncScope(b.scope) + (EncQ(b.cap) + (EncOnExceed(b.onExceed) + m)));
    ScopeRT(b.scope, EncQ(b.cap) + (EncOnExceed(b.onExceed) + m));
    QRT(b.cap, EncOnExceed(b.onExceed) + m);
    OnExceedRT(b.onExceed, m);
  }
  function EncBound(b: Bound): seq<Tok> { [TKw(451)] + (EncStr(b.bid) + (EncSel(b.sel) + EncBCore(b.core))) }
  function DecBound(ts: seq<Tok>): PR<Bound> {
    if |ts| == 0 || ts[0] != TKw(451) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(bid, r1) =>
      (match DecSel(r1) case Fail => Fail case Ok(sel, r2) =>
       (match DecBCore(r2) case Fail => Fail case Ok(core, r3) => Ok(Bound(bid, sel, core), r3)))
  }
  lemma BoundRT(b: Bound, m: seq<Tok>) ensures DecBound(EncBound(b) + m) == Ok(b, m) {
    assert EncBound(b) + m == [TKw(451)] + (EncStr(b.bid) + (EncSel(b.sel) + (EncBCore(b.core) + m)));
    StrRT(b.bid, EncSel(b.sel) + (EncBCore(b.core) + m));
    SelRT(b.sel, EncBCore(b.core) + m);
    BCoreRT(b.core, m);
  }

  function EncValidity(v: Validity): seq<Tok> { [TKw(460)] + (EncInt(v.notBefore) + (EncInt(v.notAfter) + EncInt(v.maxIdle))) }
  function DecValidity(ts: seq<Tok>): PR<Validity> {
    if |ts| == 0 || ts[0] != TKw(460) then Fail
    else
      match DecInt(ts[1..]) case Fail => Fail case Ok(nb, r1) =>
      (match DecInt(r1) case Fail => Fail case Ok(na, r2) =>
       (match DecInt(r2) case Fail => Fail case Ok(mi, r3) => Ok(Validity(nb, na, mi), r3)))
  }
  lemma ValidityRT(v: Validity, m: seq<Tok>) ensures DecValidity(EncValidity(v) + m) == Ok(v, m) {
    assert EncValidity(v) + m == [TKw(460)] + (EncInt(v.notBefore) + (EncInt(v.notAfter) + (EncInt(v.maxIdle) + m)));
    IntRT(v.notBefore, EncInt(v.notAfter) + (EncInt(v.maxIdle) + m));
    IntRT(v.notAfter, EncInt(v.maxIdle) + m);
    IntRT(v.maxIdle, m);
  }
  function EncDeleg(d: Delegation): seq<Tok> { [TKw(461)] + (EncInt(d.maxDepth) + (EncBool(d.narrowOnly) + EncStrs(d.mayTouch))) }
  function DecDeleg(ts: seq<Tok>): PR<Delegation> {
    if |ts| == 0 || ts[0] != TKw(461) then Fail
    else
      match DecInt(ts[1..]) case Fail => Fail case Ok(md, r1) =>
      (match DecBool(r1) case Fail => Fail case Ok(no, r2) =>
       (match DecStrs(r2) case Fail => Fail case Ok(mt, r3) => Ok(Delegation(md, no, mt), r3)))
  }
  lemma DelegRT(d: Delegation, m: seq<Tok>) ensures DecDeleg(EncDeleg(d) + m) == Ok(d, m) {
    assert EncDeleg(d) + m == [TKw(461)] + (EncInt(d.maxDepth) + (EncBool(d.narrowOnly) + (EncStrs(d.mayTouch) + m)));
    IntRT(d.maxDepth, EncBool(d.narrowOnly) + (EncStrs(d.mayTouch) + m));
    BoolRT(d.narrowOnly, EncStrs(d.mayTouch) + m);
    StrsRT(d.mayTouch, m);
  }
  function EncHole(h: Hole): seq<Tok> {
    [TKw(470)] + (EncStr(h.hid) + (EncStr(h.q) + (EncStrs(h.domain) + (EncStrs(h.affects) + EncBool(h.global)))))
  }
  function DecHole(ts: seq<Tok>): PR<Hole> {
    if |ts| == 0 || ts[0] != TKw(470) then Fail
    else
      match DecStr(ts[1..]) case Fail => Fail case Ok(hid, r1) =>
      (match DecStr(r1) case Fail => Fail case Ok(q, r2) =>
       (match DecStrs(r2) case Fail => Fail case Ok(dom, r3) =>
        (match DecStrs(r3) case Fail => Fail case Ok(aff, r4) =>
         (match DecBool(r4) case Fail => Fail case Ok(gl, r5) => Ok(Hole(hid, q, dom, aff, gl), r5)))))
  }
  lemma HoleRT(h: Hole, m: seq<Tok>) ensures DecHole(EncHole(h) + m) == Ok(h, m) {
    assert EncHole(h) + m == [TKw(470)] + (EncStr(h.hid) + (EncStr(h.q) + (EncStrs(h.domain) + (EncStrs(h.affects) + (EncBool(h.global) + m)))));
    StrRT(h.hid, EncStr(h.q) + (EncStrs(h.domain) + (EncStrs(h.affects) + (EncBool(h.global) + m))));
    StrRT(h.q, EncStrs(h.domain) + (EncStrs(h.affects) + (EncBool(h.global) + m)));
    StrsRT(h.domain, EncStrs(h.affects) + (EncBool(h.global) + m));
    StrsRT(h.affects, EncBool(h.global) + m);
    BoolRT(h.global, m);
  }

  function EncStrsElems(xs: seq<string>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncStr(xs[0]) + EncStrsElems(xs[1..])
  }
  function EncStrs(xs: seq<string>): seq<Tok> { [TI(|xs|)] + EncStrsElems(xs) }
  function DecStrsElems(ts: seq<Tok>, n: nat): PR<seq<string>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecStr(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecStrsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecStrs(ts: seq<Tok>): PR<seq<string>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecStrsElems(ts[1..], ts[0].i) else Fail
  }
  lemma StrsElemsRT(xs: seq<string>, m: seq<Tok>)
    ensures DecStrsElems(EncStrsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncStrsElems(xs[1..]);
      assert EncStrsElems(xs) + m == EncStr(xs[0]) + (rest + m);
      StrRT(xs[0], rest + m);
      StrsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecStr(EncStr(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecStrsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncStrsElems(xs) == [];
      assert EncStrsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecStrsElems(m, 0) == Ok([], m);
    }
  }
  lemma StrsRT(xs: seq<string>, m: seq<Tok>)
    ensures DecStrs(EncStrs(xs) + m) == Ok(xs, m)
  {
    StrsElemsRT(xs, m);
    assert EncStrs(xs) + m == [TI(|xs|)] + (EncStrsElems(xs) + m);
  }
  function EncGrantsElems(xs: seq<Grant>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncGrant(xs[0]) + EncGrantsElems(xs[1..])
  }
  function EncGrants(xs: seq<Grant>): seq<Tok> { [TI(|xs|)] + EncGrantsElems(xs) }
  function DecGrantsElems(ts: seq<Tok>, n: nat): PR<seq<Grant>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecGrant(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecGrantsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecGrants(ts: seq<Tok>): PR<seq<Grant>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecGrantsElems(ts[1..], ts[0].i) else Fail
  }
  lemma GrantsElemsRT(xs: seq<Grant>, m: seq<Tok>)
    ensures DecGrantsElems(EncGrantsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncGrantsElems(xs[1..]);
      assert EncGrantsElems(xs) + m == EncGrant(xs[0]) + (rest + m);
      GrantRT(xs[0], rest + m);
      GrantsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecGrant(EncGrant(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecGrantsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncGrantsElems(xs) == [];
      assert EncGrantsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecGrantsElems(m, 0) == Ok([], m);
    }
  }
  lemma GrantsRT(xs: seq<Grant>, m: seq<Tok>)
    ensures DecGrants(EncGrants(xs) + m) == Ok(xs, m)
  {
    GrantsElemsRT(xs, m);
    assert EncGrants(xs) + m == [TI(|xs|)] + (EncGrantsElems(xs) + m);
  }
  function EncProhibitsElems(xs: seq<Prohibit>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncProhibit(xs[0]) + EncProhibitsElems(xs[1..])
  }
  function EncProhibits(xs: seq<Prohibit>): seq<Tok> { [TI(|xs|)] + EncProhibitsElems(xs) }
  function DecProhibitsElems(ts: seq<Tok>, n: nat): PR<seq<Prohibit>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecProhibit(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecProhibitsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecProhibits(ts: seq<Tok>): PR<seq<Prohibit>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecProhibitsElems(ts[1..], ts[0].i) else Fail
  }
  lemma ProhibitsElemsRT(xs: seq<Prohibit>, m: seq<Tok>)
    ensures DecProhibitsElems(EncProhibitsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncProhibitsElems(xs[1..]);
      assert EncProhibitsElems(xs) + m == EncProhibit(xs[0]) + (rest + m);
      ProhibitRT(xs[0], rest + m);
      ProhibitsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecProhibit(EncProhibit(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecProhibitsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncProhibitsElems(xs) == [];
      assert EncProhibitsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecProhibitsElems(m, 0) == Ok([], m);
    }
  }
  lemma ProhibitsRT(xs: seq<Prohibit>, m: seq<Tok>)
    ensures DecProhibits(EncProhibits(xs) + m) == Ok(xs, m)
  {
    ProhibitsElemsRT(xs, m);
    assert EncProhibits(xs) + m == [TI(|xs|)] + (EncProhibitsElems(xs) + m);
  }
  function EncBoundsElems(xs: seq<Bound>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncBound(xs[0]) + EncBoundsElems(xs[1..])
  }
  function EncBounds(xs: seq<Bound>): seq<Tok> { [TI(|xs|)] + EncBoundsElems(xs) }
  function DecBoundsElems(ts: seq<Tok>, n: nat): PR<seq<Bound>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecBound(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecBoundsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecBounds(ts: seq<Tok>): PR<seq<Bound>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecBoundsElems(ts[1..], ts[0].i) else Fail
  }
  lemma BoundsElemsRT(xs: seq<Bound>, m: seq<Tok>)
    ensures DecBoundsElems(EncBoundsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncBoundsElems(xs[1..]);
      assert EncBoundsElems(xs) + m == EncBound(xs[0]) + (rest + m);
      BoundRT(xs[0], rest + m);
      BoundsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecBound(EncBound(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecBoundsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncBoundsElems(xs) == [];
      assert EncBoundsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecBoundsElems(m, 0) == Ok([], m);
    }
  }
  lemma BoundsRT(xs: seq<Bound>, m: seq<Tok>)
    ensures DecBounds(EncBounds(xs) + m) == Ok(xs, m)
  {
    BoundsElemsRT(xs, m);
    assert EncBounds(xs) + m == [TI(|xs|)] + (EncBoundsElems(xs) + m);
  }
  function EncCondsElems(xs: seq<Cond>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncCond(xs[0]) + EncCondsElems(xs[1..])
  }
  function EncConds(xs: seq<Cond>): seq<Tok> { [TI(|xs|)] + EncCondsElems(xs) }
  function DecCondsElems(ts: seq<Tok>, n: nat): PR<seq<Cond>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecCondTop(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecCondsElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecConds(ts: seq<Tok>): PR<seq<Cond>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecCondsElems(ts[1..], ts[0].i) else Fail
  }
  lemma CondsElemsRT(xs: seq<Cond>, m: seq<Tok>)
    ensures DecCondsElems(EncCondsElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncCondsElems(xs[1..]);
      assert EncCondsElems(xs) + m == EncCond(xs[0]) + (rest + m);
      CondTopRT(xs[0], rest + m);
      CondsElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecCondTop(EncCond(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecCondsElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncCondsElems(xs) == [];
      assert EncCondsElems(xs) + m == m;
      assert |xs| == 0;
      assert DecCondsElems(m, 0) == Ok([], m);
    }
  }
  lemma CondsRT(xs: seq<Cond>, m: seq<Tok>)
    ensures DecConds(EncConds(xs) + m) == Ok(xs, m)
  {
    CondsElemsRT(xs, m);
    assert EncConds(xs) + m == [TI(|xs|)] + (EncCondsElems(xs) + m);
  }
  function EncHolesElems(xs: seq<Hole>): seq<Tok> decreases xs {
    if |xs| == 0 then [] else EncHole(xs[0]) + EncHolesElems(xs[1..])
  }
  function EncHoles(xs: seq<Hole>): seq<Tok> { [TI(|xs|)] + EncHolesElems(xs) }
  function DecHolesElems(ts: seq<Tok>, n: nat): PR<seq<Hole>> decreases n {
    if n == 0 then Ok([], ts)
    else
      match DecHole(ts)
      case Fail => Fail
      case Ok(x, r) =>
        (match DecHolesElems(r, n - 1) case Fail => Fail case Ok(xs, r2) => Ok([x] + xs, r2))
  }
  function DecHoles(ts: seq<Tok>): PR<seq<Hole>> {
    if |ts| > 0 && ts[0].TI? && ts[0].i >= 0 then DecHolesElems(ts[1..], ts[0].i) else Fail
  }
  lemma HolesElemsRT(xs: seq<Hole>, m: seq<Tok>)
    ensures DecHolesElems(EncHolesElems(xs) + m, |xs|) == Ok(xs, m)
    decreases xs
  {
    if |xs| > 0 {
      var rest := EncHolesElems(xs[1..]);
      assert EncHolesElems(xs) + m == EncHole(xs[0]) + (rest + m);
      HoleRT(xs[0], rest + m);
      HolesElemsRT(xs[1..], m);
      assert |xs[1..]| == |xs| - 1;
      assert xs == [xs[0]] + xs[1..];
      assert DecHole(EncHole(xs[0]) + (rest + m)) == Ok(xs[0], rest + m);
      assert DecHolesElems(rest + m, |xs| - 1) == Ok(xs[1..], m);
    } else {
      assert xs == [];
      assert EncHolesElems(xs) == [];
      assert EncHolesElems(xs) + m == m;
      assert |xs| == 0;
      assert DecHolesElems(m, 0) == Ok([], m);
    }
  }
  lemma HolesRT(xs: seq<Hole>, m: seq<Tok>)
    ensures DecHoles(EncHoles(xs) + m) == Ok(xs, m)
  {
    HolesElemsRT(xs, m);
    assert EncHoles(xs) + m == [TI(|xs|)] + (EncHolesElems(xs) + m);
  }

  // ------------------------------------------------------------------ the goal
  function EncGoal(g: Goal): seq<Tok> {
    [TKw(480), TI(g.v), TS(g.principal), TS(g.ontDigest), TS(g.nlDigest)]
    + (EncStrs(g.sources) + (EncGrants(g.grants) + (EncProhibits(g.prohibits) + (EncBounds(g.bounds) + (EncValidity(g.validity)
    + (EncDeleg(g.deleg) + (EncConds(g.escalateOn) + (EncStrs(g.wildcardAck) + EncHoles(g.holes)))))))))
  }
  function DecGoal(ts: seq<Tok>): PR<Goal> {
    if |ts| < 5 || ts[0] != TKw(480) || !ts[1].TI? || !ts[2].TS? || !ts[3].TS? || !ts[4].TS? then Fail
    else
      match DecStrs(ts[5..]) case Fail => Fail case Ok(sources, r1) =>
      (match DecGrants(r1) case Fail => Fail case Ok(grants, r2) =>
       (match DecProhibits(r2) case Fail => Fail case Ok(prohibits, r3) =>
        (match DecBounds(r3) case Fail => Fail case Ok(bounds, r4) =>
         (match DecValidity(r4) case Fail => Fail case Ok(validity, r5) =>
          (match DecDeleg(r5) case Fail => Fail case Ok(deleg, r6) =>
           (match DecConds(r6) case Fail => Fail case Ok(esc, r7) =>
            (match DecStrs(r7) case Fail => Fail case Ok(ack, r8) =>
             (match DecHoles(r8) case Fail => Fail case Ok(holes, r9) =>
              Ok(Goal(ts[1].i, ts[2].s, ts[3].s, ts[4].s, sources, grants, prohibits, bounds, validity, deleg, esc, ack, holes), r9)))))))))
  }
  lemma GoalRT(g: Goal, m: seq<Tok>) ensures DecGoal(EncGoal(g) + m) == Ok(g, m) {
    var t9 := EncHoles(g.holes) + m;
    var t8 := EncStrs(g.wildcardAck) + t9;
    var t7 := EncConds(g.escalateOn) + t8;
    var t6 := EncDeleg(g.deleg) + t7;
    var t5 := EncValidity(g.validity) + t6;
    var t4 := EncBounds(g.bounds) + t5;
    var t3 := EncProhibits(g.prohibits) + t4;
    var t2 := EncGrants(g.grants) + t3;
    var t1 := EncStrs(g.sources) + t2;
    assert EncGoal(g) + m == [TKw(480), TI(g.v), TS(g.principal), TS(g.ontDigest), TS(g.nlDigest)] + t1;
    assert ([TKw(480), TI(g.v), TS(g.principal), TS(g.ontDigest), TS(g.nlDigest)] + t1)[5..] == t1;
    StrsRT(g.sources, t2);
    GrantsRT(g.grants, t3);
    ProhibitsRT(g.prohibits, t4);
    BoundsRT(g.bounds, t5);
    ValidityRT(g.validity, t6);
    DelegRT(g.deleg, t7);
    CondsRT(g.escalateOn, t8);
    StrsRT(g.wildcardAck, t9);
    HolesRT(g.holes, m);
  }

  // G-T10: Render is the card, Parse reads it back; the round trip is the identity on every goal value, hence Render is injective.
  function Render(g: Goal): seq<Tok> { EncGoal(g) }
  function Parse(ts: seq<Tok>): Option<Goal> {
    match DecGoal(ts) case Ok(g, rest) => (if |rest| == 0 then Some(g) else None) case Fail => None
  }
  lemma RenderParse(g: Goal) ensures Parse(Render(g)) == Some(g) {
    assert EncGoal(g) + [] == EncGoal(g);
    GoalRT(g, []);
  }
  lemma RenderInjective(g1: Goal, g2: Goal)
    requires Render(g1) == Render(g2)
    ensures g1 == g2
  {
    RenderParse(g1);
    RenderParse(g2);
  }
}
