// Taint.dfy - information-flow taint rules of the PCA verifier (packages/pca/src/taint.ts and the gate in pcactn.ts).
// STANDALONE (no includes). No assume / axiom / extern. The registry and the resource graph are abstract: the glue evaluates their
// (total) answers and hands the facts in; the DECISIONS (label join, classification, fail-closed pre-checks, the gate) are proved here.
module Taint {
  datatype Option<T> = None | Some(v: T)

  // ---------------------------------------------------------------- the label lattice
  datatype Kind = Trusted | FirstParty | Tool | Web | Agent

  function Rank(k: Kind): int {
    match k
    case Trusted => 0
    case FirstParty => 1
    case Tool => 2
    case Web => 3
    case Agent => 4
  }
  const MaxRank: int := 4

  lemma RankInj(a: Kind, b: Kind) ensures Rank(a) == Rank(b) ==> a == b {}
  lemma RankBounds(k: Kind) ensures 0 <= Rank(k) <= MaxRank {}

  // taint.ts labelRank on a RAW kind string: the glue maps the kind with an OWN-property lookup over the five level names (so inherited keys
  // such as 'constructor', '__proto__', 'toString' are None). An unknown kind is the WORST rank: never undefined / NaN.
  function RawRank(k: Option<Kind>): int { if k.Some? then Rank(k.v) else MaxRank }
  lemma UnknownKindRanksWorst() ensures RawRank(None) == MaxRank {}
  lemma RawRankBounds(k: Option<Kind>) ensures 0 <= RawRank(k) <= MaxRank && (k.Some? ==> RawRank(k) == Rank(k.v)) {}

  // A label is a kind plus an optional explanatory id (ids are interned to nat by the adapter; only equality matters).
  datatype Label = Label(kind: Kind, id: Option<nat>)
  const Bottom: Label := Label(Trusted, None)
  const Top: Label := Label(Agent, None)

  // taint.ts joinLabel: higher rank wins; equal rank keeps the label when the ids agree, else collapses to the bare kind.
  function Join(a: Label, b: Label): Label {
    if Rank(a.kind) > Rank(b.kind) then a
    else if Rank(b.kind) > Rank(a.kind) then b
    else if a.id == b.id then a
    else Label(a.kind, None)
  }

  lemma JoinComm(a: Label, b: Label) ensures Join(a, b) == Join(b, a) { RankInj(a.kind, b.kind); }
  lemma JoinIdem(a: Label) ensures Join(a, a) == a {}
  lemma JoinAssoc(a: Label, b: Label, c: Label) ensures Join(Join(a, b), c) == Join(a, Join(b, c)) {
    RankInj(a.kind, b.kind); RankInj(b.kind, c.kind); RankInj(a.kind, c.kind);
  }
  // BOTTOM is the identity for every label that carries no id or is above the bottom rank (a Trusted label with an id collapses, see the notes).
  lemma BottomIdentity(x: Label)
    ensures x.kind != Trusted || x.id.None? ==> Join(Bottom, x) == x && Join(x, Bottom) == x
  { RankInj(x.kind, Trusted); }
  // TOP is absorbing for EVERY label.
  lemma TopAbsorbing(x: Label) ensures Join(Top, x) == Top && Join(x, Top) == Top { RankInj(x.kind, Agent); }
  // least upper bound w.r.t. rank
  lemma JoinLub(a: Label, b: Label)
    ensures Rank(Join(a, b).kind) == (if Rank(a.kind) >= Rank(b.kind) then Rank(a.kind) else Rank(b.kind))
    ensures Rank(a.kind) <= Rank(Join(a, b).kind) && Rank(b.kind) <= Rank(Join(a, b).kind)
    ensures forall u: Label :: Rank(a.kind) <= Rank(u.kind) && Rank(b.kind) <= Rank(u.kind) ==> Rank(Join(a, b).kind) <= Rank(u.kind)
  {}

  // ---------------------------------------------------------------- the seedless fold (joinLabels, non-empty)
  function JoinList(ls: seq<Label>): Label requires |ls| > 0 decreases |ls| {
    if |ls| == 1 then ls[0] else Join(JoinList(ls[..|ls| - 1]), ls[|ls| - 1])
  }
  // The empty lineage is the worst case, never "trusted".
  // Linear-time, tail-recursive (compiled to a loop) form of the same fold; the proofs are stated on JoinList and transferred by FoldEq.
  function {:tailrecursion} JoinFrom(acc: Label, ls: seq<Label>, i: nat): Label
    requires i <= |ls| decreases |ls| - i
  { if i == |ls| then acc else JoinFrom(Join(acc, ls[i]), ls, i + 1) }

  lemma FoldEq(ls: seq<Label>, i: nat)
    requires 1 <= i <= |ls|
    ensures JoinFrom(JoinList(ls[..i]), ls, i) == JoinList(ls)
    decreases |ls| - i
  {
    if i == |ls| { assert ls[..i] == ls; }
    else {
      assert ls[..i + 1][..i] == ls[..i];
      assert JoinList(ls[..i + 1]) == Join(JoinList(ls[..i]), ls[i]);
      FoldEq(ls, i + 1);
    }
  }

  function JoinOrTop(ls: seq<Label>): Label { if |ls| == 0 then Top else JoinFrom(ls[0], ls, 1) }

  lemma JoinOrTopEq(ls: seq<Label>) requires |ls| > 0 ensures JoinOrTop(ls) == JoinList(ls) {
    assert ls[..1] == [ls[0]];
    FoldEq(ls, 1);
  }

  // Order-free characterisation: L is THE join of a multiset iff its rank is the maximum, it is attained, and the id is the common id of
  // the max-rank elements when they agree (Some) and absent otherwise.
  ghost predicate IsJoin(ms: multiset<Label>, L: Label) {
    (forall x :: x in ms ==> Rank(x.kind) <= Rank(L.kind)) &&
    (exists x :: x in ms && x.kind == L.kind) &&
    (forall x :: x in ms && x.kind == L.kind && L.id.Some? ==> x.id == L.id) &&
    (L.id.None? ==> (forall x :: x in ms && x.kind == L.kind ==> x.id.None?) ||
                    (exists x, y :: x in ms && y in ms && x.kind == L.kind && y.kind == L.kind && x.id != y.id))
  }

  lemma IsJoinUnique(ms: multiset<Label>, L1: Label, L2: Label)
    requires IsJoin(ms, L1) && IsJoin(ms, L2)
    ensures L1 == L2
  {
    var w1 :| w1 in ms && w1.kind == L1.kind;
    var w2 :| w2 in ms && w2.kind == L2.kind;
    assert Rank(w1.kind) <= Rank(L2.kind);
    assert Rank(w2.kind) <= Rank(L1.kind);
    RankInj(L1.kind, L2.kind);
    assert L1.kind == L2.kind;
    if L1.id.Some? {
      assert w1.id == L1.id;
      if L2.id.None? {
        assert w2.id == L1.id;
        assert (forall x :: x in ms && x.kind == L2.kind ==> x.id.None?) ||
               (exists x, y :: x in ms && y in ms && x.kind == L2.kind && y.kind == L2.kind && x.id != y.id);
        if forall x :: x in ms && x.kind == L2.kind ==> x.id.None? { assert w1.id.None?; assert false; }
        else {
          var x, y :| x in ms && y in ms && x.kind == L2.kind && y.kind == L2.kind && x.id != y.id;
          assert x.id == L1.id && y.id == L1.id;
          assert false;
        }
      } else { assert w1.id == L2.id; }
    } else if L2.id.Some? {
      assert w2.id == L2.id;
      assert (forall x :: x in ms && x.kind == L1.kind ==> x.id.None?) ||
             (exists x, y :: x in ms && y in ms && x.kind == L1.kind && y.kind == L1.kind && x.id != y.id);
      if forall x :: x in ms && x.kind == L1.kind ==> x.id.None? { assert w2.id.None?; assert false; }
      else {
        var x, y :| x in ms && y in ms && x.kind == L1.kind && y.kind == L1.kind && x.id != y.id;
        assert x.id == L2.id && y.id == L2.id;
        assert false;
      }
    }
  }

  lemma JoinStep(ms: multiset<Label>, L: Label, x: Label)
    requires IsJoin(ms, L)
    ensures IsJoin(ms + multiset{x}, Join(L, x))
  {
    var J := Join(L, x);
    var ms2 := ms + multiset{x};
    var w :| w in ms && w.kind == L.kind;
    RankInj(L.kind, x.kind);
    if Rank(L.kind) > Rank(x.kind) {
      assert J == L;
      forall y | y in ms2 ensures Rank(y.kind) <= Rank(L.kind) { if y == x {} else { assert y in ms; } }
      assert w in ms2;
      forall y | y in ms2 && y.kind == L.kind && L.id.Some? ensures y.id == L.id { assert y != x; assert y in ms; }
      if L.id.None? {
        if forall y :: y in ms && y.kind == L.kind ==> y.id.None? {
          forall y | y in ms2 && y.kind == L.kind ensures y.id.None? { assert y != x; assert y in ms; }
        } else {
          var a, b :| a in ms && b in ms && a.kind == L.kind && b.kind == L.kind && a.id != b.id;
          assert a in ms2 && b in ms2;
        }
      }
    } else if Rank(x.kind) > Rank(L.kind) {
      assert J == x;
      forall y | y in ms2 ensures Rank(y.kind) <= Rank(x.kind) { if y == x {} else { assert y in ms; } }
      assert x in ms2;
      forall y | y in ms2 && y.kind == x.kind && x.id.Some? ensures y.id == x.id {
        if y != x { assert y in ms; assert Rank(y.kind) <= Rank(L.kind); assert false; }
      }
      if x.id.None? {
        forall y | y in ms2 && y.kind == x.kind ensures y.id.None? {
          if y != x { assert y in ms; assert Rank(y.kind) <= Rank(L.kind); assert false; }
        }
      }
    } else {
      assert x.kind == L.kind;
      forall y | y in ms2 ensures Rank(y.kind) <= Rank(J.kind) { if y == x {} else { assert y in ms; } }
      assert w in ms2;
      if L.id == x.id {
        assert J == L;
        forall y | y in ms2 && y.kind == L.kind && L.id.Some? ensures y.id == L.id { if y == x {} else { assert y in ms; } }
        if L.id.None? {
          if forall y :: y in ms && y.kind == L.kind ==> y.id.None? {
            forall y | y in ms2 && y.kind == L.kind ensures y.id.None? { if y == x {} else { assert y in ms; } }
          } else {
            var a, b :| a in ms && b in ms && a.kind == L.kind && b.kind == L.kind && a.id != b.id;
            assert a in ms2 && b in ms2;
          }
        }
      } else {
        assert J == Label(L.kind, None);
        assert x in ms2;
        forall y | y in ms2 && y.kind == J.kind && J.id.Some? ensures y.id == J.id {}
        // ids disagree: there is a witness pair
        if L.id.Some? {
          assert w.id == L.id;
          assert w in ms2 && x in ms2 && w.id != x.id;
        } else {
          assert x.id.Some?;
          if forall y :: y in ms && y.kind == L.kind ==> y.id.None? { assert w.id.None?; assert w in ms2 && x in ms2 && w.id != x.id; }
          else {
            var a, b :| a in ms && b in ms && a.kind == L.kind && b.kind == L.kind && a.id != b.id;
            assert a in ms2 && b in ms2;
          }
        }
      }
    }
  }

  lemma JoinListSpec(ls: seq<Label>)
    requires |ls| > 0
    ensures IsJoin(multiset(ls), JoinList(ls))
    decreases |ls|
  {
    if |ls| == 1 {
      var x := ls[0];
      assert multiset(ls) == multiset{x};
      assert x in multiset(ls);
    } else {
      var pre := ls[..|ls| - 1];
      JoinListSpec(pre);
      JoinStep(multiset(pre), JoinList(pre), ls[|ls| - 1]);
      assert ls == pre + [ls[|ls| - 1]];
      assert multiset(ls) == multiset(pre) + multiset{ls[|ls| - 1]};
    }
  }

  // ORDER INDEPENDENCE: any permutation of the lineage gives the identical label (ids included).
  lemma JoinListPerm(a: seq<Label>, b: seq<Label>)
    requires |a| > 0 && multiset(a) == multiset(b)
    ensures |b| > 0 && JoinList(a) == JoinList(b)
  {
    assert |a| == |b|;
    JoinListSpec(a); JoinListSpec(b);
    IsJoinUnique(multiset(a), JoinList(a), JoinList(b));
  }

  // MONOTONE: adding refs (anywhere) never lowers the join's rank; every member is bounded by the join.
  lemma JoinListUpper(ls: seq<Label>, i: int)
    requires |ls| > 0 && 0 <= i < |ls|
    ensures Rank(ls[i].kind) <= Rank(JoinList(ls).kind)
  { JoinListSpec(ls); assert ls[i] in multiset(ls); }

  lemma JoinListMonotone(a: seq<Label>, b: seq<Label>)
    requires |a| > 0 && multiset(a) <= multiset(b)
    ensures |b| > 0 && Rank(JoinList(a).kind) <= Rank(JoinList(b).kind)
  {
    JoinListSpec(a); JoinListSpec(b);
    var w :| w in multiset(a) && w.kind == JoinList(a).kind;
    assert w in multiset(b);
  }

  // The rank is exactly the maximum rank (attained) - no hidden rank inflation or deflation.
  lemma JoinListRankIsMax(ls: seq<Label>)
    requires |ls| > 0
    ensures forall i :: 0 <= i < |ls| ==> Rank(ls[i].kind) <= Rank(JoinList(ls).kind)
    ensures exists i :: 0 <= i < |ls| && Rank(ls[i].kind) == Rank(JoinList(ls).kind)
  {
    JoinListSpec(ls);
    forall i | 0 <= i < |ls| ensures Rank(ls[i].kind) <= Rank(JoinList(ls).kind) { assert ls[i] in multiset(ls); }
    var w :| w in multiset(ls) && w.kind == JoinList(ls).kind;
    var j :| 0 <= j < |ls| && ls[j] == w;
  }

  // ---------------------------------------------------------------- classification (taint.ts classifyRef)
  // Facts the glue evaluates for ONE well-formed ref: the registry's answer, whether the resource graph names it, and the ref's id (None when
  // the ref is longer than 128 code units). The registry answer is three-way: nothing, a label whose kind is an OWN level name (VKnown), or
  // an object whose kind is anything else (VUnknown: 'constructor', '__proto__', a number, ...).
  datatype Vouch = VNone | VKnown(l: Label) | VUnknown
  datatype RefFact = RefFact(vouched: Vouch, graphHit: bool, id: Option<nat>)

  function Classify(f: RefFact): Label {
    if f.vouched.VKnown? then f.vouched.l
    else if f.graphHit then Label(FirstParty, None)
    else Label(Agent, f.id)
  }

  // OWN-KEY LOOKUP: a registry answer with an unknown / inherited kind is NOT a vouching; it classifies exactly like no answer at all.
  lemma UnknownKindIsNotVouching(f: RefFact)
    requires f.vouched.VUnknown?
    ensures Classify(f) == Classify(RefFact(VNone, f.graphHit, f.id))
  {}

  // A ref the server cannot vouch for is the WORST label, whatever id it carries.
  lemma UnvouchedIsAgent(f: RefFact)
    requires !f.vouched.VKnown? && !f.graphHit
    ensures Classify(f).kind == Agent && Rank(Classify(f).kind) == MaxRank
  {}

  // The agent never chooses the label: Classify reads only server facts (type-level: RefFact has no agent-declared field).
  function ClassifyAll(fs: seq<RefFact>): seq<Label> { seq(|fs|, i requires 0 <= i < |fs| => Classify(fs[i])) }

  lemma ClassifyAllConcat(a: seq<RefFact>, b: seq<RefFact>)
    ensures ClassifyAll(a + b) == ClassifyAll(a) + ClassifyAll(b)
  {
    var l := ClassifyAll(a + b); var r := ClassifyAll(a) + ClassifyAll(b);
    assert |l| == |r|;
    forall i | 0 <= i < |l| ensures l[i] == r[i] { if i < |a| { assert (a + b)[i] == a[i]; } else { assert (a + b)[i] == b[i - |a|]; } }
  }

  lemma ClassifyAllPerm(a: seq<RefFact>, b: seq<RefFact>)
    requires multiset(a) == multiset(b)
    ensures multiset(ClassifyAll(a)) == multiset(ClassifyAll(b))
    decreases |a|
  {
    if |a| == 0 {
      assert |b| == 0;
    } else {
      var x := a[|a| - 1];
      var a1 := a[..|a| - 1];
      assert a == a1 + [x];
      assert x in multiset(b);
      var j :| 0 <= j < |b| && b[j] == x;
      var b1 := b[..j] + b[j + 1..];
      assert b == b[..j] + [x] + b[j + 1..];
      assert multiset(b) == multiset(b[..j]) + multiset{x} + multiset(b[j + 1..]);
      assert multiset(a) == multiset(a1) + multiset{x};
      assert multiset(b1) == multiset(b[..j]) + multiset(b[j + 1..]);
      forall e ensures multiset(a1)[e] == multiset(b1)[e] {
        assert (multiset(a1) + multiset{x})[e] == (multiset(b1) + multiset{x})[e];
      }
      assert multiset(a1) == multiset(b1);
      ClassifyAllPerm(a1, b1);
      assert ClassifyAll([x]) == [Classify(x)];
      ClassifyAllConcat(a1, [x]);
      ClassifyAllConcat(b[..j], [x] + b[j + 1..]);
      ClassifyAllConcat([x], b[j + 1..]);
      ClassifyAllConcat(b[..j], b[j + 1..]);
      assert multiset(ClassifyAll(a)) == multiset(ClassifyAll(a1)) + multiset{Classify(x)};
      var L := b[..j]; var R := b[j + 1..];
      assert ClassifyAll(b) == ClassifyAll(L) + ClassifyAll([x] + R);
      assert ClassifyAll([x] + R) == [Classify(x)] + ClassifyAll(R);
      assert ClassifyAll(b) == ClassifyAll(L) + [Classify(x)] + ClassifyAll(R);
      assert multiset(ClassifyAll(b)) == multiset(ClassifyAll(L)) + multiset{Classify(x)} + multiset(ClassifyAll(R));
      assert multiset(ClassifyAll(b1)) == multiset(ClassifyAll(b[..j])) + multiset(ClassifyAll(b[j + 1..]));
    }
  }

  // ---------------------------------------------------------------- computeTaint (fail-closed pre-checks + join)
  datatype Shape = Undef | NotArr | Arr(bad: bool)   // trusted_refs: absent | present non-array | array (bad: some element is not a non-empty string)
  datatype Pre = Ok | NoRegistry | ProvMalformed | RefsNotArray | RefsBadElem | EvalError

  // order exactly as computeTaint: registry, provenance object, trusted_refs shape, element check
  function Precheck(regOk: bool, provObj: bool, shape: Shape): Pre {
    if !regOk then NoRegistry
    else if !provObj then ProvMalformed
    else if shape.NotArr? then RefsNotArray
    else if shape.Arr? && shape.bad then RefsBadElem
    else Ok
  }

  datatype Result = Result(valid: bool, reason: Pre, lab: Label)

  function Refs(shape: Shape, facts: seq<RefFact>): seq<RefFact> {
    if shape.Arr? && !shape.bad then facts else []
  }

  function Compute(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>): Result {
    var p := Precheck(regOk, provObj, shape);
    if p.Ok? then Result(true, Ok, JoinOrTop(ClassifyAll(Refs(shape, facts))))
    else Result(false, p, Top)
  }

  // computeTaint NEVER THROWS. The glue evaluates the facts in production order and stops at the first exception (a throwing ctx /
  // registry getter, provenance getter, Proxy trap, or registry.lookup; resource-graph errors are caught per ref and are the worst case).
  // `threw` is set only when every pre-check evaluated BEFORE the exception passed (otherwise production returns that pre-check's failure
  // without evaluating further, and so does the glue).
  function ComputeSafe(threw: bool, regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>): Result {
    if threw then Result(false, EvalError, Top) else Compute(regOk, provObj, shape, facts)
  }

  lemma EvalErrorFailsClosed(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    ensures var r := ComputeSafe(true, regOk, provObj, shape, facts);
            !r.valid && r.reason == EvalError && r.lab == Top && Rank(r.lab.kind) == MaxRank
  {}
  lemma ComputeSafeNoThrow(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    ensures ComputeSafe(false, regOk, provObj, shape, facts) == Compute(regOk, provObj, shape, facts)
  {}
  // Whatever happens, the result is a label of the lattice: the taint value TaintRank/4 is one of 0, .25, .5, .75, 1 (never NaN), and an
  // invalid result is exactly the worst case.
  lemma ComputeSafeTotal(threw: bool, regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    ensures var r := ComputeSafe(threw, regOk, provObj, shape, facts);
            0 <= Rank(r.lab.kind) <= MaxRank && (!r.valid ==> r.lab == Top)
  { RankBounds(ComputeSafe(threw, regOk, provObj, shape, facts).lab.kind); }

  lemma ComputeLabelEq(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    requires Compute(regOk, provObj, shape, facts).valid && |Refs(shape, facts)| > 0
    ensures |ClassifyAll(Refs(shape, facts))| > 0
    ensures Compute(regOk, provObj, shape, facts).lab == JoinList(ClassifyAll(Refs(shape, facts)))
  { JoinOrTopEq(ClassifyAll(Refs(shape, facts))); }

  function TaintRank(r: Result): int { Rank(r.lab.kind) }   // taintValue = TaintRank / 4 (done by the adapter; exact in IEEE double)

  lemma RankInRange(r: Result) ensures 0 <= TaintRank(r) <= MaxRank { RankBounds(r.lab.kind); }

  // FAIL CLOSED: every pre-check failure is invalid and taint is exactly the maximum.
  lemma FailClosed(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    ensures var r := Compute(regOk, provObj, shape, facts);
            (!regOk || !provObj || shape.NotArr? || (shape.Arr? && shape.bad)) ==> (!r.valid && r.reason != Ok && TaintRank(r) == MaxRank && r.lab == Top)
    ensures var r := Compute(regOk, provObj, shape, facts);
            r.valid ==> regOk && provObj && !shape.NotArr? && !(shape.Arr? && shape.bad)
    ensures var r := Compute(regOk, provObj, shape, facts);
            !r.valid ==> TaintRank(r) == MaxRank
  {}

  // The empty lineage is the worst case.
  lemma EmptyLineageIsWorst(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    requires |Refs(shape, facts)| == 0
    ensures Compute(regOk, provObj, shape, facts).lab == Top && TaintRank(Compute(regOk, provObj, shape, facts)) == MaxRank
  {}

  // LOWERING BELOW THE WORST CASE needs positive server evidence for EVERY ref and a non-empty set.
  lemma LowTaintNeedsEvidence(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    requires var r := Compute(regOk, provObj, shape, facts); r.valid && TaintRank(r) < MaxRank
    ensures var rs := Refs(shape, facts);
            |rs| > 0 && forall i :: 0 <= i < |rs| ==>
              (rs[i].vouched.VKnown? || rs[i].graphHit) && Rank(Classify(rs[i]).kind) < MaxRank
  {
    var rs := Refs(shape, facts);
    assert |rs| > 0;
    ComputeLabelEq(regOk, provObj, shape, facts);
    var cs := ClassifyAll(rs);
    assert |cs| == |rs|;
    forall i | 0 <= i < |rs| ensures (rs[i].vouched.VKnown? || rs[i].graphHit) && Rank(Classify(rs[i]).kind) < MaxRank {
      JoinListUpper(cs, i);
      assert cs[i] == Classify(rs[i]);
      if !rs[i].vouched.VKnown? && !rs[i].graphHit { UnvouchedIsAgent(rs[i]); assert false; }
    }
  }

  // The converse bound: a valid taint is at least the rank of every classified ref (a bad ref cannot be hidden by good ones).
  lemma TaintDominatesEveryRef(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>, i: int)
    requires Compute(regOk, provObj, shape, facts).valid
    requires 0 <= i < |Refs(shape, facts)|
    ensures Rank(Classify(Refs(shape, facts)[i]).kind) <= TaintRank(Compute(regOk, provObj, shape, facts))
  {
    var rs := Refs(shape, facts);
    var cs := ClassifyAll(rs);
    ComputeLabelEq(regOk, provObj, shape, facts);
    JoinListUpper(cs, i);
  }

  // ORDER INDEPENDENCE of the whole computation.
  lemma ComputePerm(regOk: bool, provObj: bool, shape: Shape, a: seq<RefFact>, b: seq<RefFact>)
    requires multiset(a) == multiset(b)
    ensures Compute(regOk, provObj, shape, a) == Compute(regOk, provObj, shape, b)
  {
    if Precheck(regOk, provObj, shape).Ok? && shape.Arr? && |a| > 0 {
      ClassifyAllPerm(a, b);
      assert |ClassifyAll(a)| == |a|;
      assert |b| > 0;
      JoinOrTopEq(ClassifyAll(a)); JoinOrTopEq(ClassifyAll(b));
      JoinListPerm(ClassifyAll(a), ClassifyAll(b));
    }
  }

  // MONOTONE: appending a ref never lowers taint, and never turns an invalid result valid.
  // (Over a NON-EMPTY lineage. The empty lineage is the fail-closed worst case, so going [] -> [trusted ref] legitimately LOWERS taint 1 -> 0:
  // that is by design, it is the only way to get below the worst case.)
  lemma ComputeAddRefMonotone(regOk: bool, provObj: bool, a: seq<RefFact>, x: RefFact)
    requires |a| > 0
    ensures var r1 := Compute(regOk, provObj, Arr(false), a);
            var r2 := Compute(regOk, provObj, Arr(false), a + [x]);
            r1.valid == r2.valid && TaintRank(r1) <= TaintRank(r2)
  {
    var r1 := Compute(regOk, provObj, Arr(false), a);
    if Precheck(regOk, provObj, Arr(false)).Ok? {
      ClassifyAllConcat(a, [x]);
      var c1 := ClassifyAll(a);
      var c2 := ClassifyAll(a + [x]);
      assert c2 == c1 + [Classify(x)];
      assert |c1| == |a|;
      assert multiset(c1) <= multiset(c2);
      JoinOrTopEq(c1); JoinOrTopEq(c2);
      JoinListMonotone(c1, c2);
    }
  }

  // Tighter: valid taint equals the join of the independently classified refs (nothing else is read).
  lemma ComputeIsJoinOfClassified(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>)
    requires Compute(regOk, provObj, shape, facts).valid
    ensures Compute(regOk, provObj, shape, facts).lab == JoinOrTop(ClassifyAll(Refs(shape, facts)))
  {}

  // ---------------------------------------------------------------- the enforcement gate (pcactn.ts enforce.taint)
  // allowedMax is the largest rank r with r/4 <= maxTaint (-1 when none), computed by the glue; maxOk is `maxTaint >= 0`.
  datatype GateOut = GatePass | GateInvalid | GateMisconfigured | GateExceeds

  function Gate(valid: bool, maxOk: bool, rank: int, allowedMax: int): GateOut {
    if !valid then GateInvalid
    else if !maxOk then GateMisconfigured
    else if rank > allowedMax then GateExceeds
    else GatePass
  }

  // The gate over a ComputeSafe result: an evaluation error, any invalid lineage, or a misconfigured (NaN / negative) bound never passes.
  lemma GateFailsClosedOnError(threw: bool, regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>, maxOk: bool, allowedMax: int)
    requires var r := ComputeSafe(threw, regOk, provObj, shape, facts); Gate(r.valid, maxOk, TaintRank(r), allowedMax).GatePass?
    ensures !threw && maxOk && ComputeSafe(threw, regOk, provObj, shape, facts).valid
  {}

  lemma GateSound(valid: bool, maxOk: bool, rank: int, allowedMax: int)
    ensures Gate(valid, maxOk, rank, allowedMax).GatePass? <==> (valid && maxOk && rank <= allowedMax)
  {}

  // Looser policy never rejects what a stricter one accepts; lower taint never rejects what higher accepts.
  lemma GateMonotone(valid: bool, maxOk: bool, r1: int, r2: int, m1: int, m2: int)
    requires r1 <= r2 && m2 <= m1
    requires Gate(valid, maxOk, r2, m2).GatePass?
    ensures Gate(valid, maxOk, r1, m1).GatePass?
  {}

  // End-to-end: a gate pass means a valid lineage, a well-configured bound, and EVERY classified ref within the bound.
  lemma GateImpliesAllRefsWithinBound(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>, maxOk: bool, allowedMax: int, i: int)
    requires var r := Compute(regOk, provObj, shape, facts); Gate(r.valid, maxOk, TaintRank(r), allowedMax).GatePass?
    requires 0 <= i < |Refs(shape, facts)|
    ensures maxOk && regOk && provObj && Rank(Classify(Refs(shape, facts)[i]).kind) <= allowedMax
  { TaintDominatesEveryRef(regOk, provObj, shape, facts, i); }

  // A gate pass with the strictest bound (0, trusted only) means every ref is server-vouched trusted.
  lemma GatePassZeroMeansTrusted(regOk: bool, provObj: bool, shape: Shape, facts: seq<RefFact>, i: int)
    requires var r := Compute(regOk, provObj, shape, facts); Gate(r.valid, true, TaintRank(r), 0).GatePass?
    requires 0 <= i < |Refs(shape, facts)|
    ensures Refs(shape, facts)[i].vouched.VKnown? && Refs(shape, facts)[i].vouched.l.kind == Trusted
  {
    var rs := Refs(shape, facts);
    TaintDominatesEveryRef(regOk, provObj, shape, facts, i);
    assert Rank(Classify(rs[i]).kind) <= 0;
    if !rs[i].vouched.VKnown? {
      if rs[i].graphHit { assert Classify(rs[i]).kind == FirstParty; assert false; }
      else { UnvouchedIsAgent(rs[i]); assert false; }
    }
  }

  // ---------------------------------------------------------------- combining with the agent's own claim (risk derivation: max)
  // `deriveRisk` in the spec combines max(computed, claim). The claim is bucketed by the glue to the rank scale; only max semantics matter.
  function Combine(computed: int, claim: int): int { if computed >= claim then computed else claim }

  lemma CombineSound(c: int, a: int, a2: int, c2: int)
    ensures Combine(c, a) >= c && Combine(c, a) >= a
    ensures Combine(c, a) == c || Combine(c, a) == a
    ensures a <= c ==> Combine(c, a) == c               // the claim can only RAISE, never lower
    ensures a <= a2 ==> Combine(c, a) <= Combine(c, a2) // monotone in the claim
    ensures c <= c2 ==> Combine(c, a) <= Combine(c2, a) // monotone in the computed taint
    ensures Combine(c, a) == Combine(a, c)
  {}
}
