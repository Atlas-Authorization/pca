// Chain.dfy - the capability-chain walk (capability.ts: verifyChainUnchecked) as a verified pure function.
//
// Trusted base (NOT proved here, supplied by the caller as pure closures / booleans):
//   - every closure field of `Hop` (hash comparison, suite policy, PQ binding, signature verification)
//   - `ceq` : caveat equality (a canonical-hash comparison in the TS glue)
//   - `alloc`: the budget_alloc monotonicity check
// The Dafny code decides ORDER, FIRST-FAILURE, DEPTH, PREFIX (attenuation) and the final verdict.
include "Common.dfy"
module Chain {
  import opened Common

  const MaxDepth: nat := 16

  datatype Hop<M, C> = Hop(
    wellTyped: bool,
    hasParent: bool,
    rootIssuerOk: bool,                 // read for hop 0 only (expectedRootIssuer match, or none expected)
    caveats: seq<C>,
    parentLinkOk: () -> bool,           // hops >= 1: c.parent === capHash(parent)
    issuerIsParentHolder: () -> bool,   // hops >= 1
    suite: () -> Res<M>,                // allowedSuites policy
    pq: () -> Res<M>,                   // F-2 holder_pq binding (hops >= 1); R3-01 root PQ-key authority (hop 0)
    sig: () -> Res<M>)                  // body digest + signature

  datatype ChainErr<M> =
    | Empty
    | TooLong
    | Malformed(hop: nat)
    | RootHasParent
    | RootIssuer
    | SuiteErr(hop: nat, m: M)
    | PqErr(hop: nat, m: M)
    | SigErr(hop: nat, m: M)
    | ParentLink(hop: nat)
    | IssuerNotHolder(hop: nat)
    | Drops(hop: nat)
    | Altered(hop: nat, j: nat)
    | Alloc(m: M)

  datatype ChainResult<M> = ChainOk | ChainBad(e: ChainErr<M>)

  // ---- attenuation: the parent's caveats are a prefix of the child's (as judged by ceq) ----
  ghost predicate IsPrefixBy<C>(p: seq<C>, c: seq<C>, ceq: (C, C) -> bool) {
    |p| <= |c| && forall j :: 0 <= j < |p| ==> ceq(c[j], p[j])
  }

  // first index (>= from) at which the child differs from the parent, if any
  function FirstAltered<C>(p: seq<C>, c: seq<C>, ceq: (C, C) -> bool, from: nat): Option<nat>
    requires |p| <= |c|
    requires from <= |p|
    decreases |p| - from
  {
    if from == |p| then None
    else if !ceq(c[from], p[from]) then Some(from)
    else FirstAltered(p, c, ceq, from + 1)
  }

  lemma FirstAlteredNone<C>(p: seq<C>, c: seq<C>, ceq: (C, C) -> bool, from: nat)
    requires |p| <= |c| && from <= |p|
    ensures FirstAltered(p, c, ceq, from).None? <==> forall j :: from <= j < |p| ==> ceq(c[j], p[j])
    decreases |p| - from
  {
    if from < |p| && ceq(c[from], p[from]) { FirstAlteredNone(p, c, ceq, from + 1); }
  }

  lemma FirstAlteredSome<C>(p: seq<C>, c: seq<C>, ceq: (C, C) -> bool, from: nat)
    requires |p| <= |c| && from <= |p|
    ensures FirstAltered(p, c, ceq, from).Some? ==>
              var j := FirstAltered(p, c, ceq, from).v;
              from <= j < |p| && !ceq(c[j], p[j])
    decreases |p| - from
  {
    if from < |p| && ceq(c[from], p[from]) { FirstAlteredSome(p, c, ceq, from + 1); }
  }

  function PrefixCheck<M, C>(hop: nat, p: seq<C>, c: seq<C>, ceq: (C, C) -> bool): ChainResult<M> {
    if |c| < |p| then ChainBad(Drops(hop))
    else match FirstAltered(p, c, ceq, 0) {
      case Some(j) => ChainBad(Altered(hop, j))
      case None => ChainOk
    }
  }

  // ---- hop 0 ----
  function RootCheck<M, C>(h: Hop<M, C>): ChainResult<M> {
    if h.hasParent then ChainBad(RootHasParent)
    else if !h.rootIssuerOk then ChainBad(RootIssuer)
    else match h.suite() {
      case Err(m) => ChainBad(SuiteErr(0, m))
      case Ok => match h.pq() {   // root PQ-key authority (R3-01): supplied by the glue, ok for an ed25519 root
        case Err(m) => ChainBad(PqErr(0, m))
        case Ok => match h.sig() {
          case Err(m) => ChainBad(SigErr(0, m))
          case Ok => ChainOk
        }
      }
    }
  }

  // ---- hop i >= 1 (parent = hops[i-1]) ----
  function HopCheck<M, C>(i: nat, parent: Hop<M, C>, c: Hop<M, C>, ceq: (C, C) -> bool): ChainResult<M> {
    if !c.parentLinkOk() then ChainBad(ParentLink(i))
    else if !c.issuerIsParentHolder() then ChainBad(IssuerNotHolder(i))
    else match c.suite() {
      case Err(m) => ChainBad(SuiteErr(i, m))
      case Ok => match c.pq() {
        case Err(m) => ChainBad(PqErr(i, m))
        case Ok => match c.sig() {
          case Err(m) => ChainBad(SigErr(i, m))
          case Ok => PrefixCheck(i, parent.caveats, c.caveats, ceq)
        }
      }
    }
  }

  function FirstMalformed<M, C>(hops: seq<Hop<M, C>>, from: nat): Option<nat>
    requires from <= |hops|
    decreases |hops| - from
  {
    if from == |hops| then None
    else if !hops[from].wellTyped then Some(from)
    else FirstMalformed(hops, from + 1)
  }

  function Walk<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>, i: nat): ChainResult<M>
    requires 1 <= i <= |hops|
    decreases |hops| - i
  {
    if i == |hops| then
      (match alloc() { case Err(m) => ChainBad(Alloc(m)) case Ok => ChainOk })
    else match HopCheck(i, hops[i - 1], hops[i], ceq) {
      case ChainBad(e) => ChainBad(e)
      case ChainOk => Walk(hops, ceq, alloc, i + 1)
    }
  }

  // The chain verdict. `alloc` is evaluated last, only if every hop passed.
  function VerifyChain<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>): ChainResult<M> {
    if |hops| == 0 then ChainBad(Empty)
    else if |hops| > MaxDepth then ChainBad(TooLong)
    else match FirstMalformed(hops, 0) {
      case Some(i) => ChainBad(Malformed(i))
      case None => match RootCheck(hops[0]) {
        case ChainBad(e) => ChainBad(e)
        case ChainOk => Walk(hops, ceq, alloc, 1)
      }
    }
  }

  // ===========================================================================================
  // THEOREMS (all inputs, unbounded |hops| up to the explicit MaxDepth guard that is itself proved)
  // ===========================================================================================

  // Soundness of the walk from index i: ok => every remaining hop's facts hold and caveats grow by prefix.
  lemma WalkSound<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>, i: nat)
    requires 1 <= i <= |hops|
    requires Walk(hops, ceq, alloc, i) == ChainOk
    ensures alloc().Ok?
    ensures forall k :: i <= k < |hops| ==>
              hops[k].parentLinkOk() && hops[k].issuerIsParentHolder() &&
              hops[k].suite().Ok? && hops[k].pq().Ok? && hops[k].sig().Ok? &&
              IsPrefixBy(hops[k - 1].caveats, hops[k].caveats, ceq)
    decreases |hops| - i
  {
    if i < |hops| {
      assert HopCheck(i, hops[i - 1], hops[i], ceq) == ChainOk;
      assert PrefixCheck<M, C>(i, hops[i - 1].caveats, hops[i].caveats, ceq) == ChainOk;
      FirstAlteredNone(hops[i - 1].caveats, hops[i].caveats, ceq, 0);
      WalkSound(hops, ceq, alloc, i + 1);
    }
  }

  // Soundness: VerifyChain ok => structural, per-hop, and attenuation facts.
  lemma ChainSound<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>)
    requires VerifyChain(hops, ceq, alloc) == ChainOk
    ensures 1 <= |hops| <= MaxDepth
    ensures forall k :: 0 <= k < |hops| ==> hops[k].wellTyped
    ensures !hops[0].hasParent && hops[0].rootIssuerOk
    ensures hops[0].suite().Ok? && hops[0].pq().Ok? && hops[0].sig().Ok?
    ensures alloc().Ok?
    ensures forall k :: 1 <= k < |hops| ==>
              hops[k].parentLinkOk() && hops[k].issuerIsParentHolder() &&
              hops[k].suite().Ok? && hops[k].pq().Ok? && hops[k].sig().Ok? &&
              IsPrefixBy(hops[k - 1].caveats, hops[k].caveats, ceq)
  {
    FirstMalformedNone(hops, 0);
    WalkSound(hops, ceq, alloc, 1);
  }

  lemma FirstMalformedNone<M, C>(hops: seq<Hop<M, C>>, from: nat)
    requires from <= |hops|
    ensures FirstMalformed(hops, from).None? <==> forall k :: from <= k < |hops| ==> hops[k].wellTyped
    decreases |hops| - from
  {
    if from < |hops| && hops[from].wellTyped { FirstMalformedNone(hops, from + 1); }
  }

  // Completeness / no spurious denial: if every fact passes, the chain is accepted.
  lemma WalkComplete<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>, i: nat)
    requires 1 <= i <= |hops|
    requires alloc().Ok?
    requires forall k :: i <= k < |hops| ==>
              hops[k].parentLinkOk() && hops[k].issuerIsParentHolder() &&
              hops[k].suite().Ok? && hops[k].pq().Ok? && hops[k].sig().Ok? &&
              IsPrefixBy(hops[k - 1].caveats, hops[k].caveats, ceq)
    ensures Walk(hops, ceq, alloc, i) == ChainOk
    decreases |hops| - i
  {
    if i < |hops| {
      FirstAlteredNone(hops[i - 1].caveats, hops[i].caveats, ceq, 0);
      WalkComplete(hops, ceq, alloc, i + 1);
    }
  }

  lemma ChainComplete<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>)
    requires 1 <= |hops| <= MaxDepth
    requires forall k :: 0 <= k < |hops| ==> hops[k].wellTyped
    requires !hops[0].hasParent && hops[0].rootIssuerOk
    requires hops[0].suite().Ok? && hops[0].pq().Ok? && hops[0].sig().Ok?
    requires alloc().Ok?
    requires forall k :: 1 <= k < |hops| ==>
              hops[k].parentLinkOk() && hops[k].issuerIsParentHolder() &&
              hops[k].suite().Ok? && hops[k].pq().Ok? && hops[k].sig().Ok? &&
              IsPrefixBy(hops[k - 1].caveats, hops[k].caveats, ceq)
    ensures VerifyChain(hops, ceq, alloc) == ChainOk
  {
    FirstMalformedNone(hops, 0);
    WalkComplete(hops, ceq, alloc, 1);
  }

  // ---- attenuation monotonicity: authority only narrows down an accepted chain ----
  ghost predicate Eff<C, A>(cs: seq<C>, allows: (C, A) -> bool, a: A) {
    forall k :: 0 <= k < |cs| ==> allows(cs[k], a)
  }

  // ceq-equal caveats grant identically (the trusted contract of the caveat-equality closure:
  // canonical-hash equality implies semantic equality).
  ghost predicate EqSound<C(!new), A(!new)>(ceq: (C, C) -> bool, allows: (C, A) -> bool) {
    forall x: C, y: C, a: A :: ceq(x, y) ==> allows(x, a) == allows(y, a)
  }

  lemma PrefixAntitone<C(!new), A(!new)>(p: seq<C>, c: seq<C>, ceq: (C, C) -> bool, allows: (C, A) -> bool, a: A)
    requires IsPrefixBy(p, c, ceq) && EqSound(ceq, allows)
    requires Eff(c, allows, a)
    ensures Eff(p, allows, a)
  {
    forall k | 0 <= k < |p| ensures allows(p[k], a) {
      assert allows(c[k], a);
      assert ceq(c[k], p[k]);
    }
  }

  // Accepted chain, ANY length: the action permitted at hop i is permitted at every ancestor j <= i
  // (in particular at the root grant). I.e. effective authority is antitone along the chain.
  lemma ChainAttenuates<M, C(!new), A(!new)>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>,
                                 allows: (C, A) -> bool, a: A, i: nat, j: nat)
    requires VerifyChain(hops, ceq, alloc) == ChainOk
    requires EqSound(ceq, allows)
    requires j <= i < |hops|
    requires Eff(hops[i].caveats, allows, a)
    ensures Eff(hops[j].caveats, allows, a)
    decreases i - j
  {
    ChainSound(hops, ceq, alloc);
    if j < i {
      PrefixAntitone(hops[i - 1].caveats, hops[i].caveats, ceq, allows, a);
      ChainAttenuates(hops, ceq, alloc, allows, a, i - 1, j);
    }
  }

  // Length of caveat lists never decreases along an accepted chain (no caveat is ever dropped).
  lemma ChainCaveatsGrow<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>, j: nat, i: nat)
    requires VerifyChain(hops, ceq, alloc) == ChainOk
    requires j <= i < |hops|
    ensures |hops[j].caveats| <= |hops[i].caveats|
    decreases i - j
  {
    ChainSound(hops, ceq, alloc);
    if j < i { ChainCaveatsGrow(hops, ceq, alloc, j, i - 1); }
  }

  // Depth bound: acceptance implies at most MaxDepth hops, and a longer chain is ALWAYS rejected as TooLong
  // before any hop fact is consulted.
  lemma DepthBound<M, C>(hops: seq<Hop<M, C>>, ceq: (C, C) -> bool, alloc: () -> Res<M>)
    ensures |hops| > MaxDepth ==> VerifyChain(hops, ceq, alloc) == ChainBad(TooLong)
    ensures VerifyChain(hops, ceq, alloc) == ChainOk ==> |hops| <= MaxDepth
  {
  }

  // Determinism / extensionality: the verdict is a function of the OBSERVABLE facts only.
  lemma WalkExt<M, C>(h1: seq<Hop<M, C>>, h2: seq<Hop<M, C>>, ceq: (C, C) -> bool, a1: () -> Res<M>, a2: () -> Res<M>, i: nat)
    requires 1 <= i <= |h1| && |h1| == |h2|
    requires a1() == a2()
    requires forall k :: 0 <= k < |h1| ==>
      h1[k].caveats == h2[k].caveats && h1[k].parentLinkOk() == h2[k].parentLinkOk() &&
      h1[k].issuerIsParentHolder() == h2[k].issuerIsParentHolder() &&
      h1[k].suite() == h2[k].suite() && h1[k].pq() == h2[k].pq() && h1[k].sig() == h2[k].sig()
    ensures Walk(h1, ceq, a1, i) == Walk(h2, ceq, a2, i)
    decreases |h1| - i
  {
    if i < |h1| { WalkExt(h1, h2, ceq, a1, a2, i + 1); }
  }
}
