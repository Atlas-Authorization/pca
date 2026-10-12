// Merkle.dfy - RFC 6962 / RFC 9162 Merkle tree: inclusion and consistency proof verification, proved for ALL tree sizes.
//
// Standalone (no includes). The hash function H is a PARAMETER (a total function bytes -> bytes), never an axiom:
//   * every verifier takes H as an argument and is compiled to JavaScript as a closure-taking function;
//   * every theorem is stated for an arbitrary H, with the fixed-output-length hypothesis HashLen(H, L) where it is needed
//     (a property the adapter's SHA-256 / SHA-384 has), and collision resistance is NOT assumed: soundness lemmas conclude
//     `claim || Collides(H)` where Collides(H) = (exists a != b with H(a) == H(b)). Every collision is built constructively
//     (the proofs name the two byte strings), so no axiom / assume / extern is needed anywhere in this file.
module Merkle {
  newtype byte = b: int | 0 <= b < 256
  type bytes = seq<byte>
  datatype Option<T> = None | Some(v: T)

  ghost predicate HashLen(H: bytes -> bytes, L: nat) { forall b: bytes :: |H(b)| == L }
  ghost predicate Collides(H: bytes -> bytes) { exists a: bytes, b: bytes :: a != b && H(a) == H(b) }

  lemma Wit(H: bytes -> bytes, a: bytes, b: bytes)
    requires a != b && H(a) == H(b)
    ensures Collides(H)
  {}

  // ---- domain separation -----------------------------------------------------------------------------------------
  function LeafH(H: bytes -> bytes, d: bytes): bytes { H([0] + d) }
  function NodeH(H: bytes -> bytes, l: bytes, r: bytes): bytes { H([1] + l + r) }

  // ---- powers of two and the RFC 6962 split ----------------------------------------------------------------------
  function Pow2(j: nat): nat
    ensures Pow2(j) >= 1
  { if j == 0 then 1 else 2 * Pow2(j - 1) }

  // `while (k*2 < n) k *= 2` as a recursion on the exponent j (k = 2^j).
  function SplitJ(n: int, j: nat): nat
    requires Pow2(j) < n
    ensures Pow2(SplitJ(n, j)) < n <= 2 * Pow2(SplitJ(n, j))
    ensures SplitJ(n, j) >= j
    decreases n - Pow2(j)
  { if 2 * Pow2(j) < n then SplitJ(n, j + 1) else j }

  // Largest power of two strictly below n (n >= 2); 1 for smaller n (never used there).
  function Split(n: int): nat
    ensures n >= 2 ==> 1 <= Split(n) < n <= 2 * Split(n)
  { if n < 2 then 1 else Pow2(SplitJ(n, 0)) }

  lemma SplitIs(n: int, j: nat)
    requires Pow2(j) < n <= 2 * Pow2(j)
    ensures Split(n) == Pow2(j)
  {
    var j2 := SplitJ(n, 0);
    // two exponents with 2^a < n <= 2^(a+1) are equal
    PowMono(j, j2);
    PowMono(j2, j);
  }

  // 2^a < n <= 2*2^b  ==> a <= b   (and symmetric use above)
  lemma PowMono(a: nat, b: nat)
    requires Pow2(a) < 2 * Pow2(b)
    ensures a <= b
  {
    if a > b { PowIncr(b, a); }
  }
  lemma PowIncr(b: nat, a: nat)
    requires b < a
    ensures Pow2(a) >= 2 * Pow2(b)
    decreases a - b
  { if a > b + 1 { PowIncr(b, a - 1); } }

  // ---- the tree hash (RFC 6962 MTH over DATA; leaf = H(0x00||d), node = H(0x01||l||r); empty = H("")) -----------------
  function Root(H: bytes -> bytes, ds: seq<bytes>): bytes
    decreases |ds|
  {
    if |ds| == 0 then H([])
    else if |ds| == 1 then LeafH(H, ds[0])
    else var k := Split(|ds|); NodeH(H, Root(H, ds[..k]), Root(H, ds[k..]))
  }

  lemma RootLen(H: bytes -> bytes, L: nat, ds: seq<bytes>)
    requires HashLen(H, L)
    ensures |Root(H, ds)| == L
    decreases |ds|
  {
    if |ds| >= 2 { var k := Split(|ds|); RootLen(H, L, ds[..k]); RootLen(H, L, ds[k..]); }
  }

  // Equal node-hash outputs: either the preimages are equal (hence, lengths being L, so are the children) or H collides.
  lemma NodeEq(H: bytes -> bytes, L: nat, l: bytes, r: bytes, l2: bytes, r2: bytes)
    requires |l| == L && |l2| == L
    requires NodeH(H, l, r) == NodeH(H, l2, r2)
    ensures (l == l2 && r == r2) || Collides(H)
  {
    if [1] + l + r != [1] + l2 + r2 { Wit(H, [1] + l + r, [1] + l2 + r2); }
    else {
      assert (([1] + l + r)[1..1 + L]) == l;
      assert (([1] + l2 + r2)[1..1 + L]) == l2;
      assert (([1] + l + r)[1 + L..]) == r;
      assert (([1] + l2 + r2)[1 + L..]) == r2;
    }
  }

  // A leaf hash never equals a node hash, nor the empty-tree hash, unless H collides (domain separation).
  lemma LeafNotNode(H: bytes -> bytes, d: bytes, l: bytes, r: bytes)
    requires LeafH(H, d) == NodeH(H, l, r)
    ensures Collides(H)
  { assert ([0] + d)[0] == 0; assert ([1] + l + r)[0] == 1; Wit(H, [0] + d, [1] + l + r); }
  lemma LeafNotEmpty(H: bytes -> bytes, d: bytes)
    requires LeafH(H, d) == H([])
    ensures Collides(H)
  { Wit(H, [0] + d, []); }
  lemma NodeNotEmpty(H: bytes -> bytes, l: bytes, r: bytes)
    requires NodeH(H, l, r) == H([])
    ensures Collides(H)
  { Wit(H, [1] + l + r, []); }

  // Root is injective on data lists (modulo collisions): two different leaf sequences (incl. different lengths) never share a root.
  lemma RootInj(H: bytes -> bytes, L: nat, a: seq<bytes>, b: seq<bytes>)
    requires HashLen(H, L)
    requires Root(H, a) == Root(H, b)
    ensures a == b || Collides(H)
    decreases |a|
  {
    if |a| == 0 && |b| == 0 {
    } else if |a| == 0 {
      if |b| == 1 { LeafNotEmpty(H, b[0]); }
      else { var k := Split(|b|); RootLen(H, L, b[..k]); NodeNotEmpty(H, Root(H, b[..k]), Root(H, b[k..])); }
    } else if |b| == 0 {
      if |a| == 1 { LeafNotEmpty(H, a[0]); }
      else { var k := Split(|a|); RootLen(H, L, a[..k]); NodeNotEmpty(H, Root(H, a[..k]), Root(H, a[k..])); }
    } else if |a| == 1 && |b| == 1 {
      if a[0] != b[0] { assert ([0] + a[0])[1..] == a[0]; assert ([0] + b[0])[1..] == b[0]; Wit(H, [0] + a[0], [0] + b[0]); }
    } else if |a| == 1 {
      var k := Split(|b|); LeafNotNode(H, a[0], Root(H, b[..k]), Root(H, b[k..]));
    } else if |b| == 1 {
      var k := Split(|a|); LeafNotNode(H, b[0], Root(H, a[..k]), Root(H, a[k..]));
    } else {
      var ka := Split(|a|);
      var kb := Split(|b|);
      RootLen(H, L, a[..ka]);
      NodeEq(H, L, Root(H, a[..ka]), Root(H, a[ka..]), Root(H, b[..kb]), Root(H, b[kb..]));
      if Root(H, a[..ka]) == Root(H, b[..kb]) && Root(H, a[ka..]) == Root(H, b[kb..]) {
        RootInj(H, L, a[..ka], b[..kb]);
        RootInj(H, L, a[ka..], b[kb..]);
        if a[..ka] == b[..kb] && a[ka..] == b[kb..] { assert a == a[..ka] + a[ka..]; assert b == b[..kb] + b[kb..]; }
      }
    }
  }

  // =================================================================================================================
  // INCLUSION PROOFS (merkle.ts verifyInclusion)
  // =================================================================================================================
  datatype Side = Lt | Rt
  datatype Step = Step(side: Side, hash: bytes)

  function Sides(p: seq<Step>): seq<Side> { seq(|p|, i requires 0 <= i < |p| => p[i].side) }

  lemma SnocInj<T>(a: seq<T>, b: seq<T>, x: T, y: T)
    requires a + [x] == b + [y]
    ensures a == b && x == y
  {
    assert |a| == |b|;
    assert (a + [x])[..|a|] == a;
    assert (b + [y])[..|b|] == b;
    assert (a + [x])[|a|] == x;
    assert (b + [y])[|b|] == y;
  }

  lemma SidesSnoc(p: seq<Step>)
    requires |p| >= 1
    ensures Sides(p) == Sides(p[..|p| - 1]) + [p[|p| - 1].side]
  { assert Sides(p) == Sides(p[..|p| - 1]) + [p[|p| - 1].side]; }

  // Sibling sides, LEAF -> ROOT, for leaf `idx` of a tree of `n` leaves (merkle.ts pathShape, reversed once).
  function Shape(idx: int, n: int): seq<Side>
    requires 1 <= n && 0 <= idx < n
    decreases n
  {
    if n == 1 then []
    else
      var k := Split(n);
      if idx < k then Shape(idx, k) + [Rt] else Shape(idx - k, n - k) + [Lt]
  }

  // The honest proof (merkle.ts prove()).
  function InclPath(H: bytes -> bytes, ds: seq<bytes>, idx: int): seq<Step>
    requires 0 <= idx < |ds|
    decreases |ds|
  {
    if |ds| == 1 then []
    else
      var k := Split(|ds|);
      if idx < k then InclPath(H, ds[..k], idx) + [Step(Rt, Root(H, ds[k..]))]
      else InclPath(H, ds[k..], idx - k) + [Step(Lt, Root(H, ds[..k]))]
  }

  lemma InclPathShape(H: bytes -> bytes, ds: seq<bytes>, idx: int)
    requires 0 <= idx < |ds|
    ensures Sides(InclPath(H, ds, idx)) == Shape(idx, |ds|)
    decreases |ds|
  {
    if |ds| > 1 {
      var k := Split(|ds|);
      if idx < k { InclPathShape(H, ds[..k], idx); } else { InclPathShape(H, ds[k..], idx - k); }
      assert Sides(InclPath(H, ds, idx)) == (if idx < k then Sides(InclPath(H, ds[..k], idx)) + [Rt] else Sides(InclPath(H, ds[k..], idx - k)) + [Lt]);
    }
  }

  // Leaf -> root fold, in path order (the verify loop).
  function IncStep(H: bytes -> bytes, h: bytes, s: Step): bytes
  { if s.side == Lt then NodeH(H, s.hash, h) else NodeH(H, h, s.hash) }

  function IncFold(H: bytes -> bytes, h: bytes, p: seq<Step>): bytes
    decreases |p|
  { if |p| == 0 then h else IncFold(H, IncStep(H, h, p[0]), p[1..]) }

  lemma FoldSnoc(H: bytes -> bytes, h: bytes, p: seq<Step>, s: Step)
    ensures IncFold(H, h, p + [s]) == IncStep(H, IncFold(H, h, p), s)
    decreases |p|
  {
    if |p| > 0 { assert (p + [s])[1..] == p[1..] + [s]; FoldSnoc(H, IncStep(H, h, p[0]), p[1..], s); }
  }

  ghost predicate HashesLen(p: seq<Step>, L: nat) { forall i :: 0 <= i < |p| ==> |p[i].hash| == L }

  lemma FoldLen(H: bytes -> bytes, L: nat, h: bytes, p: seq<Step>)
    requires HashLen(H, L) && |h| == L
    ensures |IncFold(H, h, p)| == L
    decreases |p|
  { if |p| > 0 { FoldLen(H, L, IncStep(H, h, p[0]), p[1..]); } }

  // THE VERIFIER (compiled). `root` is the already-decoded root; every sibling must be exactly L bytes (the strict decode).
  function VerifyInclusion(H: bytes -> bytes, L: nat, root: bytes, index: int, size: int, path: seq<Step>, leaf: bytes): bool
  {
    1 <= size && 0 <= index < size
    && Sides(path) == Shape(index, size)
    && (forall i :: 0 <= i < |path| ==> |path[i].hash| == L)
    && IncFold(H, LeafH(H, leaf), path) == root
  }

  // ---- COMPLETENESS (honest tree, honest proof) for every size and index ----------------------------------------
  lemma InclComplete(H: bytes -> bytes, L: nat, ds: seq<bytes>, idx: int)
    requires HashLen(H, L)
    requires 0 <= idx < |ds|
    ensures IncFold(H, LeafH(H, ds[idx]), InclPath(H, ds, idx)) == Root(H, ds)
    ensures HashesLen(InclPath(H, ds, idx), L)
    ensures VerifyInclusion(H, L, Root(H, ds), idx, |ds|, InclPath(H, ds, idx), ds[idx])
    decreases |ds|
  {
    InclCompleteCore(H, L, ds, idx);
    InclPathShape(H, ds, idx);
  }

  lemma InclCompleteCore(H: bytes -> bytes, L: nat, ds: seq<bytes>, idx: int)
    requires HashLen(H, L)
    requires 0 <= idx < |ds|
    ensures IncFold(H, LeafH(H, ds[idx]), InclPath(H, ds, idx)) == Root(H, ds)
    ensures HashesLen(InclPath(H, ds, idx), L)
    decreases |ds|
  {
    if |ds| > 1 {
      var k := Split(|ds|);
      if idx < k {
        InclCompleteCore(H, L, ds[..k], idx);
        FoldSnoc(H, LeafH(H, ds[idx]), InclPath(H, ds[..k], idx), Step(Rt, Root(H, ds[k..])));
        RootLen(H, L, ds[k..]);
      } else {
        InclCompleteCore(H, L, ds[k..], idx - k);
        FoldSnoc(H, LeafH(H, ds[idx]), InclPath(H, ds[k..], idx - k), Step(Lt, Root(H, ds[..k])));
        RootLen(H, L, ds[..k]);
      }
    }
  }

  // ---- SOUNDNESS ------------------------------------------------------------------------------------------------
  // Core descent: a path of the right shape for (idx, |ds|) that folds from digest h to Root(ds) starts at the real leaf hash.
  lemma InclDescend(H: bytes -> bytes, L: nat, ds: seq<bytes>, idx: int, p: seq<Step>, h: bytes)
    requires HashLen(H, L) && |h| == L
    requires 0 <= idx < |ds|
    requires Sides(p) == Shape(idx, |ds|)
    requires HashesLen(p, L)
    requires IncFold(H, h, p) == Root(H, ds)
    ensures h == LeafH(H, ds[idx]) || Collides(H)
    decreases |ds|
  {
    if |ds| == 1 {
      assert p == [];
    } else {
      var k := Split(|ds|);
      var q := p[..|p| - 1];
      var s := p[|p| - 1];
      assert p == q + [s];
      FoldSnoc(H, h, q, s);
      FoldLen(H, L, h, q);
      SidesSnoc(p);
      if idx < k {
        assert Shape(idx, |ds|) == Shape(idx, k) + [Rt];
        SnocInj(Sides(q), Shape(idx, k), s.side, Rt);
        RootLen(H, L, ds[..k]);
        NodeEq(H, L, IncFold(H, h, q), s.hash, Root(H, ds[..k]), Root(H, ds[k..]));
        if IncFold(H, h, q) == Root(H, ds[..k]) {
          InclDescend(H, L, ds[..k], idx, q, h);
        }
      } else {
        assert Shape(idx, |ds|) == Shape(idx - k, |ds| - k) + [Lt];
        SnocInj(Sides(q), Shape(idx - k, |ds| - k), s.side, Lt);
        RootLen(H, L, ds[..k]);
        NodeEq(H, L, s.hash, IncFold(H, h, q), Root(H, ds[..k]), Root(H, ds[k..]));
        if IncFold(H, h, q) == Root(H, ds[k..]) {
          InclDescend(H, L, ds[k..], idx - k, q, h);
        }
      }
    }
  }

  // SOUNDNESS (fixed size): an accepted proof for (root, index, size, leaf), against ANY leaf list of that size whose tree hash is root,
  // puts `leaf` exactly at `index` -- unless H collides.
  lemma InclSound(H: bytes -> bytes, L: nat, ds: seq<bytes>, root: bytes, index: int, size: int, path: seq<Step>, leaf: bytes)
    requires HashLen(H, L)
    requires VerifyInclusion(H, L, root, index, size, path, leaf)
    requires Root(H, ds) == root && |ds| == size
    ensures ds[index] == leaf || Collides(H)
  {
    InclDescend(H, L, ds, index, path, LeafH(H, leaf));
    if LeafH(H, leaf) == LeafH(H, ds[index]) && leaf != ds[index] {
      assert ([0] + leaf)[1..] == leaf; assert ([0] + ds[index])[1..] == ds[index];
      Wit(H, [0] + leaf, [0] + ds[index]);
    }
  }

  // MEMBERSHIP (any size, shape ignored): if an accepted proof's fold reaches the root of ANY leaf list, the leaf is one of its entries.
  lemma InclMember(H: bytes -> bytes, L: nat, ds: seq<bytes>, p: seq<Step>, leaf: bytes)
    requires HashLen(H, L)
    requires HashesLen(p, L)
    requires IncFold(H, LeafH(H, leaf), p) == Root(H, ds)
    ensures leaf in ds || Collides(H)
    decreases |p|
  {
    if |p| == 0 {
      if |ds| == 0 { LeafNotEmpty(H, leaf); }
      else if |ds| == 1 {
        if leaf != ds[0] && LeafH(H, leaf) == LeafH(H, ds[0]) {
          assert ([0] + leaf)[1..] == leaf; assert ([0] + ds[0])[1..] == ds[0];
          Wit(H, [0] + leaf, [0] + ds[0]);
        }
      } else {
        var k := Split(|ds|);
        LeafNotNode(H, leaf, Root(H, ds[..k]), Root(H, ds[k..]));
      }
    } else {
      var q := p[..|p| - 1];
      var s := p[|p| - 1];
      assert p == q + [s];
      FoldSnoc(H, LeafH(H, leaf), q, s);
      FoldLen(H, L, LeafH(H, leaf), q);
      var cur := IncFold(H, LeafH(H, leaf), q);
      if |ds| == 0 {
        NodeNotEmpty(H, if s.side == Lt then s.hash else cur, if s.side == Lt then cur else s.hash);
      } else if |ds| == 1 {
        LeafNotNode(H, ds[0], if s.side == Lt then s.hash else cur, if s.side == Lt then cur else s.hash);
      } else {
        var k := Split(|ds|);
        RootLen(H, L, ds[..k]);
        if s.side == Lt {
          NodeEq(H, L, s.hash, cur, Root(H, ds[..k]), Root(H, ds[k..]));
          if cur == Root(H, ds[k..]) { InclMember(H, L, ds[k..], q, leaf); assert leaf in ds[k..] ==> leaf in ds; }
        } else {
          NodeEq(H, L, cur, s.hash, Root(H, ds[..k]), Root(H, ds[k..]));
          if cur == Root(H, ds[..k]) { InclMember(H, L, ds[..k], q, leaf); assert leaf in ds[..k] ==> leaf in ds; }
        }
      }
    }
  }

  lemma InclSoundAnySize(H: bytes -> bytes, L: nat, ds: seq<bytes>, root: bytes, index: int, size: int, path: seq<Step>, leaf: bytes)
    requires HashLen(H, L)
    requires VerifyInclusion(H, L, root, index, size, path, leaf)
    requires Root(H, ds) == root
    ensures leaf in ds || Collides(H)
  { InclMember(H, L, ds, path, leaf); }

  // ---- FAIL-CLOSED / SHAPE ---------------------------------------------------------------------------------------
  lemma InclFailClosed(H: bytes -> bytes, L: nat, root: bytes, index: int, size: int, path: seq<Step>, leaf: bytes)
    ensures size < 1 ==> !VerifyInclusion(H, L, root, index, size, path, leaf)
    ensures (index < 0 || index >= size) ==> !VerifyInclusion(H, L, root, index, size, path, leaf)
    ensures (1 <= size && 0 <= index < size && Sides(path) != Shape(index, size)) ==> !VerifyInclusion(H, L, root, index, size, path, leaf)
    ensures (exists i :: 0 <= i < |path| && |path[i].hash| != L) ==> !VerifyInclusion(H, L, root, index, size, path, leaf)
  {}

  // The path length is determined by (index, size) alone and is at most log2-ish bounded: |Shape| <= size - 1 (termination/size bound).
  lemma ShapeLenBound(idx: int, n: int)
    requires 1 <= n && 0 <= idx < n
    ensures |Shape(idx, n)| <= n - 1
    decreases n
  {
    if n > 1 { var k := Split(n); if idx < k { ShapeLenBound(idx, k); } else { ShapeLenBound(idx - k, n - k); } }
  }

  // Honest limitation, proved: (index, size) are NOT authenticated by the root. A path valid for (2, 3) verifies the leaf b
  // against the root of the 2-leaf tree [a, b], where b sits at index 1.
  lemma IndexSizeNotAuthenticated(H: bytes -> bytes, L: nat, a: bytes, b: bytes)
    requires HashLen(H, L)
    ensures VerifyInclusion(H, L, Root(H, [a, b]), 2, 3, [Step(Lt, LeafH(H, a))], b)
    ensures |[a, b]| != 3
  {
    assert Split(2) == 1 by { SplitIs(2, 0); }
    assert Split(3) == 2 by { SplitIs(3, 1); }
    assert Shape(0, 1) == [];
    assert Shape(0, 1) == [] && Shape(2, 3) == Shape(0, 1) + [Lt];
    RootLen(H, L, [a]);
    assert Root(H, [a, b]) == NodeH(H, LeafH(H, a), LeafH(H, b));
    assert [a, b][..1] == [a] && [a, b][1..] == [b];
  }

  // =================================================================================================================
  // CONSISTENCY PROOFS (ledger.ts verifyLedgerConsistency, RFC 9162 section 2.1.4.2)
  // =================================================================================================================
  function IsPow2(m: int): bool
    decreases m
  { m >= 1 && (m == 1 || (m % 2 == 0 && IsPow2(m / 2))) }

  // `while (fn & 1) { fn >>= 1; sn >>= 1 }`
  function PreShift(fn: nat, sn: nat): (nat, nat)
    ensures PreShift(fn, sn).0 <= fn && PreShift(fn, sn).1 <= sn
    decreases fn
  { if fn % 2 == 1 then PreShift(fn / 2, sn / 2) else (fn, sn) }
  function PreJ(fn: nat): nat
    decreases fn
  { if fn % 2 == 1 then 1 + PreJ(fn / 2) else 0 }

  // `while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1 }`
  function SkipEven(fn: nat, sn: nat): (nat, nat)
    ensures SkipEven(fn, sn).0 <= fn && SkipEven(fn, sn).1 <= sn
    decreases fn
  { if fn % 2 == 0 && fn != 0 then SkipEven(fn / 2, sn / 2) else (fn, sn) }
  function SkipJ(fn: nat): nat
    decreases fn
  { if fn % 2 == 0 && fn != 0 then 1 + SkipJ(fn / 2) else 0 }

  // The verify loop over the remaining proof elements (state fn, sn, fr, sr). Every element must be exactly L bytes.
  function CLoop(H: bytes -> bytes, L: nat, fn: nat, sn: nat, fr: bytes, sr: bytes, p: seq<bytes>): Option<(bytes, bytes)>
    decreases |p|
  {
    if |p| == 0 then (if sn == 0 then Some((fr, sr)) else None)
    else if sn == 0 then None
    else if |p[0]| != L then None
    else if fn % 2 == 1 || fn == sn then
      var se := SkipEven(fn, sn);
      CLoop(H, L, se.0 / 2, se.1 / 2, NodeH(H, p[0], fr), NodeH(H, p[0], sr), p[1..])
    else
      CLoop(H, L, fn / 2, sn / 2, fr, NodeH(H, sr, p[0]), p[1..])
  }

  // THE VERIFIER (compiled). Roots are already-decoded bytes. Strictness vs the TypeScript: see the notes (all roots/elements are L bytes;
  // an empty old tree requires oldRoot == H("")).
  function VerifyConsistency(H: bytes -> bytes, L: nat, oldRoot: bytes, newRoot: bytes, m: int, n: int, p: seq<bytes>): bool
  {
    if m < 0 || m > n then false
    // RFC 9162 2.1.4.1: from the EMPTY tree consistency is vacuous, but the old root must BE the empty-tree root and the path empty;
    // the new root is unconstrained unless the new tree is empty too (then it is the empty-tree root as well).
    else if m == 0 then |p| == 0 && oldRoot == H([]) && (n == 0 ==> newRoot == H([]))
    else if m == n then |p| == 0 && oldRoot == newRoot
    else VerMid(H, L, oldRoot, newRoot, m, n, p)
  }

  // 0 < m < n
  function VerMid(H: bytes -> bytes, L: nat, oldRoot: bytes, newRoot: bytes, m: int, n: int, p: seq<bytes>): bool
    requires 0 < m < n
  {
    var path := if IsPow2(m) then [oldRoot] + p else p;
    |path| >= 1 && |oldRoot| == L && |newRoot| == L && |path[0]| == L &&
    var ps := PreShift(m - 1, n - 1);
    var r := CLoop(H, L, ps.0, ps.1, path[0], path[0], path[1..]);
    r.Some? && r.v.0 == oldRoot && r.v.1 == newRoot
  }

  // ---- honest values -------------------------------------------------------------------------------------------
  function Mn(a: int, b: int): int { if a < b then a else b }

  // Hash of the level-l block j of the (bottom-up, rightmost-promoted) tree over ds: leaves [j*2^l, min((j+1)*2^l, |ds|)).
  function NB(H: bytes -> bytes, ds: seq<bytes>, l: nat, j: nat): bytes
  {
    var a := j * Pow2(l);
    var b := Mn((j + 1) * Pow2(l), |ds|);
    if a < b then Root(H, ds[a..b]) else H([])
  }
  // Hash of the part of that block that lies inside the OLD tree (first m leaves).
  function OP(H: bytes -> bytes, ds: seq<bytes>, m: nat, l: nat, j: nat): bytes
  {
    var a := j * Pow2(l);
    if a < m && m <= |ds| then Root(H, ds[a..m]) else H([])
  }

  // Level-l position invariant: fn = (m-1) / 2^l and sn = (n-1) / 2^l.
  ghost predicate WF(n: nat, m: nat, l: nat, fn: nat, sn: nat)
  {
    1 <= m && m <= n && 1 <= n &&
    fn * Pow2(l) <= m - 1 < (fn + 1) * Pow2(l) &&
    sn * Pow2(l) <= n - 1 < (sn + 1) * Pow2(l)
  }

  lemma MulMono(x: int, y: int, P: int)
    requires x <= y && P >= 0
    ensures x * P <= y * P
  { assert y * P == x * P + (y - x) * P; NonNegMul(y - x, P); }
  lemma NonNegMul(a: int, b: int)
    requires a >= 0 && b >= 0
    ensures a * b >= 0
    decreases a
  { if a > 0 { NonNegMul(a - 1, b); assert a * b == (a - 1) * b + b; } }

  lemma WFNext(n: nat, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(n, m, l, fn, sn)
    ensures WF(n, m, l + 1, fn / 2, sn / 2)
  {
    var P := Pow2(l);
    assert Pow2(l + 1) == 2 * P;
    MulMono((fn / 2) * 2, fn, P);
    assert (fn / 2) * (2 * P) == ((fn / 2) * 2) * P;
    MulMono(fn + 1, (fn / 2 + 1) * 2, P);
    assert (fn / 2 + 1) * (2 * P) == ((fn / 2 + 1) * 2) * P;
    MulMono((sn / 2) * 2, sn, P);
    assert (sn / 2) * (2 * P) == ((sn / 2) * 2) * P;
    MulMono(sn + 1, (sn / 2 + 1) * 2, P);
    assert (sn / 2 + 1) * (2 * P) == ((sn / 2 + 1) * 2) * P;
  }

  // The RFC 6962 split of a block-aligned range.
  lemma RangeSplit(H: bytes -> bytes, ds: seq<bytes>, a: nat, b: nat, l: nat)
    requires a + Pow2(l) < b <= a + 2 * Pow2(l) && b <= |ds|
    ensures Root(H, ds[a..b]) == NodeH(H, Root(H, ds[a..a + Pow2(l)]), Root(H, ds[a + Pow2(l)..b]))
  {
    var P := Pow2(l);
    SplitIs(b - a, l);
    var s := ds[a..b];
    assert Split(|s|) == P;
    assert s[..P] == ds[a..a + P];
    assert s[P..] == ds[a + P..b];
  }

  // Odd step (sibling on the left): block fn-1 (full) joins block fn.
  lemma StepA(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(|ds|, m, l, fn, sn) && fn <= sn && fn % 2 == 1
    ensures NodeH(H, NB(H, ds, l, fn - 1), NB(H, ds, l, fn)) == NB(H, ds, l + 1, fn / 2)
    ensures NodeH(H, NB(H, ds, l, fn - 1), OP(H, ds, m, l, fn)) == OP(H, ds, m, l + 1, fn / 2)
  {
    var P := Pow2(l);
    var n := |ds|;
    assert Pow2(l + 1) == 2 * P;
    MulMono(fn, sn, P);
    assert fn * P < n;
    assert (fn - 1) * P + P == fn * P;
    assert (fn / 2) * (2 * P) == (fn - 1) * P;
    // new block
    var a := (fn - 1) * P;
    var b := Mn((fn + 1) * P, n);
    assert b <= a + 2 * P;
    assert a + P < b;
    RangeSplit(H, ds, a, b, l);
    assert Mn(fn * P, n) == fn * P;
    // old part
    assert fn * P < m;
    assert m <= (fn + 1) * P;
    RangeSplit(H, ds, a, m, l);
  }

  // Even step with a right sibling: block fn joins block fn+1 (clipped at n); the old part is unchanged.
  lemma StepB(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(|ds|, m, l, fn, sn) && fn < sn && fn % 2 == 0
    ensures NodeH(H, NB(H, ds, l, fn), NB(H, ds, l, fn + 1)) == NB(H, ds, l + 1, fn / 2)
    ensures OP(H, ds, m, l + 1, fn / 2) == OP(H, ds, m, l, fn)
  {
    var P := Pow2(l);
    var n := |ds|;
    assert Pow2(l + 1) == 2 * P;
    MulMono(fn + 1, sn, P);
    assert (fn + 1) * P < n;
    assert (fn / 2) * (2 * P) == fn * P;
    var a := fn * P;
    var b := Mn((fn + 2) * P, n);
    assert a + P == (fn + 1) * P;
    assert a + P < b;
    assert b <= a + 2 * P;
    RangeSplit(H, ds, a, b, l);
    assert (fn / 2 + 1) * (2 * P) == (fn + 2) * P;
  }

  // Promotion: fn == sn (even, nonzero) means the block is the unpaired tail; it is promoted until it is a right child.
  lemma Promote(H: bytes -> bytes, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(|ds|, m, l, fn, sn) && fn == sn
    ensures var se := SkipEven(fn, sn);
            WF(|ds|, m, l + SkipJ(fn), se.0, se.1) && se.0 == se.1 && (fn != 0 ==> se.0 % 2 == 1)
            && NB(H, ds, l + SkipJ(fn), se.0) == NB(H, ds, l, fn)
            && OP(H, ds, m, l + SkipJ(fn), se.0) == OP(H, ds, m, l, fn)
    decreases fn
  {
    if fn % 2 == 0 && fn != 0 {
      WFNext(|ds|, m, l, fn, sn);
      var P := Pow2(l);
      var n := |ds|;
      assert Pow2(l + 1) == 2 * P;
      assert (fn / 2) * (2 * P) == fn * P;
      Promote(H, ds, m, l + 1, fn / 2, sn / 2);
      // same block: n <= (fn+1)*P so both ranges end at n
      assert Mn((fn + 1) * P, n) == n;
      assert Mn((fn / 2 + 1) * (2 * P), n) == n by { assert (fn / 2 + 1) * (2 * P) == (fn + 2) * P; }
      assert l + 1 + SkipJ(fn / 2) == l + SkipJ(fn);
    }
  }

  // Expected proof elements from state (l, fn, sn): what an honest prover supplies, in consumption order.
  function HL(H: bytes -> bytes, ds: seq<bytes>, l: nat, fn: nat, sn: nat): seq<bytes>
    decreases sn
  {
    if sn == 0 then []
    else if fn % 2 == 1 || fn == sn then
      var se := SkipEven(fn, sn);
      var j := SkipJ(fn);
      [NB(H, ds, l + j, if se.0 >= 1 then se.0 - 1 else 0)] + HL(H, ds, l + j + 1, se.0 / 2, se.1 / 2)
    else
      [NB(H, ds, l, fn + 1)] + HL(H, ds, l + 1, fn / 2, sn / 2)
  }

  // One "left sibling" iteration (odd, or tail block promoted to a right child).
  lemma XStep(H: bytes -> bytes, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(|ds|, m, l, fn, sn) && fn <= sn && sn != 0 && (fn % 2 == 1 || fn == sn)
    ensures var se := SkipEven(fn, sn); var l2 := l + SkipJ(fn);
            WF(|ds|, m, l2, se.0, se.1) && se.0 % 2 == 1 && se.0 <= se.1
            && NB(H, ds, l2, se.0) == NB(H, ds, l, fn) && OP(H, ds, m, l2, se.0) == OP(H, ds, m, l, fn)
            && NodeH(H, NB(H, ds, l2, se.0 - 1), NB(H, ds, l2, se.0)) == NB(H, ds, l2 + 1, se.0 / 2)
            && NodeH(H, NB(H, ds, l2, se.0 - 1), OP(H, ds, m, l2, se.0)) == OP(H, ds, m, l2 + 1, se.0 / 2)
            && WF(|ds|, m, l2 + 1, se.0 / 2, se.1 / 2) && se.0 / 2 <= se.1 / 2
  {
    if fn % 2 == 1 {
      assert SkipEven(fn, sn) == (fn, sn) && SkipJ(fn) == 0;
      StepA(H, 0, ds, m, l, fn, sn);
      WFNext(|ds|, m, l, fn, sn);
    } else {
      Promote(H, ds, m, l, fn, sn);
      var se := SkipEven(fn, sn);
      var l2 := l + SkipJ(fn);
      StepA(H, 0, ds, m, l2, se.0, se.1);
      WFNext(|ds|, m, l2, se.0, se.1);
    }
  }

  lemma BStep(H: bytes -> bytes, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(|ds|, m, l, fn, sn) && fn < sn && fn % 2 == 0
    ensures NodeH(H, NB(H, ds, l, fn), NB(H, ds, l, fn + 1)) == NB(H, ds, l + 1, fn / 2)
            && OP(H, ds, m, l + 1, fn / 2) == OP(H, ds, m, l, fn)
            && WF(|ds|, m, l + 1, fn / 2, sn / 2) && fn / 2 <= sn / 2
  {
    StepB(H, 0, ds, m, l, fn, sn);
    WFNext(|ds|, m, l, fn, sn);
  }

  lemma NBLen(H: bytes -> bytes, L: nat, ds: seq<bytes>, l: nat, j: nat)
    requires HashLen(H, L)
    ensures |NB(H, ds, l, j)| == L
  {
    var a := j * Pow2(l);
    var b := Mn((j + 1) * Pow2(l), |ds|);
    if a < b { RootLen(H, L, ds[a..b]); }
  }
  lemma OPLen(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: nat, l: nat, j: nat)
    requires HashLen(H, L)
    ensures |OP(H, ds, m, l, j)| == L
  {
    var a := j * Pow2(l);
    if a < m && m <= |ds| { RootLen(H, L, ds[a..m]); }
  }

  // ---- COMPLETENESS of the loop: honest elements from an honest state reach (Root(old), Root(new)) -----------------
  lemma ConsForward(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat)
    requires HashLen(H, L)
    requires WF(|ds|, m, l, fn, sn) && fn <= sn
    ensures CLoop(H, L, fn, sn, OP(H, ds, m, l, fn), NB(H, ds, l, fn), HL(H, ds, l, fn, sn)).Some?
    ensures CLoop(H, L, fn, sn, OP(H, ds, m, l, fn), NB(H, ds, l, fn), HL(H, ds, l, fn, sn)).v == (Root(H, ds[..m]), Root(H, ds))
    decreases sn
  {
    var P := Pow2(l);
    if sn == 0 {
      assert fn == 0;
      assert |ds| <= P;
      assert OP(H, ds, m, l, 0) == Root(H, ds[..m]) by { assert ds[0..m] == ds[..m]; }
      assert NB(H, ds, l, 0) == Root(H, ds) by { assert Mn(P, |ds|) == |ds|; assert ds[0..|ds|] == ds; }
    } else if fn % 2 == 1 || fn == sn {
      XStep(H, ds, m, l, fn, sn);
      var se := SkipEven(fn, sn);
      var l2 := l + SkipJ(fn);
      NBLen(H, L, ds, l2, se.0 - 1);
      var c := NB(H, ds, l2, se.0 - 1);
      assert HL(H, ds, l, fn, sn) == [c] + HL(H, ds, l2 + 1, se.0 / 2, se.1 / 2);
      ConsForward(H, L, ds, m, l2 + 1, se.0 / 2, se.1 / 2);
    } else {
      BStep(H, ds, m, l, fn, sn);
      NBLen(H, L, ds, l, fn + 1);
      assert HL(H, ds, l, fn, sn) == [NB(H, ds, l, fn + 1)] + HL(H, ds, l + 1, fn / 2, sn / 2);
      ConsForward(H, L, ds, m, l + 1, fn / 2, sn / 2);
    }
  }

  // ---- SOUNDNESS of the loop (backward induction) --------------------------------------------------------------------
  // If the loop ends with the true new root, then (barring a collision) the state's new-side hash and every remaining proof element are the honest ones.
  lemma ConsBack(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: nat, l: nat, fn: nat, sn: nat, fr: bytes, sr: bytes, p: seq<bytes>)
    requires HashLen(H, L)
    requires WF(|ds|, m, l, fn, sn) && fn <= sn && |sr| == L
    requires CLoop(H, L, fn, sn, fr, sr, p).Some? && CLoop(H, L, fn, sn, fr, sr, p).v.1 == Root(H, ds)
    ensures Collides(H) || (sr == NB(H, ds, l, fn) && p == HL(H, ds, l, fn, sn))
    decreases |p|
  {
    var P := Pow2(l);
    if |p| == 0 {
      assert sn == 0 && fn == 0;
      assert |ds| <= P;
      assert NB(H, ds, l, 0) == Root(H, ds) by { assert Mn(P, |ds|) == |ds|; assert ds[0..|ds|] == ds; }
    } else if fn % 2 == 1 || fn == sn {
      XStep(H, ds, m, l, fn, sn);
      var se := SkipEven(fn, sn);
      var l2 := l + SkipJ(fn);
      var c := p[0];
      assert |c| == L;
      var fr2 := NodeH(H, c, fr);
      var sr2 := NodeH(H, c, sr);
      assert |sr2| == L;
      ConsBack(H, L, ds, m, l2 + 1, se.0 / 2, se.1 / 2, fr2, sr2, p[1..]);
      if !Collides(H) {
        NBLen(H, L, ds, l2, se.0 - 1);
        NBLen(H, L, ds, l2, se.0);
        NodeEq(H, L, c, sr, NB(H, ds, l2, se.0 - 1), NB(H, ds, l2, se.0));
        assert HL(H, ds, l, fn, sn) == [NB(H, ds, l2, se.0 - 1)] + HL(H, ds, l2 + 1, se.0 / 2, se.1 / 2);
        assert p == [p[0]] + p[1..];
      }
    } else {
      BStep(H, ds, m, l, fn, sn);
      var c := p[0];
      var sr2 := NodeH(H, sr, c);
      assert |sr2| == L;
      ConsBack(H, L, ds, m, l + 1, fn / 2, sn / 2, fr, sr2, p[1..]);
      if !Collides(H) {
        NBLen(H, L, ds, l, fn);
        NBLen(H, L, ds, l, fn + 1);
        NodeEq(H, L, sr, c, NB(H, ds, l, fn), NB(H, ds, l, fn + 1));
        assert HL(H, ds, l, fn, sn) == [NB(H, ds, l, fn + 1)] + HL(H, ds, l + 1, fn / 2, sn / 2);
        assert p == [p[0]] + p[1..];
      }
    }
  }

  // Dropping the low (odd) bits of m-1 and n-1 together: the base block of the old tree.
  lemma PreShiftWF(n: nat, m: nat, l: nat, fn: nat, sn: nat)
    requires WF(n, m, l, fn, sn) && fn <= sn
    ensures var ps := PreShift(fn, sn); var l2 := l + PreJ(fn);
            WF(n, m, l2, ps.0, ps.1) && ps.0 <= ps.1 && ps.0 % 2 == 0 && (ps.0 + 1) * Pow2(l2) == (fn + 1) * Pow2(l)
    decreases fn
  {
    if fn % 2 == 1 {
      WFNext(n, m, l, fn, sn);
      PreShiftWF(n, m, l + 1, fn / 2, sn / 2);
      assert Pow2(l + 1) == 2 * Pow2(l);
      assert (fn / 2 + 1) * (2 * Pow2(l)) == (fn + 1) * Pow2(l);
    }
  }

  lemma Pow2PreShift(m: nat, s: nat)
    requires IsPow2(m)
    ensures PreShift(m - 1, s).0 == 0
    decreases m
  { if m > 1 { Pow2PreShift(m / 2, s / 2); } }

  // The honest consistency proof elements for (m, |ds|), in the order the TypeScript consumes them (after the optional old-root prepend).
  function HonestCons(H: bytes -> bytes, ds: seq<bytes>, m: int): seq<bytes>
  {
    if m <= 0 || m >= |ds| then []
    else
      var ps := PreShift(m - 1, |ds| - 1);
      var t := PreJ(m - 1);
      (if IsPow2(m) then [] else [NB(H, ds, t, ps.0)]) + HL(H, ds, t, ps.0, ps.1)
  }

  lemma BaseBlock(H: bytes -> bytes, ds: seq<bytes>, m: nat)
    requires 1 <= m < |ds|
    ensures var ps := PreShift(m - 1, |ds| - 1); var t := PreJ(m - 1);
            WF(|ds|, m, t, ps.0, ps.1) && ps.0 <= ps.1
            && NB(H, ds, t, ps.0) == OP(H, ds, m, t, ps.0)
            && OP(H, ds, m, t, ps.0) == Root(H, ds[ps.0 * Pow2(t)..m])
            && ps.0 * Pow2(t) < m
            && (ps.0 + 1) * Pow2(t) == m
            && (IsPow2(m) ==> ps.0 == 0)
  {
    var ps := PreShift(m - 1, |ds| - 1);
    var t := PreJ(m - 1);
    assert Pow2(0) == 1;
    PreShiftWF(|ds|, m, 0, m - 1, |ds| - 1);
    assert (ps.0 + 1) * Pow2(t) == m;
    assert ps.0 * Pow2(t) + Pow2(t) == m;
    assert Pow2(t) >= 1;
    if IsPow2(m) { Pow2PreShift(m, |ds| - 1); }
    assert Mn((ps.0 + 1) * Pow2(t), |ds|) == m;
  }

  lemma ConsCompleteMid(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: int)
    requires HashLen(H, L)
    requires 0 < m < |ds|
    ensures VerMid(H, L, Root(H, ds[..m]), Root(H, ds), m, |ds|, HonestCons(H, ds, m))
  {
    RootLen(H, L, ds[..m]);
    RootLen(H, L, ds);
    BaseBlock(H, ds, m);
    var ps := PreShift(m - 1, |ds| - 1);
    var t := PreJ(m - 1);
    var base := NB(H, ds, t, ps.0);
    if IsPow2(m) { assert ps.0 == 0; assert ds[0..m] == ds[..m]; assert base == Root(H, ds[..m]); }
    ConsForward(H, L, ds, m, t, ps.0, ps.1);
    NBLen(H, L, ds, t, ps.0);
    var hc := HonestCons(H, ds, m);
    var path := if IsPow2(m) then [Root(H, ds[..m])] + hc else hc;
    assert path[0] == base;
    assert path[1..] == HL(H, ds, t, ps.0, ps.1);
    assert OP(H, ds, m, t, ps.0) == base;
  }

  // COMPLETENESS (every honest tree, every 0 <= m <= n): the honest proof is accepted for the honest roots.
  lemma ConsComplete(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: int)
    requires HashLen(H, L)
    requires 0 <= m <= |ds|
    ensures VerifyConsistency(H, L, Root(H, ds[..m]), Root(H, ds), m, |ds|, HonestCons(H, ds, m))
  {
    if m == 0 { assert ds[..0] == []; }
    else if m == |ds| { assert ds[..m] == ds; }
    else { ConsCompleteMid(H, L, ds, m); }
  }

  // SOUNDNESS: an accepted consistency proof for (oldRoot, newRoot, m, n), checked against ANY leaf list of size n whose tree hash is newRoot,
  // proves oldRoot is the tree hash of its first m leaves -- unless H collides.
  lemma ConsSound(H: bytes -> bytes, L: nat, ds: seq<bytes>, oldRoot: bytes, newRoot: bytes, m: int, p: seq<bytes>)
    requires HashLen(H, L)
    requires VerifyConsistency(H, L, oldRoot, newRoot, m, |ds|, p)
    requires Root(H, ds) == newRoot
    ensures Root(H, ds[..m]) == oldRoot || Collides(H)
  {
    if m == 0 { assert ds[..0] == []; }
    else if m == |ds| { assert ds[..m] == ds; }
    else {
      BaseBlock(H, ds, m);
      var ps := PreShift(m - 1, |ds| - 1);
      var t := PreJ(m - 1);
      var path := if IsPow2(m) then [oldRoot] + p else p;
      var r := CLoop(H, L, ps.0, ps.1, path[0], path[0], path[1..]);
      ConsBack(H, L, ds, m, t, ps.0, ps.1, path[0], path[0], path[1..]);
      if !Collides(H) {
        assert path[0] == NB(H, ds, t, ps.0);
        ConsForward(H, L, ds, m, t, ps.0, ps.1);
        assert path[0] == OP(H, ds, m, t, ps.0);
        assert r.v == (Root(H, ds[..m]), Root(H, ds));
      }
    }
  }

  // PREFIX PROPERTY (two logs): if H is collision-free, an accepted proof between the root of log A (size m) and the root of log B (size n)
  // means A is exactly the first m entries of B.
  lemma ConsPrefix(H: bytes -> bytes, L: nat, a: seq<bytes>, b: seq<bytes>, p: seq<bytes>)
    requires HashLen(H, L)
    requires VerifyConsistency(H, L, Root(H, a), Root(H, b), |a|, |b|, p)
    ensures a == b[..|a|] || Collides(H)
  {
    ConsSound(H, L, b, Root(H, a), Root(H, b), |a|, p);
    if !Collides(H) { RootInj(H, L, b[..|a|], a); }
  }

  // The proof length is bounded by the bit length of n-1 (so verification is O(log n); an over-long proof is rejected by the sn == 0 guard).
  function Bits(x: nat): nat decreases x { if x == 0 then 0 else 1 + Bits(x / 2) }
  lemma LoopLenBound(H: bytes -> bytes, L: nat, fn: nat, sn: nat, fr: bytes, sr: bytes, p: seq<bytes>)
    requires CLoop(H, L, fn, sn, fr, sr, p).Some?
    ensures |p| <= Bits(sn)
    decreases |p|
  {
    if |p| > 0 {
      if fn % 2 == 1 || fn == sn {
        var se := SkipEven(fn, sn);
        LoopLenBound(H, L, se.0 / 2, se.1 / 2, NodeH(H, p[0], fr), NodeH(H, p[0], sr), p[1..]);
        BitsMono(se.1 / 2, sn / 2);
      } else {
        LoopLenBound(H, L, fn / 2, sn / 2, fr, NodeH(H, sr, p[0]), p[1..]);
      }
    }
  }
  lemma BitsMono(a: nat, b: nat)
    requires a <= b
    ensures Bits(a) <= Bits(b)
    decreases b
  { if a > 0 { BitsMono(a / 2, b / 2); } }

  lemma ConsFailClosed(H: bytes -> bytes, L: nat, oldRoot: bytes, newRoot: bytes, m: int, n: int, p: seq<bytes>)
    ensures (m < 0 || m > n) ==> !VerifyConsistency(H, L, oldRoot, newRoot, m, n, p)
    ensures (0 < m < n && ((IsPow2(m) && |oldRoot| != L) || |newRoot| != L)) ==> !VerifyConsistency(H, L, oldRoot, newRoot, m, n, p)
    ensures (m == n && m > 0 && oldRoot != newRoot) ==> !VerifyConsistency(H, L, oldRoot, newRoot, m, n, p)
    ensures (m == n && m > 0 && |p| > 0) ==> !VerifyConsistency(H, L, oldRoot, newRoot, m, n, p)
    ensures (0 < m < n && exists i :: 0 <= i < |p| && |p[i]| != L) ==> !VerifyConsistency(H, L, oldRoot, newRoot, m, n, p)
  {
    if 0 < m < n && exists i :: 0 <= i < |p| && |p[i]| != L {
      var i :| 0 <= i < |p| && |p[i]| != L;
      var path := if IsPow2(m) then [oldRoot] + p else p;
      var ps := PreShift(m - 1, n - 1);
      CLoopLenFail(H, L, ps.0, ps.1, path[0], path[0], path[1..], if IsPow2(m) then i else i - 1);
    }
  }
  // any wrong-length element anywhere in the consumed part makes the loop fail (or the element is path[0]).
  lemma CLoopLenFail(H: bytes -> bytes, L: nat, fn: nat, sn: nat, fr: bytes, sr: bytes, p: seq<bytes>, i: int)
    requires i == -1 ==> true
    ensures (0 <= i < |p| && |p[i]| != L) ==> CLoop(H, L, fn, sn, fr, sr, p).None?
    decreases |p|
  {
    if 0 <= i < |p| && |p[i]| != L && |p| > 0 && sn != 0 {
      if i > 0 {
        if fn % 2 == 1 || fn == sn {
          var se := SkipEven(fn, sn);
          CLoopLenFail(H, L, se.0 / 2, se.1 / 2, NodeH(H, p[0], fr), NodeH(H, p[0], sr), p[1..], i - 1);
        } else {
          CLoopLenFail(H, L, fn / 2, sn / 2, fr, NodeH(H, sr, p[0]), p[1..], i - 1);
        }
      }
    }
  }

  // The tree hash a (well-shaped) inclusion proof folds to; used by size-bound callers (revocation.ts bindRoot(size, tree)).
  function InclusionRoot(H: bytes -> bytes, L: nat, index: int, size: int, path: seq<Step>, leaf: bytes): Option<bytes>
  {
    if 1 <= size && 0 <= index < size && Sides(path) == Shape(index, size) && (forall i :: 0 <= i < |path| ==> |path[i].hash| == L)
    then Some(IncFold(H, LeafH(H, leaf), path)) else None
  }

  lemma InclusionRootIff(H: bytes -> bytes, L: nat, root: bytes, index: int, size: int, path: seq<Step>, leaf: bytes)
    ensures VerifyInclusion(H, L, root, index, size, path, leaf) <==> InclusionRoot(H, L, index, size, path, leaf) == Some(root)
  {}

  // =================================================================================================================
  // THE PROOF GENERATOR (ledger.ts consistencyProof = RFC 6962 SUBPROOF) equals the honest list the verifier expects
  // =================================================================================================================
  function SubProof(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool): seq<bytes>
    requires 0 < m <= |ds|
    decreases |ds|
  {
    if m == |ds| then (if b then [] else [Root(H, ds)])
    else
      var k := Split(|ds|);
      if m <= k then SubProof(H, ds[..k], m, b) + [Root(H, ds[k..])]
      else SubProof(H, ds[k..], m - k, false) + [Root(H, ds[..k])]
  }

  function SubModel(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool): seq<bytes>
    requires 0 < m <= |ds|
  {
    if m == |ds| then (if b then [] else [Root(H, ds)])
    else
      var ps := PreShift(m - 1, |ds| - 1);
      var t := PreJ(m - 1);
      (if b && IsPow2(m) then [] else [NB(H, ds, t, ps.0)]) + HL(H, ds, t, ps.0, ps.1)
  }

  lemma Pow2Add(a: nat, b: nat)
    ensures Pow2(a + b) == Pow2(a) * Pow2(b)
    decreases b
  { if b > 0 { Pow2Add(a, b - 1); assert Pow2(a + b) == 2 * Pow2(a + b - 1); assert Pow2(b) == 2 * Pow2(b - 1); } }

  lemma QuotGe(s: int, P: int, x: int, c: int)
    requires P > 0 && s * P <= x < (s + 1) * P && c * P <= x
    ensures s >= c
  { if s < c { MulMono(s + 1, c, P); } }
  lemma QuotLt(s: int, P: int, x: int, c: int)
    requires P > 0 && s * P <= x < (s + 1) * P && x < c * P
    ensures s < c
  { if s >= c { MulMono(c, s, P); } }

  lemma NBShift(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat, jb: nat)
    requires l <= j && Pow2(j) < |ds|
    ensures NB(H, ds, l, jb + Pow2(j - l)) == NB(H, ds[Pow2(j)..], l, jb)
  {
    var P := Pow2(l);
    var Q := Pow2(j - l);
    var K := Pow2(j);
    Pow2Add(l, j - l);
    assert K == P * Q;
    assert (jb + Q) * P == jb * P + K;
    assert (jb + Q + 1) * P == (jb + 1) * P + K;
    var n := |ds|;
    var d2 := ds[K..];
    var a := jb * P;
    var b := Mn((jb + 1) * P, |d2|);
    assert Mn((jb + Q + 1) * P, n) == K + b;
    if a < b {
      assert d2[a..b] == ds[K + a..K + b];
    }
  }

  lemma NBLeft(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat, jb: nat)
    requires l <= j && Pow2(j) < |ds| && jb + 1 <= Pow2(j - l)
    ensures NB(H, ds, l, jb) == NB(H, ds[..Pow2(j)], l, jb)
  {
    var P := Pow2(l);
    var Q := Pow2(j - l);
    var K := Pow2(j);
    Pow2Add(l, j - l);
    MulMono(jb + 1, Q, P);
    assert (jb + 1) * P <= K;
    var a := jb * P;
    var b := Mn((jb + 1) * P, |ds|);
    assert b == (jb + 1) * P;
    assert Mn((jb + 1) * P, K) == (jb + 1) * P;
    if a < b { assert ds[..K][a..b] == ds[a..b]; }
  }

  lemma SkipEvenPow(i: nat)
    ensures SkipEven(Pow2(i), Pow2(i)) == (1, 1) && SkipJ(Pow2(i)) == i
  {
    if i > 0 { assert Pow2(i) == 2 * Pow2(i - 1); SkipEvenPow(i - 1); assert Pow2(i) % 2 == 0 && Pow2(i) != 0; }
  }

  // The unpaired tail block, promoted to the level of the cut: the last proof element is the root of the first K leaves.
  lemma HLTail(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat)
    requires l <= j && Pow2(j) < |ds| <= 2 * Pow2(j)
    ensures HL(H, ds, l, Pow2(j - l), Pow2(j - l)) == [Root(H, ds[..Pow2(j)])]
  {
    SkipEvenPow(j - l);
    var K := Pow2(j);
    assert NB(H, ds, j, 0) == Root(H, ds[..K]) by { assert Mn((0 + 1) * K, |ds|) == K; assert ds[0..K] == ds[..K]; }
  }

  // left sub-problem: the first K = 2^j leaves
  lemma HLLeft(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat, fn: nat, sn: nat)
    requires l <= j && Pow2(j) < |ds| <= 2 * Pow2(j)
    requires fn <= Pow2(j - l) - 1 && Pow2(j - l) <= sn < 2 * Pow2(j - l)
    ensures HL(H, ds, l, fn, sn) == HL(H, ds[..Pow2(j)], l, fn, Pow2(j - l) - 1) + [Root(H, ds[Pow2(j)..])]
    decreases j - l
  {
    var K := Pow2(j);
    var ds1 := ds[..K];
    if l == j {
      assert fn == 0 && sn == 1;
      assert NB(H, ds, j, 1) == Root(H, ds[K..]) by { assert Mn((1 + 1) * K, |ds|) == |ds|; assert ds[K..|ds|] == ds[K..]; }
      assert HL(H, ds1, j, 0, 0) == [];
    } else {
      assert Pow2(j - l) == 2 * Pow2(j - l - 1);
      var q := Pow2(j - l - 1);
      assert Pow2(j - l) >= 2;
      if fn % 2 == 1 {
        NBLeft(H, ds, j, l, fn - 1);
        HLLeft(H, ds, j, l + 1, fn / 2, sn / 2);
        assert Pow2(j - (l + 1)) == q;
        assert (Pow2(j - l) - 1) / 2 == q - 1;
        assert SkipEven(fn, sn) == (fn, sn) && SkipJ(fn) == 0;
        assert SkipEven(fn, Pow2(j - l) - 1) == (fn, Pow2(j - l) - 1) && SkipJ(fn) == 0;
      } else {
        NBLeft(H, ds, j, l, fn + 1);
        HLLeft(H, ds, j, l + 1, fn / 2, sn / 2);
        assert Pow2(j - (l + 1)) == q;
        assert (Pow2(j - l) - 1) / 2 == q - 1;
        assert fn != sn && fn != Pow2(j - l) - 1;
      }
    }
  }

  // Offset relations for the right sub-problem.
  lemma SEOff(fn: nat, sn: nat, i: nat)
    requires sn > 0 && fn <= sn < Pow2(i) && (fn % 2 == 1 || fn == sn)
    ensures SkipJ(fn + Pow2(i)) == SkipJ(fn) && SkipJ(fn) < i
    ensures SkipEven(fn + Pow2(i), sn + Pow2(i)) == (SkipEven(fn, sn).0 + Pow2(i - SkipJ(fn)), SkipEven(fn, sn).1 + Pow2(i - SkipJ(fn)))
    decreases fn
  {
    assert i >= 1;
    assert Pow2(i) == 2 * Pow2(i - 1);
    if fn % 2 == 1 {
    } else {
      assert fn == sn && fn > 0;
      assert (fn + Pow2(i)) % 2 == 0 && fn + Pow2(i) != 0;
      assert (fn + Pow2(i)) / 2 == fn / 2 + Pow2(i - 1);
      assert (sn + Pow2(i)) / 2 == sn / 2 + Pow2(i - 1);
      SEOff(fn / 2, sn / 2, i - 1);
    }
  }

  lemma NBShiftHelp(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat, jb: nat)
    requires l <= j && Pow2(j) < |ds|
    ensures NB(H, ds, l, jb + Pow2(j - l)) == NB(H, ds[Pow2(j)..], l, jb)
  { NBShift(H, ds, j, l, jb); }

  // right sub-problem: leaves K.. shifted into the big tree by the block offset Pow2(j-l)
  lemma HLRight(H: bytes -> bytes, ds: seq<bytes>, j: nat, l: nat, fn: nat, sn: nat)
    requires l <= j && Pow2(j) < |ds| <= 2 * Pow2(j)
    requires fn <= sn < Pow2(j - l)
    ensures HL(H, ds, l, fn + Pow2(j - l), sn + Pow2(j - l)) == HL(H, ds[Pow2(j)..], l, fn, sn) + [Root(H, ds[..Pow2(j)])]
    decreases sn
  {
    var K := Pow2(j);
    var ds2 := ds[K..];
    var O := Pow2(j - l);
    if sn == 0 {
      assert fn == 0;
      HLTail(H, ds, j, l);
      assert HL(H, ds2, l, 0, 0) == [];
    } else {
      assert l < j;
      assert O == 2 * Pow2(j - l - 1);
      assert O % 2 == 0;
      if fn % 2 == 1 || fn == sn {
        SEOff(fn, sn, j - l);
        var r := SkipJ(fn);
        var se := SkipEven(fn, sn);
        assert (fn + O) % 2 == 1 || fn + O == sn + O;
        var seB := SkipEven(fn + O, sn + O);
        assert seB == (se.0 + Pow2(j - l - r), se.1 + Pow2(j - l - r));
        // se.0 >= 1 and se.1 < Pow2(j-l-r)
        SEBound(fn, sn, j - l);
        assert Pow2(j - l - r) == 2 * Pow2(j - l - r - 1);
        assert (se.0 + Pow2(j - l - r)) / 2 == se.0 / 2 + Pow2(j - l - r - 1);
        assert (se.1 + Pow2(j - l - r)) / 2 == se.1 / 2 + Pow2(j - l - r - 1);
        NBShiftHelp(H, ds, j, l + r, se.0 - 1);
        assert (se.0 + Pow2(j - l - r)) - 1 == (se.0 - 1) + Pow2(j - (l + r));
        HLRight(H, ds, j, l + r + 1, se.0 / 2, se.1 / 2);
        assert j - (l + r + 1) == j - l - r - 1;
      } else {
        assert (fn + O) % 2 == 0 && fn + O != sn + O;
        NBShiftHelp(H, ds, j, l, fn + 1);
        assert (fn + O) / 2 == fn / 2 + Pow2(j - l - 1);
        assert (sn + O) / 2 == sn / 2 + Pow2(j - l - 1);
        HLRight(H, ds, j, l + 1, fn / 2, sn / 2);
        assert j - (l + 1) == j - l - 1;
      }
    }
  }

  lemma SEBound(fn: nat, sn: nat, i: nat)
    requires sn > 0 && fn <= sn < Pow2(i) && (fn % 2 == 1 || fn == sn)
    ensures SkipJ(fn) < i
    ensures SkipEven(fn, sn).0 >= 1 && SkipEven(fn, sn).0 <= SkipEven(fn, sn).1 < Pow2(i - SkipJ(fn))
    decreases fn
  {
    assert i >= 1;
    assert Pow2(i) == 2 * Pow2(i - 1);
    if fn % 2 == 1 {
    } else {
      assert fn == sn && fn > 0;
      SEBound(fn / 2, sn / 2, i - 1);
    }
  }

  lemma Pow2Mono(a: nat, b: nat)
    requires a <= b
    ensures Pow2(a) <= Pow2(b)
  { if a < b { PowIncr(a, b); } }

  lemma PreShiftIndep(fn: nat, s1: nat, s2: nat)
    ensures PreShift(fn, s1).0 == PreShift(fn, s2).0
    decreases fn
  { if fn % 2 == 1 { PreShiftIndep(fn / 2, s1 / 2, s2 / 2); } }

  lemma PreShiftPow(i: nat, s: nat)
    ensures PreShift(Pow2(i) - 1, s).0 == 0 && PreJ(Pow2(i) - 1) == i
    decreases i
  {
    if i > 0 {
      assert Pow2(i) == 2 * Pow2(i - 1);
      assert (Pow2(i) - 1) % 2 == 1 && (Pow2(i) - 1) / 2 == Pow2(i - 1) - 1;
      PreShiftPow(i - 1, s / 2);
    }
  }

  lemma PreShiftOff(fn: nat, sn: nat, i: nat)
    requires fn + 1 < Pow2(i)
    ensures PreJ(fn + Pow2(i)) == PreJ(fn) && PreJ(fn) < i
    ensures PreShift(fn + Pow2(i), sn + Pow2(i)) == (PreShift(fn, sn).0 + Pow2(i - PreJ(fn)), PreShift(fn, sn).1 + Pow2(i - PreJ(fn)))
    decreases fn
  {
    assert i >= 1;
    assert Pow2(i) == 2 * Pow2(i - 1);
    if fn % 2 == 1 {
      assert (fn + Pow2(i)) % 2 == 1;
      assert (fn + Pow2(i)) / 2 == fn / 2 + Pow2(i - 1);
      assert (sn + Pow2(i)) / 2 == sn / 2 + Pow2(i - 1);
      assert fn / 2 + 1 < Pow2(i - 1);
      PreShiftOff(fn / 2, sn / 2, i - 1);
    } else {
      assert (fn + Pow2(i)) % 2 == 0;
    }
  }

  lemma Pow2IsPow2(i: nat)
    ensures IsPow2(Pow2(i))
  { if i > 0 { assert Pow2(i) == 2 * Pow2(i - 1); Pow2IsPow2(i - 1); assert Pow2(i) % 2 == 0 && Pow2(i) / 2 == Pow2(i - 1); } }

  lemma IsPow2Is(m: nat)
    requires IsPow2(m)
    ensures exists i: nat :: m == Pow2(i)
    decreases m
  {
    if m > 1 { IsPow2Is(m / 2); var i: nat :| m / 2 == Pow2(i); assert m % 2 == 0; assert m == Pow2(i + 1); }
    else { assert m == Pow2(0); }
  }

  lemma NotPow2Between(j: nat, m: nat)
    requires Pow2(j) < m < 2 * Pow2(j)
    ensures !IsPow2(m)
  {
    if IsPow2(m) {
      IsPow2Is(m);
      var i :| m == Pow2(i);
      if i <= j { Pow2Mono(i, j); } else { PowIncr(j, i); }
    }
  }

  // The three cases of the SUBPROOF recursion, each a separate lemma (the inductive hypothesis is a precondition).
  lemma SubEqLeftFull(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool, j: nat)
    requires 0 < m < |ds| && Pow2(j) < |ds| <= 2 * Pow2(j) && m == Pow2(j)
    requires SubProof(H, ds[..Pow2(j)], m, b) == SubModel(H, ds[..Pow2(j)], m, b)
    ensures SubProof(H, ds, m, b) == SubModel(H, ds, m, b)
  {
    var n := |ds|;
    var K := Pow2(j);
    var ds1 := ds[..K];
    BaseBlock(H, ds, m);
    var ps := PreShift(m - 1, n - 1);
    var t := PreJ(m - 1);
    assert Split(n) == K by { SplitIs(n, j); }
    PreShiftPow(j, n - 1);
    assert t == j && ps.0 == 0;
    QuotGe(ps.1, K, n - 1, 1);
    QuotLt(ps.1, K, n - 1, 2);
    assert ps.1 == 1;
    Pow2IsPow2(j);
    assert NB(H, ds, j, 0) == Root(H, ds1) by { assert Mn((0 + 1) * K, n) == K; assert ds[0..K] == ds1; }
    assert NB(H, ds, j, 1) == Root(H, ds[K..]) by { assert Mn((1 + 1) * K, n) == n; assert ds[K..n] == ds[K..]; }
    assert HL(H, ds, j, 0, 1) == [NB(H, ds, j, 1)];
    assert HL(H, ds1, j, 0, 0) == [];
  }

  // pure arithmetic of the left sub-problem
  lemma LeftNum(m: nat, n: nat, j: nat, t: nat, f0: nat, s0: nat, s1: nat)
    requires (f0 + 1) * Pow2(t) == m && m < Pow2(j) && Pow2(j) < n <= 2 * Pow2(j)
    requires s1 * Pow2(t) <= Pow2(j) - 1 < (s1 + 1) * Pow2(t)
    requires s0 * Pow2(t) <= n - 1 < (s0 + 1) * Pow2(t)
    ensures t < j && s1 == Pow2(j - t) - 1 && Pow2(j - t) <= s0 < 2 * Pow2(j - t)
  {
    var K := Pow2(j);
    var P := Pow2(t);
    assert P >= 1;
    assert P <= m by { MulMono(1, f0 + 1, P); }
    if t >= j { Pow2Mono(j, t); }
    Pow2Add(t, j - t);
    assert K == P * Pow2(j - t);
    QuotLt(s1, P, K - 1, Pow2(j - t));
    QuotGe(s1, P, K - 1, Pow2(j - t) - 1);
    assert (Pow2(j - t) - 1) * P == K - P;
    QuotGe(s0, P, n - 1, Pow2(j - t));
    QuotLt(s0, P, n - 1, 2 * Pow2(j - t));
  }

  lemma LeftArith(ds: seq<bytes>, m: int, j: nat)
    requires 0 < m < |ds| && Pow2(j) < |ds| <= 2 * Pow2(j) && m < Pow2(j)
    ensures var n := |ds|; var K := Pow2(j);
            var ps := PreShift(m - 1, n - 1); var t := PreJ(m - 1); var ps1 := PreShift(m - 1, K - 1);
            ps1.0 == ps.0 && t < j && ps1.1 == Pow2(j - t) - 1 && ps.0 <= ps1.1
            && Pow2(j - t) <= ps.1 < 2 * Pow2(j - t)
  {
    var n := |ds|;
    var K := Pow2(j);
    var H0: bytes -> bytes := (x: bytes) => [];
    BaseBlock(H0, ds, m);
    BaseBlock(H0, ds[..K], m);
    PreShiftIndep(m - 1, n - 1, K - 1);
    LeftNum(m, n, j, PreJ(m - 1), PreShift(m - 1, n - 1).0, PreShift(m - 1, n - 1).1, PreShift(m - 1, K - 1).1);
  }

  lemma SubEqLeftLt(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool, j: nat)
    requires 0 < m < |ds| && Pow2(j) < |ds| <= 2 * Pow2(j) && m < Pow2(j)
    requires SubProof(H, ds[..Pow2(j)], m, b) == SubModel(H, ds[..Pow2(j)], m, b)
    ensures SubProof(H, ds, m, b) == SubModel(H, ds, m, b)
  {
    var n := |ds|;
    var K := Pow2(j);
    var ds1 := ds[..K];
    assert Split(n) == K by { SplitIs(n, j); }
    LeftArith(ds, m, j);
    var ps := PreShift(m - 1, n - 1);
    var t := PreJ(m - 1);
    var ps1 := PreShift(m - 1, K - 1);
    HLLeft(H, ds, j, t, ps.0, ps.1);
    NBLeft(H, ds, j, t, ps.0);
    assert SubProof(H, ds, m, b) == SubProof(H, ds1, m, b) + [Root(H, ds[K..])];
    assert SubModel(H, ds1, m, b) == (if b && IsPow2(m) then [] else [NB(H, ds1, t, ps1.0)]) + HL(H, ds1, t, ps1.0, ps1.1);
    assert SubModel(H, ds, m, b) == (if b && IsPow2(m) then [] else [NB(H, ds, t, ps.0)]) + HL(H, ds, t, ps.0, ps.1);
  }

  lemma SubEqRight(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool, j: nat)
    requires 0 < m < |ds| && Pow2(j) < |ds| <= 2 * Pow2(j) && m > Pow2(j)
    requires SubProof(H, ds[Pow2(j)..], m - Pow2(j), false) == SubModel(H, ds[Pow2(j)..], m - Pow2(j), false)
    ensures SubProof(H, ds, m, b) == SubModel(H, ds, m, b)
  {
    var n := |ds|;
    var K := Pow2(j);
    assert Split(n) == K by { SplitIs(n, j); }
    var ds2 := ds[K..];
    var m2 := m - K;
    BaseBlock(H, ds, m);
    var ps := PreShift(m - 1, n - 1);
    var t := PreJ(m - 1);
    BaseBlock(H, ds2, m2);
    var ps2 := PreShift(m2 - 1, |ds2| - 1);
    var t2 := PreJ(m2 - 1);
    assert m - 1 == (m2 - 1) + K && n - 1 == (|ds2| - 1) + K;
    PreShiftOff(m2 - 1, |ds2| - 1, j);
    assert t == t2 && ps.0 == ps2.0 + Pow2(j - t2) && ps.1 == ps2.1 + Pow2(j - t2);
    NotPow2Between(j, m);
    Pow2Add(t2, j - t2);
    QuotLt(ps2.1, Pow2(t2), |ds2| - 1, Pow2(j - t2));
    HLRight(H, ds, j, t2, ps2.0, ps2.1);
    NBShift(H, ds, j, t2, ps2.0);
  }

  // THE GENERATOR EQUIVALENCE: the RFC 6962 SUBPROOF list equals the list the (proved) verifier loop consumes.
  lemma SubEq(H: bytes -> bytes, ds: seq<bytes>, m: int, b: bool)
    requires 0 < m <= |ds|
    ensures SubProof(H, ds, m, b) == SubModel(H, ds, m, b)
    decreases |ds|
  {
    var n := |ds|;
    if m < n {
      var j := SplitJ(n, 0);
      var K := Pow2(j);
      assert Split(n) == K;
      if m <= K {
        SubEq(H, ds[..K], m, b);
        if m == K { SubEqLeftFull(H, ds, m, b, j); } else { SubEqLeftLt(H, ds, m, b, j); }
      } else {
        SubEq(H, ds[K..], m - K, false);
        SubEqRight(H, ds, m, b, j);
      }
    }
  }

  // Completeness for the production generator: HonestCons IS SUBPROOF(m, D[n], true) (ledger.ts consistencyProof), and it is accepted.
  lemma GeneratorComplete(H: bytes -> bytes, L: nat, ds: seq<bytes>, m: int)
    requires HashLen(H, L)
    requires 0 < m < |ds|
    ensures SubProof(H, ds, m, true) == HonestCons(H, ds, m)
    ensures VerifyConsistency(H, L, Root(H, ds[..m]), Root(H, ds), m, |ds|, SubProof(H, ds, m, true))
  {
    SubEq(H, ds, m, true);
    ConsComplete(H, L, ds, m);
  }

  // =================================================================================================================
  // EMPTY TREE and NO 2^32 ALIASING (ledger.ts used 32-bit `>>`, `&`; the fixed code and this model use exact integers)
  // =================================================================================================================
  // The empty-tree rule exactly as production: size 0 needs oldRoot == H("") and an empty path; (0, 0) needs newRoot == H("") too.
  lemma EmptyTreeIff(H: bytes -> bytes, L: nat, oldRoot: bytes, newRoot: bytes, n: int, p: seq<bytes>)
    requires n >= 0
    ensures VerifyConsistency(H, L, oldRoot, newRoot, 0, n, p) <==> (|p| == 0 && oldRoot == H([]) && (n == 0 ==> newRoot == H([])))
  {}

  // The number of proof elements the loop consumes depends ONLY on (fn, sn), never on hash values.
  function ExpLen(fn: nat, sn: nat): nat
    decreases sn
  {
    if sn == 0 then 0
    else if fn % 2 == 1 || fn == sn then (var se := SkipEven(fn, sn); 1 + ExpLen(se.0 / 2, se.1 / 2))
    else 1 + ExpLen(fn / 2, sn / 2)
  }

  // Acceptance requires the EXACT path length: a shorter path leaves sn != 0, a longer one hits the sn == 0 guard.
  lemma CLoopExactLen(H: bytes -> bytes, L: nat, fn: nat, sn: nat, fr: bytes, sr: bytes, p: seq<bytes>)
    requires CLoop(H, L, fn, sn, fr, sr, p).Some?
    ensures |p| == ExpLen(fn, sn)
    decreases |p|
  {
    if |p| > 0 {
      if fn % 2 == 1 || fn == sn {
        var se := SkipEven(fn, sn);
        CLoopExactLen(H, L, se.0 / 2, se.1 / 2, NodeH(H, p[0], fr), NodeH(H, p[0], sr), p[1..]);
      } else {
        CLoopExactLen(H, L, fn / 2, sn / 2, fr, NodeH(H, sr, p[0]), p[1..]);
      }
    }
  }

  // The expected proof length for 0 < m < n (elements after the optional old-root prepend).
  function ConsLen(m: nat, n: nat): nat
    requires 0 < m < n
  { var ps := PreShift(m - 1, n - 1); ExpLen(ps.0, ps.1) + 1 - (if IsPow2(m) then 1 else 0) }

  lemma VerMidExactLen(H: bytes -> bytes, L: nat, oldRoot: bytes, newRoot: bytes, m: int, n: int, p: seq<bytes>)
    requires 0 < m < n
    requires VerMid(H, L, oldRoot, newRoot, m, n, p)
    ensures |p| == ConsLen(m, n)
  {
    var path := if IsPow2(m) then [oldRoot] + p else p;
    var ps := PreShift(m - 1, n - 1);
    CLoopExactLen(H, L, ps.0, ps.1, path[0], path[0], path[1..]);
  }

  // Arithmetic helpers for shifts by K = k * 2^i.
  lemma Half2(x: nat, y: nat) ensures (x + 2 * y) / 2 == x / 2 + y && (x + 2 * y) % 2 == x % 2 {}
  lemma KPow(k: nat, i: nat)
    requires i >= 1
    ensures k * Pow2(i) == 2 * (k * Pow2(i - 1))
  { assert Pow2(i) == 2 * Pow2(i - 1); MulAssoc(k, 2, Pow2(i - 1)); MulAssoc(2, k, Pow2(i - 1)); }
  lemma KPos(k: nat, i: nat) requires k >= 1 ensures k * Pow2(i) >= Pow2(i) >= 1 { MulMono(1, k, Pow2(i)); }

  // SkipEven commutes with adding ANY multiple k * 2^i above every bit of (fn, sn) (no 32-bit style truncation of high bits).
  lemma SkipEvenOffK(fn: nat, sn: nat, i: nat, k: nat)
    requires 0 < fn <= sn < Pow2(i) && k >= 1
    ensures SkipJ(fn) < i
    ensures SkipEven(fn + k * Pow2(i), sn + k * Pow2(i)) == (SkipEven(fn, sn).0 + k * Pow2(i - SkipJ(fn)), SkipEven(fn, sn).1 + k * Pow2(i - SkipJ(fn)))
    decreases fn
  {
    assert i >= 1 by { if i == 0 { assert Pow2(0) == 1; } }
    assert Pow2(i) == 2 * Pow2(i - 1);
    KPow(k, i);
    var y := k * Pow2(i - 1);
    Half2(fn, y); Half2(sn, y);
    if fn % 2 == 0 {
      assert 0 < fn / 2 <= sn / 2 < Pow2(i - 1);
      SkipEvenOffK(fn / 2, sn / 2, i - 1, k);
    }
  }

  lemma SkipEvenMono(fn: nat, sn: nat)
    requires fn <= sn
    ensures SkipEven(fn, sn).0 <= SkipEven(fn, sn).1
    ensures SkipEven(fn, sn).1 == sn / Pow2(SkipJ(fn))
    decreases fn
  {
    if fn % 2 == 0 && fn != 0 {
      SkipEvenMono(fn / 2, sn / 2);
      var j := SkipJ(fn / 2);
      assert Pow2(j + 1) == 2 * Pow2(j);
      DivDiv(sn, 2, Pow2(j));
    } else {
      assert Pow2(0) == 1;
    }
  }

  lemma DivDiv(x: nat, a: nat, b: nat)
    requires a > 0 && b > 0
    ensures x / a / b == x / (a * b)
  {
    var q := x / a; var r := x % a;
    var q2 := q / b; var r2 := q % b;
    assert q == b * q2 + r2;
    assert x == a * q + r;
    assert a * q == a * (b * q2) + a * r2 by { Distrib(a, b * q2, r2); }
    assert a * (b * q2) == (a * b) * q2 by { MulAssoc(a, b, q2); }
    assert r2 <= b - 1;
    MulLe(a, r2, b - 1);
    assert a * (b - 1) == a * b - a by { Distrib(a, b, -1); }
    DivUnique(x, a * b, q2, a * r2 + r);
  }
  lemma Distrib(a: int, b: int, c: int) ensures a * (b + c) == a * b + a * c {}
  lemma MulAssoc(a: int, b: int, c: int) ensures a * (b * c) == (a * b) * c {}
  lemma MulLe(a: nat, x: nat, y: nat) requires x <= y ensures a * x <= a * y { MulMono(x, y, a); }
  lemma DivUnique(x: nat, d: nat, q: nat, r: nat)
    requires d > 0 && x == d * q + r && 0 <= r < d
    ensures x / d == q
  {
    var q0 := x / d;
    var r0 := x % d;
    assert x == d * q0 + r0 && 0 <= r0 < d;
    if q > q0 { MulMono(q0 + 1, q, d); assert (q0 + 1) * d == q0 * d + d; }
    if q < q0 { MulMono(q + 1, q0, d); assert (q + 1) * d == q * d + d; }
  }

  lemma DivPow(sn: nat, i: nat, j: nat)
    requires j <= i && sn < Pow2(i)
    ensures sn / Pow2(j) < Pow2(i - j)
  {
    var d := Pow2(j);
    var q := sn / d;
    Pow2Add(j, i - j);
    assert Pow2(i) == d * Pow2(i - j);
    assert sn == d * q + sn % d && 0 <= sn % d < d;
    assert (q + 1) * d == q * d + d;
    assert q * d <= sn < (q + 1) * d;
    QuotLt(q, d, sn, Pow2(i - j));
  }

  // THE SHIFT LEMMA: adding ANY multiple k * 2^i (k >= 1) above every bit of (fn, sn) strictly INCREASES the number of proof elements
  // the loop needs (the loop has no modular structure: the high part is never dropped, it only adds iterations).
  lemma ExpLenShiftK(fn: nat, sn: nat, i: nat, k: nat)
    requires fn <= sn < Pow2(i) && k >= 1
    ensures ExpLen(fn + k * Pow2(i), sn + k * Pow2(i)) > ExpLen(fn, sn)
    decreases i
  {
    KPos(k, i);
    if sn == 0 {
      assert ExpLen(fn + k * Pow2(i), sn + k * Pow2(i)) >= 1;
    } else {
      assert i >= 1 by { if i == 0 { assert Pow2(0) == 1; } }
      assert Pow2(i) == 2 * Pow2(i - 1);
      KPow(k, i);
      var y := k * Pow2(i - 1);
      Half2(fn, y); Half2(sn, y);
      if fn % 2 == 1 || fn == sn {
        assert fn > 0;
        SkipEvenOffK(fn, sn, i, k);
        SkipEvenMono(fn, sn);
        var j := SkipJ(fn);
        var se := SkipEven(fn, sn);
        DivPow(sn, i, j);
        assert se.1 < Pow2(i - j);
        assert i - j >= 1;
        assert Pow2(i - j) == 2 * Pow2(i - j - 1);
        KPow(k, i - j);
        var y2 := k * Pow2(i - j - 1);
        Half2(se.0, y2); Half2(se.1, y2);
        assert se.0 / 2 <= se.1 / 2 < Pow2(i - j - 1);
        ExpLenShiftK(se.0 / 2, se.1 / 2, i - j - 1, k);
      } else {
        assert fn / 2 <= sn / 2 < Pow2(i - 1);
        ExpLenShiftK(fn / 2, sn / 2, i - 1, k);
      }
    }
  }

  // PreShift commutes with adding k * 2^i when fn + 1 < 2^i (fn's trailing ones stay below bit i).
  lemma PreShiftOffK(fn: nat, sn: nat, i: nat, k: nat)
    requires fn + 1 < Pow2(i) && k >= 1
    ensures PreJ(fn + k * Pow2(i)) == PreJ(fn) && PreJ(fn) < i
    ensures PreShift(fn + k * Pow2(i), sn + k * Pow2(i)) == (PreShift(fn, sn).0 + k * Pow2(i - PreJ(fn)), PreShift(fn, sn).1 + k * Pow2(i - PreJ(fn)))
    decreases fn
  {
    assert i >= 1 by { if i == 0 { assert Pow2(0) == 1; } }
    assert Pow2(i) == 2 * Pow2(i - 1);
    KPow(k, i);
    var y := k * Pow2(i - 1);
    Half2(fn, y); Half2(sn, y);
    if fn % 2 == 1 {
      assert fn / 2 + 1 < Pow2(i - 1);
      PreShiftOffK(fn / 2, sn / 2, i - 1, k);
    }
  }

  // m + k * 2^j is never a power of two when 0 < m < 2^j.
  lemma NotPow2Shift(m: nat, j: nat, k: nat)
    requires 0 < m < Pow2(j) && k >= 1
    ensures !IsPow2(m + k * Pow2(j))
  {
    var P := Pow2(j);
    var x := m + k * P;
    KPos(k, j);
    if IsPow2(x) {
      IsPow2Is(x);
      var r: nat :| x == Pow2(r);
      if r <= j { Pow2Mono(r, j); assert false; }
      else {
        Pow2Add(j, r - j);
        assert x == P * Pow2(r - j);
        DivUnique(x, P, k, m);
        DivUnique(x, P, Pow2(r - j), 0);
        assert false;
      }
    }
  }

  // A proof between two non-empty, different sizes always needs at least one element: the empty path is never accepted for 0 < m < n.
  lemma MidRejectsEmpty(H: bytes -> bytes, L: nat, o: bytes, nw: bytes, m: int, n: int)
    requires 0 < m < n
    ensures !VerMid(H, L, o, nw, m, n, [])
  {
    if IsPow2(m) { PreShiftLow(m - 1, n - 1); }
  }

  // NO ALIASING UNDER ANY SHIFT k * 2^j (k >= 1, j >= 0), for every n <= 2^j: a consistency proof accepted for sizes (m, n), 0 <= m < n,
  // is NEVER accepted for (m + k * 2^j, n + k * 2^j), whatever the roots. In particular for j = 32: every truncation-alias of the old 32-bit
  // code ((m, n) and (m + k * 2^32, n + k * 2^32), n <= 2^32, any k >= 1) is refused. Equal sizes carry no path (decided by the roots).
  // The bound n <= 2^j is NECESSARY, see DyadicTwins: for n > 2^j some shifts are the SAME RFC 9162 problem (identical decision).
  lemma NoAliasShiftK(H: bytes -> bytes, L: nat, o: bytes, nw: bytes, o2: bytes, nw2: bytes, m: int, n: int, j: nat, k: nat, p: seq<bytes>)
    requires 0 <= m < n <= Pow2(j) && k >= 1
    requires VerifyConsistency(H, L, o, nw, m, n, p)
    ensures !VerifyConsistency(H, L, o2, nw2, m + k * Pow2(j), n + k * Pow2(j), p)
  {
    var K := k * Pow2(j);
    KPos(k, j);
    var m2 := m + K;
    var n2 := n + K;
    assert 0 < m2 < n2;
    if m == 0 {
      assert |p| == 0;
      MidRejectsEmpty(H, L, o2, nw2, m2, n2);
    } else if VerifyConsistency(H, L, o2, nw2, m2, n2, p) {
      VerMidExactLen(H, L, o2, nw2, m2, n2, p);
      VerMidExactLen(H, L, o, nw, m, n, p);
      NotPow2Shift(m, j, k);
      PreShiftOffK(m - 1, n - 1, j, k);
      var t := PreJ(m - 1);
      var ps := PreShift(m - 1, n - 1);
      var ps2 := PreShift(m2 - 1, n2 - 1);
      assert m2 - 1 == (m - 1) + K && n2 - 1 == (n - 1) + K;
      assert ps2 == (ps.0 + k * Pow2(j - t), ps.1 + k * Pow2(j - t));
      PreShiftShape(m - 1, n - 1, j);
      ExpLenShiftK(ps.0, ps.1, j - t, k);
      assert ConsLen(m2, n2) == ExpLen(ps2.0, ps2.1) + 1;
      assert ConsLen(m, n) <= ExpLen(ps.0, ps.1) + 1;
      assert false;
    }
  }

  // THE EXACT TRUTH about "is the decision a function of the exact (m, n)?": NO, and it must not be. For 0 < m < n the decision is a function
  // of the DYADIC SIGNATURE Sig(m, n) = (IsPow2(m), PreShift(m - 1, n - 1)): pairs with the same signature are the same RFC 9162 problem (the
  // old tree's boundary sits at the same node shape), so the same path and roots verify identically. That is not aliasing: soundness is per
  // pair (ConsSound / ConsPrefix: an accept for (m, n) against a size-n log with root newRoot forces oldRoot == root of its first m leaves,
  // or H collides), and signed heads bind each size to its root.
  lemma SigDecides(H: bytes -> bytes, L: nat, o: bytes, nw: bytes, m: int, n: int, m2: int, n2: int, p: seq<bytes>)
    requires 0 < m < n && 0 < m2 < n2
    requires IsPow2(m) == IsPow2(m2) && PreShift(m - 1, n - 1) == PreShift(m2 - 1, n2 - 1)
    ensures VerifyConsistency(H, L, o, nw, m, n, p) == VerifyConsistency(H, L, o, nw, m2, n2, p)
  {}

  // Counterexample showing the n <= 2^j bound of NoAliasShiftK is necessary: (1, 2) and its shift by 1 = 1 * 2^0, (2, 3), are the same
  // problem (tree [a, b] vs [a, b, c] with the old boundary after the first full pair), so their decisions coincide for every path and roots.
  lemma DyadicTwins(H: bytes -> bytes, L: nat, o: bytes, nw: bytes, p: seq<bytes>)
    ensures VerifyConsistency(H, L, o, nw, 1, 2, p) == VerifyConsistency(H, L, o, nw, 2, 3, p)
  {
    assert IsPow2(1) && IsPow2(2);
    assert PreShift(0, 1) == (0, 1);
    assert PreShift(1, 2) == PreShift(0, 1);
    SigDecides(H, L, o, nw, 1, 2, 2, 3, p);
  }

  // PreShift keeps fn <= sn and divides both by 2^PreJ(fn).
  lemma PreShiftShape(fn: nat, sn: nat, i: nat)
    requires fn <= sn < Pow2(i) && fn + 1 < Pow2(i)
    ensures PreJ(fn) <= i
    ensures PreShift(fn, sn).0 <= PreShift(fn, sn).1 < Pow2(i - PreJ(fn))
    decreases fn
  {
    assert i >= 1 by { if i == 0 { assert Pow2(0) == 1; } }
    assert Pow2(i) == 2 * Pow2(i - 1);
    if fn % 2 == 1 {
      assert fn / 2 + 1 < Pow2(i - 1);
      PreShiftShape(fn / 2, sn / 2, i - 1);
    }
  }

  // PreShift of an all-ones fn = 2^i - 1 shifts sn right by i: a value >= 2^i keeps a non-zero high part.
  lemma PreShiftLow(fn: nat, sn: nat)
    requires fn < sn
    ensures PreShift(fn, sn).1 >= 1
    decreases fn
  {
    if fn % 2 == 1 { PreShiftLow(fn / 2, sn / 2); }
  }

  // The production cap (path length <= 2*53+2) never rejects an acceptable proof for sizes below 2^53: it is a DoS bound only.
  lemma BitsBound(x: nat, k: nat)
    requires x < Pow2(k)
    ensures Bits(x) <= k
    decreases k
  {
    if x > 0 {
      assert k >= 1 by { if k == 0 { assert Pow2(0) == 1; } }
      assert Pow2(k) == 2 * Pow2(k - 1);
      BitsBound(x / 2, k - 1);
    }
  }
  lemma PathCapRedundant(H: bytes -> bytes, L: nat, o: bytes, nw: bytes, m: int, n: int, p: seq<bytes>)
    requires n < Pow2(53)
    requires VerifyConsistency(H, L, o, nw, m, n, p)
    ensures |p| <= 54
  {
    if 0 < m < n {
      var path := if IsPow2(m) then [o] + p else p;
      var ps := PreShift(m - 1, n - 1);
      LoopLenBound(H, L, ps.0, ps.1, path[0], path[0], path[1..]);
      BitsMono(ps.1, n - 1);
      BitsBound(n - 1, 53);
    }
  }
}
