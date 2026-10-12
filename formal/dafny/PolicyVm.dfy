// PolicyVm.dfy - the predicate DSL, the envelope-caveat evaluator and the Policy-VM decision of the PCA verifier
// (packages/pca/src/predicates.ts, agent-native.ts agentNativeCaveatEvaluator, policy-vm.ts decide, risk.ts thresholds/admission).
// STANDALONE (no includes). No assume / axiom / extern. The ONLY things taken as given are the answers of the regex guard / matcher
// (record `Rx`: another module proves them), of the tool_schema evaluator (`ToolEv`), and one double-arithmetic expression of the
// `rate` caveat (`Fl`); each is a function parameter, so every theorem below holds for EVERY such oracle.
module PolicyVm {
  datatype Option<T> = None | Some(v: T)

  // ------------------------------------------------------------------ strings: UTF-16 code units, exactly as in JavaScript
  newtype U = x: int | 0 <= x < 65536
  type Str = seq<U>

  // ASCII literal -> Str (used for property names and operator names only)
  function S(s: string): Str {
    seq(|s|, i requires 0 <= i < |s| => (if (s[i] as int) < 65536 then s[i] as int else 0) as U)
  }

  // ------------------------------------------------------------------ JSON-like JS values
  // VNum holds the EXACT rational value of a finite double (comparisons on doubles are exact, so this is faithful);
  // VNonFinite = typeof number but NaN / +-Infinity; VFn = function / symbol / bigint (not 'object', not serialisable);
  // VObj(plain=false) = a non-plain object (class instance, Date, ...): an object for typeof/has, but canonicalisation throws.
  // Cyclic data, sparse-array holes (other than as VUndef elements), getters and proxies are OUT of the model (the adapter refuses them).
  datatype Value =
    | VNull | VUndef | VBool(b: bool) | VNum(r: real) | VNonFinite | VFn
    | VStr(s: Str) | VArr(xs: seq<Value>) | VObj(es: seq<Entry>, plain: bool)
  datatype Entry = Entry(k: Str, v: Value)

  // own-property lookup (keys are unique in any real object, the first match is THE match)
  function Has(es: seq<Entry>, k: Str): bool decreases es {
    |es| > 0 && (es[0].k == k || Has(es[1..], k))
  }
  function Get(es: seq<Entry>, k: Str): Value decreases es {
    if |es| == 0 then VUndef else if es[0].k == k then es[0].v else Get(es[1..], k)
  }
  // property read `v.k` for the property names this module reads (none is an Array/Object prototype member): objects read an own
  // property, every other value reads undefined.
  function Field(v: Value, k: Str): Value {
    match v case VObj(es, _) => Get(es, k) case _ => VUndef
  }
  predicate IsObjRec(v: Value) { v.VObj? }                 // x !== null && typeof x === 'object' && !Array.isArray(x)
  predicate IsObjLike(v: Value) { v.VObj? || v.VArr? }     // x !== null && typeof x === 'object'

  // ------------------------------------------------------------------ three-valued truth (Kleene strong logic)
  datatype Tri = TT | TF | TU

  function NotT(t: Tri): Tri { match t case TT => TF case TF => TT case TU => TU }

  // all_of / any_of results over the list of CHILD results (the TS short-circuits; the result is the same, see AllCharacterisation)
  function AllT(ts: seq<Tri>): Tri {
    if TF in ts then TF else if TU in ts then TU else TT
  }
  function AnyT(ts: seq<Tri>): Tri {
    if TT in ts then TT else if TU in ts then TU else TF
  }

  // information order: TU is below TT and TF
  predicate Refines(a: Tri, b: Tri) { a == TU || a == b }   // a is less defined than (or equal to) b

  // ------------------------------------------------------------------ dotted paths (resolvePath)
  function SplitDot(s: Str): seq<Str> { SplitAcc(s, [], []) }
  function SplitAcc(s: Str, cur: Str, acc: seq<Str>): seq<Str> decreases |s| {
    if |s| == 0 then acc + [cur]
    else if s[0] == 46 then SplitAcc(s[1..], [], acc + [cur])
    else SplitAcc(s[1..], cur + [s[0]], acc)
  }
  lemma SplitAccNonEmpty(s: Str, cur: Str, acc: seq<Str>) ensures |SplitAcc(s, cur, acc)| >= 1 decreases |s| {
    if |s| > 0 { SplitAccNonEmpty(s[1..], if s[0] == 46 then [] else cur + [s[0]], if s[0] == 46 then acc + [cur] else acc); }
  }
  lemma SplitNonEmpty(s: Str) ensures |SplitDot(s)| >= 1 { SplitAccNonEmpty(s, [], []); }

  predicate IsRoot(s: Str) { s == S("action") || s == S("subject") || s == S("env") }
  predicate Forbidden(s: Str) { s == S("__proto__") || s == S("constructor") || s == S("prototype") }
  predicate IsDigit(u: U) { 48 <= u && u <= 57 }
  predicate AllDigits(s: Str) { forall i :: 0 <= i < |s| ==> IsDigit(s[i]) }
  // /^(0|[1-9]\d*)$/
  predicate IsIndex(s: Str) { s == [48] || (|s| > 0 && 49 <= s[0] && s[0] <= 57 && AllDigits(s)) }
  function DigitsVal(s: Str): nat requires AllDigits(s) decreases |s| {
    if |s| == 0 then 0 else DigitsVal(s[..|s|-1]) * 10 + ((s[|s|-1] as int) - 48)
  } by method {
    var n: nat := 0;
    var i := 0;
    while i < |s|
      invariant 0 <= i <= |s|
      invariant n == DigitsVal(s[..i])
    {
      assert s[..i+1][..i] == s[..i];
      assert IsDigit(s[i]);
      n := n * 10 + ((s[i] as int) - 48);
      i := i + 1;
    }
    assert s[..|s|] == s;
    return n;
  }

  datatype Res = Res(found: bool, v: Value)
  const NotFound: Res := Res(false, VUndef)

  function Walk(cur: Value, segs: seq<Str>, i: nat): Res
    requires i <= |segs| decreases |segs| - i
  {
    if i == |segs| then Res(true, cur)
    else
      var s := segs[i];
      if Forbidden(s) || !IsObjLike(cur) then NotFound
      else match cur
        case VArr(xs) =>
          if !IsIndex(s) then NotFound
          else
            var idx := DigitsVal(s);
            if idx >= |xs| then NotFound
            else if xs[idx].VUndef? then NotFound
            else Walk(xs[idx], segs, i + 1)
        case VObj(es, _) =>
          if !Has(es, s) then NotFound
          else
            var nx := Get(es, s);
            if nx.VUndef? then NotFound else Walk(nx, segs, i + 1)
  }

  function ResolvePath(ctx: Value, path: Value): Res {
    if !path.VStr? || |path.s| == 0 then NotFound
    else
      SplitNonEmpty(path.s);
      var segs := SplitDot(path.s);
      if !IsRoot(segs[0]) then NotFound
      else
        var cur := Field(ctx, segs[0]);
        if cur.VUndef? then NotFound else Walk(cur, segs, 1)
  }

  // ------------------------------------------------------------------ UTF-8 (TextEncoder semantics: a lone surrogate encodes as U+FFFD)
  predicate IsHigh(u: U) { 0xD800 <= u && u <= 0xDBFF }
  predicate IsLow(u: U) { 0xDC00 <= u && u <= 0xDFFF }

  // lone surrogate anywhere in s (hasLoneSurrogate)
  predicate LoneAt(s: Str, i: nat) requires i < |s| {
    (IsHigh(s[i]) && !(i + 1 < |s| && IsLow(s[i+1]))) || (IsLow(s[i]) && !(i > 0 && IsHigh(s[i-1])))
  }
  predicate HasLone(s: Str) { exists i :: 0 <= i < |s| && LoneAt(s, i) }

  function Enc(cp: int): seq<int> requires 0 <= cp <= 0x10FFFF {
    if cp < 0x80 then [cp]
    else if cp < 0x800 then [0xC0 + cp / 64, 0x80 + cp % 64]
    else if cp < 0x10000 then [0xE0 + cp / 4096, 0x80 + (cp / 64) % 64, 0x80 + cp % 64]
    else [0xF0 + cp / 262144, 0x80 + (cp / 4096) % 64, 0x80 + (cp / 64) % 64, 0x80 + cp % 64]
  }
  function Utf8(s: Str): seq<int> decreases |s| {
    if |s| == 0 then []
    else
      var u := s[0] as int;
      if IsHigh(s[0]) && |s| > 1 && IsLow(s[1]) then
        Enc(0x10000 + (u - 0xD800) * 1024 + ((s[1] as int) - 0xDC00)) + Utf8(s[2..])
      else if IsHigh(s[0]) || IsLow(s[0]) then Enc(0xFFFD) + Utf8(s[1..])
      else Enc(u) + Utf8(s[1..])
  }
  // lexicographic byte order, sign in {-1,0,1}; equals Math.sign(compareUtf8(a, b)) of hash.ts
  function CmpBytes(a: seq<int>, b: seq<int>): int decreases |a| + |b| {
    if |a| == 0 && |b| == 0 then 0
    else if |a| == 0 then -1
    else if |b| == 0 then 1
    else if a[0] < b[0] then -1
    else if a[0] > b[0] then 1
    else CmpBytes(a[1..], b[1..])
  }
  // hash.ts compareUtf8 (fixed): equal strings compare 0; otherwise UTF-8 byte order, and when the BYTES tie (only lone surrogates can do
  // that: each encodes as U+FFFD) the UTF-16 code-unit order breaks the tie. So the comparator is a strict total order on strings.
  function Units(s: Str): seq<int> { seq(|s|, i requires 0 <= i < |s| => s[i] as int) }
  function CmpStr(a: Str, b: Str): int {
    if a == b then 0
    else
      var c := CmpBytes(Utf8(a), Utf8(b));
      if c != 0 then c else CmpBytes(Units(a), Units(b))
  }

  lemma CmpBytesAntisym(a: seq<int>, b: seq<int>) ensures CmpBytes(a, b) == -CmpBytes(b, a) decreases |a| + |b| {
    if |a| > 0 && |b| > 0 && a[0] == b[0] { CmpBytesAntisym(a[1..], b[1..]); }
  }
  lemma CmpBytesZero(a: seq<int>, b: seq<int>) ensures CmpBytes(a, b) == 0 <==> a == b decreases |a| + |b| {
    if |a| > 0 && |b| > 0 && a[0] == b[0] {
      CmpBytesZero(a[1..], b[1..]);
      if a[1..] == b[1..] { assert a == [a[0]] + a[1..] && b == [b[0]] + b[1..]; }
    }
  }
  lemma CmpBytesRange(a: seq<int>, b: seq<int>) ensures -1 <= CmpBytes(a, b) <= 1 decreases |a| + |b| {
    if |a| > 0 && |b| > 0 && a[0] == b[0] { CmpBytesRange(a[1..], b[1..]); }
  }
  lemma CmpBytesTrans(a: seq<int>, b: seq<int>, c: seq<int>)
    requires CmpBytes(a, b) < 0 && CmpBytes(b, c) < 0
    ensures CmpBytes(a, c) < 0
    decreases |a| + |b| + |c|
  {
    if |a| > 0 && |b| > 0 && |c| > 0 && a[0] == b[0] && b[0] == c[0] { CmpBytesTrans(a[1..], b[1..], c[1..]); }
  }
  lemma UnitsInj(a: Str, b: Str) ensures Units(a) == Units(b) ==> a == b {
    if Units(a) == Units(b) {
      assert |a| == |b|;
      forall i | 0 <= i < |a| ensures a[i] == b[i] { assert Units(a)[i] == Units(b)[i]; }
    }
  }
  lemma CmpStrAntisym(a: Str, b: Str) ensures CmpStr(a, b) == -CmpStr(b, a) {
    CmpBytesAntisym(Utf8(a), Utf8(b)); CmpBytesAntisym(Units(a), Units(b));
  }
  // 0 ONLY for equal strings (the old byte-only comparator returned 0 for "\ud800" vs "\ud801", so key order fell back to insertion order)
  lemma CmpStrZero(a: Str, b: Str) ensures CmpStr(a, b) == 0 <==> a == b {
    if a != b {
      CmpBytesZero(Utf8(a), Utf8(b));
      if CmpBytes(Utf8(a), Utf8(b)) == 0 { CmpBytesZero(Units(a), Units(b)); UnitsInj(a, b); }
    }
  }
  lemma CmpStrTrans(a: Str, b: Str, c: Str)
    requires CmpStr(a, b) < 0 && CmpStr(b, c) < 0
    ensures CmpStr(a, c) < 0
  {
    var x := CmpBytes(Utf8(a), Utf8(b)); var y := CmpBytes(Utf8(b), Utf8(c));
    CmpBytesZero(Utf8(a), Utf8(b)); CmpBytesZero(Utf8(b), Utf8(c)); CmpBytesZero(Utf8(a), Utf8(c));
    CmpBytesZero(Units(a), Units(c)); UnitsInj(a, c);
    if x < 0 && y < 0 { CmpBytesTrans(Utf8(a), Utf8(b), Utf8(c)); }
    else if x < 0 { assert y == 0; assert Utf8(b) == Utf8(c); }
    else if y < 0 { assert x == 0; assert Utf8(a) == Utf8(b); }
    else {
      assert x == 0 && y == 0;
      assert Utf8(a) == Utf8(c);
      CmpBytesTrans(Units(a), Units(b), Units(c));
      CmpBytesZero(Units(a), Units(c));
    }
  }

  // ------------------------------------------------------------------ deepEq: canonicalize(a) === canonicalize(b) (LENIENT canonical form)
  // Canon(v): canonicalize does not throw. Objects serialise with keys sorted by a STABLE sort on compareUtf8; the token list below is
  // the canonical text (strings and numbers are represented by their value, JSON.stringify being injective on them).
  datatype Tok = TOpenA | TCloseA | TOpenO | TCloseO | TComma | TColon | TNullT | TTrueT | TFalseT | TNumT(r: real) | TStrT(s: Str)

  predicate CanonL(xs: seq<Value>) decreases xs { forall i :: 0 <= i < |xs| ==> Canon(xs[i]) }
  predicate CanonE(es: seq<Entry>) decreases es { forall i :: 0 <= i < |es| ==> Canon(es[i].v) }
  predicate Canon(v: Value) decreases v {
    match v
    case VNull => true
    case VBool(_) => true
    case VNum(_) => true
    case VStr(_) => true
    case VArr(xs) => CanonL(xs)
    case VObj(es, plain) => plain && CanonE(es)
    case _ => false
  }

  // sizes (termination measures for the serialiser, which recurses through a SORTED copy of the entries)
  function SzV(v: Value): nat decreases v {
    match v
    case VArr(xs) => 1 + SzL(xs)
    case VObj(es, _) => 1 + SzE(es)
    case _ => 1
  }
  function SzL(xs: seq<Value>): nat decreases xs { if |xs| == 0 then 0 else SzV(xs[0]) + SzL(xs[1..]) }
  function SzE(es: seq<Entry>): nat decreases es { if |es| == 0 then 0 else SzV(es[0].v) + 1 + SzE(es[1..]) }

  // stable sort of the entries by compareUtf8 of the key (V8's Array.prototype.sort is stable; the comparator is a total preorder):
  // an entry goes in front of the first already-sorted LATER entry whose key is >= its own.
  function InsertE(e: Entry, sorted: seq<Entry>): seq<Entry> decreases |sorted| {
    if |sorted| == 0 then [e]
    else if CmpStr(sorted[0].k, e.k) >= 0 then [e] + sorted
    else [sorted[0]] + InsertE(e, sorted[1..])
  }
  function SortE(es: seq<Entry>): seq<Entry> decreases |es| {
    if |es| == 0 then [] else InsertE(es[0], SortE(es[1..]))
  }
  lemma InsertSz(e: Entry, sorted: seq<Entry>)
    ensures SzE(InsertE(e, sorted)) == SzE(sorted) + SzV(e.v) + 1
    ensures CanonE(sorted) && Canon(e.v) ==> CanonE(InsertE(e, sorted))
    ensures |InsertE(e, sorted)| == |sorted| + 1
    decreases |sorted|
  {
    if |sorted| > 0 && CmpStr(sorted[0].k, e.k) < 0 {
      InsertSz(e, sorted[1..]);
      if CanonE(sorted) && Canon(e.v) {
        assert CanonE(sorted[1..]) by { forall i | 0 <= i < |sorted[1..]| ensures Canon(sorted[1..][i].v) { assert sorted[1..][i] == sorted[i+1]; } }
        var r := InsertE(e, sorted[1..]);
        forall i | 0 <= i < |[sorted[0]] + r| ensures Canon(([sorted[0]] + r)[i].v) {
          if i > 0 { assert ([sorted[0]] + r)[i] == r[i-1]; }
        }
      }
    } else if |sorted| > 0 {
      if CanonE(sorted) && Canon(e.v) {
        forall i | 0 <= i < |[e] + sorted| ensures Canon(([e] + sorted)[i].v) { if i > 0 { assert ([e] + sorted)[i] == sorted[i-1]; } }
      }
    }
  }
  lemma SortSz(es: seq<Entry>)
    ensures SzE(SortE(es)) == SzE(es)
    ensures CanonE(es) ==> CanonE(SortE(es))
    ensures |SortE(es)| == |es|
    decreases |es|
  {
    if |es| > 0 {
      SortSz(es[1..]);
      InsertSz(es[0], SortE(es[1..]));
      if CanonE(es) {
        assert CanonE(es[1..]) by { forall i | 0 <= i < |es[1..]| ensures Canon(es[1..][i].v) { assert es[1..][i] == es[i+1]; } }
        assert Canon(es[0].v);
      }
    }
  }

  function SerL(xs: seq<Value>): seq<Tok> requires CanonL(xs) decreases SzL(xs), 1 {
    if |xs| == 0 then []
    else
      assert CanonL(xs[1..]) by { forall i | 0 <= i < |xs[1..]| ensures Canon(xs[1..][i]) { assert xs[1..][i] == xs[i+1]; } }
      assert Canon(xs[0]);
      Ser(xs[0]) + (if |xs| == 1 then [] else [TComma] + SerL(xs[1..]))
  }
  function SerE(es: seq<Entry>): seq<Tok> requires CanonE(es) decreases SzE(es), 1 {
    if |es| == 0 then []
    else
      assert CanonE(es[1..]) by { forall i | 0 <= i < |es[1..]| ensures Canon(es[1..][i].v) { assert es[1..][i] == es[i+1]; } }
      assert Canon(es[0].v);
      [TStrT(es[0].k), TColon] + Ser(es[0].v) + (if |es| == 1 then [] else [TComma] + SerE(es[1..]))
  }
  function Ser(v: Value): seq<Tok> requires Canon(v) decreases SzV(v), 0 {
    match v
    case VNull => [TNullT]
    case VBool(b) => [if b then TTrueT else TFalseT]
    case VNum(r) => [TNumT(r)]
    case VStr(s) => [TStrT(s)]
    case VArr(xs) => [TOpenA] + SerL(xs) + [TCloseA]
    case VObj(es, _) =>
      SortSz(es);
      [TOpenO] + SerE(SortE(es)) + [TCloseO]
  }
  predicate DeepEq(a: Value, b: Value) { Canon(a) && Canon(b) && Ser(a) == Ser(b) }

  lemma DeepEqSym(a: Value, b: Value) ensures DeepEq(a, b) == DeepEq(b, a) {}
  lemma DeepEqRefl(a: Value) requires Canon(a) ensures DeepEq(a, a) {}
  lemma DeepEqTrans(a: Value, b: Value, c: Value) requires DeepEq(a, b) && DeepEq(b, c) ensures DeepEq(a, c) {}
  // an uncanonicalisable value (undefined, function, NaN/Infinity, non-plain object, ...) is never equal to anything
  lemma DeepEqFailClosed(a: Value, b: Value) requires !Canon(a) || !Canon(b) ensures !DeepEq(a, b) {}

  // ---- KEY-ORDER INSENSITIVITY. A JS object has pairwise distinct keys. With the strict total order CmpStr the stable insertion sort
  // yields THE unique strictly sorted arrangement, so any permutation of the entries serialises identically (lone-surrogate keys included).
  ghost predicate KeysDistinct(es: seq<Entry>) { forall i, j :: 0 <= i < j < |es| ==> es[i].k != es[j].k }
  ghost predicate SortedE(es: seq<Entry>) { forall i, j :: 0 <= i < j < |es| ==> CmpStr(es[i].k, es[j].k) < 0 }

  lemma InsertProps(e: Entry, s: seq<Entry>)
    requires SortedE(s) && forall i :: 0 <= i < |s| ==> s[i].k != e.k
    ensures SortedE(InsertE(e, s)) && multiset(InsertE(e, s)) == multiset(s) + multiset{e}
    decreases |s|
  {
    if |s| == 0 {
    } else if CmpStr(s[0].k, e.k) >= 0 {
      CmpStrZero(s[0].k, e.k); CmpStrAntisym(s[0].k, e.k);
      assert CmpStr(e.k, s[0].k) < 0;
      var r := [e] + s;
      forall i, j | 0 <= i < j < |r| ensures CmpStr(r[i].k, r[j].k) < 0 {
        if i == 0 { if j > 1 { assert r[j] == s[j-1]; CmpStrTrans(e.k, s[0].k, s[j-1].k); } }
        else { assert r[i] == s[i-1] && r[j] == s[j-1]; }
      }
      assert s == [s[0]] + s[1..];
    } else {
      var t := s[1..];
      assert SortedE(t) by { forall i, j | 0 <= i < j < |t| ensures CmpStr(t[i].k, t[j].k) < 0 { assert t[i] == s[i+1] && t[j] == s[j+1]; } }
      InsertProps(e, t);
      var r := InsertE(e, t);
      assert InsertE(e, s) == [s[0]] + r;
      forall j | 0 <= j < |r| ensures CmpStr(s[0].k, r[j].k) < 0 {
        assert r[j] in multiset(r);
        assert r[j] in multiset(t) || r[j] == e;
        if r[j] == e {} else { var m :| 0 <= m < |t| && t[m] == r[j]; assert t[m] == s[m+1]; }
      }
      var q := [s[0]] + r;
      forall i, j | 0 <= i < j < |q| ensures CmpStr(q[i].k, q[j].k) < 0 {
        if i == 0 { assert q[j] == r[j-1]; } else { assert q[i] == r[i-1] && q[j] == r[j-1]; }
      }
      assert s == [s[0]] + t;
    }
  }

  lemma SortProps(es: seq<Entry>)
    requires KeysDistinct(es)
    ensures SortedE(SortE(es)) && multiset(SortE(es)) == multiset(es)
    decreases |es|
  {
    if |es| > 0 {
      var t := es[1..];
      assert KeysDistinct(t) by { forall i, j | 0 <= i < j < |t| ensures t[i].k != t[j].k { assert t[i] == es[i+1] && t[j] == es[j+1]; } }
      SortProps(t);
      var st := SortE(t);
      forall i | 0 <= i < |st| ensures st[i].k != es[0].k {
        assert st[i] in multiset(st);
        var m :| 0 <= m < |t| && t[m] == st[i];
        assert t[m] == es[m+1];
      }
      InsertProps(es[0], st);
      assert es == [es[0]] + t;
    }
  }

  lemma SortedUnique(a: seq<Entry>, b: seq<Entry>)
    requires SortedE(a) && SortedE(b) && multiset(a) == multiset(b)
    ensures a == b
    decreases |a|
  {
    assert |a| == |b| by { assert |multiset(a)| == |multiset(b)|; }
    if |a| > 0 {
      assert a[0] in multiset(b);
      var j :| 0 <= j < |b| && b[j] == a[0];
      assert b[0] in multiset(a);
      var i :| 0 <= i < |a| && a[i] == b[0];
      if i > 0 && j > 0 {
        assert CmpStr(a[0].k, b[0].k) < 0;
        assert CmpStr(b[0].k, a[0].k) < 0;
        CmpStrAntisym(a[0].k, b[0].k);
        assert false;
      }
      assert a[0] == b[0];
      assert a == [a[0]] + a[1..] && b == [b[0]] + b[1..];
      assert multiset(a) == multiset{a[0]} + multiset(a[1..]);
      assert multiset(b) == multiset{b[0]} + multiset(b[1..]);
      assert multiset(a[1..]) == multiset(a) - multiset{a[0]};
      assert multiset(b[1..]) == multiset(b) - multiset{b[0]};
      assert multiset(a[1..]) == multiset(b[1..]);
      assert SortedE(a[1..]) by { forall p, q | 0 <= p < q < |a[1..]| ensures CmpStr(a[1..][p].k, a[1..][q].k) < 0 { assert a[1..][p] == a[p+1] && a[1..][q] == a[q+1]; } }
      assert SortedE(b[1..]) by { forall p, q | 0 <= p < q < |b[1..]| ensures CmpStr(b[1..][p].k, b[1..][q].k) < 0 { assert b[1..][p] == b[p+1] && b[1..][q] == b[q+1]; } }
      SortedUnique(a[1..], b[1..]);
    }
  }

  // The sort is a function of the entry SET (for distinct keys): any permutation sorts to the same sequence.
  lemma SortPerm(es1: seq<Entry>, es2: seq<Entry>)
    requires KeysDistinct(es1) && multiset(es1) == multiset(es2)
    ensures SortE(es1) == SortE(es2)
  {
    assert KeysDistinct(es2) by {
      forall i, j | 0 <= i < j < |es2| ensures es2[i].k != es2[j].k {
        if es2[i].k == es2[j].k {
          if es2[i] == es2[j] {
            assert multiset(es2)[es2[i]] >= 2 by {
              assert es2 == es2[..j] + [es2[j]] + es2[j+1..];
              assert es2[i] in multiset(es2[..j]);
            }
            var m :| 0 <= m < |es1| && es1[m] == es2[i];
            assert multiset(es1)[es1[m]] >= 2;
            var es1m := es1[..m] + es1[m+1..];
            assert es1 == es1[..m] + [es1[m]] + es1[m+1..];
            assert es1[m] in multiset(es1m);
            var n :| 0 <= n < |es1m| && es1m[n] == es1[m];
            if n < m { assert es1m[n] == es1[n]; } else { assert es1m[n] == es1[n+1]; }
          } else {
            assert es2[i] in multiset(es1) && es2[j] in multiset(es1);
            var p :| 0 <= p < |es1| && es1[p] == es2[i];
            var q :| 0 <= q < |es1| && es1[q] == es2[j];
            assert p != q;
            if p < q {} else {}
          }
        }
      }
    }
    SortProps(es1); SortProps(es2);
    SortedUnique(SortE(es1), SortE(es2));
  }

  // deepEq is KEY-ORDER INSENSITIVE: a permutation of an object's entries never changes any deepEq verdict (eq / ne / in / nin).
  lemma DeepEqObjPerm(es1: seq<Entry>, es2: seq<Entry>, plain: bool, x: Value)
    requires KeysDistinct(es1) && multiset(es1) == multiset(es2)
    ensures DeepEq(VObj(es1, plain), x) == DeepEq(VObj(es2, plain), x)
    ensures DeepEq(x, VObj(es1, plain)) == DeepEq(x, VObj(es2, plain))
  {
    assert CanonE(es1) <==> CanonE(es2) by {
      if CanonE(es1) { forall i | 0 <= i < |es2| ensures Canon(es2[i].v) { assert es2[i] in multiset(es1); var m :| 0 <= m < |es1| && es1[m] == es2[i]; } }
      if CanonE(es2) { forall i | 0 <= i < |es1| ensures Canon(es1[i].v) { assert es1[i] in multiset(es2); var m :| 0 <= m < |es2| && es2[m] == es1[i]; } }
    }
    SortPerm(es1, es2);
    if Canon(VObj(es1, plain)) { assert Ser(VObj(es1, plain)) == Ser(VObj(es2, plain)); }
  }

  // ---- NESTED KEY-ORDER INSENSITIVITY (by induction over the value structure). Normalize sorts the entries of EVERY object at EVERY
  // depth (values normalised first). Two well-keyed values with the same normal form are deepEq-indistinguishable, and permuting the
  // entries of any object at any depth (NormPermTop + the congruences NormCongArr / NormCongObj, iterated along the path) keeps the
  // normal form. JS objects are well-keyed (pairwise distinct own keys at every depth).
  ghost predicate WellKeyed(v: Value) decreases v {
    match v
    case VArr(xs) => forall i :: 0 <= i < |xs| ==> WellKeyed(xs[i])
    case VObj(es, _) => KeysDistinct(es) && WellKeyedE(es)
    case _ => true
  }
  ghost predicate WellKeyedE(es: seq<Entry>) decreases es { forall i :: 0 <= i < |es| ==> WellKeyed(es[i].v) }

  ghost function Normalize(v: Value): Value decreases SzV(v), 0 {
    match v
    case VArr(xs) => VArr(NormL(xs))
    case VObj(es, p) => VObj(SortE(NormE(es)), p)
    case _ => v
  }
  ghost function NormL(xs: seq<Value>): seq<Value> decreases SzL(xs), 1 {
    if |xs| == 0 then [] else [Normalize(xs[0])] + NormL(xs[1..])
  }
  ghost function NormE(es: seq<Entry>): seq<Entry> decreases SzE(es), 1 {
    if |es| == 0 then [] else [Entry(es[0].k, Normalize(es[0].v))] + NormE(es[1..])
  }

  lemma NormLIdx(xs: seq<Value>)
    ensures |NormL(xs)| == |xs| && forall j :: 0 <= j < |xs| ==> NormL(xs)[j] == Normalize(xs[j])
    decreases |xs|
  { if |xs| > 0 { NormLIdx(xs[1..]); forall j | 1 <= j < |xs| ensures NormL(xs)[j] == Normalize(xs[j]) { assert xs[1..][j-1] == xs[j]; } } }
  lemma NormEIdx(es: seq<Entry>)
    ensures |NormE(es)| == |es| && forall j :: 0 <= j < |es| ==> NormE(es)[j] == Entry(es[j].k, Normalize(es[j].v))
    decreases |es|
  { if |es| > 0 { NormEIdx(es[1..]); forall j | 1 <= j < |es| ensures NormE(es)[j] == Entry(es[j].k, Normalize(es[j].v)) { assert es[1..][j-1] == es[j]; } } }

  lemma NormEKeys(es: seq<Entry>) ensures KeysDistinct(es) ==> KeysDistinct(NormE(es)) {
    NormEIdx(es);
    if KeysDistinct(es) { forall i, j | 0 <= i < j < |NormE(es)| ensures NormE(es)[i].k != NormE(es)[j].k { assert NormE(es)[i].k == es[i].k && NormE(es)[j].k == es[j].k; } }
  }

  // sorting compares keys only, so it commutes with normalising the values
  lemma InsertNormComm(e: Entry, s: seq<Entry>)
    ensures InsertE(Entry(e.k, Normalize(e.v)), NormE(s)) == NormE(InsertE(e, s))
    decreases |s|
  {
    if |s| > 0 {
      assert NormE(s)[0].k == s[0].k && NormE(s)[1..] == NormE(s[1..]);
      if CmpStr(s[0].k, e.k) >= 0 {
        assert NormE([e] + s) == [Entry(e.k, Normalize(e.v))] + NormE(s) by { assert ([e] + s)[0] == e && ([e] + s)[1..] == s; }
      } else {
        InsertNormComm(e, s[1..]);
        var r := InsertE(e, s[1..]);
        assert NormE([s[0]] + r) == [NormE(s)[0]] + NormE(r) by { assert ([s[0]] + r)[0] == s[0] && ([s[0]] + r)[1..] == r; }
      }
    } else {
      assert NormE([e]) == [Entry(e.k, Normalize(e.v))] by { assert [e][1..] == []; }
    }
  }
  lemma SortNormComm(es: seq<Entry>) ensures SortE(NormE(es)) == NormE(SortE(es)) decreases |es| {
    if |es| > 0 {
      assert NormE(es)[0] == Entry(es[0].k, Normalize(es[0].v)) && NormE(es)[1..] == NormE(es[1..]);
      SortNormComm(es[1..]);
      InsertNormComm(es[0], SortE(es[1..]));
    }
  }

  lemma SortedDistinct(s: seq<Entry>) requires SortedE(s) ensures KeysDistinct(s) {
    forall i, j | 0 <= i < j < |s| ensures s[i].k != s[j].k { CmpStrZero(s[i].k, s[j].k); }
  }
  // the sort is idempotent on a strictly sorted list
  lemma SortIdem(s: seq<Entry>) requires SortedE(s) ensures SortE(s) == s {
    SortedDistinct(s); SortProps(s); SortedUnique(SortE(s), s);
  }
  lemma CanonEMs(a: seq<Entry>, b: seq<Entry>) requires multiset(a) == multiset(b) ensures CanonE(a) == CanonE(b) {
    if CanonE(a) { forall i | 0 <= i < |b| ensures Canon(b[i].v) { assert b[i] in multiset(a); var m :| 0 <= m < |a| && a[m] == b[i]; } }
    if CanonE(b) { forall i | 0 <= i < |a| ensures Canon(a[i].v) { assert a[i] in multiset(b); var m :| 0 <= m < |b| && b[m] == a[i]; } }
  }
  lemma WellKeyedEMs(a: seq<Entry>, b: seq<Entry>) requires multiset(a) == multiset(b) && WellKeyedE(a) ensures WellKeyedE(b) {
    forall i | 0 <= i < |b| ensures WellKeyed(b[i].v) { assert b[i] in multiset(a); var m :| 0 <= m < |a| && a[m] == b[i]; }
  }

  // Normalisation preserves canonicalisability and the canonical text (induction over the structure).
  lemma SerNorm(v: Value)
    requires WellKeyed(v)
    ensures Canon(Normalize(v)) == Canon(v) && (Canon(v) ==> Ser(Normalize(v)) == Ser(v))
    decreases SzV(v), 0
  {
    match v
    case VArr(xs) => SerNormL(xs);
    case VObj(es, p) =>
      SortSz(es);
      SortProps(es);
      WellKeyedEMs(es, SortE(es));
      SerNormE(SortE(es));
      SortNormComm(es);
      CanonEMs(es, SortE(es));
      var ne := NormE(es);
      NormEKeys(es);
      SortProps(ne);
      SortIdem(SortE(ne));
      assert Normalize(v) == VObj(SortE(ne), p);
      assert SortE(ne) == NormE(SortE(es));
      if Canon(v) {
        assert CanonE(SortE(es));
        assert Ser(Normalize(v)) == [TOpenO] + SerE(SortE(SortE(ne))) + [TCloseO];
        assert Ser(v) == [TOpenO] + SerE(SortE(es)) + [TCloseO];
      }
    case _ =>
  }
  lemma SerNormL(xs: seq<Value>)
    requires forall i :: 0 <= i < |xs| ==> WellKeyed(xs[i])
    ensures CanonL(NormL(xs)) == CanonL(xs) && (CanonL(xs) ==> SerL(NormL(xs)) == SerL(xs))
    decreases SzL(xs), 1
  {
    NormLIdx(xs);
    if |xs| > 0 {
      SerNorm(xs[0]);
      SerNormL(xs[1..]);
      var n := NormL(xs);
      assert n[0] == Normalize(xs[0]) && n[1..] == NormL(xs[1..]);
      assert CanonL(n) == (Canon(n[0]) && CanonL(n[1..])) by {
        if Canon(n[0]) && CanonL(n[1..]) { forall i | 0 <= i < |n| ensures Canon(n[i]) { if i > 0 { assert n[i] == n[1..][i-1]; } } }
      }
      assert CanonL(xs) == (Canon(xs[0]) && CanonL(xs[1..])) by {
        if Canon(xs[0]) && CanonL(xs[1..]) { forall i | 0 <= i < |xs| ensures Canon(xs[i]) { if i > 0 { assert xs[i] == xs[1..][i-1]; } } }
      }
    }
  }
  lemma SerNormE(es: seq<Entry>)
    requires WellKeyedE(es)
    ensures CanonE(NormE(es)) == CanonE(es) && (CanonE(es) ==> SerE(NormE(es)) == SerE(es))
    decreases SzE(es), 1
  {
    NormEIdx(es);
    if |es| > 0 {
      SerNorm(es[0].v);
      assert WellKeyedE(es[1..]) by { forall i | 0 <= i < |es[1..]| ensures WellKeyed(es[1..][i].v) { assert es[1..][i] == es[i+1]; } }
      SerNormE(es[1..]);
      var n := NormE(es);
      assert n[0] == Entry(es[0].k, Normalize(es[0].v)) && n[1..] == NormE(es[1..]);
      assert CanonE(n) == (Canon(n[0].v) && CanonE(n[1..])) by {
        if Canon(n[0].v) && CanonE(n[1..]) { forall i | 0 <= i < |n| ensures Canon(n[i].v) { if i > 0 { assert n[i] == n[1..][i-1]; } } }
      }
      assert CanonE(es) == (Canon(es[0].v) && CanonE(es[1..])) by {
        if Canon(es[0].v) && CanonE(es[1..]) { forall i | 0 <= i < |es| ensures Canon(es[i].v) { if i > 0 { assert es[i] == es[1..][i-1]; } } }
      }
    }
  }

  // THEOREM (nested key-order insensitivity): well-keyed values with the same normal form serialise identically, so no deepEq verdict
  // (eq / ne / in / nin, either argument position) can tell them apart.
  lemma NormEqSer(a: Value, b: Value)
    requires WellKeyed(a) && WellKeyed(b) && Normalize(a) == Normalize(b)
    ensures Canon(a) == Canon(b) && (Canon(a) ==> Ser(a) == Ser(b))
  { SerNorm(a); SerNorm(b); }

  lemma DeepEqDeepPerm(a: Value, b: Value, x: Value)
    requires WellKeyed(a) && WellKeyed(b) && Normalize(a) == Normalize(b)
    ensures DeepEq(a, x) == DeepEq(b, x) && DeepEq(x, a) == DeepEq(x, b)
  { NormEqSer(a, b); }

  // ... and permuting the entries of ANY object at ANY depth keeps the normal form:
  // (1) at the top: a permutation of an object's entries (distinct keys);
  lemma NormPermTop(es1: seq<Entry>, es2: seq<Entry>, p: bool)
    requires KeysDistinct(es1) && multiset(es1) == multiset(es2)
    ensures Normalize(VObj(es1, p)) == Normalize(VObj(es2, p))
  { SortPerm(es1, es2); SortNormComm(es1); SortNormComm(es2); }
  // (2) inside an array element / (3) inside an object entry value: replacing a child by one with the same normal form.
  lemma NormCongArr(xs: seq<Value>, i: nat, y: Value)
    requires i < |xs| && Normalize(y) == Normalize(xs[i])
    ensures Normalize(VArr(xs[i := y])) == Normalize(VArr(xs))
  {
    NormLIdx(xs); NormLIdx(xs[i := y]);
    assert NormL(xs[i := y]) == NormL(xs);
  }
  lemma NormCongObj(es: seq<Entry>, i: nat, y: Value, p: bool)
    requires i < |es| && Normalize(y) == Normalize(es[i].v)
    ensures Normalize(VObj(es[i := Entry(es[i].k, y)], p)) == Normalize(VObj(es, p))
  {
    NormEIdx(es); NormEIdx(es[i := Entry(es[i].k, y)]);
    assert NormE(es[i := Entry(es[i].k, y)]) == NormE(es);
  }

  // ------------------------------------------------------------------ ordering (lt/lte/gt/gte)
  function Ordered(a: Value, b: Value): Option<int> {
    if a.VNum? && b.VNum? then Some(if a.r < b.r then -1 else if a.r > b.r then 1 else 0)
    else if a.VStr? && b.VStr? then (if HasLone(a.s) || HasLone(b.s) then None else Some(CmpStr(a.s, b.s)))
    else None
  }

  predicate StartsWith(s: Str, p: Str) { |p| <= |s| && s[..|p|] == p }

  // ------------------------------------------------------------------ is_a
  function ExistsStrEq(xs: seq<Value>, t: Str): bool decreases xs {
    |xs| > 0 && ((xs[0].VStr? && xs[0].s == t) || ExistsStrEq(xs[1..], t))
  }
  function TypeTagMatch(v: Value, t: Str): Option<bool> {
    match v
    case VStr(s) => Some(s == t || StartsWith(s, t + S("::")))
    case VObj(es, _) =>
      var ty := if Has(es, S("type")) then Get(es, S("type")) else VUndef;
      var tg := if Has(es, S("tags")) then Get(es, S("tags")) else VUndef;
      var d1 := ty.VStr?;
      var m1 := d1 && (ty.s == t || StartsWith(ty.s, t + S("::")));
      var d2 := tg.VArr?;
      var m2 := d2 && ExistsStrEq(tg.xs, t);
      if d1 || d2 then Some(m1 || m2) else None
    case _ => None
  }

  // ------------------------------------------------------------------ member_of: bounded reflexive transitive closure
  const MaxClosure: nat := 10000
  function StrsOf(xs: seq<Value>): seq<Str> decreases xs {
    if |xs| == 0 then [] else (if xs[0].VStr? then [xs[0].s] else []) + StrsOf(xs[1..])
  }
  function Neighbours(es: seq<Entry>, node: Str): seq<Str> {
    if Forbidden(node) || !Has(es, node) then []
    else match Get(es, node)
      case VStr(s) => [s]
      case VArr(xs) => StrsOf(xs)
      case _ => []
  }
  function AddNs(ns: seq<Str>, seen: set<Str>, q: seq<Str>): (set<Str>, seq<Str>) decreases |ns| {
    if |ns| == 0 then (seen, q)
    else if ns[0] in seen then AddNs(ns[1..], seen, q)
    else AddNs(ns[1..], seen + {ns[0]}, q + [ns[0]])
  }
  // while (queue.length > 0 && visited < MAX) { visited++; node = queue.shift(); for n of neighbours: if !seen has n: seen.add, queue.push }
  function Bfs(es: seq<Entry>, q: seq<Str>, qi: nat, seen: set<Str>, visited: nat): set<Str>
    requires visited <= MaxClosure decreases MaxClosure - visited
  {
    if qi >= |q| || visited >= MaxClosure then seen
    else
      var r := AddNs(Neighbours(es, q[qi]), seen, q);
      Bfs(es, r.1, qi + 1, r.0, visited + 1)
  }
  function Closure(start: Str, es: seq<Entry>): set<Str> { Bfs(es, [start], 0, {start}, 0) }

  lemma BfsKeepsSeen(es: seq<Entry>, q: seq<Str>, qi: nat, seen: set<Str>, visited: nat)
    requires visited <= MaxClosure ensures seen <= Bfs(es, q, qi, seen, visited) decreases MaxClosure - visited
  {
    if !(qi >= |q| || visited >= MaxClosure) {
      var r := AddNs(Neighbours(es, q[qi]), seen, q);
      AddNsGrows(Neighbours(es, q[qi]), seen, q);
      BfsKeepsSeen(es, r.1, qi + 1, r.0, visited + 1);
    }
  }
  lemma AddNsGrows(ns: seq<Str>, seen: set<Str>, q: seq<Str>) ensures seen <= AddNs(ns, seen, q).0 decreases |ns| {
    if |ns| > 0 { if ns[0] in seen { AddNsGrows(ns[1..], seen, q); } else { AddNsGrows(ns[1..], seen + {ns[0]}, q); } }
  }
  // reflexive: the start node is always in its own closure
  lemma ClosureReflexive(start: Str, es: seq<Entry>) ensures start in Closure(start, es) { BfsKeepsSeen(es, [start], 0, {start}, 0); }

  // ------------------------------------------------------------------ like: anchored glob, O(|glob| x |s|), no regex engine
  datatype GTok = GLit(c: U) | GOne | GStar
  function ParseGlob(g: Str, i: nat, acc: seq<GTok>): Option<seq<GTok>> requires i <= |g| decreases |g| - i {
    if i == |g| then Some(acc)
    else if g[i] == 92 then (if i + 1 >= |g| then None else ParseGlob(g, i + 2, acc + [GLit(g[i+1])]))
    else if g[i] == 42 then ParseGlob(g, i + 1, if |acc| > 0 && acc[|acc|-1].GStar? then acc else acc + [GStar])
    else if g[i] == 63 then ParseGlob(g, i + 1, acc + [GOne])
    else ParseGlob(g, i + 1, acc + [GLit(g[i])])
  }
  lemma ParseGlobLen(g: Str, i: nat, acc: seq<GTok>)
    requires i <= |g| ensures ParseGlob(g, i, acc).Some? ==> |ParseGlob(g, i, acc).v| <= |acc| + (|g| - i) decreases |g| - i
  {
    if i < |g| {
      if g[i] == 92 { if i + 1 < |g| { ParseGlobLen(g, i + 2, acc + [GLit(g[i+1])]); } }
      else if g[i] == 42 { ParseGlobLen(g, i + 1, if |acc| > 0 && acc[|acc|-1].GStar? then acc else acc + [GStar]); }
      else if g[i] == 63 { ParseGlobLen(g, i + 1, acc + [GOne]); }
      else { ParseGlobLen(g, i + 1, acc + [GLit(g[i])]); }
    }
  }

  // declarative semantics of an anchored glob (`*` any run, `?` one code unit, literals)
  function Gm(t: seq<GTok>, s: Str): bool decreases |t| + |s|, |t| {
    if |t| == 0 then |s| == 0
    else match t[0]
      case GStar => Gm(t[1..], s) || (|s| > 0 && Gm(t, s[1..]))
      case GOne => |s| > 0 && Gm(t[1..], s[1..])
      case GLit(c) => |s| > 0 && s[0] == c && Gm(t[1..], s[1..])
  }

  lemma MulSucc(a: nat, b: nat) ensures (a + 1) * b == a * b + b {}

  method GlobFullCounted(t: seq<GTok>, s: Str) returns (r: bool, steps: nat)
    ensures r == Gm(t, s)
    ensures steps == (|t| + 1) * (|s| + 1)
  {
    var n := |s|;
    var prev := new bool[n + 1];
    var k := 0;
    while k <= n
      invariant 0 <= k <= n + 1
      invariant prev.Length == n + 1
      invariant forall j :: 0 <= j < k ==> prev[j] == (j == n)
    { prev[k] := (k == n); k := k + 1; }
    assert t[|t|..] == [];
    assert forall j :: 0 <= j <= n ==> prev[j] == Gm(t[|t|..], s[j..]);
    var i := |t|;
    steps := n + 1;
    while i > 0
      invariant 0 <= i <= |t|
      invariant prev.Length == n + 1
      invariant forall j :: 0 <= j <= n ==> prev[j] == Gm(t[i..], s[j..])
      invariant steps == (|t| - i + 1) * (n + 1)
    {
      i := i - 1;
      var cur := new bool[n + 1];
      var j: int := n;
      while j >= 0
        decreases j + 1
        invariant -1 <= j <= n
        invariant cur.Length == n + 1 && prev.Length == n + 1
        invariant forall m :: j < m <= n ==> cur[m] == Gm(t[i..], s[m..])
        invariant forall m :: 0 <= m <= n ==> prev[m] == Gm(t[i+1..], s[m..])
      {
        assert t[i..][1..] == t[i+1..];
        if j < n { assert s[j..][1..] == s[j+1..]; }
        assert t[i..][0] == t[i];
        match t[i] {
        case GStar => { cur[j] := prev[j] || (j < n && cur[j + 1]); }
        case GOne => { cur[j] := j < n && prev[j + 1]; }
        case GLit(c) => { cur[j] := j < n && s[j] == c && prev[j + 1]; }
        }
        j := j - 1;
      }
      prev := cur;
      MulSucc(|t| - i, n + 1);
      steps := steps + (n + 1);
    }
    assert t[0..] == t;
    assert s[0..] == s;
    r := prev[0];
  }
  function GlobFull(t: seq<GTok>, s: Str): bool { Gm(t, s) } by method {
    var r, st := GlobFullCounted(t, s);
    return r;
  }

  // ------------------------------------------------------------------ the oracles
  // `safe` = isSafeRegexSource (the guard), `full` = safeRegexFullMatch (None = unsupported / over budget). Another module proves them;
  // everything below holds for EVERY pair of functions.
  datatype Rx = Rx(safe: Str -> bool, full: (Str, Str) -> Option<bool>)

  const MaxPatternSubjectLen: nat := 512
  const MaxLikePatternLen: nat := 512
  const MaxMatchesPatternLen: nat := 200
  const MaxReResourceLen: nat := 512

  predicate ParamsRooted(s: Str) { s == S("action.params") || StartsWith(s, S("action.params.")) }
  // ctx?.action?.params is an object (arrays included)
  predicate ParamsAvail(ctx: Value) { IsObjLike(Field(Field(ctx, S("action")), S("params"))) }

  // the right-hand operand of a leaf: `ref` (resolved path) else the literal `value`; None = unresolved / missing
  function Operand(c: Value, ctx: Value): Option<Value> {
    var refV := Field(c, S("ref"));
    if !refV.VUndef? then (var r := ResolvePath(ctx, refV); if r.found then Some(r.v) else None)
    else (var vv := Field(c, S("value")); if vv.VUndef? then None else Some(vv))
  }

  function ExistsDeepEq(v: Value, xs: seq<Value>): bool decreases xs {
    |xs| > 0 && (DeepEq(v, xs[0]) || ExistsDeepEq(v, xs[1..]))
  }
  function B2T(b: bool): Tri { if b then TT else TF }

  function LeafOp(op: Str, v: Value, operand: Value, rx: Rx): Tri {
    if op == S("eq") then B2T(DeepEq(v, operand))
    else if op == S("ne") then B2T(!DeepEq(v, operand))
    else if op == S("in") then (if operand.VArr? then B2T(ExistsDeepEq(v, operand.xs)) else TU)
    else if op == S("nin") then (if operand.VArr? then B2T(!ExistsDeepEq(v, operand.xs)) else TU)
    else if op == S("lt") || op == S("lte") || op == S("gt") || op == S("gte") then
      (match Ordered(v, operand)
       case None => TU
       case Some(o) => B2T(if op == S("lt") then o < 0 else if op == S("lte") then o <= 0 else if op == S("gt") then o > 0 else o >= 0))
    else if op == S("prefix") then (if v.VStr? && operand.VStr? then B2T(StartsWith(v.s, operand.s)) else TU)
    else if op == S("like") then
      (if !(v.VStr? && operand.VStr?) then TU
       else if |operand.s| > MaxLikePatternLen || |v.s| > MaxPatternSubjectLen then TU
       else match ParseGlob(operand.s, 0, [])
         case None => TU
         case Some(t) => B2T(GlobFull(t, v.s)))
    else if op == S("matches") then
      (if !(v.VStr? && operand.VStr?) then TU
       else if |operand.s| > MaxMatchesPatternLen || |v.s| > MaxPatternSubjectLen then TU
       else if !rx.safe(operand.s) then TU
       else match rx.full(operand.s, v.s)
         case None => TU
         case Some(b) => B2T(b))
    else if op == S("is_a") then
      (if !(operand.VStr? && |operand.s| > 0) then TU
       else match TypeTagMatch(v, operand.s)
         case None => TU
         case Some(b) => B2T(b))
    else TU
  }

  function MemberOfLeaf(c: Value, ctx: Value, v: Value): Tri {
    if !v.VStr? then TU
    else
      var cv := Field(c, S("collection"));
      if !cv.VStr? || |cv.s| == 0 then TU
      else
        var coll := ResolvePath(ctx, cv);
        if !coll.found || !IsObjRec(coll.v) then TU
        else match Operand(c, ctx)
          case None => TU
          case Some(opd) =>
            var targets := if opd.VArr? then StrsOf(opd.xs) else if opd.VStr? then [opd.s] else [];
            if |targets| == 0 then TU
            else
              var reach := Closure(v.s, coll.v.es);
              B2T(exists i :: 0 <= i < |targets| && targets[i] in reach)
  }

  // Tri-valued evaluation of one LEAF (triLeaf)
  function TriLeaf(c: Value, ctx: Value, rx: Rx): Tri {
    var fv := Field(c, S("field"));
    var ov := Field(c, S("op"));
    var rv := Field(c, S("ref"));
    if !fv.VStr? || |fv.s| == 0 then TU
    else if !ov.VStr? then TU
    else if ParamsRooted(fv.s) && !ParamsAvail(ctx) then TU
    else if rv.VStr? && ParamsRooted(rv.s) && !ParamsAvail(ctx) then TU
    else
      var f := ResolvePath(ctx, fv);
      var op := ov.s;
      if op == S("exists") then
        (if Field(c, S("value")) == VBool(false) then B2T(!f.found) else B2T(f.found))
      else if !f.found then TU
      else if op == S("member_of") then MemberOfLeaf(c, ctx, f.v)
      else match Operand(c, ctx)
        case None => TU
        case Some(operand) => LeafOp(op, f.v, operand, rx)
  }

  lemma SzGet(es: seq<Entry>, k: Str) requires Has(es, k) ensures SzV(Get(es, k)) < SzE(es) decreases es {
    if es[0].k != k { SzGet(es[1..], k); }
  }

  // evaluateConditionTri together with the number of condition nodes visited
  function EvalTriC(c: Value, ctx: Value, rx: Rx): (Tri, nat) decreases SzV(c), 1 {
    match c
    case VObj(es, _) =>
      if Has(es, S("all_of")) then
        SzGet(es, S("all_of"));
        var a := Get(es, S("all_of"));
        if !a.VArr? || |a.xs| == 0 then (TU, 1)
        else var r := EvalAllC(a.xs, ctx, rx, false); (r.0, 1 + r.1)
      else if Has(es, S("any_of")) then
        SzGet(es, S("any_of"));
        var a := Get(es, S("any_of"));
        if !a.VArr? || |a.xs| == 0 then (TU, 1)
        else var r := EvalAnyC(a.xs, ctx, rx, false); (r.0, 1 + r.1)
      else if Has(es, S("not")) then
        SzGet(es, S("not"));
        var r := EvalTriC(Get(es, S("not")), ctx, rx);
        (NotT(r.0), 1 + r.1)
      else (TriLeaf(c, ctx, rx), 1)
    case _ => (TU, 1)
  }
  // all_of: stop at the first false, remember unknowns
  function EvalAllC(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool): (Tri, nat) decreases SzL(xs), 2 {
    if |xs| == 0 then ((if sawU then TU else TT), 0)
    else
      var r := EvalTriC(xs[0], ctx, rx);
      if r.0 == TF then (TF, r.1)
      else var q := EvalAllC(xs[1..], ctx, rx, sawU || r.0 == TU); (q.0, r.1 + q.1)
  }
  // any_of: stop at the first true
  function EvalAnyC(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool): (Tri, nat) decreases SzL(xs), 2 {
    if |xs| == 0 then ((if sawU then TU else TF), 0)
    else
      var r := EvalTriC(xs[0], ctx, rx);
      if r.0 == TT then (TT, r.1)
      else var q := EvalAnyC(xs[1..], ctx, rx, sawU || r.0 == TU); (q.0, r.1 + q.1)
  }

  function EvalTri(c: Value, ctx: Value, rx: Rx): Tri { EvalTriC(c, ctx, rx).0 }
  // evaluateCondition: exactly `=== 'true'`
  predicate EvalCond(c: Value, ctx: Value, rx: Rx) { EvalTri(c, ctx, rx) == TT }

  // ------------------------------------------------------------------ theorems: Kleene logic
  lemma NotInvolutive(t: Tri) ensures NotT(NotT(t)) == t {}
  lemma NotUnknown() ensures NotT(TU) == TU {}
  // De Morgan duality of the two connectives
  function MapNot(ts: seq<Tri>): seq<Tri> { seq(|ts|, i requires 0 <= i < |ts| => NotT(ts[i])) }
  lemma NotInMapNot(ts: seq<Tri>, t: Tri) ensures (NotT(t) in MapNot(ts)) <==> (t in ts) {
    if t in ts { var i :| 0 <= i < |ts| && ts[i] == t; assert MapNot(ts)[i] == NotT(t); }
    if NotT(t) in MapNot(ts) { var i :| 0 <= i < |ts| && MapNot(ts)[i] == NotT(t); assert NotT(ts[i]) == NotT(t); assert ts[i] == t; }
  }
  lemma DeMorganAll(ts: seq<Tri>) ensures NotT(AllT(ts)) == AnyT(MapNot(ts)) {
    NotInMapNot(ts, TF); NotInMapNot(ts, TU); NotInMapNot(ts, TT);
    assert (TT in MapNot(ts)) <==> (TF in ts);
    assert (TU in MapNot(ts)) <==> (TU in ts);
  }
  lemma DeMorganAny(ts: seq<Tri>) ensures NotT(AnyT(ts)) == AllT(MapNot(ts)) {
    NotInMapNot(ts, TT); NotInMapNot(ts, TU);
    assert (TF in MapNot(ts)) <==> (TT in ts);
    assert (TU in MapNot(ts)) <==> (TU in ts);
  }
  // order independence: only the SET of child results matters (hence any permutation / duplication gives the same result)
  lemma AllSetOnly(a: seq<Tri>, b: seq<Tri>) requires forall t :: t in a <==> t in b ensures AllT(a) == AllT(b) {}
  lemma AnySetOnly(a: seq<Tri>, b: seq<Tri>) requires forall t :: t in a <==> t in b ensures AnyT(a) == AnyT(b) {}
  lemma AllPerm(a: seq<Tri>, b: seq<Tri>) requires multiset(a) == multiset(b) ensures AllT(a) == AllT(b) {
    assert forall t :: (t in a) <==> (t in multiset(a));
    assert forall t :: (t in b) <==> (t in multiset(b));
  }
  lemma AnyPerm(a: seq<Tri>, b: seq<Tri>) requires multiset(a) == multiset(b) ensures AnyT(a) == AnyT(b) {
    assert forall t :: (t in a) <==> (t in multiset(a));
    assert forall t :: (t in b) <==> (t in multiset(b));
  }
  // information monotonicity (Kleene): making children MORE defined can only make the result more defined, never contradicting it
  predicate PointRefines(a: seq<Tri>, b: seq<Tri>) { |a| == |b| && forall i :: 0 <= i < |a| ==> Refines(a[i], b[i]) }
  lemma AllRefines(a: seq<Tri>, b: seq<Tri>) requires PointRefines(a, b) ensures Refines(AllT(a), AllT(b)) {
    if AllT(a) == TF { var i :| 0 <= i < |a| && a[i] == TF; assert b[i] == TF; }
    if AllT(a) == TT { forall i | 0 <= i < |a| ensures b[i] == TT { assert a[i] == TT; } assert !(TF in b); assert !(TU in b); }
  }
  lemma AnyRefines(a: seq<Tri>, b: seq<Tri>) requires PointRefines(a, b) ensures Refines(AnyT(a), AnyT(b)) {
    if AnyT(a) == TT { var i :| 0 <= i < |a| && a[i] == TT; assert b[i] == TT; }
    if AnyT(a) == TF { forall i | 0 <= i < |a| ensures b[i] == TF { assert a[i] == TF; } assert !(TT in b); assert !(TU in b); }
  }
  lemma NotRefines(a: Tri, b: Tri) requires Refines(a, b) ensures Refines(NotT(a), NotT(b)) {}
  // a clean verdict is what satisfies: `all_of` is TT only if every child is TT, `any_of` only if some child is TT
  lemma AllTrueIff(ts: seq<Tri>) ensures (AllT(ts) == TT) <==> (forall i :: 0 <= i < |ts| ==> ts[i] == TT) {
    if forall i :: 0 <= i < |ts| ==> ts[i] == TT { assert !(TF in ts); assert !(TU in ts); }
    if AllT(ts) == TT { forall i | 0 <= i < |ts| ensures ts[i] == TT { assert ts[i] != TF; assert ts[i] != TU; } }
  }
  lemma AnyTrueIff(ts: seq<Tri>) ensures (AnyT(ts) == TT) <==> (exists i :: 0 <= i < |ts| && ts[i] == TT) {
    if TT in ts { var i :| 0 <= i < |ts| && ts[i] == TT; }
  }
  // appending a child to all_of never turns a false/unknown into true; appending to any_of never turns a true into anything else
  lemma AllAppendAntitone(ts: seq<Tri>, t: Tri) ensures AllT(ts + [t]) == TT ==> AllT(ts) == TT {
    if AllT(ts + [t]) == TT { assert !(TF in ts) && !(TU in ts) by { assert forall x :: x in ts ==> x in ts + [t]; } }
  }

  // ------------------------------------------------------------------ theorems: the condition evaluator
  function Results(xs: seq<Value>, ctx: Value, rx: Rx): seq<Tri> decreases xs {
    if |xs| == 0 then [] else [EvalTri(xs[0], ctx, rx)] + Results(xs[1..], ctx, rx)
  }
  lemma ResultsIdx(xs: seq<Value>, ctx: Value, rx: Rx)
    ensures |Results(xs, ctx, rx)| == |xs|
    ensures forall i :: 0 <= i < |xs| ==> Results(xs, ctx, rx)[i] == EvalTri(xs[i], ctx, rx)
    decreases xs
  {
    if |xs| > 0 { ResultsIdx(xs[1..], ctx, rx); }
  }
  lemma AllChar(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool)
    ensures EvalAllC(xs, ctx, rx, sawU).0 == (if TF in Results(xs, ctx, rx) then TF else if sawU || TU in Results(xs, ctx, rx) then TU else TT)
    decreases xs
  {
    if |xs| > 0 {
      var r := EvalTriC(xs[0], ctx, rx);
      AllChar(xs[1..], ctx, rx, sawU || r.0 == TU);
      assert Results(xs, ctx, rx) == [r.0] + Results(xs[1..], ctx, rx);
    }
  }
  lemma AnyChar(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool)
    ensures EvalAnyC(xs, ctx, rx, sawU).0 == (if TT in Results(xs, ctx, rx) then TT else if sawU || TU in Results(xs, ctx, rx) then TU else TF)
    decreases xs
  {
    if |xs| > 0 {
      var r := EvalTriC(xs[0], ctx, rx);
      AnyChar(xs[1..], ctx, rx, sawU || r.0 == TU);
      assert Results(xs, ctx, rx) == [r.0] + Results(xs[1..], ctx, rx);
    }
  }
  // all_of / any_of / not are exactly the Kleene connectives of the children's verdicts (the TS short-circuit changes nothing)
  lemma EvalAllOf(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && Has(c.es, S("all_of")) && Get(c.es, S("all_of")).VArr? && |Get(c.es, S("all_of")).xs| > 0
    ensures EvalTri(c, ctx, rx) == AllT(Results(Get(c.es, S("all_of")).xs, ctx, rx))
  { SzGet(c.es, S("all_of")); AllChar(Get(c.es, S("all_of")).xs, ctx, rx, false); }
  lemma EvalAnyOf(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && !Has(c.es, S("all_of")) && Has(c.es, S("any_of")) && Get(c.es, S("any_of")).VArr? && |Get(c.es, S("any_of")).xs| > 0
    ensures EvalTri(c, ctx, rx) == AnyT(Results(Get(c.es, S("any_of")).xs, ctx, rx))
  { SzGet(c.es, S("any_of")); AnyChar(Get(c.es, S("any_of")).xs, ctx, rx, false); }
  lemma EvalNot(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && !Has(c.es, S("all_of")) && !Has(c.es, S("any_of")) && Has(c.es, S("not"))
    ensures EvalTri(c, ctx, rx) == NotT(EvalTri(Get(c.es, S("not")), ctx, rx))
  { SzGet(c.es, S("not")); }
  // fail closed: an empty / non-array group, a non-object, null, undefined, a function ... is `unknown`, hence never satisfied
  lemma EvalGroupMalformed(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && ((Has(c.es, S("all_of")) && !(Get(c.es, S("all_of")).VArr? && |Get(c.es, S("all_of")).xs| > 0))
                      || (!Has(c.es, S("all_of")) && Has(c.es, S("any_of")) && !(Get(c.es, S("any_of")).VArr? && |Get(c.es, S("any_of")).xs| > 0)))
    ensures EvalTri(c, ctx, rx) == TU && !EvalCond(c, ctx, rx)
  { if Has(c.es, S("all_of")) { SzGet(c.es, S("all_of")); } else { SzGet(c.es, S("any_of")); } }
  lemma EvalNonObjectUnknown(c: Value, ctx: Value, rx: Rx)
    requires !c.VObj? ensures EvalTri(c, ctx, rx) == TU && !EvalCond(c, ctx, rx) {}
  // `not` fails closed: an unknown child never satisfies it
  lemma NotUnknownNeverSatisfies(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && !Has(c.es, S("all_of")) && !Has(c.es, S("any_of")) && Has(c.es, S("not")) && EvalTri(Get(c.es, S("not")), ctx, rx) == TU
    ensures !EvalCond(c, ctx, rx)
  { EvalNot(c, ctx, rx); }
  lemma NotSatisfiedIffChildFalse(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && !Has(c.es, S("all_of")) && !Has(c.es, S("any_of")) && Has(c.es, S("not"))
    ensures EvalCond(c, ctx, rx) <==> EvalTri(Get(c.es, S("not")), ctx, rx) == TF
  { EvalNot(c, ctx, rx); }
  lemma AllOfSatisfiedImpliesChildren(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && Has(c.es, S("all_of")) && Get(c.es, S("all_of")).VArr? && |Get(c.es, S("all_of")).xs| > 0 && EvalCond(c, ctx, rx)
    ensures forall i :: 0 <= i < |Get(c.es, S("all_of")).xs| ==> EvalCond(Get(c.es, S("all_of")).xs[i], ctx, rx)
  {
    EvalAllOf(c, ctx, rx);
    var xs := Get(c.es, S("all_of")).xs;
    AllTrueIff(Results(xs, ctx, rx)); ResultsIdx(xs, ctx, rx);
  }
  lemma AnyOfSatisfiedImpliesChild(c: Value, ctx: Value, rx: Rx)
    requires c.VObj? && !Has(c.es, S("all_of")) && Has(c.es, S("any_of")) && Get(c.es, S("any_of")).VArr? && |Get(c.es, S("any_of")).xs| > 0 && EvalCond(c, ctx, rx)
    ensures exists i :: 0 <= i < |Get(c.es, S("any_of")).xs| && EvalCond(Get(c.es, S("any_of")).xs[i], ctx, rx)
  {
    EvalAnyOf(c, ctx, rx);
    var xs := Get(c.es, S("any_of")).xs;
    AnyTrueIff(Results(xs, ctx, rx)); ResultsIdx(xs, ctx, rx);
  }
  // leaf fail-closed pre-checks: a leaf without a non-empty string `field` / a string `op` is unknown
  lemma LeafMalformedUnknown(c: Value, ctx: Value, rx: Rx)
    requires !(Field(c, S("field")).VStr? && |Field(c, S("field")).s| > 0 && Field(c, S("op")).VStr?)
    ensures TriLeaf(c, ctx, rx) == TU {}
  // params-rooted conditions fail closed when params were not supplied (exists:false cannot pass vacuously)
  lemma ParamsUnavailableUnknown(c: Value, ctx: Value, rx: Rx)
    requires Field(c, S("field")).VStr? && ParamsRooted(Field(c, S("field")).s) && Field(c, S("op")).VStr? && !ParamsAvail(ctx)
    ensures TriLeaf(c, ctx, rx) == TU {}
  // unknown operator => unknown
  lemma UnknownOpUnknown(op: Str, v: Value, operand: Value, rx: Rx)
    requires op !in {S("eq"), S("ne"), S("in"), S("nin"), S("lt"), S("lte"), S("gt"), S("gte"), S("prefix"), S("like"), S("matches"), S("is_a")}
    ensures LeafOp(op, v, operand, rx) == TU {}

  // ------------------------------------------------------------------ theorems: resource use
  lemma CountBoundC(c: Value, ctx: Value, rx: Rx) ensures EvalTriC(c, ctx, rx).1 <= SzV(c) decreases SzV(c), 1 {
    match c
    case VObj(es, _) =>
      if Has(es, S("all_of")) {
        SzGet(es, S("all_of")); var a := Get(es, S("all_of"));
        if a.VArr? && |a.xs| > 0 { CountBoundA(a.xs, ctx, rx, false); }
      } else if Has(es, S("any_of")) {
        SzGet(es, S("any_of")); var a := Get(es, S("any_of"));
        if a.VArr? && |a.xs| > 0 { CountBoundN(a.xs, ctx, rx, false); }
      } else if Has(es, S("not")) { SzGet(es, S("not")); CountBoundC(Get(es, S("not")), ctx, rx); }
    case _ =>
  }
  lemma CountBoundA(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool) ensures EvalAllC(xs, ctx, rx, sawU).1 <= SzL(xs) decreases SzL(xs), 2 {
    if |xs| > 0 { CountBoundC(xs[0], ctx, rx); CountBoundA(xs[1..], ctx, rx, sawU || EvalTri(xs[0], ctx, rx) == TU); }
  }
  lemma CountBoundN(xs: seq<Value>, ctx: Value, rx: Rx, sawU: bool) ensures EvalAnyC(xs, ctx, rx, sawU).1 <= SzL(xs) decreases SzL(xs), 2 {
    if |xs| > 0 { CountBoundC(xs[0], ctx, rx); CountBoundN(xs[1..], ctx, rx, sawU || EvalTri(xs[0], ctx, rx) == TU); }
  }
  // every condition node is visited at most once: the number of visited nodes never exceeds the size of the condition tree
  lemma EvalVisitsAtMostSize(c: Value, ctx: Value, rx: Rx) ensures EvalTriC(c, ctx, rx).1 <= SzV(c) { CountBoundC(c, ctx, rx); }

  // budgeted variant: refuse (fail closed, unknown) when the tree is larger than the budget; otherwise identical to the evaluator
  function EvalBudgeted(c: Value, ctx: Value, rx: Rx, budget: nat): Option<Tri> {
    if SzV(c) > budget then None else Some(EvalTri(c, ctx, rx))
  }
  lemma BudgetedSound(c: Value, ctx: Value, rx: Rx, budget: nat)
    ensures EvalBudgeted(c, ctx, rx, budget).Some? ==> EvalBudgeted(c, ctx, rx, budget).v == EvalTri(c, ctx, rx) && EvalTriC(c, ctx, rx).1 <= budget
    ensures EvalBudgeted(c, ctx, rx, budget).None? ==> SzV(c) > budget
  { CountBoundC(c, ctx, rx); }

  // a glob leaf costs at most (|pattern|+1)(|subject|+1) <= 513 * 513 cell updates (the caps are enforced before the matcher runs)
  lemma GlobLeafBound(g: Str, s: Str)
    requires |g| <= MaxLikePatternLen && |s| <= MaxPatternSubjectLen
    ensures ParseGlob(g, 0, []).Some? ==> |ParseGlob(g, 0, []).v| <= MaxLikePatternLen && (|ParseGlob(g, 0, []).v| + 1) * (|s| + 1) <= 513 * 513
  {
    ParseGlobLen(g, 0, []);
    if ParseGlob(g, 0, []).Some? {
      var n := |ParseGlob(g, 0, []).v|;
      assert (n + 1) * (|s| + 1) <= 513 * 513 by { assert n + 1 <= 513 && |s| + 1 <= 513; MulLe(n + 1, 513, |s| + 1, 513); }
    }
  }
  lemma MulMono(a: nat, b: nat, c: nat) requires a <= b ensures a * c <= b * c decreases c {
    if c > 0 { MulMono(a, b, c - 1); assert a * c == a * (c - 1) + a; assert b * c == b * (c - 1) + b; }
  }
  lemma MulLe(a: nat, b: nat, c: nat, d: nat) requires a <= b && c <= d ensures a * c <= b * d {
    MulMono(a, b, c); MulMono(c, d, b); assert a * c <= b * c; assert c * b <= d * b;
  }
  // the member_of closure visits at most MaxClosure = 10000 nodes (the loop guard): Bfs recurses at most MaxClosure times
  lemma ClosureBounded() ensures MaxClosure == 10000 {}

  // ================================================================== predicates (predicateMatches / evaluatePredicates)
  function ExistsVerb(xs: seq<Value>, verb: Str): bool decreases xs {
    |xs| > 0 && ((xs[0].VStr? && (xs[0].s == S("*") || xs[0].s == verb)) || ExistsVerb(xs[1..], verb))
  }
  function VerbMatches(pv: Value, verb: Str): bool {
    match pv
    case VStr(s) => s == S("*") || s == verb
    case VArr(xs) => ExistsVerb(xs, verb)
    case _ => false
  }
  predicate EndsStar(s: Str) { |s| > 0 && s[|s|-1] == 42 }
  function ResourceMatches(pattern: Value, resource: Str, rx: Rx): bool {
    if pattern.VUndef? then true
    else if !pattern.VStr? then false
    else
      var p := pattern.s;
      if p == S("*") then true
      else if StartsWith(p, S("re:")) then
        var src := p[3..];
        if |src| > 200 then false
        else if |resource| > MaxReResourceLen then false
        else if !rx.safe(src) then false
        else rx.full(src, resource) == Some(true)
      else if EndsStar(p) then StartsWith(resource, p[..|p|-1])
      else p == resource
  }
  // every `where` condition holds (implicit AND)
  function WhereAll(ws: seq<Value>, ctx: Value, rx: Rx): bool decreases ws {
    |ws| == 0 || (EvalCond(ws[0], ctx, rx) && WhereAll(ws[1..], ctx, rx))
  }
  // verb AND resource (the part of a predicate that does not depend on `where`)
  predicate PreOk(p: Value, ctx: Value, rx: Rx) {
    IsObjLike(p) &&
    (var a := Field(ctx, S("action"));
     var verb := Field(a, S("verb"));
     var res := Field(a, S("resource"));
     verb.VStr? && res.VStr? && VerbMatches(Field(p, S("verb")), verb.s) && ResourceMatches(Field(p, S("resource")), res.s, rx))
  }
  predicate PredicateMatches(p: Value, ctx: Value, rx: Rx) {
    PreOk(p, ctx, rx) &&
    (var w := Field(p, S("where")); w.VUndef? || (w.VArr? && WhereAll(w.xs, ctx, rx)))
  }
  // index of the first matching predicate, or -1
  function FirstMatch(xs: seq<Value>, ctx: Value, rx: Rx): int decreases xs {
    if |xs| == 0 then -1
    else if PredicateMatches(xs[0], ctx, rx) then 0
    else var r := FirstMatch(xs[1..], ctx, rx); if r < 0 then -1 else r + 1
  }
  // why: 0 allowed, 1 'envelope grants no predicates', 2 'no predicate permits ...'
  datatype PredRes = PredRes(allowed: bool, idx: int, why: int)
  function EvalPredicates(ps: Value, ctx: Value, rx: Rx): PredRes {
    if !ps.VArr? || |ps.xs| == 0 then PredRes(false, -1, 1)
    else
      var i := FirstMatch(ps.xs, ctx, rx);
      if i >= 0 then PredRes(true, i, 0) else PredRes(false, -1, 2)
  }

  lemma FirstMatchSpec(xs: seq<Value>, ctx: Value, rx: Rx)
    ensures FirstMatch(xs, ctx, rx) < |xs|
    ensures FirstMatch(xs, ctx, rx) >= 0 ==> PredicateMatches(xs[FirstMatch(xs, ctx, rx)], ctx, rx) &&
              (forall j :: 0 <= j < FirstMatch(xs, ctx, rx) ==> !PredicateMatches(xs[j], ctx, rx))
    ensures FirstMatch(xs, ctx, rx) < 0 ==> forall j :: 0 <= j < |xs| ==> !PredicateMatches(xs[j], ctx, rx)
    decreases xs
  {
    if |xs| > 0 && !PredicateMatches(xs[0], ctx, rx) {
      FirstMatchSpec(xs[1..], ctx, rx);
      var r := FirstMatch(xs[1..], ctx, rx);
      if r >= 0 { forall j | 0 <= j < r + 1 ensures !PredicateMatches(xs[j], ctx, rx) { if j > 0 { assert xs[j] == xs[1..][j-1]; } } }
      else { forall j | 0 <= j < |xs| ensures !PredicateMatches(xs[j], ctx, rx) { if j > 0 { assert xs[j] == xs[1..][j-1]; } } }
    }
  }
  // default deny
  lemma EmptyPredicatesDeny(ps: Value, ctx: Value, rx: Rx) requires !ps.VArr? || |ps.xs| == 0 ensures !EvalPredicates(ps, ctx, rx).allowed {}
  // allowed <=> some predicate matches; the matched one is the FIRST; a malformed action never matches
  lemma PredicatesAllowedIff(ps: Value, ctx: Value, rx: Rx) requires ps.VArr?
    ensures EvalPredicates(ps, ctx, rx).allowed <==> (exists j :: 0 <= j < |ps.xs| && PredicateMatches(ps.xs[j], ctx, rx))
    ensures EvalPredicates(ps, ctx, rx).allowed ==> 0 <= EvalPredicates(ps, ctx, rx).idx < |ps.xs| &&
              PredicateMatches(ps.xs[EvalPredicates(ps, ctx, rx).idx], ctx, rx) &&
              forall j :: 0 <= j < EvalPredicates(ps, ctx, rx).idx ==> !PredicateMatches(ps.xs[j], ctx, rx)
  { FirstMatchSpec(ps.xs, ctx, rx); }
  lemma MalformedActionNeverMatches(p: Value, ctx: Value, rx: Rx)
    requires !(Field(Field(ctx, S("action")), S("verb")).VStr? && Field(Field(ctx, S("action")), S("resource")).VStr?)
    ensures !PredicateMatches(p, ctx, rx) {}
  // appending a predicate can only broaden the allowed set (union), and never changes which predicate matches first
  lemma PredicatesAppendUnion(xs: seq<Value>, q: Value, ctx: Value, rx: Rx)
    ensures FirstMatch(xs, ctx, rx) >= 0 ==> FirstMatch(xs + [q], ctx, rx) == FirstMatch(xs, ctx, rx)
    ensures FirstMatch(xs, ctx, rx) < 0 ==> FirstMatch(xs + [q], ctx, rx) == (if PredicateMatches(q, ctx, rx) then |xs| else -1)
    decreases xs
  {
    if |xs| > 0 && !PredicateMatches(xs[0], ctx, rx) {
      assert (xs + [q])[1..] == xs[1..] + [q];
      PredicatesAppendUnion(xs[1..], q, ctx, rx);
    }
  }
  // `where` is a conjunction: more conditions can only narrow
  lemma WhereAllAppend(a: seq<Value>, b: seq<Value>, ctx: Value, rx: Rx) ensures WhereAll(a + b, ctx, rx) == (WhereAll(a, ctx, rx) && WhereAll(b, ctx, rx)) decreases a {
    if |a| > 0 { assert (a + b)[1..] == a[1..] + b; WhereAllAppend(a[1..], b, ctx, rx); }
    else { assert a + b == b; }
  }
  lemma WhereAttenuates(ws: seq<Value>, c: Value, ctx: Value, rx: Rx) ensures WhereAll(ws + [c], ctx, rx) ==> WhereAll(ws, ctx, rx) { WhereAllAppend(ws, [c], ctx, rx); }
  lemma WhereAllIff(ws: seq<Value>, ctx: Value, rx: Rx) ensures WhereAll(ws, ctx, rx) <==> (forall i :: 0 <= i < |ws| ==> EvalCond(ws[i], ctx, rx)) decreases ws {
    if |ws| > 0 {
      WhereAllIff(ws[1..], ctx, rx);
      if WhereAll(ws, ctx, rx) { forall i | 0 <= i < |ws| ensures EvalCond(ws[i], ctx, rx) { if i > 0 { assert ws[i] == ws[1..][i-1]; } } }
      if forall i :: 0 <= i < |ws| ==> EvalCond(ws[i], ctx, rx) { forall i | 0 <= i < |ws[1..]| ensures EvalCond(ws[1..][i], ctx, rx) { assert ws[1..][i] == ws[i+1]; } }
    }
  }
  // a condition that does not evaluate cleanly to true (unknown!) makes the predicate not match
  lemma UnknownWhereDenies(p: Value, ctx: Value, rx: Rx)
    requires Field(p, S("where")).VArr? && exists i :: 0 <= i < |Field(p, S("where")).xs| && EvalTri(Field(p, S("where")).xs[i], ctx, rx) != TT
    ensures !PredicateMatches(p, ctx, rx)
  { WhereAllIff(Field(p, S("where")).xs, ctx, rx); }
  // the regex matcher is consulted only for an in-range, guard-accepted pattern (resource side)
  lemma ReOnlyUnderGuards(pattern: Value, resource: Str, rx1: Rx, rx2: Rx)
    requires pattern.VStr? && StartsWith(pattern.s, S("re:")) && pattern.s != S("*")
    requires rx1.safe == rx2.safe
    requires forall src, subj :: rx1.safe(src) && |src| <= 200 && |subj| <= MaxReResourceLen ==> rx1.full(src, subj) == rx2.full(src, subj)
    ensures ResourceMatches(pattern, resource, rx1) == ResourceMatches(pattern, resource, rx2) {}

  // ================================================================== envelope caveats (envelopeCaveatEvaluator / evaluateCaveats)
  // reversibility_max reads `class` / `reversibilityClass` only as STRINGS (VStr); the former String() coercion model (JsToString) is gone.
  function ClassIndex(s: Str): int {
    if s == S("reversible") then 0 else if s == S("rate_limited") then 1 else if s == S("irreversible") then 2 else -1
  }
  function CountIn(xs: seq<Value>, lo: real, hi: real): nat decreases xs {
    if |xs| == 0 then 0 else (if xs[0].VNum? && xs[0].r > lo && xs[0].r <= hi then 1 else 0) + CountIn(xs[1..], lo, hi)
  }
  // `fl` = the double-arithmetic expression `now - per_secs * 1000` (the only inexact operation the evaluator performs)
  type Fl = (real, real) -> real

  function EnvelopeEv(cv: Value, ctx: Value, fl: Fl): bool {
    if !IsObjLike(cv) || !IsObjLike(ctx) then false
    else
      var now := Field(ctx, S("now"));
      if !now.VNum? then false
      else
        var ty := Field(cv, S("type"));
        if !ty.VStr? then false
        else
          var t := ty.s;
          if t == S("expires") then (var at := Field(cv, S("at")); at.VNum? && now.r < at.r)
          else if t == S("not_before") then (var at := Field(cv, S("at")); at.VNum? && now.r >= at.r)
          else if t == S("rate") then
            (var mx := Field(cv, S("max")); var per := Field(cv, S("per_secs"));
             if !(mx.VNum? && per.VNum? && per.r > 0.0) then false
             else
               var rec := Field(ctx, S("recentActionTimes"));
               if !rec.VArr? then false
               else (CountIn(rec.xs, fl(now.r, per.r), now.r) as real) < mx.r)
          else if t == S("max_blast_radius") then
            (var mx := Field(cv, S("max")); var bl := Field(ctx, S("blastRadius")); mx.VNum? && bl.VNum? && bl.r <= mx.r)
          else if t == S("reversibility_max") then
            (var c := Field(cv, S("class")); var rc := Field(ctx, S("reversibilityClass"));
             c.VStr? && rc.VStr? &&
             (var lim := ClassIndex(c.s); var cur := ClassIndex(rc.s); lim >= 0 && cur >= 0 && cur <= lim))
          else if t == S("delegation_depth") then
            (var mx := Field(cv, S("max")); var d := Field(ctx, S("delegationDepth")); mx.VNum? && d.VNum? && d.r <= mx.r)
          else if t == S("budget_alloc") then (var l := Field(cv, S("limit")); l.VNum? && l.r >= 0.0)
          else false
  }

  type ToolEv = (Value, Value) -> bool
  // agentNativeCaveatEvaluator: stock caveats + `predicates` (the action must match one `allow` predicate) + `tool_schema` (oracle)
  function ExistsPred(xs: seq<Value>, a: Value, rx: Rx): bool decreases xs {
    |xs| > 0 && (PredicateMatches(xs[0], a, rx) || ExistsPred(xs[1..], a, rx))
  }
  function AgentEv(cv: Value, ctx: Value, rx: Rx, fl: Fl, tool: ToolEv): bool {
    if !IsObjRec(cv) || !IsObjRec(ctx) then false
    else
      var ty := Field(cv, S("type"));
      if ty == VStr(S("tool_schema")) then tool(cv, ctx)
      else if ty == VStr(S("predicates")) then
        (var a := Field(ctx, S("action")); var allow := Field(cv, S("allow"));
         if !IsObjRec(a) || !allow.VArr? then false else ExistsPred(allow.xs, a, rx))
      else if ty == VStr(S("max_spend")) then MaxSpendEv(cv, ctx)
      else EnvelopeEv(cv, ctx, fl)
  }

  // ---- max_spend (0.4.1; agent-native.ts maxSpendSatisfied / actionSpendUsd) ----------------------------------------------
  // `{type: 'max_spend', usd}`: the limit is a finite number >= 0 and the action's OWN params carry an own `amount`, a finite number
  // with 0 <= amount <= usd; an own `currency`, when present (even as undefined), is exactly "usd" or "USD". It does not read `now`.
  predicate HasKey(v: Value, k: Str) { match v case VObj(es, _) => Has(es, k) case _ => false }
  function SpendParams(ctx: Value): Value { Field(Field(Field(ctx, S("action")), S("action")), S("params")) }
  predicate CurrencyOk(ps: Value) {
    !HasKey(ps, S("currency")) || Field(ps, S("currency")) == VStr(S("usd")) || Field(ps, S("currency")) == VStr(S("USD"))
  }
  function MaxSpendEv(cv: Value, ctx: Value): bool {
    var lim := Field(cv, S("usd"));
    var a := Field(ctx, S("action"));
    var act := Field(a, S("action"));
    var ps := Field(act, S("params"));
    var amt := Field(ps, S("amount"));
    lim.VNum? && lim.r >= 0.0 && IsObjRec(a) && IsObjRec(act) && IsObjRec(ps) && amt.VNum? && amt.r >= 0.0 && CurrencyOk(ps) && amt.r <= lim.r
  }
  // soundness: a satisfied max_spend means the action's own amount is a finite number within [0, usd], in USD
  lemma MaxSpendSound(cv: Value, ctx: Value, rx: Rx, fl: Fl, tool: ToolEv)
    requires Field(cv, S("type")) == VStr(S("max_spend")) && AgentEv(cv, ctx, rx, fl, tool)
    ensures Field(cv, S("usd")).VNum? && Field(SpendParams(ctx), S("amount")).VNum?
    ensures 0.0 <= Field(SpendParams(ctx), S("amount")).r <= Field(cv, S("usd")).r
    ensures CurrencyOk(SpendParams(ctx)) { assert S("max_spend")[0] != S("tool_schema")[0]; assert S("max_spend")[0] != S("predicates")[0]; }
  // fail closed: no readable amount (absent, non-number, negative), a malformed limit or a foreign currency never satisfies it
  lemma MaxSpendNoAmountUnsatisfied(cv: Value, ctx: Value, rx: Rx, fl: Fl, tool: ToolEv)
    requires Field(cv, S("type")) == VStr(S("max_spend"))
    requires !Field(SpendParams(ctx), S("amount")).VNum? || Field(SpendParams(ctx), S("amount")).r < 0.0 || !Field(cv, S("usd")).VNum?
             || !CurrencyOk(SpendParams(ctx))
    ensures !AgentEv(cv, ctx, rx, fl, tool) { assert S("max_spend")[0] != S("tool_schema")[0]; assert S("max_spend")[0] != S("predicates")[0]; }
  // monotone in the amount: if a spend is within the ceiling, every smaller non-negative spend is too
  lemma MaxSpendMonotone(lim: real, a1: real, a2: real) requires 0.0 <= a1 <= a2 && a2 <= lim ensures a1 <= lim {}

  // evaluateCaveats: ok iff every caveat is satisfied; `failed` lists the unsatisfied types in order ('<malformed>' for a non-string type)
  const MalformedName: Str := S("<malformed>")
  datatype CavRes = CavRes(ok: bool, failed: seq<Str>)
  function CavName(cv: Value): Str { var t := Field(cv, S("type")); if t.VStr? then t.s else MalformedName }
  function EvalCaveats(cs: seq<Value>, ev: Value -> bool): CavRes decreases cs {
    if |cs| == 0 then CavRes(true, [])
    else
      var r := EvalCaveats(cs[1..], ev);
      if ev(cs[0]) then r else CavRes(false, [CavName(cs[0])] + r.failed)
  }
  // non-array caveat list => fail closed
  function EvalCaveatList(cs: Value, ev: Value -> bool): CavRes {
    if cs.VArr? then EvalCaveats(cs.xs, ev) else CavRes(false, [S("<malformed caveats>")])
  }

  lemma CavOkIff(cs: seq<Value>, ev: Value -> bool) ensures EvalCaveats(cs, ev).ok <==> (forall i :: 0 <= i < |cs| ==> ev(cs[i])) decreases cs {
    if |cs| > 0 {
      CavOkIff(cs[1..], ev);
      if EvalCaveats(cs, ev).ok { forall i | 0 <= i < |cs| ensures ev(cs[i]) { if i > 0 { assert cs[i] == cs[1..][i-1]; } } }
      if forall i :: 0 <= i < |cs| ==> ev(cs[i]) { forall i | 0 <= i < |cs[1..]| ensures ev(cs[1..][i]) { assert cs[1..][i] == cs[i+1]; } }
    }
  }
  lemma CavFailedEmptyIff(cs: seq<Value>, ev: Value -> bool) ensures EvalCaveats(cs, ev).ok <==> |EvalCaveats(cs, ev).failed| == 0 decreases cs {
    if |cs| > 0 { CavFailedEmptyIff(cs[1..], ev); }
  }
  lemma CavConcat(a: seq<Value>, b: seq<Value>, ev: Value -> bool)
    ensures EvalCaveats(a + b, ev).ok == (EvalCaveats(a, ev).ok && EvalCaveats(b, ev).ok)
    ensures EvalCaveats(a + b, ev).failed == EvalCaveats(a, ev).failed + EvalCaveats(b, ev).failed
    decreases a
  {
    if |a| > 0 { assert (a + b)[1..] == a[1..] + b; CavConcat(a[1..], b, ev); }
    else { assert a + b == b; }
  }
  // MONOTONE ATTENUATION of the caveat conjunction: adding a caveat can only remove authority
  lemma CavAppendAttenuates(cs: seq<Value>, c: Value, ev: Value -> bool)
    ensures EvalCaveats(cs + [c], ev).ok ==> EvalCaveats(cs, ev).ok
    ensures EvalCaveats(cs + [c], ev).ok == (EvalCaveats(cs, ev).ok && ev(c))
    ensures EvalCaveats(cs + [c], ev).failed == EvalCaveats(cs, ev).failed + (if ev(c) then [] else [CavName(c)])
  { CavConcat(cs, [c], ev); }
  lemma CavPrefixAntitone(pre: seq<Value>, cs: seq<Value>, ev: Value -> bool)
    requires |pre| <= |cs| && cs[..|pre|] == pre ensures EvalCaveats(cs, ev).ok ==> EvalCaveats(pre, ev).ok
  { assert cs == pre + cs[|pre|..]; CavConcat(pre, cs[|pre|..], ev); }
  // order independence of the verdict (not of the failed list)
  lemma CavPerm(a: seq<Value>, b: seq<Value>, ev: Value -> bool) requires multiset(a) == multiset(b) ensures EvalCaveats(a, ev).ok == EvalCaveats(b, ev).ok {
    CavOkIff(a, ev); CavOkIff(b, ev);
    assert forall x :: (x in a) <==> (x in multiset(a));
    assert forall x :: (x in b) <==> (x in multiset(b));
    if EvalCaveats(a, ev).ok { forall i | 0 <= i < |b| ensures ev(b[i]) { assert b[i] in b; assert b[i] in a; var j :| 0 <= j < |a| && a[j] == b[i]; } }
    if EvalCaveats(b, ev).ok { forall i | 0 <= i < |a| ensures ev(a[i]) { assert a[i] in a; assert a[i] in b; var j :| 0 <= j < |b| && b[j] == a[i]; } }
  }
  // fail closed: an unknown / non-string type, a missing clock, a non-object caveat or context is never satisfied
  lemma EnvelopeUnknownTypeUnsatisfied(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")).VStr? ==> Field(cv, S("type")).s !in {S("expires"), S("not_before"), S("rate"), S("max_blast_radius"), S("reversibility_max"), S("delegation_depth"), S("budget_alloc")}
    ensures !EnvelopeEv(cv, ctx, fl) {}
  lemma EnvelopeNoClockUnsatisfied(cv: Value, ctx: Value, fl: Fl) requires !Field(ctx, S("now")).VNum? ensures !EnvelopeEv(cv, ctx, fl) {}
  lemma EnvelopeMalformedUnsatisfied(cv: Value, ctx: Value, fl: Fl) requires !IsObjLike(cv) || !IsObjLike(ctx) ensures !EnvelopeEv(cv, ctx, fl) {}
  lemma AgentMalformedUnsatisfied(cv: Value, ctx: Value, rx: Rx, fl: Fl, tool: ToolEv) requires !IsObjRec(cv) || !IsObjRec(ctx) ensures !AgentEv(cv, ctx, rx, fl, tool) {}
  // the numeric kernels
  lemma ExpiresSound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("expires")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(ctx, S("now")).VNum? && Field(cv, S("at")).VNum? && Field(ctx, S("now")).r < Field(cv, S("at")).r {}
  lemma NotBeforeSound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("not_before")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(ctx, S("now")).VNum? && Field(cv, S("at")).VNum? && Field(ctx, S("now")).r >= Field(cv, S("at")).r {}
  lemma MaxBlastSound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("max_blast_radius")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(cv, S("max")).VNum? && Field(ctx, S("blastRadius")).VNum? && Field(ctx, S("blastRadius")).r <= Field(cv, S("max")).r {}
  lemma CaveatNamesDistinct()
    ensures S("expires") != S("delegation_depth") && S("not_before") != S("delegation_depth") && S("rate") != S("delegation_depth")
         && S("max_blast_radius") != S("delegation_depth") && S("reversibility_max") != S("delegation_depth")
         && S("max_blast_radius") != S("budget_alloc") && S("delegation_depth") != S("budget_alloc")
  {
    assert S("max_blast_radius")[0] != S("delegation_depth")[0];
  }
  lemma DelegationDepthSound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("delegation_depth")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(cv, S("max")).VNum? && Field(ctx, S("delegationDepth")).VNum? && Field(ctx, S("delegationDepth")).r <= Field(cv, S("max")).r
  { CaveatNamesDistinct(); }
  lemma ReversibilitySound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("reversibility_max")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(cv, S("class")).VStr? && Field(ctx, S("reversibilityClass")).VStr?
    ensures 0 <= ClassIndex(Field(ctx, S("reversibilityClass")).s) <= ClassIndex(Field(cv, S("class")).s) { CaveatNamesDistinct(); }
  // TYPE CHECK: a non-string `class` (an array such as ['irreversible'], an object with a toString, a number) or a non-string context class
  // never satisfies reversibility_max (no String() coercion).
  lemma ReversibilityNonStringUnsatisfied(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("reversibility_max"))
    requires !Field(cv, S("class")).VStr? || !Field(ctx, S("reversibilityClass")).VStr?
    ensures !EnvelopeEv(cv, ctx, fl)
  { CaveatNamesDistinct(); }
  lemma RateSound(cv: Value, ctx: Value, fl: Fl)
    requires Field(cv, S("type")) == VStr(S("rate")) && EnvelopeEv(cv, ctx, fl)
    ensures Field(cv, S("max")).VNum? && Field(cv, S("per_secs")).VNum? && Field(cv, S("per_secs")).r > 0.0 && Field(ctx, S("recentActionTimes")).VArr? {}
  // an `expires` caveat satisfied at a later time was satisfied at every earlier time; `not_before` the other way round
  lemma ExpiresTimeMonotone(now1: real, now2: real, at: real) requires now1 <= now2 && now2 < at ensures now1 < at {}
  lemma NotBeforeTimeMonotone(now1: real, now2: real, at: real) requires now1 <= now2 && now1 >= at ensures now2 >= at {}

  // ------------------------------------------------------------------ the regex oracle is consulted ONLY under the guards
  // Two oracles that agree on every call the evaluator is allowed to make (pattern accepted by the guard, |pattern| <= 200, |subject| <= 512)
  // give the same verdict on every condition / predicate: the evaluator never relies on the matcher outside the guarded region.
  ghost predicate RxAgree(a: Rx, b: Rx) {
    (forall s :: a.safe(s) == b.safe(s)) &&
    (forall src, subj :: a.safe(src) && |src| <= MaxMatchesPatternLen && |subj| <= MaxPatternSubjectLen ==> a.full(src, subj) == b.full(src, subj))
  }
  lemma LeafOpRxExt(op: Str, v: Value, operand: Value, a: Rx, b: Rx) requires RxAgree(a, b) ensures LeafOp(op, v, operand, a) == LeafOp(op, v, operand, b) {}
  lemma TriLeafRxExt(c: Value, ctx: Value, a: Rx, b: Rx) requires RxAgree(a, b) ensures TriLeaf(c, ctx, a) == TriLeaf(c, ctx, b) {}
  lemma EvalTriRxExt(c: Value, ctx: Value, a: Rx, b: Rx) requires RxAgree(a, b) ensures EvalTriC(c, ctx, a) == EvalTriC(c, ctx, b) decreases SzV(c), 1 {
    match c
    case VObj(es, _) =>
      if Has(es, S("all_of")) {
        SzGet(es, S("all_of")); var x := Get(es, S("all_of"));
        if x.VArr? && |x.xs| > 0 { EvalAllRxExt(x.xs, ctx, a, b, false); }
      } else if Has(es, S("any_of")) {
        SzGet(es, S("any_of")); var x := Get(es, S("any_of"));
        if x.VArr? && |x.xs| > 0 { EvalAnyRxExt(x.xs, ctx, a, b, false); }
      } else if Has(es, S("not")) { SzGet(es, S("not")); EvalTriRxExt(Get(es, S("not")), ctx, a, b); }
      else { TriLeafRxExt(c, ctx, a, b); }
    case _ =>
  }
  lemma EvalAllRxExt(xs: seq<Value>, ctx: Value, a: Rx, b: Rx, sawU: bool) requires RxAgree(a, b) ensures EvalAllC(xs, ctx, a, sawU) == EvalAllC(xs, ctx, b, sawU) decreases SzL(xs), 2 {
    if |xs| > 0 { EvalTriRxExt(xs[0], ctx, a, b); EvalAllRxExt(xs[1..], ctx, a, b, sawU || EvalTri(xs[0], ctx, a) == TU); }
  }
  lemma EvalAnyRxExt(xs: seq<Value>, ctx: Value, a: Rx, b: Rx, sawU: bool) requires RxAgree(a, b) ensures EvalAnyC(xs, ctx, a, sawU) == EvalAnyC(xs, ctx, b, sawU) decreases SzL(xs), 2 {
    if |xs| > 0 { EvalTriRxExt(xs[0], ctx, a, b); EvalAnyRxExt(xs[1..], ctx, a, b, sawU || EvalTri(xs[0], ctx, a) == TU); }
  }
  lemma WhereRxExt(ws: seq<Value>, ctx: Value, a: Rx, b: Rx) requires RxAgree(a, b) ensures WhereAll(ws, ctx, a) == WhereAll(ws, ctx, b) decreases ws {
    if |ws| > 0 { EvalTriRxExt(ws[0], ctx, a, b); WhereRxExt(ws[1..], ctx, a, b); }
  }
  lemma ResourceRxExt(pattern: Value, resource: Str, a: Rx, b: Rx) requires RxAgree(a, b) ensures ResourceMatches(pattern, resource, a) == ResourceMatches(pattern, resource, b) {}
  lemma PredicateRxExt(p: Value, ctx: Value, a: Rx, b: Rx) requires RxAgree(a, b) ensures PredicateMatches(p, ctx, a) == PredicateMatches(p, ctx, b) {
    var w := Field(p, S("where"));
    if w.VArr? { WhereRxExt(w.xs, ctx, a, b); }
  }

  // ================================================================== Policy-VM decision (policy-vm.ts decide, risk.ts)
  // The glue computes the floating-point risk score and budget (riskScore, leak: sums and products of doubles) and hands the RESULTS in as
  // exact rationals; every decision below is a comparison / selection on those numbers, and comparisons of doubles are exact.
  function Clamp01(x: real): real { if x < 0.0 then 0.0 else if x > 1.0 then 1.0 else x }
  function Nz(x: real): real { if x > 0.0 then x else 0.0 }           // callers map a non-finite input to 0 (= nz)
  function Cost(r: real, kappa: real): real { Nz(kappa) * Clamp01(r) } // c(A) = kappa * r(A), r finite

  datatype Thr = Thr(t: int, proof: int, opt: bool)     // proof: 0 claim, 1 standard, 2 strong
  // requiredThreshold (r already mapped: a non-finite risk is 1)
  function ReqThr(r: real, th1: real, th2: real, irreversible: bool): Thr {
    if r <= th1 then Thr(1, 0, !irreversible) else if r <= th2 then Thr(2, 1, false) else Thr(3, 2, false)
  }
  // escalateThreshold: raise to at least minT, keep coherent; never lowers anything
  function Escalate(rt: Thr, minT: int): Thr {
    var t := if minT > rt.t then minT else rt.t;
    var floor := t - 1;
    Thr(t, if rt.proof >= floor then rt.proof else floor, if t > 1 then false else rt.opt)
  }
  datatype Adm = Adm(admit: bool, needStepUp: bool, t: int, metered: bool)
  // admit(r, b, p) given t = requiredThreshold(r).t and bge = (b.B >= cost(r)) (false when B is NaN)
  function AdmitOf(t: int, bge: bool): Adm {
    if t < 3 && !bge then Adm(false, true, 3, false)
    else if t == 1 then Adm(true, false, 1, true)
    else if t == 2 then Adm(false, true, 2, true)
    else Adm(false, true, 3, false)
  }
  datatype Dec = Dec(release: bool, admit: bool, needStepUp: bool, thr: Thr, debit: bool)
  // cvOk = the envelope's caveats AND (0.4.1) the root caveats outside the envelope all hold (see ReleaseOf / RootCaveats)
  function DecideCore(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, rt: Thr, adm: Adm): Dec {
    var release := prOk && cvOk && dcvOk && chainOk;
    Dec(release, release && adm.admit, if release then adm.needStepUp else true, Escalate(rt, adm.t), release && adm.metered)
  }
  // the whole numeric decision for a risk r, budget B and policy
  function DecideAt(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irreversible: bool): Dec {
    var rt := ReqThr(r, th1, th2, irreversible);
    DecideCore(prOk, cvOk, dcvOk, chainOk, rt, AdmitOf(rt.t, B >= Cost(r, kappa)))
  }

  lemma ReqThrRange(r: real, th1: real, th2: real, irr: bool) ensures 1 <= ReqThr(r, th1, th2, irr).t <= 3 {}
  lemma ReqThrCoherent(r: real, th1: real, th2: real, irr: bool)
    ensures ReqThr(r, th1, th2, irr).proof == ReqThr(r, th1, th2, irr).t - 1
    ensures ReqThr(r, th1, th2, irr).opt ==> ReqThr(r, th1, th2, irr).t == 1 && !irr {}
  // the threshold is monotone non-decreasing in the risk (th1 <= th2), and optimistic acceptance is anti-monotone
  lemma ReqThrMonotone(r1: real, r2: real, th1: real, th2: real, irr: bool)
    requires r1 <= r2 && th1 <= th2
    ensures ReqThr(r1, th1, th2, irr).t <= ReqThr(r2, th1, th2, irr).t
    ensures ReqThr(r2, th1, th2, irr).opt ==> ReqThr(r1, th1, th2, irr).opt {}
  lemma EscalateNeverLowers(rt: Thr, minT: int)
    requires 1 <= rt.t <= 3 && rt.proof == rt.t - 1 && 1 <= minT <= 3
    ensures Escalate(rt, minT).t >= rt.t && Escalate(rt, minT).t >= minT
    ensures Escalate(rt, minT).proof >= rt.proof
    ensures Escalate(rt, minT).proof == Escalate(rt, minT).t - 1                       // coherent: t=2 => standard, t=3 => strong
    ensures Escalate(rt, minT).opt ==> Escalate(rt, minT).t == 1 && rt.opt             // optimistic only at t = 1, never gained by escalating
    ensures Escalate(rt, minT).t == (if minT > rt.t then minT else rt.t) {}

  // policy before risk: nothing but policy AND caveats AND delegated caveats AND chain releases the guardian share
  lemma ReleaseIff(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, rt: Thr, adm: Adm)
    ensures DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm).release == (prOk && cvOk && dcvOk && chainOk) {}
  lemma NoReleaseNoAdmit(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, rt: Thr, adm: Adm)
    requires !(prOk && cvOk && dcvOk && chainOk)
    ensures !DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm).admit && DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm).needStepUp
         && !DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm).debit {}
  // auto-admission: only when released, only at t = 1 (no co-signer), only when the budget covers the cost
  lemma AdmitSound(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    requires DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).admit
    ensures prOk && cvOk && dcvOk && chainOk
    ensures r <= th1 && B >= Cost(r, kappa)
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).thr.t == 1
    ensures !DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).needStepUp {}
  // a depleted budget never admits and never debits: the action escalates to a human (t = 3) when it could have run machine-only
  lemma ExhaustedBudgetEscalates(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    requires th1 <= th2 && r <= th2 && B < Cost(r, kappa)
    ensures !DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).admit
    ensures !DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).debit
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).thr.t == 3
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).needStepUp {}
  // machine-only execution (debit) is possible only when the budget covers the cost, and only below the human band (t <= 2)
  lemma DebitRequiresCover(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    requires th1 <= th2 && DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).debit
    ensures B >= Cost(r, kappa) && r <= th2 {}
  // an irreversible action is never offered the optimistic fast path
  lemma IrreversibleNeverOptimistic(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real)
    ensures !DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, true).thr.opt {}
  lemma OptimisticOnlyAtT1(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).thr.opt ==> DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).thr.t == 1 {}
  lemma ThresholdNeverBelowRequired(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irr).thr.t >= ReqThr(r, th1, th2, irr).t {}

  lemma MulMonoR(k: real, a: real, b: real) requires k >= 0.0 && a <= b ensures k * a <= k * b {
    assert k * (b - a) >= 0.0 by { MulNonneg(k, b - a); }
  }
  lemma MulNonneg(x: real, y: real) requires x >= 0.0 && y >= 0.0 ensures x * y >= 0.0 {}
  lemma CostMonotone(r1: real, r2: real, kappa: real) requires r1 <= r2 ensures Cost(r1, kappa) <= Cost(r2, kappa) { MulMonoR(Nz(kappa), Clamp01(r1), Clamp01(r2)); }
  lemma CostRange(r: real, kappa: real) ensures 0.0 <= Cost(r, kappa) { MulNonneg(Nz(kappa), Clamp01(r)); }

  // MONOTONE IN RISK (the intuitive law, and it holds): with everything else fixed, a riskier action is never auto-admitted if a
  // safer one is not, its required threshold is never lower, and it never gets the machine-only path when the safer one does not.
  lemma AdmitAntitoneInRisk(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r1: real, r2: real, th1: real, th2: real, kappa: real, B: real, irr: bool)
    requires r1 <= r2 && th1 <= th2
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r2, th1, th2, kappa, B, irr).admit ==> DecideAt(prOk, cvOk, dcvOk, chainOk, r1, th1, th2, kappa, B, irr).admit
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r2, th1, th2, kappa, B, irr).debit ==> DecideAt(prOk, cvOk, dcvOk, chainOk, r1, th1, th2, kappa, B, irr).debit
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r1, th1, th2, kappa, B, irr).thr.t <= DecideAt(prOk, cvOk, dcvOk, chainOk, r2, th1, th2, kappa, B, irr).thr.t
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r2, th1, th2, kappa, B, irr).thr.opt ==> DecideAt(prOk, cvOk, dcvOk, chainOk, r1, th1, th2, kappa, B, irr).thr.opt
  {
    CostMonotone(r1, r2, kappa);
    ReqThrMonotone(r1, r2, th1, th2, irr);
  }
  // a larger budget never turns an admission into a refusal
  lemma AdmitMonotoneInBudget(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, r: real, th1: real, th2: real, kappa: real, B1: real, B2: real, irr: bool)
    requires B1 <= B2
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B1, irr).admit ==> DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B2, irr).admit
    ensures DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B2, irr).thr.t <= DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B1, irr).thr.t {}
  // risk floor (the signed `caution`): r = max(score, floor) can only raise risk
  function RiskWithFloor(score: real, floor: real): real { if score >= floor then score else floor }
  lemma FloorOnlyRaises(score: real, floor: real) ensures RiskWithFloor(score, floor) >= score && RiskWithFloor(score, floor) >= floor {}

  // ---------------------------------------------------------------- the trust budget (leak, debit) and the safety bound
  function Debit(B: real, c: real): real { var x := B - Nz(c); if x > 0.0 then x else 0.0 }
  function Leak(B: real, lambda: real, dtSecs: real): real requires dtSecs >= 0.0 {
    var x := B - Nz(lambda) * dtSecs; if x > 0.0 then x else 0.0
  }
  lemma DebitNeverRaises(B: real, c: real) requires B >= 0.0 ensures 0.0 <= Debit(B, c) <= B {}
  lemma LeakNeverRaises(B: real, lambda: real, dt: real) requires B >= 0.0 && dt >= 0.0 ensures 0.0 <= Leak(B, lambda, dt) <= B { MulNonneg(Nz(lambda), dt); }

  datatype Step = LeakStep(lambda: real, dt: real) | RiskStep(r: real)
  // run a history: a leak lowers B; an action with risk r is admitted machine-only iff B >= cost, and then B is debited
  function Run(B: real, steps: seq<Step>, kappa: real): (real, real) decreases steps {   // (final budget, total admitted cost)
    if |steps| == 0 then (B, 0.0)
    else
      var h := steps[0];
      match h
      case LeakStep(l, dt) =>
        var B2 := if dt >= 0.0 then Leak(B, l, dt) else B;
        Run(B2, steps[1..], kappa)
      case RiskStep(r) =>
        var c := Cost(r, kappa);
        if B >= c then (var q := Run(B - c, steps[1..], kappa); (q.0, q.1 + c)) else Run(B, steps[1..], kappa)
  }
  // SAFETY BOUND: between recharges the total cost of machine-only actions never exceeds the starting budget, and the budget stays >= 0
  lemma SafetyBound(B: real, steps: seq<Step>, kappa: real)
    requires B >= 0.0
    ensures Run(B, steps, kappa).1 <= B
    ensures Run(B, steps, kappa).0 >= 0.0
    ensures Run(B, steps, kappa).0 + Run(B, steps, kappa).1 <= B
    decreases steps
  {
    if |steps| > 0 {
      match steps[0]
      case LeakStep(l, dt) => { if dt >= 0.0 { LeakNeverRaises(B, l, dt); SafetyBound(Leak(B, l, dt), steps[1..], kappa); } else { SafetyBound(B, steps[1..], kappa); } }
      case RiskStep(r) => { CostRange(r, kappa); if B >= Cost(r, kappa) { SafetyBound(B - Cost(r, kappa), steps[1..], kappa); } else { SafetyBound(B, steps[1..], kappa); } }
    }
  }

  // ---------------------------------------------------------------- end to end: what a released guardian share implies
  // release = predicates allow AND every grant caveat holds AND every delegated caveat holds AND the chain is well formed
  function CaveatEvFor(cctx: Value, rx: Rx, fl: Fl, tool: ToolEv): Value -> bool { (cv: Value) => AgentEv(cv, cctx, rx, fl, tool) }

  // ---- root caveats (0.4.1 security fix; policy-vm.ts rootCaveats) ---------------------------------------------------------
  // The caveats on the ROOT grant that are evaluated as caveats: every entry except the FIRST `envelope` caveat (the one readEnvelope
  // reads as the policy container; its predicates and inner caveats are evaluated on their own). Before 0.4.1 these were signed but never
  // evaluated.
  function RootCaveats(cs: seq<Value>): seq<Value> decreases cs {
    if |cs| == 0 then [] else if Field(cs[0], S("type")) == VStr(S("envelope")) then cs[1..] else [cs[0]] + RootCaveats(cs[1..])
  }
  lemma RootCaveatsSubset(cs: seq<Value>) ensures forall c :: c in RootCaveats(cs) ==> c in cs decreases cs {
    if |cs| > 0 && Field(cs[0], S("type")) != VStr(S("envelope")) { RootCaveatsSubset(cs[1..]); }
  }
  // COVERAGE: every grant caveat that is not of type `envelope` is evaluated (and so is every `envelope` caveat after the first)
  lemma RootCaveatsCover(cs: seq<Value>, i: int)
    requires 0 <= i < |cs| && Field(cs[i], S("type")) != VStr(S("envelope"))
    ensures cs[i] in RootCaveats(cs)
    decreases cs
  {
    if Field(cs[0], S("type")) == VStr(S("envelope")) { assert cs[i] == cs[1..][i - 1]; }
    else if i > 0 { RootCaveatsCover(cs[1..], i - 1); }
  }
  lemma RootCaveatsLaterEnvelopes(cs: seq<Value>, j: int, i: int)
    requires 0 <= j < i < |cs| && Field(cs[j], S("type")) == VStr(S("envelope"))
    ensures cs[i] in RootCaveats(cs)
    decreases cs
  {
    if Field(cs[0], S("type")) == VStr(S("envelope")) { assert cs[i] == cs[1..][i - 1]; }
    else { RootCaveatsLaterEnvelopes(cs[1..], j - 1, i - 1); }
  }

  // release = predicates allow AND every envelope caveat AND every ROOT caveat AND every delegated caveat holds AND the chain is well formed
  function ReleaseOf(preds: Value, action: Value, caveats: Value, root: seq<Value>, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv): bool {
    EvalPredicates(preds, action, rx).allowed &&
    EvalCaveatList(caveats, CaveatEvFor(cctx, rx, fl, tool)).ok &&
    EvalCaveats(root, CaveatEvFor(cctx, rx, fl, tool)).ok &&
    EvalCaveats(extra, CaveatEvFor(cctx, rx, fl, tool)).ok && chainOk
  }
  lemma ReleaseSound(preds: Value, action: Value, caveats: Value, root: seq<Value>, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv)
    requires ReleaseOf(preds, action, caveats, root, extra, cctx, chainOk, rx, fl, tool)
    ensures preds.VArr? && exists j :: 0 <= j < |preds.xs| && PredicateMatches(preds.xs[j], action, rx)
    ensures caveats.VArr? && forall i :: 0 <= i < |caveats.xs| ==> AgentEv(caveats.xs[i], cctx, rx, fl, tool)
    ensures forall i :: 0 <= i < |root| ==> AgentEv(root[i], cctx, rx, fl, tool)
    ensures forall i :: 0 <= i < |extra| ==> AgentEv(extra[i], cctx, rx, fl, tool)
    ensures chainOk
  {
    PredicatesAllowedIff(preds, action, rx);
    CavOkIff(caveats.xs, CaveatEvFor(cctx, rx, fl, tool));
    CavOkIff(root, CaveatEvFor(cctx, rx, fl, tool));
    CavOkIff(extra, CaveatEvFor(cctx, rx, fl, tool));
  }
  // THE 0.4.1 PROPERTY: a release under a grant implies that EVERY caveat on the grant other than its envelope container holds --
  // attenuation applies from the root exactly as it does to the caveats delegation hops append.
  lemma RootCaveatsEnforced(preds: Value, action: Value, caveats: Value, gcs: seq<Value>, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv, i: int)
    requires ReleaseOf(preds, action, caveats, RootCaveats(gcs), extra, cctx, chainOk, rx, fl, tool)
    requires 0 <= i < |gcs| && Field(gcs[i], S("type")) != VStr(S("envelope"))
    ensures AgentEv(gcs[i], cctx, rx, fl, tool)
  {
    ReleaseSound(preds, action, caveats, RootCaveats(gcs), extra, cctx, chainOk, rx, fl, tool);
    RootCaveatsCover(gcs, i);
    var k :| 0 <= k < |RootCaveats(gcs)| && RootCaveats(gcs)[k] == gcs[i];
  }
  // in particular a root max_spend: no release for an action whose amount exceeds the root ceiling
  lemma RootMaxSpendEnforced(preds: Value, action: Value, caveats: Value, gcs: seq<Value>, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv, i: int)
    requires 0 <= i < |gcs| && Field(gcs[i], S("type")) == VStr(S("max_spend"))
    requires ReleaseOf(preds, action, caveats, RootCaveats(gcs), extra, cctx, chainOk, rx, fl, tool)
    ensures Field(gcs[i], S("usd")).VNum? && Field(SpendParams(cctx), S("amount")).VNum?
    ensures Field(SpendParams(cctx), S("amount")).r <= Field(gcs[i], S("usd")).r
  {
    assert S("max_spend")[0] != S("envelope")[0];
    RootCaveatsEnforced(preds, action, caveats, gcs, extra, cctx, chainOk, rx, fl, tool, i);
    MaxSpendSound(gcs[i], cctx, rx, fl, tool);
  }
  // delegation can only narrow: adding a delegated caveat never turns a refusal into a release
  lemma DelegationAttenuates(preds: Value, action: Value, caveats: Value, root: seq<Value>, extra: seq<Value>, c: Value, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv)
    ensures ReleaseOf(preds, action, caveats, root, extra + [c], cctx, chainOk, rx, fl, tool) ==> ReleaseOf(preds, action, caveats, root, extra, cctx, chainOk, rx, fl, tool)
  { CavAppendAttenuates(extra, c, CaveatEvFor(cctx, rx, fl, tool)); }
  // and so can adding an envelope caveat
  lemma GrantCaveatAttenuates(preds: Value, action: Value, cs: seq<Value>, c: Value, root: seq<Value>, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv)
    ensures ReleaseOf(preds, action, VArr(cs + [c]), root, extra, cctx, chainOk, rx, fl, tool) ==> ReleaseOf(preds, action, VArr(cs), root, extra, cctx, chainOk, rx, fl, tool)
  { CavAppendAttenuates(cs, c, CaveatEvFor(cctx, rx, fl, tool)); }
  // and so can adding a root caveat
  lemma RootCaveatAttenuates(preds: Value, action: Value, caveats: Value, root: seq<Value>, c: Value, extra: seq<Value>, cctx: Value, chainOk: bool, rx: Rx, fl: Fl, tool: ToolEv)
    ensures ReleaseOf(preds, action, caveats, root + [c], extra, cctx, chainOk, rx, fl, tool) ==> ReleaseOf(preds, action, caveats, root, extra, cctx, chainOk, rx, fl, tool)
  { CavAppendAttenuates(root, c, CaveatEvFor(cctx, rx, fl, tool)); }
}
