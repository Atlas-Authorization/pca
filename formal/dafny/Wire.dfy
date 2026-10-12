// Wire.dfy: machine-proved model of the PCA wire layer: UTF-16 / UTF-8 / byte order, strict base64url, canonical hex,
// and the strict JSON profile (parser + canonical printer). STANDALONE (no includes). See docs/pca/security/verified-core.md.
// Strings are sequences of UTF-16 code units (seq<int>), exactly like JavaScript strings. Trusted contracts: NONE (no assume/axiom/extern).

module Utf {
  type S = seq<int>

  predicate IsUnit(x: int) { 0 <= x < 0x10000 }
  predicate IsHigh(x: int) { 0xD800 <= x <= 0xDBFF }
  predicate IsLow(x: int) { 0xDC00 <= x <= 0xDFFF }

  // Well-formed UTF-16: every unit is a 16-bit value, no lone surrogate (== !hasLoneSurrogate in hash.ts).
  // Index-based and tail-recursive so the COMPILED code is a loop with no slicing; `Valid16Unfold` gives the recursive shape for proofs.
  predicate Valid16From(s: S, i: int)
    requires 0 <= i
    decreases |s| - i
  {
    if i >= |s| then true
    else if !IsUnit(s[i]) then false
    else if IsHigh(s[i]) then (if i + 1 < |s| && IsLow(s[i + 1]) && IsUnit(s[i + 1]) then Valid16From(s, i + 2) else false)
    else if IsLow(s[i]) then false
    else Valid16From(s, i + 1)
  }
  predicate Valid16(s: S) { Valid16From(s, 0) }

  lemma Valid16Shift(s: S, i: int)
    requires 0 <= i <= |s|
    ensures Valid16From(s, i) == Valid16From(s[i..], 0)
    decreases |s| - i
  {
    var u := s[i..];
    if i < |s| && IsUnit(s[i]) {
      if IsHigh(s[i]) {
        if i + 1 < |s| && IsLow(s[i + 1]) && IsUnit(s[i + 1]) {
          Valid16Shift(s, i + 2);
          Valid16Shift(u, 2);
          assert u[2..] == s[i + 2..];
        }
      } else if !IsLow(s[i]) {
        Valid16Shift(s, i + 1);
        Valid16Shift(u, 1);
        assert u[1..] == s[i + 1..];
      }
    }
  }

  lemma Valid16Unfold(s: S)
    ensures Valid16(s) <==> (|s| == 0 ||
      (IsUnit(s[0]) && (if IsHigh(s[0]) then |s| >= 2 && IsLow(s[1]) && IsUnit(s[1]) && Valid16(s[2..]) else !IsLow(s[0]) && Valid16(s[1..]))))
  {
    if |s| > 0 && IsUnit(s[0]) {
      if IsHigh(s[0]) { if |s| >= 2 && IsLow(s[1]) && IsUnit(s[1]) { Valid16Shift(s, 2); } }
      else if !IsLow(s[0]) { Valid16Shift(s, 1); }
    }
  }

  // Total decoder to code points (a lone surrogate maps to itself; meaningful only under Valid16).
  function Cps(s: S): seq<int>
    decreases |s|
  {
    if |s| == 0 then []
    else if IsHigh(s[0]) && |s| >= 2 && IsLow(s[1]) then [0x10000 + (s[0] - 0xD800) * 0x400 + (s[1] - 0xDC00)] + Cps(s[2..])
    else [s[0]] + Cps(s[1..])
  }

  predicate ValidCp(c: int) { 0 <= c <= 0x10FFFF && !(0xD800 <= c <= 0xDFFF) }
  predicate AllCp(c: seq<int>) { forall i :: 0 <= i < |c| ==> ValidCp(c[i]) }

  lemma CpsValid(s: S)
    requires Valid16(s)
    ensures AllCp(Cps(s))
    decreases |s|
  {
    Valid16Unfold(s);
    if |s| > 0 {
      if IsHigh(s[0]) { CpsValid(s[2..]); } else { CpsValid(s[1..]); }
    }
  }

  // UTF-16 -> code points is injective on well-formed strings.
  lemma CpsInjective(a: S, b: S)
    requires Valid16(a) && Valid16(b) && Cps(a) == Cps(b)
    ensures a == b
    decreases |a|
  {
    Valid16Unfold(a); Valid16Unfold(b);
    if |a| == 0 { return; }
    assert |b| > 0;
    if IsHigh(a[0]) {
      assert Cps(a)[0] >= 0x10000;
      assert IsHigh(b[0]);
      assert Cps(a)[0] == Cps(b)[0];
      assert a[0] == b[0] && a[1] == b[1];
      assert Cps(a)[1..] == Cps(b)[1..];
      CpsInjective(a[2..], b[2..]);
    } else {
      assert !IsHigh(b[0]);
      assert Cps(a)[1..] == Cps(b)[1..];
      CpsInjective(a[1..], b[1..]);
    }
  }

  // ---- UTF-8 ----
  function Enc8(c: int): seq<int> {
    if c < 0x80 then [c]
    else if c < 0x800 then [0xC0 + c / 64, 0x80 + c % 64]
    else if c < 0x10000 then [0xE0 + c / 4096, 0x80 + (c / 64) % 64, 0x80 + c % 64]
    else [0xF0 + c / 262144, 0x80 + (c / 4096) % 64, 0x80 + (c / 64) % 64, 0x80 + c % 64]
  }

  function Utf8(cs: seq<int>): seq<int>
    decreases |cs|
  {
    if |cs| == 0 then [] else Enc8(cs[0]) + Utf8(cs[1..])
  }

  // Length-determining first byte: the code is prefix-free.
  lemma Enc8Lead(c: int)
    requires ValidCp(c)
    ensures |Enc8(c)| == (if Enc8(c)[0] < 0x80 then 1 else if Enc8(c)[0] < 0xE0 then 2 else if Enc8(c)[0] < 0xF0 then 3 else 4)
    ensures forall i :: 0 <= i < |Enc8(c)| ==> 0 <= Enc8(c)[i] < 256
  {}

  lemma Enc8Injective(c1: int, c2: int)
    requires ValidCp(c1) && ValidCp(c2) && Enc8(c1) == Enc8(c2)
    ensures c1 == c2
  {}

  predicate IsPrefix(p: seq<int>, q: seq<int>) { |p| <= |q| && q[..|p|] == p }

  lemma Enc8PrefixFree(c1: int, c2: int)
    requires ValidCp(c1) && ValidCp(c2) && IsPrefix(Enc8(c1), Enc8(c2))
    ensures c1 == c2
  {
    Enc8Lead(c1); Enc8Lead(c2);
    assert Enc8(c1)[0] == Enc8(c2)[0];
    assert |Enc8(c1)| == |Enc8(c2)|;
    assert Enc8(c1) == Enc8(c2);
  }

  // Lexicographic strict order on integer sequences ("a < b").
  predicate LexLess(a: seq<int>, b: seq<int>)
    decreases |a|
  {
    |b| > 0 && (|a| == 0 || a[0] < b[0] || (a[0] == b[0] && LexLess(a[1..], b[1..])))
  }

  lemma LexIrrefl(a: seq<int>) ensures !LexLess(a, a) decreases |a| { if |a| > 0 { LexIrrefl(a[1..]); } }
  lemma LexAsym(a: seq<int>, b: seq<int>) requires LexLess(a, b) ensures !LexLess(b, a) decreases |a|
  { if |a| > 0 && |b| > 0 && a[0] == b[0] { LexAsym(a[1..], b[1..]); } }
  lemma LexTrans(a: seq<int>, b: seq<int>, c: seq<int>) requires LexLess(a, b) && LexLess(b, c) ensures LexLess(a, c) decreases |a|
  { if |a| > 0 && a[0] == b[0] && b[0] == c[0] { LexTrans(a[1..], b[1..], c[1..]); } }
  lemma LexTotal(a: seq<int>, b: seq<int>) ensures a == b || LexLess(a, b) || LexLess(b, a) decreases |a|
  { if |a| > 0 && |b| > 0 && a[0] == b[0] { LexTotal(a[1..], b[1..]); } }

  lemma LexCommonPrefix(p: seq<int>, a: seq<int>, b: seq<int>)
    ensures LexLess(p + a, p + b) <==> LexLess(a, b)
    decreases |p|
  {
    if |p| == 0 { assert p + a == a; assert p + b == b; }
    else { assert (p + a)[1..] == p[1..] + a; assert (p + b)[1..] == p[1..] + b; assert (p + a)[0] == p[0] && (p + b)[0] == p[0]; assert |p + b| > 0; LexCommonPrefix(p[1..], a, b); }
  }

  // If p < q and p is not a prefix of q (they differ at a position inside both) the tails are irrelevant.
  lemma LexDiffTail(p: seq<int>, q: seq<int>, a: seq<int>, b: seq<int>)
    requires LexLess(p, q) && !IsPrefix(p, q)
    ensures LexLess(p + a, q + b)
    decreases |p|
  {
    if |p| > 0 && p[0] == q[0] {
      assert (p + a)[1..] == p[1..] + a; assert (q + b)[1..] == q[1..] + b;
      assert !IsPrefix(p[1..], q[1..]);
      LexDiffTail(p[1..], q[1..], a, b);
    }
  }

  // a and b agree before index i and a[i] < b[i]  ==>  a < b.
  lemma LexByIndex(a: seq<int>, b: seq<int>, i: int)
    requires 0 <= i < |a| && i < |b| && a[..i] == b[..i] && a[i] < b[i]
    ensures LexLess(a, b)
    decreases i
  {
    if i > 0 { assert a[1..][..i-1] == b[1..][..i-1]; LexByIndex(a[1..], b[1..], i - 1); }
  }

  lemma Enc8Order(c1: int, c2: int)
    requires ValidCp(c1) && ValidCp(c2) && c1 < c2
    ensures LexLess(Enc8(c1), Enc8(c2))
  {
    var a := Enc8(c1); var b := Enc8(c2);
    if c2 < 0x80 { LexByIndex(a, b, 0); }
    else if c2 < 0x800 {
      if c1 < 0x80 { LexByIndex(a, b, 0); }
      else if c1 / 64 < c2 / 64 { LexByIndex(a, b, 0); } else { LexByIndex(a, b, 1); }
    } else if c2 < 0x10000 {
      if c1 < 0x800 { LexByIndex(a, b, 0); }
      else if c1 / 4096 < c2 / 4096 { LexByIndex(a, b, 0); }
      else if (c1 / 64) % 64 < (c2 / 64) % 64 { LexByIndex(a, b, 1); } else { LexByIndex(a, b, 2); }
    } else {
      if c1 < 0x10000 { LexByIndex(a, b, 0); }
      else if c1 / 262144 < c2 / 262144 { LexByIndex(a, b, 0); }
      else if (c1 / 4096) % 64 < (c2 / 4096) % 64 { LexByIndex(a, b, 1); }
      else if (c1 / 64) % 64 < (c2 / 64) % 64 { LexByIndex(a, b, 2); } else { LexByIndex(a, b, 3); }
    }
  }

  lemma Enc8OrderNotPrefix(c1: int, c2: int)
    requires ValidCp(c1) && ValidCp(c2) && c1 != c2
    ensures !IsPrefix(Enc8(c1), Enc8(c2))
  { if IsPrefix(Enc8(c1), Enc8(c2)) { Enc8PrefixFree(c1, c2); } }

  lemma Utf8Nonempty(cs: seq<int>) requires AllCp(cs) && |cs| > 0 ensures |Utf8(cs)| > 0 {}

  // THE ORDER THEOREM: comparing the UTF-8 BYTES of two strings is exactly comparing their code point sequences.
  lemma Utf8OrderIsCodePointOrder(x: seq<int>, y: seq<int>)
    requires AllCp(x) && AllCp(y)
    ensures LexLess(Utf8(x), Utf8(y)) <==> LexLess(x, y)
    decreases |x|
  {
    if |x| == 0 {
      if |y| > 0 { Utf8Nonempty(y); }
    } else if |y| == 0 {
    } else {
      assert AllCp(x[1..]) && AllCp(y[1..]);
      if x[0] == y[0] {
        LexCommonPrefix(Enc8(x[0]), Utf8(x[1..]), Utf8(y[1..]));
        Utf8OrderIsCodePointOrder(x[1..], y[1..]);
      } else if x[0] < y[0] {
        Enc8Order(x[0], y[0]); Enc8OrderNotPrefix(x[0], y[0]);
        LexDiffTail(Enc8(x[0]), Enc8(y[0]), Utf8(x[1..]), Utf8(y[1..]));
      } else {
        Enc8Order(y[0], x[0]); Enc8OrderNotPrefix(y[0], x[0]);
        LexDiffTail(Enc8(y[0]), Enc8(x[0]), Utf8(y[1..]), Utf8(x[1..]));
        LexAsym(Utf8(y), Utf8(x));
      }
    }
  }

  lemma Utf8Injective(x: seq<int>, y: seq<int>)
    requires AllCp(x) && AllCp(y) && Utf8(x) == Utf8(y)
    ensures x == y
    decreases |x|
  {
    LexTotal(x, y);
    Utf8OrderIsCodePointOrder(x, y);
    if x != y {
      if LexLess(x, y) { LexIrrefl(Utf8(x)); }
      else { Utf8OrderIsCodePointOrder(y, x); LexIrrefl(Utf8(x)); }
    }
  }

  // UTF-16 string -> UTF-8 bytes (what TextEncoder does on well-formed input) and its injectivity.
  function Utf8Of16(s: S): seq<int> { Utf8(Cps(s)) }

  lemma Utf8Of16Injective(a: S, b: S)
    requires Valid16(a) && Valid16(b) && Utf8Of16(a) == Utf8Of16(b)
    ensures a == b
  { CpsValid(a); CpsValid(b); Utf8Injective(Cps(a), Cps(b)); CpsInjective(a, b); }

  // The string order used for object keys: UTF-8 bytewise (compareUtf8 in hash.ts) == code point order.
  predicate KLess(a: S, b: S) { LexLess(Cps(a), Cps(b)) }

  lemma KLessIsUtf8Bytewise(a: S, b: S)
    requires Valid16(a) && Valid16(b)
    ensures KLess(a, b) <==> LexLess(Utf8Of16(a), Utf8Of16(b))
  { CpsValid(a); CpsValid(b); Utf8OrderIsCodePointOrder(Cps(a), Cps(b)); }

  lemma KLessIrrefl(a: S) ensures !KLess(a, a) { LexIrrefl(Cps(a)); }
  lemma KLessAsym(a: S, b: S) requires KLess(a, b) ensures !KLess(b, a) { LexAsym(Cps(a), Cps(b)); }
  lemma KLessTrans(a: S, b: S, c: S) requires KLess(a, b) && KLess(b, c) ensures KLess(a, c) { LexTrans(Cps(a), Cps(b), Cps(c)); }
  lemma KLessTrichotomy(a: S, b: S)
    requires Valid16(a) && Valid16(b)
    ensures a == b || KLess(a, b) || KLess(b, a)
  {
    LexTotal(Cps(a), Cps(b));
    if Cps(a) == Cps(b) { CpsInjective(a, b); }
  }

  // Byte length TextEncoder.encode would produce (a lone surrogate encodes as U+FFFD = 3 bytes). Spec form (recursive on slices):
  function Utf8LenSpec(s: S): int
    decreases |s|
  {
    if |s| == 0 then 0
    else if IsHigh(s[0]) && |s| >= 2 && IsLow(s[1]) then 4 + Utf8LenSpec(s[2..])
    else (if s[0] < 0x80 then 1 else if s[0] < 0x800 then 2 else 3) + Utf8LenSpec(s[1..])
  }
  // Compiled form: index + accumulator, tail-recursive (a loop).
  function Utf8LenFrom(s: S, i: int, acc: int): int
    requires 0 <= i
    decreases |s| - i
  {
    if i >= |s| then acc
    else if IsHigh(s[i]) && i + 1 < |s| && IsLow(s[i + 1]) then Utf8LenFrom(s, i + 2, acc + 4)
    else Utf8LenFrom(s, i + 1, acc + (if s[i] < 0x80 then 1 else if s[i] < 0x800 then 2 else 3))
  }
  function Utf8LenLoose(s: S): int { Utf8LenFrom(s, 0, 0) }

  lemma Utf8LenFromSpec(s: S, i: int, acc: int)
    requires 0 <= i <= |s|
    ensures Utf8LenFrom(s, i, acc) == acc + Utf8LenSpec(s[i..])
    decreases |s| - i
  {
    if i < |s| {
      if IsHigh(s[i]) && i + 1 < |s| && IsLow(s[i + 1]) { Utf8LenFromSpec(s, i + 2, acc + 4); assert s[i..][2..] == s[i + 2..]; }
      else { Utf8LenFromSpec(s, i + 1, acc + (if s[i] < 0x80 then 1 else if s[i] < 0x800 then 2 else 3)); assert s[i..][1..] == s[i + 1..]; }
    }
  }
  lemma Utf8LenLooseSpec(s: S) ensures Utf8LenLoose(s) == Utf8LenSpec(s) { Utf8LenFromSpec(s, 0, 0); assert s[0..] == s; }

  lemma Utf8LenIsEncodingSpec(s: S)
    requires Valid16(s)
    ensures Utf8LenSpec(s) == |Utf8Of16(s)|
    decreases |s|
  {
    Valid16Unfold(s);
    if |s| > 0 {
      CpsValid(s);
      if IsHigh(s[0]) { Utf8LenIsEncodingSpec(s[2..]); } else { Utf8LenIsEncodingSpec(s[1..]); }
    }
  }

  lemma Utf8LenIsEncoding(s: S)
    requires Valid16(s)
    ensures Utf8LenLoose(s) == |Utf8Of16(s)|
  { Utf8LenLooseSpec(s); Utf8LenIsEncodingSpec(s); }
}

// ---------------------------------------------------------------------------------------------------------------------
// Strict base64url (RFC 4648 s5, NO padding) and canonical lowercase hex. Bytes are ints in [0,256); characters are UTF-16 units.
// ---------------------------------------------------------------------------------------------------------------------
module B64 {
  type S = seq<int>
  predicate IsByte(x: int) { 0 <= x < 256 }
  predicate AllBytes(b: S) { forall i :: 0 <= i < |b| ==> IsByte(b[i]) }

  // sextet -> character:  0..25 'A'.., 26..51 'a'.., 52..61 '0'.., 62 '-', 63 '_'
  function Ch(v: int): int
    requires 0 <= v < 64
  { if v < 26 then 65 + v else if v < 52 then 97 + (v - 26) else if v < 62 then 48 + (v - 52) else if v == 62 then 45 else 95 }

  // character -> sextet, or -1 when the character is outside [A-Za-z0-9_-]
  function Val(c: int): int
    ensures -1 <= Val(c) < 64
  { if 65 <= c <= 90 then c - 65 else if 97 <= c <= 122 then c - 97 + 26 else if 48 <= c <= 57 then c - 48 + 52 else if c == 45 then 62 else if c == 95 then 63 else -1 }

  lemma ValCh(v: int) requires 0 <= v < 64 ensures Val(Ch(v)) == v {}
  lemma ChVal(c: int) requires Val(c) >= 0 ensures Ch(Val(c)) == c {}

  function Enc(b: S): S
    requires AllBytes(b)
    decreases |b|
  {
    if |b| == 0 then []
    else if |b| == 1 then [Ch(b[0] / 4), Ch((b[0] % 4) * 16)]
    else if |b| == 2 then [Ch(b[0] / 4), Ch((b[0] % 4) * 16 + b[1] / 16), Ch((b[1] % 16) * 4)]
    else [Ch(b[0] / 4), Ch((b[0] % 4) * 16 + b[1] / 16), Ch((b[1] % 16) * 4 + b[2] / 64), Ch(b[2] % 64)] + Enc(b[3..])
  }

  // Strict decoder: None for ANY deviation (bad character, length mod 4 == 1, non-zero trailing bits).
  function Dec(s: S): Option<S>
    decreases |s|
  {
    if |s| == 0 then Some([])
    else if |s| == 1 then None
    else if |s| == 2 then
      (if Val(s[0]) >= 0 && Val(s[1]) >= 0 && Val(s[1]) % 16 == 0 then Some([Val(s[0]) * 4 + Val(s[1]) / 16]) else None)
    else if |s| == 3 then
      (if Val(s[0]) >= 0 && Val(s[1]) >= 0 && Val(s[2]) >= 0 && Val(s[2]) % 4 == 0
       then Some([Val(s[0]) * 4 + Val(s[1]) / 16, (Val(s[1]) % 16) * 16 + Val(s[2]) / 4]) else None)
    else if Val(s[0]) >= 0 && Val(s[1]) >= 0 && Val(s[2]) >= 0 && Val(s[3]) >= 0 then
      (match Dec(s[4..])
       case None => None
       case Some(rest) =>
         Some([Val(s[0]) * 4 + Val(s[1]) / 16, (Val(s[1]) % 16) * 16 + Val(s[2]) / 4, (Val(s[2]) % 4) * 64 + Val(s[3])] + rest))
    else None
  }

  datatype Option<T> = None | Some(v: T)

  function EncLen(n: int): int requires n >= 0 { (n / 3) * 4 + (if n % 3 == 0 then 0 else n % 3 + 1) }

  lemma EncLength(b: S) requires AllBytes(b) ensures |Enc(b)| == EncLen(|b|) && EncLen(|b|) == (4 * |b| + 2) / 3
    decreases |b|
  { if |b| >= 3 { EncLength(b[3..]); } }

  lemma EncBytesOk(b: S) requires AllBytes(b) ensures forall i :: 0 <= i < |Enc(b)| ==> Val(Enc(b)[i]) >= 0
    decreases |b|
  {
    if |b| >= 3 { EncBytesOk(b[3..]); }
    forall i | 0 <= i < |Enc(b)| ensures Val(Enc(b)[i]) >= 0 {
      if |b| >= 3 && i >= 4 { assert Enc(b)[i] == Enc(b[3..])[i - 4]; }
    }
  }

  // Round trip: decoding what we encode returns the bytes.
  lemma DecEnc(b: S) requires AllBytes(b) ensures Dec(Enc(b)) == Some(b)
    decreases |b|
  {
    if |b| >= 3 {
      DecEnc(b[3..]);
      var e := Enc(b);
      assert e[4..] == Enc(b[3..]);
      forall v | 0 <= v < 64 ensures Val(Ch(v)) == v { ValCh(v); }
      assert b[0] == (b[0] / 4) * 4 + b[0] % 4;
      assert b[1] == (b[1] / 16) * 16 + b[1] % 16;
      assert b[2] == (b[2] / 64) * 64 + b[2] % 64;
      var v0 := b[0] / 4; var v1 := (b[0] % 4) * 16 + b[1] / 16; var v2 := (b[1] % 16) * 4 + b[2] / 64; var v3 := b[2] % 64;
      assert Val(e[0]) == v0 && Val(e[1]) == v1 && Val(e[2]) == v2 && Val(e[3]) == v3;
      assert v0 * 4 + v1 / 16 == b[0];
      assert (v1 % 16) * 16 + v2 / 4 == b[1];
      assert (v2 % 4) * 64 + v3 == b[2];
      assert Dec(e[4..]) == Some(b[3..]);
      assert b == [b[0], b[1], b[2]] + b[3..];
      assert Dec(e) == Some(b);
    } else if |b| == 2 {
      forall v | 0 <= v < 64 ensures Val(Ch(v)) == v { ValCh(v); }
      var e := Enc(b);
      var v0 := b[0] / 4; var v1 := (b[0] % 4) * 16 + b[1] / 16; var v2 := (b[1] % 16) * 4;
      assert Val(e[0]) == v0 && Val(e[1]) == v1 && Val(e[2]) == v2;
      assert v0 * 4 + v1 / 16 == b[0];
      assert (v1 % 16) * 16 + v2 / 4 == b[1];
      assert b == [b[0], b[1]];
      assert Dec(e) == Some(b);
    } else if |b| == 1 {
      forall v | 0 <= v < 64 ensures Val(Ch(v)) == v { ValCh(v); }
      var e := Enc(b);
      var v0 := b[0] / 4; var v1 := (b[0] % 4) * 16;
      assert Val(e[0]) == v0 && Val(e[1]) == v1;
      assert v0 * 4 + v1 / 16 == b[0];
      assert b == [b[0]];
      assert Dec(e) == Some(b);
    }
  }

  lemma DecBytes(s: S) ensures Dec(s).Some? ==> AllBytes(Dec(s).v)
    decreases |s|
  { if |s| >= 4 { DecBytes(s[4..]); } }

  // CANONICALITY: an accepted string is THE encoding of the bytes it decodes to (exactly one accepted spelling per byte string).
  lemma EncDec(s: S) requires Dec(s).Some? ensures AllBytes(Dec(s).v) && Enc(Dec(s).v) == s
    decreases |s|
  {
    DecBytes(s);
    if |s| >= 4 {
      EncDec(s[4..]);
      var b := Dec(s).v;
      assert b[3..] == Dec(s[4..]).v;
      assert Enc(b[3..]) == s[4..];
      forall i | 0 <= i < 4 ensures Val(s[i]) >= 0 {}
      forall i | 0 <= i < 4 ensures Ch(Val(s[i])) == s[i] { ChVal(s[i]); }
      assert Enc(b)[..4] == s[..4];
    } else if |s| >= 2 {
      forall i | 0 <= i < |s| ensures Ch(Val(s[i])) == s[i] { ChVal(s[i]); }
    }
  }

  // Injectivity on accepted strings (two accepted spellings of the same bytes are equal).
  lemma AcceptedUnique(s1: S, s2: S) requires Dec(s1).Some? && Dec(s1) == Dec(s2) ensures s1 == s2
  { EncDec(s1); EncDec(s2); }

  // length mod 4 == 1 is never accepted.
  lemma Mod1Rejected(s: S) requires |s| % 4 == 1 ensures Dec(s) == None
    decreases |s|
  { if |s| >= 4 { Mod1Rejected(s[4..]); } }

  // Alphabet: acceptance implies every character is in [A-Za-z0-9_-] (no padding, no whitespace).
  lemma AlphabetOnly(s: S) requires Dec(s).Some? ensures forall i :: 0 <= i < |s| ==> Val(s[i]) >= 0
    decreases |s|
  { if |s| >= 4 { AlphabetOnly(s[4..]); } }

  // decodeB64uStrict(s, len): length pre-check, strict decode, decoded-length check.
  function DecodeStrict(s: S, len: Option<int>): Option<S>
  {
    if len.Some? && (len.v < 0 || |s| != EncLen(len.v)) then None
    else match Dec(s)
      case None => None
      case Some(b) => if len.Some? && |b| != len.v then None else Some(b)
  }

  lemma DecodeStrictSound(s: S, len: Option<int>)
    requires DecodeStrict(s, len).Some?
    ensures AllBytes(DecodeStrict(s, len).v) && Enc(DecodeStrict(s, len).v) == s && (len.Some? ==> |DecodeStrict(s, len).v| == len.v)
  { EncDec(s); }

  // Fixed-length acceptance is exactly the encodings of len-byte strings (completeness for fixed-length fields).
  lemma DecodeStrictComplete(b: S, n: int)
    requires AllBytes(b) && |b| == n
    ensures DecodeStrict(Enc(b), Some(n)) == Some(b)
  { EncLength(b); DecEnc(b); }

  // ---- canonical lowercase hex ----
  function HexCh(v: int): int requires 0 <= v < 16 { if v < 10 then 48 + v else 97 + (v - 10) }
  function HexVal(c: int): int ensures -1 <= HexVal(c) < 16 { if 48 <= c <= 57 then c - 48 else if 97 <= c <= 102 then c - 97 + 10 else -1 }
  function HexEnc(b: S): S requires AllBytes(b) decreases |b| { if |b| == 0 then [] else [HexCh(b[0] / 16), HexCh(b[0] % 16)] + HexEnc(b[1..]) }
  function HexDec(s: S): Option<S> decreases |s|
  {
    if |s| == 0 then Some([])
    else if |s| == 1 || HexVal(s[0]) < 0 || HexVal(s[1]) < 0 then None
    else match HexDec(s[2..]) case None => None case Some(r) => Some([HexVal(s[0]) * 16 + HexVal(s[1])] + r)
  }
  lemma HexRoundTrip(b: S) requires AllBytes(b) ensures HexDec(HexEnc(b)) == Some(b) decreases |b|
  {
    if |b| > 0 {
      HexRoundTrip(b[1..]);
      assert HexVal(HexCh(b[0] / 16)) == b[0] / 16 && HexVal(HexCh(b[0] % 16)) == b[0] % 16;
      assert HexEnc(b)[2..] == HexEnc(b[1..]);
      var e := HexEnc(b);
      assert e[0] == HexCh(b[0] / 16) && e[1] == HexCh(b[0] % 16);
      assert HexVal(e[0]) * 16 + HexVal(e[1]) == b[0];
      assert [b[0]] + b[1..] == b;
    }
  }
  lemma HexBytes(s: S) ensures HexDec(s).Some? ==> AllBytes(HexDec(s).v) decreases |s| { if |s| >= 2 { HexBytes(s[2..]); } }
  lemma HexCanonical(s: S) requires HexDec(s).Some? ensures AllBytes(HexDec(s).v) && HexEnc(HexDec(s).v) == s decreases |s|
  {
    HexBytes(s);
    if |s| >= 2 {
      HexCanonical(s[2..]);
      var b := HexDec(s).v;
      assert b[1..] == HexDec(s[2..]).v;
      assert HexEnc(b)[2..] == s[2..];
      assert HexEnc(b)[0] == s[0] && HexEnc(b)[1] == s[1];
    }
  }
  lemma HexOddRejected(s: S) requires |s| % 2 == 1 ensures HexDec(s) == None decreases |s| { if |s| >= 3 { HexOddRejected(s[2..]); } }
}

// ---------------------------------------------------------------------------------------------------------------------
// Strict JSON profile: value model, parser (mirror of strict-json.ts), canonical printer (mirror of hash.ts canonicalizeStrict).
// ---------------------------------------------------------------------------------------------------------------------
module Json {
  import opened Utf

  const MaxDepth: int := 32
  const MaxBytes: int := 1048576
  const MaxSafe: int := 9007199254740991

  // Values. Numbers are modelled LEXICALLY: Int(n) is an exact safe integer; Dec is a canonical plain decimal
  // (sign, integer part, fractional digits 0..9). The IEEE-754 double behind a decimal is NOT modelled (see ext-notes).
  datatype KV = KV(k: S, v: J)
  datatype J = Null | Bool(b: bool) | Int(n: int) | Dec(neg: bool, ip: int, fr: seq<int>) | Str(s: S) | Arr(a: seq<J>) | Obj(kv: seq<KV>)

  datatype R<T> = Fail | Ok(v: T, pos: int)

  // ---- digits ----
  predicate IsDig(c: int) { 48 <= c <= 57 }
  predicate AllDig(d: S) { forall i :: 0 <= i < |d| ==> IsDig(d[i]) }
  function Dig(n: int): S requires n >= 0 decreases n { if n < 10 then [48 + n] else Dig(n / 10) + [48 + n % 10] }
  function ValSeq(d: S): int decreases |d| { if |d| == 0 then 0 else ValSeq(d[..|d| - 1]) * 10 + (d[|d| - 1] - 48) }
  function FrTxt(fr: seq<int>): S { seq(|fr|, i requires 0 <= i < |fr| => 48 + fr[i]) }
  function FrOf(t: S, a: int, b: int): seq<int> requires 0 <= a <= b <= |t| { seq(b - a, i requires 0 <= i < b - a => t[a + i] - 48) }

  predicate Digits09(f: seq<int>) { forall i :: 0 <= i < |f| ==> 0 <= f[i] <= 9 }
  function LeadZeros(f: seq<int>): int decreases |f| { if |f| > 0 && f[0] == 0 then 1 + LeadZeros(f[1..]) else 0 }
  // significant digits of "ip.fr" (leading zeros stripped), exactly what strict-json.ts counts
  function Sig(ip: int, fr: seq<int>): int requires ip >= 0 { if ip > 0 then |Dig(ip)| + |fr| else |fr| - LeadZeros(fr) }
  predicate MagOk(ip: int, fr: seq<int>) { ip > 0 || (exists i :: 0 <= i < 6 && i < |fr| && fr[i] != 0) }
  // the canonical non-integer decimal: >=1 fractional digit, no trailing fractional zero, <=15 significant digits, magnitude >= 1e-6
  predicate ValidDec(neg: bool, ip: int, fr: seq<int>) {
    ip >= 0 && |fr| >= 1 && Digits09(fr) && fr[|fr| - 1] != 0 && Sig(ip, fr) <= 15 && MagOk(ip, fr)
  }

  // ---- parser ----
  predicate IsWs(c: int) { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }
  function Ws(t: S, i: int): int
    ensures i <= Ws(t, i) && (i <= |t| ==> Ws(t, i) <= |t|)
    decreases |t| - i
  { if i >= 0 && i < |t| && IsWs(t[i]) then Ws(t, i + 1) else i }

  function ScanDigits(t: S, i: int): int
    requires 0 <= i
    ensures i <= ScanDigits(t, i) && (i <= |t| ==> ScanDigits(t, i) <= |t|)
    decreases |t| - i
  { if i < |t| && IsDig(t[i]) then ScanDigits(t, i + 1) else i }

  // end of the integer part "0" | [1-9][0-9]*  starting at k, or -1
  function IntEnd(t: S, k: int): int
    requires 0 <= k
    ensures IntEnd(t, k) == -1 || (k < IntEnd(t, k) <= |t|)
  { if k < |t| && t[k] == 48 then k + 1 else if k < |t| && 49 <= t[k] <= 57 then ScanDigits(t, k + 1) else -1 }

  predicate ExpMatches(t: S, L: int) {
    0 <= L < |t| && (t[L] == 101 || t[L] == 69) &&
    (var m := if L + 1 < |t| && (t[L + 1] == 43 || t[L + 1] == 45) then L + 2 else L + 1; m < |t| && IsDig(t[m]))
  }

  function ParseNum(t: S, j: int): R<J>
    requires 0 <= j < |t|
    ensures ParseNum(t, j).Ok? ==> j < ParseNum(t, j).pos <= |t|
  {
    var neg := t[j] == 45;
    var k := if neg then j + 1 else j;
    var e := IntEnd(t, k);
    if e < 0 then Fail
    else
      var hasFrac := e + 1 < |t| && t[e] == 46 && IsDig(t[e + 1]);
      var L := if hasFrac then ScanDigits(t, e + 1) else e;
      if ExpMatches(t, L) then Fail
      else if hasFrac then
        (var ip := ValSeq(t[k..e]); var fr := FrOf(t, e + 1, L);
         if ValidDec(neg, ip, fr) then Ok(Dec(neg, ip, fr), L) else Fail)
      else
        (var n := ValSeq(t[k..e]);
         if (neg && n == 0) || n > MaxSafe then Fail else Ok(Int(if neg then -n else n), L))
  }

  function HexD(c: int): int { if 48 <= c <= 57 then c - 48 else if 97 <= c <= 102 then c - 87 else if 65 <= c <= 70 then c - 55 else -1 }
  function Hex4(t: S, i: int): int
    requires 0 <= i
    ensures -1 <= Hex4(t, i) < 65536
  {
    if i + 4 > |t| then -1
    else if HexD(t[i]) < 0 || HexD(t[i + 1]) < 0 || HexD(t[i + 2]) < 0 || HexD(t[i + 3]) < 0 then -1
    else ((HexD(t[i]) * 16 + HexD(t[i + 1])) * 16 + HexD(t[i + 2])) * 16 + HexD(t[i + 3])
  }

  // string body after the opening quote; `acc` is the decoded UTF-16 so far
  function StrBody(t: S, i: int, acc: S): R<S>
    requires 0 <= i
    ensures StrBody(t, i, acc).Ok? ==> i < StrBody(t, i, acc).pos <= |t|
    decreases |t| - i
  {
    if i >= |t| then Fail
    else
      var c := t[i];
      if c == 34 then Ok(acc, i + 1)
      else if c < 0x20 then Fail
      else if c == 92 then
        (if i + 1 >= |t| then Fail
         else
           var e := t[i + 1];
           if e == 34 then StrBody(t, i + 2, acc + [34])
           else if e == 92 then StrBody(t, i + 2, acc + [92])
           else if e == 47 then StrBody(t, i + 2, acc + [47])
           else if e == 98 then StrBody(t, i + 2, acc + [8])
           else if e == 102 then StrBody(t, i + 2, acc + [12])
           else if e == 110 then StrBody(t, i + 2, acc + [10])
           else if e == 114 then StrBody(t, i + 2, acc + [13])
           else if e == 116 then StrBody(t, i + 2, acc + [9])
           else if e == 117 then
             (var h := Hex4(t, i + 2); if h < 0 then Fail else StrBody(t, i + 6, acc + [h]))
           else Fail)
      else StrBody(t, i + 1, acc + [c])
  }

  // Compiled form of StrBody: runs of plain characters are copied as ONE slice (no per-character concatenation); StrBodyFEq proves it equal.
  function PlainEnd(t: S, i: int): int
    requires 0 <= i
    ensures i <= PlainEnd(t, i) && (i <= |t| ==> PlainEnd(t, i) <= |t|)
    decreases |t| - i
  { if i < |t| && t[i] != 34 && t[i] != 92 && t[i] >= 0x20 then PlainEnd(t, i + 1) else i }

  function StrBodyF(t: S, i: int, acc: S): R<S>
    requires 0 <= i
    ensures StrBodyF(t, i, acc).Ok? ==> i < StrBodyF(t, i, acc).pos <= |t|
    decreases |t| - i
  {
    if i >= |t| then Fail
    else
      var j := PlainEnd(t, i);
      var acc2 := if j == i then acc else acc + t[i..j];
      if j >= |t| then Fail
      else
        var c := t[j];
        if c == 34 then Ok(acc2, j + 1)
        else if c < 0x20 then Fail
        else if c == 92 then
          (if j + 1 >= |t| then Fail
           else
             var e := t[j + 1];
             if e == 34 then StrBodyF(t, j + 2, acc2 + [34])
             else if e == 92 then StrBodyF(t, j + 2, acc2 + [92])
             else if e == 47 then StrBodyF(t, j + 2, acc2 + [47])
             else if e == 98 then StrBodyF(t, j + 2, acc2 + [8])
             else if e == 102 then StrBodyF(t, j + 2, acc2 + [12])
             else if e == 110 then StrBodyF(t, j + 2, acc2 + [10])
             else if e == 114 then StrBodyF(t, j + 2, acc2 + [13])
             else if e == 116 then StrBodyF(t, j + 2, acc2 + [9])
             else if e == 117 then
               (var h := Hex4(t, j + 2); if h < 0 then Fail else StrBodyF(t, j + 6, acc2 + [h]))
             else Fail)
        else Fail
  }

  lemma StrBodyFEq(t: S, i: int, acc: S)
    requires 0 <= i
    ensures StrBodyF(t, i, acc) == StrBody(t, i, acc)
    decreases |t| - i
  {
    if i < |t| {
      var c := t[i];
      if c != 34 && c != 92 && c >= 0x20 {
        StrBodyFEq(t, i + 1, acc + [c]);
        var j := PlainEnd(t, i);
        assert PlainEnd(t, i + 1) == j;
        if j == i + 1 { assert t[i..j] == [c]; } else { assert t[i..j] == [c] + t[i + 1..j]; assert (acc + [c]) + t[i + 1..j] == acc + t[i..j]; }
      } else if c == 92 && i + 1 < |t| {
        var e := t[i + 1];
        if e == 34 || e == 92 || e == 47 || e == 98 || e == 102 || e == 110 || e == 114 || e == 116 {
          StrBodyFEq(t, i + 2, acc + [if e == 34 then 34 else if e == 92 then 92 else if e == 47 then 47 else if e == 98 then 8 else if e == 102 then 12 else if e == 110 then 10 else if e == 114 then 13 else 9]);
        } else if e == 117 {
          var h := Hex4(t, i + 2);
          if h >= 0 { StrBodyFEq(t, i + 6, acc + [h]); }
        }
      }
    }
  }

  function ParseStr(t: S, i: int): R<S>
    requires 0 <= i < |t| && t[i] == 34
    ensures ParseStr(t, i).Ok? ==> i < ParseStr(t, i).pos <= |t| && Valid16(ParseStr(t, i).v)
  {
    match StrBodyF(t, i + 1, [])
    case Fail => Fail
    case Ok(s, p) => if Valid16(s) then Ok(s, p) else Fail
  }

  predicate StartsWith(t: S, j: int, lit: S) { 0 <= j && j + |lit| <= |t| && t[j..j + |lit|] == lit }
  const LitTrue: S := [116, 114, 117, 101]
  const LitFalse: S := [102, 97, 108, 115, 101]
  const LitNull: S := [110, 117, 108, 108]

  predicate HasKey(acc: seq<KV>, k: S) { exists i :: 0 <= i < |acc| && acc[i].k == k }

  function ParseValue(t: S, i: int, d: int): R<J>
    requires 0 <= i
    ensures ParseValue(t, i, d).Ok? ==> i < ParseValue(t, i, d).pos <= |t|
    decreases |t| - i, 0
  {
    var j := Ws(t, i);
    if j >= |t| then Fail
    else
      var c := t[j];
      if c == 123 then (if d > MaxDepth then Fail else ObjStart(t, j + 1, d))
      else if c == 91 then (if d > MaxDepth then Fail else ArrStart(t, j + 1, d))
      else if c == 34 then (match ParseStr(t, j) case Fail => Fail case Ok(s, p) => Ok(Str(s), p))
      else if c == 45 || IsDig(c) then ParseNum(t, j)
      else if StartsWith(t, j, LitTrue) then Ok(Bool(true), j + 4)
      else if StartsWith(t, j, LitFalse) then Ok(Bool(false), j + 5)
      else if StartsWith(t, j, LitNull) then Ok(Null, j + 4)
      else Fail
  }

  function ArrStart(t: S, i: int, d: int): R<J>
    requires 0 <= i
    ensures ArrStart(t, i, d).Ok? ==> i < ArrStart(t, i, d).pos <= |t|
    decreases |t| - i, 2
  {
    var j := Ws(t, i);
    if j < |t| && t[j] == 93 then Ok(Arr([]), j + 1) else ArrLoop(t, i, d, [])
  }

  function ArrLoop(t: S, i: int, d: int, acc: seq<J>): R<J>
    requires 0 <= i
    ensures ArrLoop(t, i, d, acc).Ok? ==> i < ArrLoop(t, i, d, acc).pos <= |t|
    decreases |t| - i, 1
  {
    match ParseValue(t, i, d + 1)
    case Fail => Fail
    case Ok(v, p) =>
      var j := Ws(t, p);
      if j >= |t| then Fail
      else if t[j] == 44 then ArrLoop(t, j + 1, d, acc + [v])
      else if t[j] == 93 then Ok(Arr(acc + [v]), j + 1)
      else Fail
  }

  function ObjStart(t: S, i: int, d: int): R<J>
    requires 0 <= i
    ensures ObjStart(t, i, d).Ok? ==> i < ObjStart(t, i, d).pos <= |t|
    decreases |t| - i, 2
  {
    var j := Ws(t, i);
    if j < |t| && t[j] == 125 then Ok(Obj([]), j + 1) else ObjLoop(t, i, d, [])
  }

  function ObjLoop(t: S, i: int, d: int, acc: seq<KV>): R<J>
    requires 0 <= i
    ensures ObjLoop(t, i, d, acc).Ok? ==> i < ObjLoop(t, i, d, acc).pos <= |t|
    decreases |t| - i, 1
  {
    var j := Ws(t, i);
    if j >= |t| || t[j] != 34 then Fail
    else
      match ParseStr(t, j)
      case Fail => Fail
      case Ok(k, p) =>
        if HasKey(acc, k) then Fail
        else
          var j2 := Ws(t, p);
          if j2 >= |t| || t[j2] != 58 then Fail
          else
            match ParseValue(t, j2 + 1, d + 1)
            case Fail => Fail
            case Ok(v, q) =>
              var j3 := Ws(t, q);
              if j3 >= |t| then Fail
              else if t[j3] == 44 then ObjLoop(t, j3 + 1, d, acc + [KV(k, v)])
              else if t[j3] == 125 then Ok(Obj(acc + [KV(k, v)]), j3 + 1)
              else Fail
  }

  datatype Option<T> = None | Some(v: T)

  // strictParse: size bound in UTF-8 bytes, value at depth 1, nothing but whitespace afterwards.
  function ParseTop(t: S): Option<J> {
    if Utf8LenLoose(t) > MaxBytes then None
    else match ParseValue(t, 0, 1)
      case Fail => None
      case Ok(v, p) => if Ws(t, p) == |t| then Some(v) else None
  }

  // ---- validity of values (the strict profile) ----
  predicate DistinctKeys(kv: seq<KV>) {
    forall i :: 0 <= i < |kv| ==> forall j :: i < j < |kv| ==> kv[i].k != kv[j].k
  }
  predicate Valid(v: J, d: int) decreases v
  {
    match v
    case Null => true
    case Bool(_) => true
    case Int(n) => -MaxSafe <= n <= MaxSafe
    case Dec(neg, ip, fr) => ValidDec(neg, ip, fr)
    case Str(s) => Valid16(s)
    case Arr(a) => d <= MaxDepth && ValidElems(a, d + 1)
    case Obj(kv) => d <= MaxDepth && ValidMembers(kv, d + 1) && DistinctKeys(kv)
  }
  predicate ValidElems(a: seq<J>, d: int) decreases a { forall i :: 0 <= i < |a| ==> Valid(a[i], d) }
  predicate ValidMembers(kv: seq<KV>, d: int) decreases kv { forall i :: 0 <= i < |kv| ==> Valid16(kv[i].k) && Valid(kv[i].v, d) }

  lemma ValSeqNonneg(d: S) requires AllDig(d) ensures ValSeq(d) >= 0 decreases |d|
  { if |d| > 0 { assert AllDig(d[..|d| - 1]); ValSeqNonneg(d[..|d| - 1]); } }

  lemma ScanAllDig(t: S, i: int)
    requires 0 <= i <= |t|
    ensures AllDig(t[i..ScanDigits(t, i)])
    decreases |t| - i
  {
    if i < |t| && IsDig(t[i]) {
      ScanAllDig(t, i + 1);
      assert t[i..ScanDigits(t, i)] == [t[i]] + t[i + 1..ScanDigits(t, i + 1)];
    }
  }

  lemma IntEndDigits(t: S, k: int)
    requires 0 <= k && IntEnd(t, k) >= 0
    ensures k < IntEnd(t, k) <= |t| && AllDig(t[k..IntEnd(t, k)])
  {
    if k < |t| && t[k] == 48 {
    } else {
      ScanAllDig(t, k + 1);
      assert t[k..IntEnd(t, k)] == [t[k]] + t[k + 1..ScanDigits(t, k + 1)];
    }
  }

  lemma ParseNumValid(t: S, j: int)
    requires 0 <= j < |t| && ParseNum(t, j).Ok?
    ensures Valid(ParseNum(t, j).v, 1)
  {
    var neg := t[j] == 45;
    var k := if neg then j + 1 else j;
    var e := IntEnd(t, k);
    IntEndDigits(t, k);
    ValSeqNonneg(t[k..e]);
  }

  lemma ParseValueValid(t: S, i: int, d: int)
    requires 0 <= i && ParseValue(t, i, d).Ok?
    ensures Valid(ParseValue(t, i, d).v, d)
    decreases |t| - i, 0
  {
    var j := Ws(t, i);
    var c := t[j];
    if c == 123 { ObjStartValid(t, j + 1, d); }
    else if c == 91 { ArrStartValid(t, j + 1, d); }
    else if c == 34 { }
    else if c == 45 || IsDig(c) {
      ParseNumValid(t, j);
      var n := ParseNum(t, j).v;
      assert Valid(n, d) <== Valid(n, 1) && !n.Arr? && !n.Obj?;
    }
  }

  lemma ArrStartValid(t: S, i: int, d: int)
    requires 0 <= i && d <= MaxDepth && ArrStart(t, i, d).Ok?
    ensures Valid(ArrStart(t, i, d).v, d)
    decreases |t| - i, 2
  {
    var j := Ws(t, i);
    if !(j < |t| && t[j] == 93) { ArrLoopValid(t, i, d, []); }
  }

  lemma ArrLoopValid(t: S, i: int, d: int, acc: seq<J>)
    requires 0 <= i && d <= MaxDepth && ValidElems(acc, d + 1) && ArrLoop(t, i, d, acc).Ok?
    ensures Valid(ArrLoop(t, i, d, acc).v, d)
    decreases |t| - i, 1
  {
    var r := ParseValue(t, i, d + 1);
    ParseValueValid(t, i, d + 1);
    var j := Ws(t, r.pos);
    if t[j] == 44 {
      ArrLoopValid(t, j + 1, d, acc + [r.v]);
    }
  }

  lemma ObjStartValid(t: S, i: int, d: int)
    requires 0 <= i && d <= MaxDepth && ObjStart(t, i, d).Ok?
    ensures Valid(ObjStart(t, i, d).v, d)
    decreases |t| - i, 2
  {
    var j := Ws(t, i);
    if !(j < |t| && t[j] == 125) { ObjLoopValid(t, i, d, []); }
  }

  lemma KeyFreshExtends(acc: seq<KV>, k: S, v: J)
    requires DistinctKeys(acc) && !HasKey(acc, k)
    ensures DistinctKeys(acc + [KV(k, v)])
  {
    var n := acc + [KV(k, v)];
    forall i | 0 <= i < |n| ensures forall j :: i < j < |n| ==> n[i].k != n[j].k {
      forall j | i < j < |n| ensures n[i].k != n[j].k {
        if j == |n| - 1 { assert i < |acc|; assert n[i] == acc[i]; if n[i].k == k { assert HasKey(acc, k); } }
        else { assert n[i] == acc[i] && n[j] == acc[j]; }
      }
    }
  }

  lemma ObjLoopValid(t: S, i: int, d: int, acc: seq<KV>)
    requires 0 <= i && d <= MaxDepth && ValidMembers(acc, d + 1) && DistinctKeys(acc) && ObjLoop(t, i, d, acc).Ok?
    ensures Valid(ObjLoop(t, i, d, acc).v, d)
    decreases |t| - i, 1
  {
    var j := Ws(t, i);
    var rk := ParseStr(t, j);
    var j2 := Ws(t, rk.pos);
    var rv := ParseValue(t, j2 + 1, d + 1);
    ParseValueValid(t, j2 + 1, d + 1);
    var j3 := Ws(t, rv.pos);
    var nacc := acc + [KV(rk.v, rv.v)];
    KeyFreshExtends(acc, rk.v, rv.v);
    assert ValidMembers(nacc, d + 1) by {
      forall x | 0 <= x < |nacc| ensures Valid16(nacc[x].k) && Valid(nacc[x].v, d + 1) {
        if x < |acc| { assert nacc[x] == acc[x]; }
      }
    }
    if t[j3] == 44 { ObjLoopValid(t, j3 + 1, d, nacc); }
  }

  // THEOREM (parse soundness): everything strictParse accepts is a profile-valid value: no duplicate keys at any level,
  // no lone surrogates, depth <= 32, every number in the canonical wire form, input <= 1 MiB (UTF-8 bytes).
  lemma ParseTopValid(t: S)
    requires ParseTop(t).Some?
    ensures Valid(ParseTop(t).v, 1) && Utf8LenLoose(t) <= MaxBytes
  { ParseValueValid(t, 0, 1); }

  // ---- canonical key order: sorting object members by UTF-8 bytewise key order (== code point order) ----
  function Insert(x: KV, s: seq<KV>): seq<KV> decreases |s|
  { if |s| == 0 then [x] else if KLess(x.k, s[0].k) then [x] + s else [s[0]] + Insert(x, s[1..]) }
  function SortKV(kv: seq<KV>): seq<KV> decreases |kv|
  { if |kv| == 0 then [] else Insert(kv[0], SortKV(kv[1..])) }
  predicate StrictSorted(s: seq<KV>) {
    forall i :: 0 <= i < |s| ==> forall j :: i < j < |s| ==> KLess(s[i].k, s[j].k)
  }

  lemma InsertMultiset(x: KV, s: seq<KV>)
    ensures multiset(Insert(x, s)) == multiset(s) + multiset{x} && |Insert(x, s)| == |s| + 1
    decreases |s|
  {
    if |s| > 0 && !KLess(x.k, s[0].k) {
      InsertMultiset(x, s[1..]);
      assert s == [s[0]] + s[1..];
    } else if |s| > 0 { assert [x] + s == [x] + s; }
  }
  lemma SortMultiset(kv: seq<KV>) ensures multiset(SortKV(kv)) == multiset(kv) && |SortKV(kv)| == |kv| decreases |kv|
  {
    if |kv| > 0 {
      SortMultiset(kv[1..]);
      InsertMultiset(kv[0], SortKV(kv[1..]));
      assert kv == [kv[0]] + kv[1..];
    }
  }

  predicate KeysValid(s: seq<KV>) { forall i :: 0 <= i < |s| ==> Valid16(s[i].k) }

  lemma InsertSorted(x: KV, s: seq<KV>)
    requires StrictSorted(s) && KeysValid(s) && Valid16(x.k) && !HasKey(s, x.k)
    ensures StrictSorted(Insert(x, s))
    decreases |s|
  {
    if |s| == 0 { return; }
    if KLess(x.k, s[0].k) {
      var r := [x] + s;
      forall j | 0 < j < |r| ensures KLess(r[0].k, r[j].k) {
        if j == 1 { } else { assert r[j] == s[j - 1]; KLessTrans(x.k, s[0].k, s[j - 1].k); }
      }
      forall i | 0 < i < |r| ensures forall j :: i < j < |r| ==> KLess(r[i].k, r[j].k) {
        forall j | i < j < |r| ensures KLess(r[i].k, r[j].k) { assert r[i] == s[i - 1] && r[j] == s[j - 1]; }
      }
    } else {
      assert s[0].k != x.k by { if s[0].k == x.k { assert HasKey(s, x.k); } }
      KLessTrichotomy(s[0].k, x.k);
      assert KLess(s[0].k, x.k);
      var tl := s[1..];
      assert StrictSorted(tl) by { forall i | 0 <= i < |tl| ensures forall j :: i < j < |tl| ==> KLess(tl[i].k, tl[j].k) { forall j | i < j < |tl| ensures KLess(tl[i].k, tl[j].k) { assert tl[i] == s[i + 1] && tl[j] == s[j + 1]; } } }
      assert !HasKey(tl, x.k) by { if HasKey(tl, x.k) { var i :| 0 <= i < |tl| && tl[i].k == x.k; assert s[i + 1].k == x.k; assert HasKey(s, x.k); } }
      assert KeysValid(tl);
      InsertSorted(x, tl);
      var I := Insert(x, tl);
      InsertMultiset(x, tl);
      var r := [s[0]] + I;
      forall m | 0 < m < |r| ensures KLess(s[0].k, r[m].k) {
        var e := I[m - 1];
        assert e in multiset(I);
        if e == x { } else {
          assert e in multiset(tl);
          assert e in tl;
          var q :| 0 <= q < |tl| && tl[q] == e;
          assert s[q + 1] == e;
        }
      }
      forall i | 0 <= i < |r| ensures forall j :: i < j < |r| ==> KLess(r[i].k, r[j].k) {
        forall j | i < j < |r| ensures KLess(r[i].k, r[j].k) {
          if i == 0 {} else { assert r[i] == I[i - 1] && r[j] == I[j - 1]; }
        }
      }
    }
  }

  lemma StrictSortedTail(s: seq<KV>) requires StrictSorted(s) && |s| > 0 ensures StrictSorted(s[1..])
  {
    var tl := s[1..];
    forall i | 0 <= i < |tl| ensures forall j :: i < j < |tl| ==> KLess(tl[i].k, tl[j].k) {
      forall j | i < j < |tl| ensures KLess(tl[i].k, tl[j].k) { assert tl[i] == s[i + 1] && tl[j] == s[j + 1]; }
    }
  }

  lemma SortSorted(kv: seq<KV>)
    requires DistinctKeys(kv) && KeysValid(kv)
    ensures StrictSorted(SortKV(kv)) && KeysValid(SortKV(kv))
    decreases |kv|
  {
    if |kv| == 0 { return; }
    var tl := kv[1..];
    assert DistinctKeys(tl) by { forall i | 0 <= i < |tl| ensures forall j :: i < j < |tl| ==> tl[i].k != tl[j].k { forall j | i < j < |tl| ensures tl[i].k != tl[j].k { assert tl[i] == kv[i + 1] && tl[j] == kv[j + 1]; } } }
    assert KeysValid(tl) by { forall i | 0 <= i < |tl| ensures Valid16(tl[i].k) { assert tl[i] == kv[i + 1]; } }
    SortSorted(tl);
    SortMultiset(tl);
    var st := SortKV(tl);
    assert !HasKey(st, kv[0].k) by {
      if HasKey(st, kv[0].k) {
        var i :| 0 <= i < |st| && st[i].k == kv[0].k;
        assert st[i] in multiset(st);
        assert st[i] in tl;
        var q :| 0 <= q < |tl| && tl[q] == st[i];
        assert kv[q + 1].k == kv[0].k;
      }
    }
    InsertSorted(kv[0], st);
    InsertMultiset(kv[0], st);
    assert KeysValid(Insert(kv[0], st)) by {
      forall i | 0 <= i < |Insert(kv[0], st)| ensures Valid16(Insert(kv[0], st)[i].k) {
        var e := Insert(kv[0], st)[i];
        assert e in multiset(Insert(kv[0], st));
        if e == kv[0] {} else { assert e in multiset(st); assert e in st; var q :| 0 <= q < |st| && st[q] == e; }
      }
    }
  }

  lemma StrictSortedDistinct(s: seq<KV>) requires StrictSorted(s) ensures DistinctKeys(s)
  {
    forall i | 0 <= i < |s| ensures forall j :: i < j < |s| ==> s[i].k != s[j].k {
      forall j | i < j < |s| ensures s[i].k != s[j].k { KLessIrrefl(s[i].k); }
    }
  }

  // Sorted sequences with the same members are equal: the canonical member order is UNIQUE.
  lemma SortedUnique(a: seq<KV>, b: seq<KV>)
    requires StrictSorted(a) && StrictSorted(b) && multiset(a) == multiset(b)
    ensures a == b
    decreases |a|
  {
    assert |a| == |b|;
    if |a| == 0 { return; }
    assert a[0] in multiset(b) && b[0] in multiset(a);
    var p :| 0 <= p < |b| && b[p] == a[0];
    var q :| 0 <= q < |a| && a[q] == b[0];
    if p > 0 && q > 0 { KLessAsym(b[0].k, b[p].k); assert false; }
    if p > 0 && q == 0 { assert a[0] == b[0]; }
    assert a[0] == b[0];
    StrictSortedTail(a); StrictSortedTail(b);
    assert a == [a[0]] + a[1..] && b == [b[0]] + b[1..];
    assert multiset(a) == multiset{a[0]} + multiset(a[1..]);
    assert multiset(b) == multiset{b[0]} + multiset(b[1..]);
    assert forall e :: multiset(a[1..])[e] == multiset(b[1..])[e] by {
      forall e ensures multiset(a[1..])[e] == multiset(b[1..])[e] { assert multiset(a)[e] == multiset{a[0]}[e] + multiset(a[1..])[e]; assert multiset(b)[e] == multiset{b[0]}[e] + multiset(b[1..])[e]; }
    }
    assert multiset(a[1..]) == multiset(b[1..]);
    SortedUnique(a[1..], b[1..]);
  }

  // ---- normal form: recursively sort every object's members ----
  function NormJ(v: J): J decreases v
  { match v case Arr(a) => Arr(NormElems(a)) case Obj(kv) => Obj(SortKV(NormMembers(kv))) case _ => v }
  function NormElems(a: seq<J>): seq<J> decreases a { if |a| == 0 then [] else [NormJ(a[0])] + NormElems(a[1..]) }
  function NormMembers(kv: seq<KV>): seq<KV> decreases kv { if |kv| == 0 then [] else [KV(kv[0].k, NormJ(kv[0].v))] + NormMembers(kv[1..]) }

  predicate Canon(v: J) decreases v
  { match v case Arr(a) => CanonElems(a) case Obj(kv) => StrictSorted(kv) && CanonMembers(kv) case _ => true }
  predicate CanonElems(a: seq<J>) decreases a { forall i :: 0 <= i < |a| ==> Canon(a[i]) }
  predicate CanonMembers(kv: seq<KV>) decreases kv { forall i :: 0 <= i < |kv| ==> Canon(kv[i].v) }

  lemma NormElemsIdx(a: seq<J>) ensures |NormElems(a)| == |a| && forall i :: 0 <= i < |a| ==> NormElems(a)[i] == NormJ(a[i]) decreases |a|
  { if |a| > 0 { NormElemsIdx(a[1..]); } }
  lemma NormMembersIdx(kv: seq<KV>) ensures |NormMembers(kv)| == |kv| && forall i :: 0 <= i < |kv| ==> NormMembers(kv)[i] == KV(kv[i].k, NormJ(kv[i].v)) decreases |kv|
  { if |kv| > 0 { NormMembersIdx(kv[1..]); } }

  lemma NormKeysDistinct(kv: seq<KV>) requires DistinctKeys(kv) ensures DistinctKeys(NormMembers(kv)) && (KeysValid(kv) ==> KeysValid(NormMembers(kv)))
  { NormMembersIdx(kv); }

  lemma ValidNorm(v: J, d: int) requires Valid(v, d) ensures Valid(NormJ(v), d) && Canon(NormJ(v)) decreases v
  {
    match v
    case Arr(a) =>
      NormElemsIdx(a);
      forall i | 0 <= i < |a| ensures Valid(NormElems(a)[i], d + 1) && Canon(NormElems(a)[i]) { ValidNorm(a[i], d + 1); }
    case Obj(kv) =>
      NormMembersIdx(kv);
      var nm := NormMembers(kv);
      forall i | 0 <= i < |kv| ensures Valid16(nm[i].k) && Valid(nm[i].v, d + 1) && Canon(nm[i].v) { ValidNorm(kv[i].v, d + 1); }
      NormKeysDistinct(kv);
      assert KeysValid(nm);
      SortSorted(nm);
      SortMultiset(nm);
      var sr := SortKV(nm);
      StrictSortedDistinct(sr);
      forall i | 0 <= i < |sr| ensures Valid16(sr[i].k) && Valid(sr[i].v, d + 1) && Canon(sr[i].v) {
        assert sr[i] in multiset(sr);
        assert sr[i] in nm;
        var q :| 0 <= q < |nm| && nm[q] == sr[i];
      }
    case _ =>
  }

  lemma NormIdem(v: J, d: int) requires Valid(v, d) && Canon(v) ensures NormJ(v) == v decreases v
  {
    match v
    case Arr(a) =>
      NormElemsIdx(a);
      forall i | 0 <= i < |a| ensures NormJ(a[i]) == a[i] { NormIdem(a[i], d + 1); }
      assert NormElems(a) == a;
    case Obj(kv) =>
      NormMembersIdx(kv);
      forall i | 0 <= i < |kv| ensures NormJ(kv[i].v) == kv[i].v { NormIdem(kv[i].v, d + 1); }
      assert NormMembers(kv) == kv;
      SortMultiset(kv);
      StrictSortedDistinct(kv);
      SortSorted(kv);
      SortedUnique(SortKV(kv), kv);
    case _ =>
  }

  // THEOREM: normalisation is idempotent and the result is canonical.
  lemma NormNorm(v: J, d: int) requires Valid(v, d) ensures NormJ(NormJ(v)) == NormJ(v)
  { ValidNorm(v, d); NormIdem(NormJ(v), d); }

  // ---- canonical printer (mirror of ser(..., strict=true): JSON.stringify string escaping, no whitespace) ----
  function HexL(v: int): int requires 0 <= v < 16 { if v < 10 then 48 + v else 97 + (v - 10) }
  function PrintU(x: int): S {
    if x == 34 then [92, 34] else if x == 92 then [92, 92] else if x == 8 then [92, 98] else if x == 12 then [92, 102]
    else if x == 10 then [92, 110] else if x == 13 then [92, 114] else if x == 9 then [92, 116]
    else if 0 <= x < 0x20 then [92, 117, 48, 48, HexL(x / 16), HexL(x % 16)]
    else [x]
  }
  function PrintBody(s: S): S decreases |s| { if |s| == 0 then [] else PrintU(s[0]) + PrintBody(s[1..]) }
  function PrintNat(n: int): S { if n < 0 then Dig(0) else Dig(n) }

  function Print(v: J): S decreases v
  {
    match v
    case Null => LitNull
    case Bool(b) => if b then LitTrue else LitFalse
    case Int(n) => if n < 0 then [45] + PrintNat(-n) else PrintNat(n)
    case Dec(neg, ip, fr) => (if neg then [45] else []) + PrintNat(ip) + [46] + FrTxt(fr)
    case Str(s) => [34] + PrintBody(s) + [34]
    case Arr(a) => [91] + PrintElems(a) + [93]
    case Obj(kv) => [123] + PrintMembers(kv) + [125]
  }
  function PrintElems(a: seq<J>): S decreases a
  { if |a| == 0 then [] else if |a| == 1 then Print(a[0]) else Print(a[0]) + [44] + PrintElems(a[1..]) }
  function PrintMembers(kv: seq<KV>): S decreases kv
  {
    if |kv| == 0 then []
    else ([34] + PrintBody(kv[0].k) + [34, 58] + Print(kv[0].v)) + (if |kv| == 1 then [] else [44] + PrintMembers(kv[1..]))
  }

  // canonicalizeStrict(value): None <=> the TypeError cases (out of profile); otherwise the keys-sorted text.
  function CanonText(v: J): Option<S> { if Valid(v, 1) then Some(Print(NormJ(v))) else None }

  // ---- digit lemmas ----
  lemma DigFacts(n: int)
    requires n >= 0
    ensures AllDig(Dig(n)) && |Dig(n)| >= 1 && (n > 0 ==> Dig(n)[0] != 48) && ValSeq(Dig(n)) == n
    decreases n
  {
    if n >= 10 {
      DigFacts(n / 10);
      var d := Dig(n);
      assert d[..|d| - 1] == Dig(n / 10);
      assert d[0] == Dig(n / 10)[0];
    }
  }

  lemma ScanDigitsExact(t: S, i: int, ds: S, rest: S)
    requires 0 <= i <= |t| && AllDig(ds) && t[i..] == ds + rest && (|rest| == 0 || !IsDig(rest[0]))
    ensures ScanDigits(t, i) == i + |ds|
    decreases |ds|
  {
    if |ds| == 0 { assert i == |t| || t[i] == rest[0]; }
    else {
      assert t[i] == ds[0];
      assert t[i + 1..] == ds[1..] + rest;
      assert AllDig(ds[1..]);
      ScanDigitsExact(t, i + 1, ds[1..], rest);
    }
  }

  lemma IntEndExact(t: S, k: int, n: int, rest: S)
    requires 0 <= k <= |t| && n >= 0 && t[k..] == Dig(n) + rest && (|rest| == 0 || !IsDig(rest[0]))
    ensures IntEnd(t, k) == k + |Dig(n)|
  {
    DigFacts(n);
    var d := Dig(n);
    assert t[k] == d[0];
    if n == 0 { assert d == [48]; }
    else {
      assert d[0] != 48 && IsDig(d[0]);
      assert t[k + 1..] == d[1..] + rest;
      assert AllDig(d[1..]);
      ScanDigitsExact(t, k + 1, d[1..], rest);
    }
  }

  lemma Valid16Units(s: S) requires Valid16(s) ensures forall i :: 0 <= i < |s| ==> IsUnit(s[i]) decreases |s|
  { Valid16Unfold(s); if |s| > 0 { if IsHigh(s[0]) { Valid16Units(s[2..]); } else { Valid16Units(s[1..]); } } }

  // ---- string round trip ----
  lemma HexL4(x: int) requires 0 <= x < 0x20 ensures HexD(48) == 0 && HexD(HexL(x / 16)) == x / 16 && HexD(HexL(x % 16)) == x % 16 {}

  lemma StrBodyPrint(s: S, t: S, i: int, acc: S, rest: S)
    requires 0 <= i <= |t| && (forall k :: 0 <= k < |s| ==> IsUnit(s[k])) && t[i..] == PrintBody(s) + [34] + rest
    ensures StrBody(t, i, acc) == Ok(acc + s, i + |PrintBody(s)| + 1)
    decreases |s|
  {
    if |s| == 0 { assert t[i] == 34; assert PrintBody(s) == [] && acc + s == acc; return; }
    var x := s[0];
    var pu := PrintU(x);
    var full := PrintBody(s) + [34] + rest;
    assert full == pu + (PrintBody(s[1..]) + [34] + rest);
    assert t[i + |pu|..] == PrintBody(s[1..]) + [34] + rest;
    assert acc + s == (acc + [x]) + s[1..];
    assert PrintBody(s) == pu + PrintBody(s[1..]);
    StrBodyPrint(s[1..], t, i + |pu|, acc + [x], rest);
    assert t[i..i + |pu|] == pu;
    assert i < |t| && t[i] == pu[0];
    if 0 <= x < 0x20 && x != 8 && x != 12 && x != 10 && x != 13 && x != 9 {
      HexL4(x);
      assert |pu| == 6 && t[i + 1] == 117 && t[i + 2] == 48 && t[i + 3] == 48;
      assert t[i + 4] == HexL(x / 16) && t[i + 5] == HexL(x % 16);
      assert Hex4(t, i + 2) == x;
    }
    assert StrBody(t, i, acc) == StrBody(t, i + |pu|, acc + [x]);
  }

  lemma ParseStrPrint(s: S, t: S, i: int, rest: S)
    requires 0 <= i <= |t| && Valid16(s) && t[i..] == [34] + PrintBody(s) + [34] + rest
    ensures i < |t| && t[i] == 34 && ParseStr(t, i) == Ok(s, i + |PrintBody(s)| + 2)
  {
    Valid16Units(s);
    assert t[i + 1..] == PrintBody(s) + [34] + rest;
    StrBodyPrint(s, t, i + 1, [], rest);
    StrBodyFEq(t, i + 1, []);
    assert [] + s == s;
  }

  // ---- values ----
  predicate Delim(rest: S) { |rest| == 0 || rest[0] in {32, 9, 10, 13, 44, 93, 125} }

  lemma PrintHead(v: J)
    ensures |Print(v)| > 0 && !IsWs(Print(v)[0]) && Print(v)[0] != 93 && Print(v)[0] != 125
    ensures (v.Int? || v.Dec?) ==> (Print(v)[0] == 45 || IsDig(Print(v)[0]))
  {
    match v
    case Int(n) => if n < 0 { } else { if n >= 0 { DigFacts(n); } }
    case Dec(neg, ip, fr) => if !neg { if ip >= 0 { DigFacts(ip); } }
    case _ =>
  }

  lemma WsNone(t: S, i: int) requires 0 <= i < |t| && !IsWs(t[i]) ensures Ws(t, i) == i {}

  lemma ParseNumPrint(v: J, t: S, j: int, rest: S)
    requires 0 <= j <= |t| && (v.Int? || v.Dec?) && Valid(v, 1) && t[j..] == Print(v) + rest && Delim(rest)
    ensures j < |t| && ParseNum(t, j) == Ok(v, j + |Print(v)|)
  {
    PrintHead(v);
    var p := Print(v);
    assert t[j] == p[0];
    match v
    case Int(n) =>
      var neg := n < 0;
      var m := if neg then -n else n;
      DigFacts(m);
      var k := if neg then j + 1 else j;
      assert t[k..] == Dig(m) + rest;
      assert PrintNat(m) == Dig(m);
      IntEndExact(t, k, m, rest);
      var e := k + |Dig(m)|;
      assert t[e..] == t[k..][|Dig(m)|..];
      assert t[e..] == rest;
      assert !(e + 1 < |t| && t[e] == 46 && IsDig(t[e + 1]));
      assert !ExpMatches(t, e);
      assert t[k..e] == t[k..][..|Dig(m)|];
      assert t[k..e] == Dig(m);
      assert (t[j] == 45) == neg;
    case Dec(neg, ip, fr) =>
      DigFacts(ip);
      var k := if neg then j + 1 else j;
      assert PrintNat(ip) == Dig(ip);
      assert t[k..] == Dig(ip) + ([46] + FrTxt(fr) + rest);
      IntEndExact(t, k, ip, [46] + FrTxt(fr) + rest);
      var e := k + |Dig(ip)|;
      assert t[e] == 46;
      assert t[e + 1..] == FrTxt(fr) + rest;
      assert IsDig(t[e + 1]);
      assert AllDig(FrTxt(fr));
      ScanDigitsExact(t, e + 1, FrTxt(fr), rest);
      var L := e + 1 + |fr|;
      assert t[L..] == rest;
      if L < |t| { assert t[L] == rest[0]; }
      assert !ExpMatches(t, L);
      assert t[k..e] == t[k..][..|Dig(ip)|];
      assert t[k..e] == Dig(ip);
      assert |FrOf(t, e + 1, L)| == |fr|;
      forall x | 0 <= x < |fr| ensures FrOf(t, e + 1, L)[x] == fr[x] {
        assert t[e + 1 + x] == t[e + 1..][x];
        assert t[e + 1..][x] == (FrTxt(fr) + rest)[x];
        assert (FrTxt(fr) + rest)[x] == FrTxt(fr)[x];
        assert FrTxt(fr)[x] == 48 + fr[x];
        assert FrOf(t, e + 1, L)[x] == t[e + 1 + x] - 48;
      }
      assert FrOf(t, e + 1, L) == fr;
      assert (t[j] == 45) == neg;
  }

  lemma PrintParse(v: J, d: int, t: S, i: int, rest: S)
    requires 0 <= i <= |t| && Valid(v, d) && t[i..] == Print(v) + rest && Delim(rest)
    ensures ParseValue(t, i, d) == Ok(v, i + |Print(v)|)
    decreases v
  {
    PrintHead(v);
    var p := Print(v);
    assert i < |t| && t[i] == p[0];
    WsNone(t, i);
    match v
    case Null => assert t[i..i + 4] == LitNull; assert LitNull != LitTrue && LitNull != LitFalse;
    case Bool(b) =>
      if b { assert t[i..i + 4] == LitTrue; } else { assert t[i..i + 5] == LitFalse; assert LitFalse != LitTrue; }
    case Int(n) => ParseNumPrint(v, t, i, rest);
    case Dec(neg, ip, fr) => ParseNumPrint(v, t, i, rest);
    case Str(s) => ParseStrPrint(s, t, i, rest);
    case Arr(a) =>
      assert t[i] == 91;
      if |a| == 0 {
        assert p == [91, 93];
        assert t[i + 1] == 93;
        WsNone(t, i + 1);
      } else {
        var pe := PrintElems(a);
        assert t[i + 1..] == pe + [93] + rest;
        PrintHead(a[0]);
        assert i + 1 < |t| && t[i + 1] == Print(a[0])[0];
        WsNone(t, i + 1);
        ArrLoopPrint(a, d, t, i + 1, [], rest);
        assert [] + a == a;
      }
    case Obj(kv) =>
      assert t[i] == 123;
      if |kv| == 0 {
        assert p == [123, 125];
        WsNone(t, i + 1);
      } else {
        var pm := PrintMembers(kv);
        assert t[i + 1..] == pm + [125] + rest;
        assert pm[0] == 34;
        assert t[i + 1] == 34;
        WsNone(t, i + 1);
        ObjLoopPrint(kv, d, t, i + 1, [], rest);
        assert [] + kv == kv;
      }
  }

  lemma ArrLoopPrint(a: seq<J>, d: int, t: S, i: int, acc: seq<J>, rest: S)
    requires |a| >= 1 && 0 <= i <= |t| && d <= MaxDepth && ValidElems(a, d + 1) && Delim(rest) && t[i..] == PrintElems(a) + [93] + rest
    ensures ArrLoop(t, i, d, acc) == Ok(Arr(acc + a), i + |PrintElems(a)| + 1)
    decreases a
  {
    var a0 := a[0];
    var pa := Print(a0);
    var rest0 := if |a| == 1 then [93] + rest else [44] + PrintElems(a[1..]) + [93] + rest;
    assert PrintElems(a) + [93] + rest == pa + rest0;
    assert t[i..] == pa + rest0;
    assert Delim(rest0);
    PrintParse(a0, d + 1, t, i, rest0);
    var p := i + |pa|;
    assert p < |t| && t[p] == rest0[0];
    assert !IsWs(t[p]);
    WsNone(t, p);
    if |a| == 1 {
      assert PrintElems(a) == pa;
      assert acc + a == acc + [a0];
    } else {
      assert PrintElems(a) == pa + [44] + PrintElems(a[1..]);
      assert t[p + 1..] == PrintElems(a[1..]) + [93] + rest;
      ValidElemsTail(a, d + 1);
      ArrLoopPrint(a[1..], d, t, p + 1, acc + [a0], rest);
      assert (acc + [a0]) + a[1..] == acc + a;
    }
  }

  lemma FreshKey(acc: seq<KV>, kv: seq<KV>)
    requires |kv| >= 1 && DistinctKeys(acc + kv)
    ensures !HasKey(acc, kv[0].k)
  {
    if HasKey(acc, kv[0].k) {
      var x :| 0 <= x < |acc| && acc[x].k == kv[0].k;
      assert (acc + kv)[x].k == kv[0].k && (acc + kv)[|acc|].k == kv[0].k;
    }
  }
  lemma ValidMembersTail(kv: seq<KV>, d: int) requires |kv| >= 1 && ValidMembers(kv, d) ensures ValidMembers(kv[1..], d)
  { forall x | 0 <= x < |kv| - 1 ensures Valid16(kv[1..][x].k) && Valid(kv[1..][x].v, d) { assert kv[1..][x] == kv[x + 1]; } }
  lemma ValidElemsTail(a: seq<J>, d: int) requires |a| >= 1 && ValidElems(a, d) ensures ValidElems(a[1..], d)
  { forall x | 0 <= x < |a| - 1 ensures Valid(a[1..][x], d) { assert a[1..][x] == a[x + 1]; } }

  lemma {:isolate_assertions} ObjLoopPrint(kv: seq<KV>, d: int, t: S, i: int, acc: seq<KV>, rest: S)
    requires |kv| >= 1 && 0 <= i <= |t| && d <= MaxDepth && ValidMembers(kv, d + 1) && DistinctKeys(acc + kv) && Delim(rest)
    requires t[i..] == PrintMembers(kv) + [125] + rest
    ensures ObjLoop(t, i, d, acc) == Ok(Obj(acc + kv), i + |PrintMembers(kv)| + 1)
    decreases kv
  {
    var k := kv[0].k; var v := kv[0].v;
    var pk := PrintBody(k);
    var tail := if |kv| == 1 then [] else [44] + PrintMembers(kv[1..]);
    assert PrintMembers(kv) == ([34] + pk + [34, 58] + Print(v)) + tail;
    var rest1 := [58] + Print(v) + tail + [125] + rest;
    assert t[i..] == [34] + pk + [34] + rest1;
    assert t[i] == 34;
    WsNone(t, i);
    ParseStrPrint(k, t, i, rest1);
    var p := i + |pk| + 2;
    FreshKey(acc, kv);
    assert t[p..] == t[i..][|pk| + 2..];
    assert t[p..] == rest1;
    assert p < |t| && t[p] == 58;
    WsNone(t, p);
    var rest2 := tail + [125] + rest;
    assert rest1[1..] == Print(v) + rest2;
    assert t[p + 1..] == t[p..][1..];
    assert t[p + 1..] == Print(v) + rest2;
    assert Delim(rest2);
    PrintParse(v, d + 1, t, p + 1, rest2);
    var q := p + 1 + |Print(v)|;
    assert q < |t| && t[q] == rest2[0];
    WsNone(t, q);
    if |kv| == 1 {
      assert PrintMembers(kv) == [34] + pk + [34, 58] + Print(v);
      assert acc + kv == acc + [KV(k, v)];
    } else {
      assert t[q + 1..] == PrintMembers(kv[1..]) + [125] + rest;
      ValidMembersTail(kv, d + 1);
      assert (acc + [KV(k, v)]) + kv[1..] == acc + kv;
      ObjLoopPrint(kv[1..], d, t, q + 1, acc + [KV(k, v)], rest);
    }
  }

  // ======== THE THEOREMS ========

  // (1) PARSE o PRINT = id on every profile-valid value (no size caveat at the ParseValue level).
  lemma RoundTrip(v: J)
    requires Valid(v, 1)
    ensures ParseValue(Print(v), 0, 1) == Ok(v, |Print(v)|)
  { PrintParse(v, 1, Print(v), 0, []); }

  lemma RoundTripTop(v: J)
    requires Valid(v, 1) && Utf8LenLoose(Print(v)) <= MaxBytes
    ensures ParseTop(Print(v)) == Some(v)
  { RoundTrip(v); }

  // (2) the canonical text of any valid value re-parses to its normal form (<= 1 MiB).
  lemma CanonRoundTrip(v: J)
    requires Valid(v, 1)
    ensures ParseValue(Print(NormJ(v)), 0, 1) == Ok(NormJ(v), |Print(NormJ(v))|)
  { ValidNorm(v, 1); RoundTrip(NormJ(v)); }

  lemma CanonRoundTripTop(v: J)
    requires Valid(v, 1) && Utf8LenLoose(Print(NormJ(v))) <= MaxBytes
    ensures ParseTop(Print(NormJ(v))) == Some(NormJ(v))
  { CanonRoundTrip(v); }

  // (3) INJECTIVITY: print is injective on valid values; the canonical text determines the value up to member order, and two
  //     values with the same normal form have the SAME canonical text (two spellings of one value share one canonical form).
  lemma PrintInjective(v1: J, v2: J)
    requires Valid(v1, 1) && Valid(v2, 1) && Print(v1) == Print(v2)
    ensures v1 == v2
  { RoundTrip(v1); RoundTrip(v2); }

  lemma CanonTextInjective(v1: J, v2: J)
    requires Valid(v1, 1) && Valid(v2, 1) && CanonText(v1) == CanonText(v2)
    ensures NormJ(v1) == NormJ(v2)
  { ValidNorm(v1, 1); ValidNorm(v2, 1); PrintInjective(NormJ(v1), NormJ(v2)); }

  lemma CanonTextEquiv(v1: J, v2: J)
    requires Valid(v1, 1) && Valid(v2, 1)
    ensures CanonText(v1) == CanonText(v2) <==> NormJ(v1) == NormJ(v2)
  { if NormJ(v1) == NormJ(v2) { } else if CanonText(v1) == CanonText(v2) { CanonTextInjective(v1, v2); } }

  // (4) idempotence: canonicalising what the parser read back from a canonical text gives the same text.
  lemma CanonReparse(v: J, w: J)
    requires Valid(v, 1) && Utf8LenLoose(Print(NormJ(v))) <= MaxBytes && ParseTop(Print(NormJ(v))) == Some(w)
    ensures CanonText(w) == CanonText(v)
  {
    CanonRoundTripTop(v);
    assert w == NormJ(v);
    ValidNorm(v, 1);
    NormNorm(v, 1);
  }

  // (5) every accepted document has a canonical text, and that text is the one a canonical-form producer emits.
  lemma ParseThenCanon(s: S, v: J)
    requires ParseTop(s) == Some(v)
    ensures Valid(v, 1) && CanonText(v) == Some(Print(NormJ(v)))
  { ParseTopValid(s); }

  // ---- accepted numbers have exactly ONE spelling (the canonical one) ----
  lemma DigOfVal(ds: S)
    requires AllDig(ds) && |ds| >= 1 && (ds == [48] || ds[0] != 48)
    ensures ValSeq(ds) >= 0 && Dig(ValSeq(ds)) == ds
    decreases |ds|
  {
    ValSeqNonneg(ds);
    if |ds| == 1 {
      assert ValSeq(ds) == ds[0] - 48;
    } else {
      var pre := ds[..|ds| - 1];
      assert AllDig(pre) && pre[0] == ds[0] && pre != [48];
      DigOfVal(pre);
      var v1 := ValSeq(pre);
      if v1 == 0 { assert Dig(0) == [48]; assert pre == [48]; }
      var n := ValSeq(ds);
      assert n == v1 * 10 + (ds[|ds| - 1] - 48);
      assert n >= 10 && n / 10 == v1 && n % 10 == ds[|ds| - 1] - 48;
      assert Dig(n) == Dig(v1) + [48 + n % 10];
      assert ds == pre + [ds[|ds| - 1]];
    }
  }

  lemma ParseNumSpelling(t: S, j: int)
    requires 0 <= j < |t| && ParseNum(t, j).Ok?
    ensures var r := ParseNum(t, j); t[j..r.pos] == Print(r.v)
  {
    var neg := t[j] == 45;
    var k := if neg then j + 1 else j;
    var e := IntEnd(t, k);
    IntEndDigits(t, k);
    var ds := t[k..e];
    assert ds == [48] || ds[0] != 48 by {
      if t[k] == 48 { assert e == k + 1; assert ds == [48]; } else { assert ds[0] == t[k]; }
    }
    DigOfVal(ds);
    var hasFrac := e + 1 < |t| && t[e] == 46 && IsDig(t[e + 1]);
    var L := if hasFrac then ScanDigits(t, e + 1) else e;
    if hasFrac {
      ScanAllDig(t, e + 1);
      var ip := ValSeq(ds); var fr := FrOf(t, e + 1, L);
      assert FrTxt(fr) == t[e + 1..L];
      assert PrintNat(ip) == Dig(ip);
      assert t[j..L] == (if neg then [45] else []) + ds + [46] + t[e + 1..L];
    } else {
      var m := ValSeq(ds);
      ValSeqNonneg(ds);
      assert t[j..L] == (if neg then [45] else []) + ds;
      assert PrintNat(m) == Dig(m);
    }
  }

  // ---- duplicate keys and depth are rejected by construction ----
  lemma ObjDuplicateRejected(t: S, i: int, d: int, acc: seq<KV>, j: int, k: S)
    requires 0 <= i && Ws(t, i) == j && j < |t| && t[j] == 34 && ParseStr(t, j).Ok? && ParseStr(t, j).v == k && HasKey(acc, k)
    ensures ObjLoop(t, i, d, acc) == Fail
  {}

  lemma TooDeepRejected(t: S, i: int, d: int)
    requires 0 <= i && d > MaxDepth && Ws(t, i) < |t| && (t[Ws(t, i)] == 91 || t[Ws(t, i)] == 123)
    ensures ParseValue(t, i, d) == Fail
  {}

  lemma DeepContainerInvalid(v: J, d: int) requires d > MaxDepth && (v.Arr? || v.Obj?) ensures !Valid(v, d) {}

  // The size bound: an accepted document fits in MaxBytes UTF-8 bytes; a larger one is never accepted.
  lemma OversizeRejected(t: S) requires Utf8LenLoose(t) > MaxBytes ensures ParseTop(t) == None {}
}

// Thin entry points compiled for the TypeScript adapter (ext-wire.ts).
module Api {
  import Utf
  import Json
  import B64

  // strictParse then canonicalizeStrict, on UTF-16 code units. None <=> strictParse would throw.
  function CanonicalOfText(t: Utf.S): Json.Option<Utf.S>
  {
    match Json.ParseTop(t)
    case None => Json.None
    case Some(v) => Json.CanonText(v)
  }

  lemma CanonicalOfTextTotalOnAccepted(t: Utf.S)
    requires Json.ParseTop(t).Some?
    ensures CanonicalOfText(t).Some?
  { Json.ParseTopValid(t); }

  // canonicalizeStrict on an imported value. None <=> the value is outside the strict profile (the TS function throws).
  function CanonicalOfValue(v: Json.J): Json.Option<Utf.S> { Json.CanonText(v) }

  // compareUtf8 on well-formed UTF-16: 0 if equal, -1 / 1 by UTF-8 bytewise (== code point) order.
  function CompareUtf8(a: Utf.S, b: Utf.S): int { if a == b then 0 else if Utf.KLess(a, b) then -1 else 1 }

  lemma CompareUtf8Spec(a: Utf.S, b: Utf.S)
    requires Utf.Valid16(a) && Utf.Valid16(b)
    ensures (CompareUtf8(a, b) == 0 <==> a == b)
    ensures (CompareUtf8(a, b) < 0 <==> Utf.LexLess(Utf.Utf8Of16(a), Utf.Utf8Of16(b)))
    ensures CompareUtf8(a, b) == -CompareUtf8(b, a)
  {
    Utf.KLessIsUtf8Bytewise(a, b);
    Utf.KLessIsUtf8Bytewise(b, a);
    Utf.KLessTrichotomy(a, b);
    if a == b { Utf.LexIrrefl(Utf.Utf8Of16(a)); }
    else if Utf.KLess(a, b) { Utf.KLessAsym(a, b); }
    else { Utf.KLessAsym(b, a); }
  }

  function B64Decode(s: Utf.S, len: B64.Option<int>): B64.Option<Utf.S> { B64.DecodeStrict(s, len) }
  function B64Encode(b: Utf.S): Utf.S requires B64.AllBytes(b) { B64.Enc(b) }
  function HexDecode(s: Utf.S): B64.Option<Utf.S> { B64.HexDec(s) }
  function HexEncode(b: Utf.S): Utf.S requires B64.AllBytes(b) { B64.HexEnc(b) }
}
