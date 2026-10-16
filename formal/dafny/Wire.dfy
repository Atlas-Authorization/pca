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
  lemma FrOfAt(t: S, a: int, b: int, q: int) requires 0 <= a <= b <= |t| && 0 <= q < b - a ensures FrOf(t, a, b)[q] == t[a + q] - 48 {}

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
    // drop the shared head from both multisets (stated as a calc: one small step each)
    calc {
      multiset(a[1..]);
      == (multiset{a[0]} + multiset(a[1..])) - multiset{a[0]};
      == multiset(a) - multiset{a[0]};
      == multiset(b) - multiset{b[0]};
      == (multiset{b[0]} + multiset(b[1..])) - multiset{b[0]};
      == multiset(b[1..]);
    }
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

  // t[i..] == a + b splits at |a| (stated once so the long proofs below do not leave it to the solver)
  lemma SliceAfter(t: S, i: int, a: S, b: S)
    requires 0 <= i <= |t| && t[i..] == a + b
    ensures i + |a| <= |t| && t[i + |a|..] == b && t[i..i + |a|] == a
  { assert t[i..][|a|..] == b; assert t[i..][..|a|] == a; }
  lemma SliceTake(t: S, k: int, n: int) requires 0 <= k && 0 <= n && k + n <= |t| ensures t[k..k + n] == t[k..][..n] {}
  lemma SliceSplit(t: S, a: int, b: int, c: int) requires 0 <= a <= b <= c <= |t| ensures t[a..c] == t[a..b] + t[b..c] {}

  lemma {:isolate_assertions} {:fuel ScanDigits, 0, 0} {:fuel IntEnd, 0, 0} {:fuel Dig, 0, 0} {:fuel ValSeq, 0, 0} ParseNumPrint(v: J, t: S, j: int, rest: S)
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
      SliceTake(t, k, |Dig(m)|);
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
      SliceTake(t, k, |Dig(ip)|);
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
    SliceAfter(t, i, p, rest);
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

  // one member of ObjLoop, given the results of its parts
  lemma {:fuel ParseValue, 0, 0} {:fuel ParseStr, 0, 0} ObjLoopStep(t: S, i: int, d: int, acc: seq<KV>, k: S, p: int, v: J, q: int)
    requires 0 <= i < |t| && Ws(t, i) == i && t[i] == 34 && ParseStr(t, i) == Ok(k, p) && !HasKey(acc, k)
    requires 0 <= p < |t| && Ws(t, p) == p && t[p] == 58 && ParseValue(t, p + 1, d + 1) == Ok(v, q)
    requires 0 <= q < |t| && Ws(t, q) == q
    ensures ObjLoop(t, i, d, acc) ==
      (if t[q] == 44 then ObjLoop(t, q + 1, d, acc + [KV(k, v)]) else if t[q] == 125 then Ok(Obj(acc + [KV(k, v)]), q + 1) else Fail)
  {}

  lemma {:isolate_assertions} {:fuel ParseValue, 0, 0} {:fuel ParseStr, 0, 0} {:fuel ObjLoop, 0, 0} ObjLoopPrint(kv: seq<KV>, d: int, t: S, i: int, acc: seq<KV>, rest: S)
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
    // the one unfolding of ObjLoop at i, in a small lemma; then the postcondition is stated per branch
    assert Ws(t, i) == i && ParseStr(t, i) == Ok(k, p);
    assert !HasKey(acc, k);
    assert Ws(t, p) == p;
    assert ParseValue(t, p + 1, d + 1) == Ok(v, q);
    assert Ws(t, q) == q;
    ObjLoopStep(t, i, d, acc, k, p, v, q);
    assert q == i + |pk| + 3 + |Print(v)|;
    if |kv| == 1 {
      assert PrintMembers(kv) == [34] + pk + [34, 58] + Print(v);
      assert |PrintMembers(kv)| == |pk| + 3 + |Print(v)|;
      assert t[q] == 125;
      assert acc + kv == acc + [KV(k, v)];
      assert ObjLoop(t, i, d, acc) == Ok(Obj(acc + kv), i + |PrintMembers(kv)| + 1);
    } else {
      assert t[q] == 44;
      assert tail == [44] + PrintMembers(kv[1..]);
      assert rest2 == [44] + (PrintMembers(kv[1..]) + [125] + rest);
      SliceAfter(t, p + 1, Print(v), rest2);
      SliceAfter(t, q, [44], PrintMembers(kv[1..]) + [125] + rest);
      assert t[q + 1..] == PrintMembers(kv[1..]) + [125] + rest;
      ValidMembersTail(kv, d + 1);
      assert (acc + [KV(k, v)]) + kv[1..] == acc + kv;
      ObjLoopPrint(kv[1..], d, t, q + 1, acc + [KV(k, v)], rest);
      assert |PrintMembers(kv)| == |pk| + 3 + |Print(v)| + 1 + |PrintMembers(kv[1..])|;
      assert ObjLoop(t, i, d, acc) == ObjLoop(t, q + 1, d, acc + [KV(k, v)]);
      assert ObjLoop(t, i, d, acc) == Ok(Obj(acc + kv), i + |PrintMembers(kv)| + 1);
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

  lemma {:isolate_assertions} {:fuel ScanDigits, 0, 0} {:fuel Dig, 0, 0} {:fuel ValSeq, 0, 0} ParseNumSpelling(t: S, j: int)
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
      SliceSplit(t, j, k, L); SliceSplit(t, k, e, L); SliceSplit(t, e, e + 1, L);
      assert t[j..k] == (if neg then [45] else []) && t[e..e + 1] == [46];
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
module Fast {
  import opened Utf
  import opened Json

  newtype U16 = x: int | 0 <= x < 0x10000
  newtype N = x: int | 0 <= x < 0x20_0000_0000_0000

  ghost function W(t: seq<U16>): S { seq(|t|, i requires 0 <= i < |t| => t[i] as int) }

  lemma WInj(a: seq<U16>, b: seq<U16>) requires W(a) == W(b) ensures a == b
  {
    assert |a| == |W(a)| == |W(b)| == |b|;
    forall i | 0 <= i < |a| ensures a[i] == b[i] { assert W(a)[i] == W(b)[i]; }
  }

  lemma WSnoc(a: seq<U16>, x: U16) ensures W(a + [x]) == W(a) + [x as int] {}

  // ---- whitespace ----
  method SkipWs(t: seq<U16>, ghost T: S, i: N) returns (j: N)
    requires T == W(t) && |t| <= MaxBytes && i as int <= |t|
    ensures j as int == Ws(T, i as int) && i <= j && j as int <= |t|
  {
    j := i;
    var n := |t| as N;
    while j < n && (t[j] == 0x20 || t[j] == 0x09 || t[j] == 0x0A || t[j] == 0x0D)
      invariant i <= j <= n && Ws(T, i as int) == Ws(T, j as int)
      decreases n - j
    { j := j + 1; }
  }

  // ---- UTF-8 length bound ----
  lemma Utf8LenGe(s: S, i: int, acc: int)
    requires 0 <= i <= |s|
    ensures Utf8LenFrom(s, i, acc) >= acc + (|s| - i)
    decreases |s| - i
  {
    if i < |s| {
      if IsHigh(s[i]) && i + 1 < |s| && IsLow(s[i + 1]) { Utf8LenGe(s, i + 2, acc + 4); } else { Utf8LenGe(s, i + 1, acc + (if s[i] < 0x80 then 1 else if s[i] < 0x800 then 2 else 3)); }
    }
  }

  method Utf8LenN(t: seq<U16>, ghost T: S) returns (r: N)
    requires T == W(t) && |t| <= MaxBytes
    ensures r as int == Utf8LenLoose(T)
  {
    var i: N := 0;
    var n := |t| as N;
    r := 0;
    while i < n
      invariant i <= n && r as int <= 4 * i as int && Utf8LenLoose(T) == Utf8LenFrom(T, i as int, r as int)
      decreases n - i
    {
      var c := t[i];
      if 0xD800 <= c <= 0xDBFF && i + 1 < n && 0xDC00 <= t[i + 1] <= 0xDFFF { r := r + 4; i := i + 2; }
      else { r := r + (if c < 0x80 then 1 else if c < 0x800 then 2 else 3); i := i + 1; }
    }
  }

  // ---- numbers ----
  method ScanDigitsN(t: seq<U16>, ghost T: S, i: N) returns (j: N)
    requires T == W(t) && |t| <= MaxBytes && i as int <= |t|
    ensures j as int == ScanDigits(T, i as int) && i <= j && j as int <= |t|
  {
    j := i;
    var n := |t| as N;
    while j < n && 48 <= t[j] <= 57
      invariant i <= j <= n && ScanDigits(T, i as int) == ScanDigits(T, j as int)
      decreases n - j
    { j := j + 1; }
  }

  ghost function Pow10(k: nat): int { if k == 0 then 1 else 10 * Pow10(k - 1) }
  lemma Pow10At16() ensures Pow10(16) == 10000000000000000
  {
    assert Pow10(1) == 10; assert Pow10(2) == 100; assert Pow10(3) == 1000; assert Pow10(4) == 10000;
    assert Pow10(5) == 100000; assert Pow10(6) == 1000000; assert Pow10(7) == 10000000; assert Pow10(8) == 100000000;
    assert Pow10(9) == 1000000000; assert Pow10(10) == 10000000000; assert Pow10(11) == 100000000000;
    assert Pow10(12) == 1000000000000; assert Pow10(13) == 10000000000000; assert Pow10(14) == 100000000000000;
    assert Pow10(15) == 1000000000000000;
  }
  lemma Pow10Mono(a: nat, b: nat) requires a <= b ensures 1 <= Pow10(a) <= Pow10(b) decreases b { if b > a { Pow10Mono(a, b - 1); } }

  lemma ValSeqSnoc(d: S, q: int)
    requires 0 <= q < |d|
    ensures ValSeq(d[..q + 1]) == ValSeq(d[..q]) * 10 + (d[q] - 48)
  { assert d[..q + 1][..q] == d[..q]; }

  // ValSeq of a digit string with a non-zero lead digit is at least 10^(len-1)
  lemma ValSeqLow(d: S)
    requires |d| >= 1 && AllDig(d) && d[0] != 48
    ensures ValSeq(d) >= Pow10(|d| - 1)
    decreases |d|
  {
    if |d| > 1 {
      var p := d[..|d| - 1];
      assert p[0] == d[0] && AllDig(p);
      ValSeqLow(p);
    }
  }

  lemma ValSeqPrefixLe(d: S, q: int)
    requires 0 <= q <= |d| && AllDig(d)
    ensures 0 <= ValSeq(d[..q]) <= ValSeq(d)
    decreases |d| - q
  {
    ValSeqNonneg(d[..q]);
    if q < |d| {
      ValSeqPrefixLe(d, q + 1);
      ValSeqSnoc(d, q);
      assert AllDig(d[..q]);
      ValSeqNonneg(d[..q]);
    } else { assert d[..q] == d; }
  }

  lemma DigValSeq(d: S)
    requires |d| >= 1 && AllDig(d) && d[0] != 48
    ensures ValSeq(d) >= 1 && Dig(ValSeq(d)) == d
    decreases |d|
  {
    if |d| == 1 {
    } else {
      var p := d[..|d| - 1];
      assert p[0] == d[0] && AllDig(p);
      DigValSeq(p);
      var v := ValSeq(d);
      assert v == ValSeq(p) * 10 + (d[|d| - 1] - 48);
      assert v >= 10;
      assert v / 10 == ValSeq(p) && v % 10 == d[|d| - 1] - 48;
      assert d == p + [d[|d| - 1]];
    }
  }

  // LeadZeros by a forward count
  lemma LeadZerosStep(f: seq<int>, z: int)
    requires 0 <= z < |f| && f[z] == 0
    ensures LeadZeros(f[z..]) == 1 + LeadZeros(f[z + 1..])
  { assert f[z..][1..] == f[z + 1..]; }

  lemma Pow10Lits() ensures Pow10(15) == 1000000000000000 && Pow10(16) == 10000000000000000
  { Pow10At16(); assert Pow10(16) == 10 * Pow10(15); }

  // ParseNum unfolded once with its intermediate values named (NumM reasons through these, not the definition)
  lemma ParseNumNoInt(T: S, j: int, k: int)
    requires 0 <= j < |T| && k == (if T[j] == 45 then j + 1 else j) && IntEnd(T, k) < 0
    ensures ParseNum(T, j) == Fail
  {}
  lemma ParseNumAt(T: S, j: int, k: int, e: int, hasFrac: bool, L: int)
    requires 0 <= j < |T| && k == (if T[j] == 45 then j + 1 else j) && e == IntEnd(T, k) && e >= 0
    requires hasFrac == (e + 1 < |T| && T[e] == 46 && IsDig(T[e + 1]))
    requires L == (if hasFrac then ScanDigits(T, e + 1) else e)
    ensures ParseNum(T, j) ==
      if ExpMatches(T, L) then Fail
      else if hasFrac then
        (var ip := ValSeq(T[k..e]); var fr := FrOf(T, e + 1, L);
         if ValidDec(T[j] == 45, ip, fr) then Ok(Dec(T[j] == 45, ip, fr), L) else Fail)
      else
        (var n := ValSeq(T[k..e]);
         if (T[j] == 45 && n == 0) || n > MaxSafe then Fail else Ok(Int(if T[j] == 45 then -n else n), L))
  {}

  method {:isolate_assertions} {:fuel ParseNum, 0, 0} NumM(t: seq<U16>, ghost T: S, j: N) returns (ok: bool, p: N)
    requires T == W(t) && |t| <= MaxBytes && j as int < |t|
    ensures ok == ParseNum(T, j as int).Ok? && (ok ==> p as int == ParseNum(T, j as int).pos && j < p && p as int <= |t|)
  {
    var n := |t| as N;
    var neg := t[j] == 45;
    var k := if neg then j + 1 else j;
    // IntEnd
    var e: N;
    if k < n && t[k] == 48 { e := k + 1; }
    else if k < n && 49 <= t[k] <= 57 { e := ScanDigitsN(t, T, k + 1); }
    else { assert IntEnd(T, k as int) < 0; ParseNumNoInt(T, j as int, k as int); return false, 0; }
    assert e as int == IntEnd(T, k as int);
    IntEndDigits(T, k as int);
    ghost var D := T[k as int .. e as int];
    assert |D| == (e - k) as int && forall w :: 0 <= w < |D| ==> D[w] == T[k as int + w];
    var hasFrac := e + 1 < n && t[e] == 46 && 48 <= t[e + 1] <= 57;
    var L: N := e;
    if hasFrac { L := ScanDigitsN(t, T, e + 1); }
    var expm := L < n && (t[L] == 101 || t[L] == 69) &&
      (var m := if L + 1 < n && (t[L + 1] == 43 || t[L + 1] == 45) then L + 2 else L + 1; m < n && 48 <= t[m] <= 57);
    assert expm == ExpMatches(T, L as int);
    assert hasFrac == (e as int + 1 < |T| && T[e] == 46 && IsDig(T[e as int + 1]));
    ParseNumAt(T, j as int, k as int, e as int, hasFrac, L as int);
    if expm { return false, 0; }
    var lead0 := t[k] == 48;
    assert D[0] == T[k];
    if lead0 { assert D == [48]; assert ValSeq(D) == 0; } else { DigValSeq(D); }
    if hasFrac {
      ghost var fr := FrOf(T, e as int + 1, L as int);
      ScanAllDig(T, e as int + 1);
      assert L as int >= e as int + 2;
      assert |fr| == L as int - e as int - 1 >= 1;
      assert AllDig(T[e as int + 1 .. L as int]);
      forall q | 0 <= q < |fr| ensures 0 <= fr[q] <= 9 {
        FrOfAt(T, e as int + 1, L as int, q);
        assert T[e as int + 1 .. L as int][q] == T[e as int + 1 + q];
        assert IsDig(T[e as int + 1 .. L as int][q]);
      }
      assert Digits09(fr);
      var lastNz := t[L - 1] != 48;
      // the last fractional digit is T[L - 1] - 48, spelled out (FrOf index arithmetic + T == W(t))
      ghost var li := |fr| - 1;
      assert e as int + 1 + li == L as int - 1;
      assert fr[li] == T[e as int + 1 + li] - 48;
      assert T[L as int - 1] == t[L - 1] as int;
      assert lastNz == (fr[li] != 0);
      assert lastNz == (fr[|fr| - 1] != 0);
      if !lastNz { return false, 0; }
      if !lead0 {
        // ip > 0: Sig = |Dig(ip)| + |fr| = (e - k) + (L - e - 1)
        var sig := (e - k) + (L - e - 1);
        assert Sig(ValSeq(D), fr) == sig as int;
        if sig > 15 { return false, 0; }
        assert ValidDec(neg, ValSeq(D), fr);
        return true, L;
      } else {
        // ip == 0: count leading fractional zeros
        var z: N := 0;
        var fl := L - e - 1;
        while z < fl && t[e + 1 + z] == 48
          invariant z <= fl && LeadZeros(fr) == z as int + LeadZeros(fr[z..])
          invariant forall q :: 0 <= q < z as int ==> fr[q] == 0
          decreases fl - z
        { LeadZerosStep(fr, z as int); z := z + 1; }
        assert z < fl;   // the last digit is non-zero
        assert fl as int == L as int - (e as int + 1) == |fr|;
        assert 0 <= z as int < |fr|;
        FrOfAt(T, e as int + 1, L as int, z as int);
        assert T[e as int + 1 + z as int] == t[e + 1 + z] as int != 48;
        assert fr[z] != 0;
        assert fr[z..][0] == fr[z];
        assert LeadZeros(fr[z..]) == 0;
        var sig := fl - z;
        assert Sig(ValSeq(D), fr) == sig as int;
        var magOk := z < 6;
        assert magOk ==> MagOk(ValSeq(D), fr);
        assert MagOk(ValSeq(D), fr) ==> magOk by {
          if MagOk(ValSeq(D), fr) { var w :| 0 <= w < 6 && w < |fr| && fr[w] != 0; assert w >= z as int; }
        }
        if sig > 15 || !magOk { return false, 0; }
        assert ValidDec(neg, ValSeq(D), fr);
        return true, L;
      }
    } else {
      assert L == e;
      if lead0 {
        if neg { return false, 0; }
        return true, L;
      }
      // non-zero integer: compare with MaxSafe
      var c := e - k;
      if c >= 17 {
        ValSeqLow(D);
        Pow10Mono(16, |D| - 1);
        Pow10Lits();
        assert Pow10(16) == 10000000000000000;
        return false, 0;
      }
      // value of the first min(c, 15) digits, natively (< 10^15)
      var lim := if c < 15 then c else 15;
      var v: N := 0;
      var q: N := 0;
      while q < lim
        invariant q <= lim <= 15 && v as int == ValSeq(D[..q]) && v as int < Pow10(q as nat)
        decreases lim - q
      {
        ValSeqSnoc(D, q as int);
        Pow10Mono(q as nat, 14);
        assert Pow10(14) == 100000000000000;
        var dg := t[k + q] as N;
        assert D[q] == T[k as int + q as int] == t[k + q] as int;
        assert dg as int == D[q] && IsDig(D[q]);
        v := v * 10 + (dg - 48);
        q := q + 1;
      }
      if c <= 15 {
        assert D[..q] == D;
        Pow10Mono(q as nat, 15);
        Pow10Lits();
        assert Pow10(15) == 1000000000000000;
        return true, L;
      }
      // c == 16
      ValSeqSnoc(D, 15);
      assert D[..16] == D;
      assert c == 16 && |D| == 16 && k as int + 15 < |t|;
      var k15 := k + 15;
      var dl := t[k15] as N;
      assert T[k15 as int] == t[k15] as int;
      assert D[15] == T[k15 as int];
      assert dl as int == D[15] && IsDig(D[15]);
      var last := dl - 48;
      var big := v > 900719925474099 || (v == 900719925474099 && last > 1);
      assert big == (ValSeq(D) > MaxSafe);
      if big { return false, 0; }
      return true, L;
    }
  }

  // ---- strings ----
  newtype Hx = x: int | -1 <= x < 16
  newtype H4 = x: int | -1 <= x < 0x10000
  function HexDH(c: U16): Hx ensures HexDH(c) as int == HexD(c as int)
  { if 48 <= c <= 57 then (c - 48) as Hx else if 97 <= c <= 102 then (c - 87) as Hx else if 65 <= c <= 70 then (c - 55) as Hx else -1 }

  method Hex4N(t: seq<U16>, ghost T: S, i: N) returns (h: H4)
    requires T == W(t) && |t| <= MaxBytes && i as int <= |t|
    ensures h as int == Hex4(T, i as int)
  {
    if i + 4 > |t| as N { return -1; }
    var a := HexDH(t[i]); var b := HexDH(t[i + 1]); var c := HexDH(t[i + 2]); var d := HexDH(t[i + 3]);
    if a < 0 || b < 0 || c < 0 || d < 0 { return -1; }
    return ((a as H4 * 16 + b as H4) * 16 + c as H4) * 16 + d as H4;
  }

  // Decode the string body that starts at source index i (just after the opening quote) into ar[cur..c).
  method StrM(t: seq<U16>, ghost T: S, ar: array<U16>, i: N, cur: N) returns (ok: bool, p: N, c: N)
    requires T == W(t) && |t| <= MaxBytes && ar.Length == |t| && i as int <= |t| && cur <= i
    modifies ar
    ensures ar[..cur] == old(ar[..cur])
    ensures ok == StrBody(T, i as int, []).Ok?
    ensures ok ==> p as int == StrBody(T, i as int, []).pos && cur <= c <= p && p as int <= |t| && W(ar[cur..c]) == StrBody(T, i as int, []).v
  {
    var k := i;
    c := cur;
    ghost var acc: S := [];
    var n := |t| as N;
    while true
      invariant i <= k <= n && cur <= c <= k
      invariant ar[..cur] == old(ar[..cur])
      invariant W(ar[cur..c]) == acc
      invariant StrBody(T, i as int, []) == StrBody(T, k as int, acc)
      decreases n - k
    {
      if k >= n { return false, 0, 0; }
      var x := t[k];
      if x == 34 { return true, k + 1, c; }
      if x < 0x20 { return false, 0, 0; }
      var v: U16;
      var adv: N;
      if x == 92 {
        if k + 1 >= n { return false, 0, 0; }
        var e := t[k + 1];
        if e == 34 { v := 34; adv := 2; }
        else if e == 92 { v := 92; adv := 2; }
        else if e == 47 { v := 47; adv := 2; }
        else if e == 98 { v := 8; adv := 2; }
        else if e == 102 { v := 12; adv := 2; }
        else if e == 110 { v := 10; adv := 2; }
        else if e == 114 { v := 13; adv := 2; }
        else if e == 116 { v := 9; adv := 2; }
        else if e == 117 {
          var h := Hex4N(t, T, k + 2);
          if h < 0 { return false, 0, 0; }
          v := h as U16; adv := 6;
          assert Hex4(T, k as int + 2) >= 0 ==> k as int + 6 <= |t|;
        } else { return false, 0, 0; }
      } else { v := x; adv := 1; }
      ghost var before := ar[cur..c];
      ar[c] := v;
      assert ar[cur..c + 1] == before + [v];
      WSnoc(before, v);
      acc := acc + [v as int];
      c := c + 1;
      k := k + adv;
    }
  }

  // Valid16 of the decoded units ar[a..b)
  method V16M(ar: array<U16>, a: N, b: N) returns (r: bool)
    requires a <= b && b as int <= ar.Length <= MaxBytes
    ensures r == Valid16(W(ar[a..b]))
  {
    ghost var s := W(ar[a..b]);
    var k := a;
    while k < b
      invariant a <= k <= b && Valid16(s) == Valid16From(s, (k - a) as int)
      decreases b - k
    {
      var x := ar[k];
      if 0xD800 <= x <= 0xDBFF {
        if k + 1 < b && 0xDC00 <= ar[k + 1] <= 0xDFFF { k := k + 2; } else { return false; }
      } else if 0xDC00 <= x <= 0xDFFF { return false; }
      else { k := k + 1; }
    }
    return true;
  }

  // ---- the per-document key table (object id, key) ----
  const P: N := 67108859   // prime < 2^26
  datatype Ent = Ent(oid: N, off: N, len: N)

  lemma MulNonneg(x: int, y: int) requires x >= 0 && y >= 0 ensures x * y >= 0 {}
  lemma MulBound(h: N, r: N) requires h < P && r < P ensures (h as int) * (r as int) <= 4503598822064164
  {
    var H := h as int; var R := r as int;
    assert H <= 67108858 && R <= 67108858;
    MulNonneg(H, 67108858 - R);
    assert H * (67108858 - R) == H * 67108858 - H * R;
    MulNonneg(67108858 - H, 67108858);
    assert (67108858 - H) * 67108858 == 4503598822064164 - H * 67108858;
  }
  function HStep(h: N, u: U16, r: N): N requires h < P && r < P ensures HStep(h, u, r) < P
  {
    assert 0 <= (h as int) * (r as int) <= 4503598822064164 by { MulBound(h, r); MulNonneg(h as int, r as int); }
    var hr: N := h * r;
    (hr + u as N + 1) % P
  }
  ghost function HSeq(x: seq<U16>, h: N, r: N): N requires h < P && r < P ensures HSeq(x, h, r) < P decreases |x|
  { if |x| == 0 then h else HSeq(x[1..], HStep(h, x[0], r), r) }
  ghost function Bk(oid: N, x: seq<U16>, r: N, m: N): N requires r < P && m > 0 { HSeq(x, oid % P, r) % m }

  ghost function KeyOf(A: seq<U16>, e: Ent): seq<U16> requires e.off as int + e.len as int <= |A| { A[e.off as int .. e.off as int + e.len as int] }

  ghost predicate TblOk(tb: seq<seq<Ent>>, A: seq<U16>, nid: N, r: N)
  {
    r < P && 0 < |tb| < 0x20_0000_0000_0000 &&
    (forall b :: 0 <= b < |tb| ==> |tb[b]| <= nid as int) &&
    forall b, q :: 0 <= b < |tb| && 0 <= q < |tb[b]| ==>
      tb[b][q].off as int + tb[b][q].len as int <= |A| && tb[b][q].oid < nid &&
      Bk(tb[b][q].oid, KeyOf(A, tb[b][q]), r, |tb| as N) as int == b
  }

  lemma KeyOfPrefix(A: seq<U16>, B: seq<U16>, e: Ent)
    requires |A| <= |B| && B[..|A|] == A && e.off as int + e.len as int <= |A|
    ensures KeyOf(B, e) == KeyOf(A, e)
  {
    var a := e.off as int; var b := a + e.len as int;
    SlicePrefix(A, B, a, b);
  }
  lemma SlicePrefix<X>(A: seq<X>, B: seq<X>, a: int, b: int)
    requires |A| <= |B| && B[..|A|] == A && 0 <= a <= b <= |A|
    ensures B[a..b] == A[a..b]
  {
    forall q | 0 <= q < b - a ensures B[a..b][q] == A[a..b][q] { assert B[a + q] == B[..|A|][a + q]; }
  }

  lemma TblOkExtend(tb: seq<seq<Ent>>, A: seq<U16>, B: seq<U16>, nid: N, nid2: N, r: N)
    requires TblOk(tb, A, nid, r) && |A| <= |B| && B[..|A|] == A && nid <= nid2
    ensures TblOk(tb, B, nid2, r)
  {
    forall b, q | 0 <= b < |tb| && 0 <= q < |tb[b]| ensures Bk(tb[b][q].oid, KeyOf(B, tb[b][q]), r, |tb| as N) as int == b { KeyOfPrefix(A, B, tb[b][q]); }
  }

  method HashRange(ar: array<U16>, a: N, b: N, oid: N, r: N) returns (h: N)
    requires a <= b && b as int <= ar.Length <= MaxBytes && r < P
    ensures h == HSeq(ar[a..b], oid % P, r)
  {
    ghost var x := ar[a..b];
    h := oid % P;
    var k := a;
    while k < b
      invariant a <= k <= b && h < P && HSeq(x, oid % P, r) == HSeq(x[(k - a)..], h, r)
      decreases b - k
    {
      assert x[(k - a)..][1..] == x[(k - a) + 1..];
      h := HStep(h, ar[k], r);
      k := k + 1;
    }
  }

  // Is (oid, ar[a..a+len)) in the bucket?
  method Lookup(bucket: seq<Ent>, ar: array<U16>, oid: N, a: N, len: N, ghost A: seq<U16>) returns (found: bool)
    requires a as int + len as int <= ar.Length <= MaxBytes && |A| <= ar.Length && ar[..|A|] == A && |bucket| <= MaxBytes
    requires forall q :: 0 <= q < |bucket| ==> bucket[q].off as int + bucket[q].len as int <= |A|
    ensures found <==> exists q :: 0 <= q < |bucket| && bucket[q].oid == oid && KeyOf(A, bucket[q]) == ar[a .. a as int + len as int]
  {
    var q: N := 0;
    var nb := |bucket| as N;
    while q < nb
      invariant q <= nb && forall w :: 0 <= w < q as int ==> !(bucket[w].oid == oid && KeyOf(A, bucket[w]) == ar[a .. a as int + len as int])
      decreases nb - q
    {
      var e := bucket[q];
      assert KeyOf(A, e) == ar[e.off as int .. e.off as int + e.len as int] by { SlicePrefix(A, ar[..], e.off as int, e.off as int + e.len as int); }
      if e.oid == oid && e.len == len {
        var w: N := 0;
        while w < len && ar[e.off + w] == ar[a + w]
          invariant w <= len && ar[e.off .. e.off + w] == ar[a .. a + w]
          decreases len - w
        { w := w + 1; }
        if w == len { return true; }
        assert ar[e.off as int .. e.off as int + len as int][w] != ar[a as int .. a as int + len as int][w];
      }
      q := q + 1;
    }
    return false;
  }

  // ---- literals ----
  lemma StartsWithAt(t: S, j: int, lit: S, q: int) requires StartsWith(t, j, lit) && 0 <= q < |lit| ensures t[j + q] == lit[q]
  { assert t[j..j + |lit|][q] == t[j + q]; }
  lemma StartsWithIntro(t: S, j: int, lit: S)
    requires 0 <= j && j + |lit| <= |t| && forall q :: 0 <= q < |lit| ==> t[j + q] == lit[q]
    ensures StartsWith(t, j, lit)
  { assert t[j..j + |lit|] == lit; }
  // which literal starts at j: 1 true, 2 false, 3 null, 0 none
  method LitM(t: seq<U16>, ghost T: S, j: N) returns (w: N)
    requires T == W(t) && |t| <= MaxBytes && j as int < |t|
    ensures w <= 3
    ensures w == 1 <==> StartsWith(T, j as int, LitTrue)
    ensures w == 2 <==> (StartsWith(T, j as int, LitFalse) && !StartsWith(T, j as int, LitTrue))
    ensures w == 3 <==> (StartsWith(T, j as int, LitNull) && !StartsWith(T, j as int, LitTrue) && !StartsWith(T, j as int, LitFalse))
    ensures w == 0 <==> (!StartsWith(T, j as int, LitTrue) && !StartsWith(T, j as int, LitFalse) && !StartsWith(T, j as int, LitNull))
  {
    var n := |t| as N;
    var isT := j + 4 <= n && t[j] == 116 && t[j + 1] == 114 && t[j + 2] == 117 && t[j + 3] == 101;
    var isF := j + 5 <= n && t[j] == 102 && t[j + 1] == 97 && t[j + 2] == 108 && t[j + 3] == 115 && t[j + 4] == 101;
    var isN := j + 4 <= n && t[j] == 110 && t[j + 1] == 117 && t[j + 2] == 108 && t[j + 3] == 108;
    assert isT <==> StartsWith(T, j as int, LitTrue) by {
      if isT { StartsWithIntro(T, j as int, LitTrue); }
      if StartsWith(T, j as int, LitTrue) { StartsWithAt(T, j as int, LitTrue, 0); StartsWithAt(T, j as int, LitTrue, 1); StartsWithAt(T, j as int, LitTrue, 2); StartsWithAt(T, j as int, LitTrue, 3); }
    }
    assert isF <==> StartsWith(T, j as int, LitFalse) by {
      if isF { StartsWithIntro(T, j as int, LitFalse); }
      if StartsWith(T, j as int, LitFalse) { StartsWithAt(T, j as int, LitFalse, 0); StartsWithAt(T, j as int, LitFalse, 1); StartsWithAt(T, j as int, LitFalse, 2); StartsWithAt(T, j as int, LitFalse, 3); StartsWithAt(T, j as int, LitFalse, 4); }
    }
    assert isN <==> StartsWith(T, j as int, LitNull) by {
      if isN { StartsWithIntro(T, j as int, LitNull); }
      if StartsWith(T, j as int, LitNull) { StartsWithAt(T, j as int, LitNull, 0); StartsWithAt(T, j as int, LitNull, 1); StartsWithAt(T, j as int, LitNull, 2); StartsWithAt(T, j as int, LitNull, 3); }
    }
    w := if isT then 1 else if isF then 2 else if isN then 3 else 0;
  }

  // ---- values ----
  ghost predicate Ctx(t: seq<U16>, T: S, ar: array<U16>, tb: array<seq<Ent>>, r: N)
    reads ar, tb
  { T == W(t) && |t| <= MaxBytes && ar.Length == |t| && r < P && 0 < tb.Length < 0x20_0000_0000_0000 }

  ghost predicate Grown(o: seq<seq<Ent>>, n: seq<seq<Ent>>, nid: N)
  {
    |o| == |n| && forall b :: 0 <= b < |o| ==>
      (forall e :: e in o[b] ==> e in n[b]) && (forall e :: e in n[b] && e.oid < nid ==> e in o[b])
  }
  lemma GrownTrans(a: seq<seq<Ent>>, b: seq<seq<Ent>>, c: seq<seq<Ent>>, n1: N, n2: N)
    requires Grown(a, b, n1) && Grown(b, c, n2) && n1 <= n2 ensures Grown(a, c, n1) {}

  method ValueM(t: seq<U16>, ghost T: S, ar: array<U16>, tb: array<seq<Ent>>, r: N, i: N, d: N, cur: N, nid: N)
    returns (ok: bool, p: N, cur2: N, nid2: N)
    requires Ctx(t, T, ar, tb, r) && i as int <= |t| && cur <= i && nid <= i && 1 <= d <= 33
    requires TblOk(tb[..], ar[..cur], nid, r)
    modifies ar, tb
    ensures ok == ParseValue(T, i as int, d as int).Ok?
    ensures ok ==> p as int == ParseValue(T, i as int, d as int).pos && cur <= cur2 <= p && nid <= nid2 <= p && p as int <= |t|
    ensures ok ==> ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], nid)
    decreases |t| - i as int, 0
  {
    var n := |t| as N;
    var j := SkipWs(t, T, i);
    if j >= n { return false, 0, 0, 0; }
    var c := t[j];
    if c == 123 {
      if d > 32 { return false, 0, 0, 0; }
      ok, p, cur2, nid2 := ObjM(t, T, ar, tb, r, j + 1, d, cur, nid);
    } else if c == 91 {
      if d > 32 { return false, 0, 0, 0; }
      ok, p, cur2, nid2 := ArrM(t, T, ar, tb, r, j + 1, d, cur, nid);
    } else if c == 34 {
      var okS, pS, c2 := StrM(t, T, ar, j + 1, cur);
      StrBodyFEq(T, j as int + 1, []);
      if !okS { return false, 0, 0, 0; }
      var v16 := V16M(ar, cur, c2);
      if !v16 { return false, 0, 0, 0; }
      assert ar[..c2][..cur] == ar[..cur];
      TblOkExtend(tb[..], ar[..cur], ar[..c2], nid, nid, r);
      return true, pS, c2, nid;
    } else if c == 45 || (48 <= c <= 57) {
      var okN, pN := NumM(t, T, j);
      if !okN { return false, 0, 0, 0; }
      return true, pN, cur, nid;
    } else {
      var w := LitM(t, T, j);
      if w == 0 { return false, 0, 0, 0; }
      return true, if w == 2 then j + 5 else j + 4, cur, nid;
    }
  }

  method ArrM(t: seq<U16>, ghost T: S, ar: array<U16>, tb: array<seq<Ent>>, r: N, i: N, d: N, cur: N, nid: N)
    returns (ok: bool, p: N, cur2: N, nid2: N)
    requires Ctx(t, T, ar, tb, r) && i as int <= |t| && cur <= i && nid <= i && 1 <= d <= 32
    requires TblOk(tb[..], ar[..cur], nid, r)
    modifies ar, tb
    ensures ok == ArrStart(T, i as int, d as int).Ok?
    ensures ok ==> p as int == ArrStart(T, i as int, d as int).pos && cur <= cur2 <= p && nid <= nid2 <= p && p as int <= |t|
    ensures ok ==> ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], nid)
    decreases |t| - i as int, 2
  {
    var n := |t| as N;
    var j := SkipWs(t, T, i);
    if j < n && t[j] == 93 { return true, j + 1, cur, nid; }
    ghost var acc: seq<J> := [];
    var k := i;
    cur2 := cur; nid2 := nid;
    while true
      invariant i <= k <= n && cur <= cur2 <= k && nid <= nid2 <= k
      invariant ArrStart(T, i as int, d as int) == ArrLoop(T, k as int, d as int, acc)
      invariant ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], nid)
      decreases n - k
    {
      ghost var tb0 := tb[..];
      ghost var A0 := ar[..cur2];
      var okV, q, c3, n3 := ValueM(t, T, ar, tb, r, k, d + 1, cur2, nid2);
      if !okV { return false, 0, 0, 0; }
      assert ar[..cur2] == A0;
      assert ar[..cur] == A0[..cur];
      GrownTrans(old(tb[..]), tb0, tb[..], nid, nid2);
      acc := acc + [ParseValue(T, k as int, d as int + 1).v];
      cur2, nid2 := c3, n3;
      var j2 := SkipWs(t, T, q);
      if j2 >= n { return false, 0, 0, 0; }
      if t[j2] == 44 { k := j2 + 1; continue; }
      if t[j2] == 93 { return true, j2 + 1, cur2, nid2; }
      return false, 0, 0, 0;
    }
  }

  // ---- per-object key bookkeeping (the entries of object `oid` are exactly `ents`, one per key of `acc`) ----
  ghost predicate ObjInv(tb: seq<seq<Ent>>, A: seq<U16>, oid: N, ents: seq<Ent>, acc: seq<KV>, r: N)
  {
    r < P && 0 < |tb| < 0x20_0000_0000_0000 && |ents| == |acc| &&
    (forall w :: 0 <= w < |ents| ==> (ents[w].oid == oid && ents[w].off as int + ents[w].len as int <= |A| &&
       W(KeyOf(A, ents[w])) == acc[w].k && ents[w] in tb[Bk(oid, KeyOf(A, ents[w]), r, |tb| as N)])) &&
    (forall b, e :: 0 <= b < |tb| && e in tb[b] && e.oid == oid ==> e in ents)
  }

  lemma DupCheck(tb: seq<seq<Ent>>, A: seq<U16>, oid: N, ents: seq<Ent>, acc: seq<KV>, r: N, nid: N, key: seq<U16>, b: N)
    requires ObjInv(tb, A, oid, ents, acc, r) && TblOk(tb, A, nid, r) && b == Bk(oid, key, r, |tb| as N)
    ensures (exists q :: 0 <= q < |tb[b]| && tb[b][q].oid == oid && KeyOf(A, tb[b][q]) == key) <==> HasKey(acc, W(key))
  {
    if exists q :: 0 <= q < |tb[b]| && tb[b][q].oid == oid && KeyOf(A, tb[b][q]) == key {
      var q :| 0 <= q < |tb[b]| && tb[b][q].oid == oid && KeyOf(A, tb[b][q]) == key;
      var e := tb[b][q];
      assert e in tb[b];
      assert e in ents;
      var w :| 0 <= w < |ents| && ents[w] == e;
      assert acc[w].k == W(key);
    }
    if HasKey(acc, W(key)) {
      var w :| 0 <= w < |acc| && acc[w].k == W(key);
      WInj(KeyOf(A, ents[w]), key);
      var e := ents[w];
      assert e in tb[b];
      var q :| 0 <= q < |tb[b]| && tb[b][q] == e;
      assert tb[b][q].oid == oid && KeyOf(A, tb[b][q]) == key;
    }
  }

  lemma InsertKey(tb: seq<seq<Ent>>, A0: seq<U16>, A1: seq<U16>, oid: N, ents: seq<Ent>, acc: seq<KV>, r: N, nid: N, key: seq<U16>, b: N, v: J, tb2: seq<seq<Ent>>)
    requires ObjInv(tb, A0, oid, ents, acc, r) && TblOk(tb, A0, nid, r) && oid < nid
    requires |A0| <= |A1| && A1[..|A0|] == A0 && key == A1[|A0|..] && b == Bk(oid, key, r, |tb| as N)
    requires !HasKey(acc, W(key)) && |A1| < 0x20_0000_0000_0000 && nid as int + 1 < 0x20_0000_0000_0000
    requires tb2 == tb[b := tb[b] + [Ent(oid, |A0| as N, |key| as N)]]
    ensures ObjInv(tb2, A1, oid, ents + [Ent(oid, |A0| as N, |key| as N)], acc + [KV(W(key), v)], r)
    ensures TblOk(tb2, A1, nid + 1, r) && Grown(tb, tb2, oid)
  {
    var ne := Ent(oid, |A0| as N, |key| as N);
    assert KeyOf(A1, ne) == key;
    TblOkExtend(tb, A0, A1, nid, nid, r);
    forall w | 0 <= w < |ents| ensures KeyOf(A1, ents[w]) == KeyOf(A0, ents[w]) { KeyOfPrefix(A0, A1, ents[w]); }
    var ents2 := ents + [ne];
    var acc2 := acc + [KV(W(key), v)];
    forall w | 0 <= w < |ents2|
      ensures ents2[w].oid == oid && ents2[w].off as int + ents2[w].len as int <= |A1| && W(KeyOf(A1, ents2[w])) == acc2[w].k && ents2[w] in tb2[Bk(oid, KeyOf(A1, ents2[w]), r, |tb2| as N)]
    {
      if w < |ents| { assert ents2[w] == ents[w]; assert ents[w] in tb[Bk(oid, KeyOf(A0, ents[w]), r, |tb| as N)]; }
    }
    forall bb, e | 0 <= bb < |tb2| && e in tb2[bb] && e.oid == oid ensures e in ents2 {
      if bb != b as int || e in tb[bb] { assert e in tb[bb]; } else { assert e == ne; }
    }
    forall bb, q | 0 <= bb < |tb2| && 0 <= q < |tb2[bb]|
      ensures tb2[bb][q].off as int + tb2[bb][q].len as int <= |A1| && tb2[bb][q].oid < nid + 1 && Bk(tb2[bb][q].oid, KeyOf(A1, tb2[bb][q]), r, |tb2| as N) as int == bb
    {
      if bb != b as int || q < |tb[b]| { assert tb2[bb][q] == tb[bb][q]; }
    }
  }

  lemma AfterNested(tb1: seq<seq<Ent>>, tb2: seq<seq<Ent>>, A2: seq<U16>, A3: seq<U16>, oid: N, ents: seq<Ent>, acc: seq<KV>, r: N, nid: N, v: J)
    requires ObjInv(tb1, A2, oid, ents, acc, r) && Grown(tb1, tb2, nid) && oid < nid
    requires |A2| <= |A3| && A3[..|A2|] == A2
    ensures ObjInv(tb2, A3, oid, ents, acc, r)
  {
    forall w | 0 <= w < |ents| ensures KeyOf(A3, ents[w]) == KeyOf(A2, ents[w]) { KeyOfPrefix(A2, A3, ents[w]); }
    forall bb, e | 0 <= bb < |tb2| && e in tb2[bb] && e.oid == oid ensures e in ents { assert e in tb1[bb]; }
  }

  // what ObjLoop does after a member's value ends at q
  ghost function ObjTail(T: S, q: int, d: int, acc: seq<KV>): R<J>
    requires 0 <= q
    decreases |T| - q, 0
  {
    var j3 := Ws(T, q);
    if j3 >= |T| then Fail
    else if T[j3] == 44 then ObjLoop(T, j3 + 1, d, acc)
    else if T[j3] == 125 then Ok(Obj(acc), j3 + 1)
    else Fail
  }

  // one object member: key, ':', value (the body of ObjLoop up to the separator)
  method {:isolate_assertions} MemberM(t: seq<U16>, ghost T: S, ar: array<U16>, tb: array<seq<Ent>>, r: N, k: N, d: N, cur: N, nid: N, oid: N,
                    ghost acc: seq<KV>, ghost ents: seq<Ent>)
    returns (ok: bool, q: N, cur2: N, nid2: N, ghost acc2: seq<KV>, ghost ents2: seq<Ent>)
    requires Ctx(t, T, ar, tb, r) && k as int <= |t| && cur <= k && oid < nid <= k && 1 <= d <= 32
    requires TblOk(tb[..], ar[..cur], nid, r) && ObjInv(tb[..], ar[..cur], oid, ents, acc, r)
    modifies ar, tb
    ensures !ok ==> ObjLoop(T, k as int, d as int, acc).Fail?
    ensures ok ==> k < q && q as int <= |t| && ObjLoop(T, k as int, d as int, acc) == ObjTail(T, q as int, d as int, acc2)
    ensures ok ==> cur <= cur2 <= q && nid < nid2 <= q
    ensures ok ==> ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], oid)
    ensures ok ==> ObjInv(tb[..], ar[..cur2], oid, ents2, acc2, r)
    decreases |t| - k as int, 1
  {
    var n := |t| as N;
    var m := tb.Length as N;
    var j := SkipWs(t, T, k);
    if j >= n || t[j] != 34 { return false, 0, 0, 0, [], []; }
    ghost var A0 := ar[..cur];
    ghost var tb0 := tb[..];
    var okS, pS, c2 := StrM(t, T, ar, j + 1, cur);
    StrBodyFEq(T, j as int + 1, []);
    if !okS { return false, 0, 0, 0, [], []; }
    var v16 := V16M(ar, cur, c2);
    if !v16 { return false, 0, 0, 0, [], []; }
    ghost var key := ar[cur..c2];
    assert ParseStr(T, j as int) == Ok(W(key), pS as int);
    ghost var A1 := ar[..c2];
    assert A1[..cur] == A0 && key == A1[cur..];
    var h := HashRange(ar, cur, c2, oid, r);
    var b := h % m;
    DupCheck(tb0, A0, oid, ents, acc, r, nid, key, b);
    var dup := Lookup(tb[b], ar, oid, cur, c2 - cur, A0);
    if dup { return false, 0, 0, 0, [], []; }
    var j2 := SkipWs(t, T, pS);
    if j2 >= n || t[j2] != 58 { return false, 0, 0, 0, [], []; }
    ghost var pv := ParseValue(T, j2 as int + 1, d as int + 1);
    ghost var vv := if pv.Ok? then pv.v else Null;
    tb[b] := tb[b] + [Ent(oid, cur, c2 - cur)];
    InsertKey(tb0, A0, A1, oid, ents, acc, r, nid, key, b, vv, tb[..]);
    ents2 := ents + [Ent(oid, cur, c2 - cur)];
    acc2 := acc + [KV(W(key), vv)];
    ghost var tb1 := tb[..];
    ghost var A2 := ar[..c2];
    var okV, q0, c3, n3 := ValueM(t, T, ar, tb, r, j2 + 1, d + 1, c2, nid + 1);
    if !okV { return false, 0, 0, 0, [], []; }
    assert ar[..c2] == A2;
    assert ar[..c3][..c2] == A2;
    AfterNested(tb1, tb[..], A2, ar[..c3], oid, ents2, acc2, r, nid + 1, vv);
    GrownTrans(tb0, tb1, tb[..], oid, nid + 1);
    assert ar[..cur] == A2[..cur];
    return true, q0, c3, n3, acc2, ents2;
  }

  method {:isolate_assertions} ObjM(t: seq<U16>, ghost T: S, ar: array<U16>, tb: array<seq<Ent>>, r: N, i: N, d: N, cur: N, nid: N)
    returns (ok: bool, p: N, cur2: N, nid2: N)
    requires Ctx(t, T, ar, tb, r) && i as int <= |t| && cur <= i && nid < i && 1 <= d <= 32
    requires TblOk(tb[..], ar[..cur], nid, r)
    modifies ar, tb
    ensures ok == ObjStart(T, i as int, d as int).Ok?
    ensures ok ==> p as int == ObjStart(T, i as int, d as int).pos && cur <= cur2 <= p && nid <= nid2 <= p && p as int <= |t|
    ensures ok ==> ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], nid)
    decreases |t| - i as int, 2
  {
    var n := |t| as N;
    var j0 := SkipWs(t, T, i);
    if j0 < n && t[j0] == 125 { return true, j0 + 1, cur, nid; }
    var oid := nid;
    ghost var acc: seq<KV> := [];
    ghost var ents: seq<Ent> := [];
    var k := i;
    cur2 := cur; nid2 := nid + 1;
    TblOkExtend(tb[..], ar[..cur], ar[..cur], nid, nid2, r);
    while true
      invariant i <= k <= n && cur <= cur2 <= k && oid < nid2 <= k
      invariant ObjStart(T, i as int, d as int) == ObjLoop(T, k as int, d as int, acc)
      invariant ar[..cur] == old(ar[..cur]) && TblOk(tb[..], ar[..cur2], nid2, r) && Grown(old(tb[..]), tb[..], oid)
      invariant ObjInv(tb[..], ar[..cur2], oid, ents, acc, r)
      decreases n - k
    {
      ghost var tbB := tb[..];
      ghost var AB := ar[..cur2];
      var okM, q, c3, n3, acc2, ents2 := MemberM(t, T, ar, tb, r, k, d, cur2, nid2, oid, acc, ents);
      if !okM { return false, 0, 0, 0; }
      GrownTrans(old(tb[..]), tbB, tb[..], oid, oid);
      assert ar[..cur] == AB[..cur];
      acc, ents := acc2, ents2;
      cur2, nid2 := c3, n3;
      var j3 := SkipWs(t, T, q);
      if j3 >= n { return false, 0, 0, 0; }
      if t[j3] == 44 { k := j3 + 1; continue; }
      if t[j3] == 125 { return true, j3 + 1, cur2, nid2; }
      return false, 0, 0, 0;
    }
  }

  // ---- strictParse acceptance, proved equal to the specification ----
  function AcceptsU(t: seq<U16>, seed: N): bool { ParseTop(W(t)).Some? } by method {
    if |t| > MaxBytes { Utf8LenGe(W(t), 0, 0); return false; }
    var u8 := Utf8LenN(t, W(t));
    if u8 > MaxBytes as N { return false; }
    var n := |t| as N;
    var ar := new U16[n];
    var m: N := n / 8 + 16;
    var tb := new seq<Ent>[m];
    var empty: seq<Ent> := [];
    var b: N := 0;
    while b < m
      invariant b <= m && forall q :: 0 <= q < b as int ==> tb[q] == []
      decreases m - b
    { tb[b] := empty; b := b + 1; }
    var ok, p, c, nid := ValueM(t, W(t), ar, tb, seed % P, 0, 1, 0, 0);
    if !ok { return false; }
    var q := SkipWs(t, W(t), p);
    return q == n;
  }
}

// =====================================================================================================================
// canonicalizeStrict fast path: CanonU == Json.CanonText on the imported value (see the comment on module Fast)
// =====================================================================================================================
module FastP {
  import opened Utf
  import opened Json
  import opened Fast

  newtype I = x: int | -0x1F_FFFF_FFFF_FFFF <= x <= 0x1F_FFFF_FFFF_FFFF

  // An imported JS value with native strings. UBig carries an integer outside the native range (never profile-valid);
  // UDec is a non-integer number as its plain decimal spelling (integer part, fractional digits).
  datatype JU = UNull | UBool(b: bool) | UInt(n: I) | UBig(bn: int) | UDec(neg: bool, ip: N, fr: seq<U16>) | UStr(s: seq<U16>)
              | UArr(a: seq<JU>) | UObj(kv: seq<KU>)
  datatype KU = KU(k: seq<U16>, v: JU)

  ghost function ToJ(u: JU): J decreases u
  {
    match u
    case UNull => Null
    case UBool(b) => Bool(b)
    case UInt(n) => Int(n as int)
    case UBig(n) => Int(n)
    case UDec(neg, ip, fr) => Dec(neg, ip as int, W(fr))
    case UStr(s) => Str(W(s))
    case UArr(a) => Arr(seq(|a|, i requires 0 <= i < |a| => ToJ(a[i])))
    case UObj(kv) => Obj(seq(|kv|, i requires 0 <= i < |kv| => KV(W(kv[i].k), ToJ(kv[i].v))))
  }

  datatype St = Done | Bad | Exh   // Done: printed; Bad: outside the profile; Exh: past the 2^40-unit output limit (no verdict)

  const LIMIT: N := 0x100_0000_0000

  // ---- the output buffer ----
  method Room(buf: array<U16>, n: N, k: N) returns (ok: bool, b2: array<U16>)
    requires n as int <= buf.Length <= LIMIT as int && k <= 64
    ensures n as int <= b2.Length <= LIMIT as int && b2[..n] == buf[..n] && (b2 == buf || fresh(b2))
    ensures ok ==> n as int + k as int <= b2.Length
  {
    var len := buf.Length as N;
    if n + k <= len { return true, buf; }
    if n + k > LIMIT { return false, buf; }
    var cap := 2 * len + k + 16;
    if cap > LIMIT { cap := LIMIT; }
    b2 := new U16[cap];
    var i: N := 0;
    while i < n
      invariant i <= n && b2[..i] == buf[..i]
      decreases n - i
    { b2[i] := buf[i]; i := i + 1; }
    return true, b2;
  }

  // Append a short literal.
  method PutSeq(buf: array<U16>, n: N, x: seq<U16>) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int && |x| <= 64
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> b2[..n2] == old(buf[..n]) + x
  {
    ok, b2 := Room(buf, n, |x| as N);
    n2 := n;
    if !ok { return; }
    var i: N := 0;
    while i < |x| as N
      invariant i as int <= |x| && n2 == n + i && n2 as int <= b2.Length && b2[..n2] == old(buf[..n]) + x[..i]
      decreases |x| - i as int
    {
      b2[n2] := x[i];
      assert x[..i + 1] == x[..i] + [x[i]];
      n2 := n2 + 1;
      i := i + 1;
    }
    assert x[..i] == x;
  }

  // Append one / two units (no literal sequence allocated at run time).
  method Put1(buf: array<U16>, n: N, x: U16) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> b2[..n2] == old(buf[..n]) + [x]
  {
    ok, b2 := Room(buf, n, 1);
    n2 := n;
    if !ok { return; }
    b2[n] := x;
    n2 := n + 1;
  }
  method Put2(buf: array<U16>, n: N, x: U16, y: U16) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> b2[..n2] == old(buf[..n]) + [x, y]
  {
    ok, b2 := Room(buf, n, 2);
    n2 := n;
    if !ok { return; }
    b2[n] := x;
    b2[n + 1] := y;
    n2 := n + 2;
  }

  lemma WCat(a: seq<U16>, b: seq<U16>) ensures W(a + b) == W(a) + W(b) {}

  // ---- digits ----
  method DigM(v: N, buf: array<U16>, n: N) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> W(b2[..n2]) == W(old(buf[..n])) + Dig(v as int)
  {
    DigLenLe16(v);
    ok, b2 := Room(buf, n, DigLen(v));
    n2 := n;
    if !ok { return; }
    n2 := DigW(v, b2, n);
  }

  // the digits of v written in place (room already made)
  method DigW(v: N, b: array<U16>, n: N) returns (n2: N)
    requires n as int + DigLen(v) as int <= b.Length <= LIMIT as int
    modifies b
    ensures n2 as int == n as int + DigLen(v) as int && b[..n] == old(b[..n]) && W(b[..n2]) == W(old(b[..n])) + Dig(v as int)
    decreases v
  {
    var m := n;
    if v >= 10 { m := DigW(v / 10, b, n); }
    ghost var before := b[..m];
    var x := (48 + v % 10) as U16;
    b[m] := x;
    assert b[..m + 1] == before + [x];
    WCat(before, [x]);
    assert b[..n] == before[..n];
    return m + 1;
  }

  lemma DigLenLe(v: N, k: nat) requires 1 <= k && v as int < Pow10(k) ensures DigLen(v) as int <= k decreases k
  {
    if v >= 10 {
      if k == 1 { assert Pow10(1) == 10; }
      DigLenLe(v / 10, k - 1);
    }
  }
  lemma DigLenLe16(v: N) ensures DigLen(v) <= 16
  { Pow10At16(); DigLenLe(v, 16); }

  function DigLen(v: N): N ensures DigLen(v) as int == |Dig(v as int)| && 1 <= DigLen(v) as int <= v as int + 1 decreases v
  { if v < 10 then 1 else DigLen(v / 10) + 1 }

  // ---- strings ----
  method V16S(s: seq<U16>) returns (r: bool)
    requires |s| < 0x20_0000_0000_0000
    ensures r == Valid16(W(s))
  {
    ghost var S0 := W(s);
    var k: N := 0;
    var n := |s| as N;
    while k < n
      invariant k <= n && Valid16(S0) == Valid16From(S0, k as int)
      decreases n - k
    {
      var x := s[k];
      if 0xD800 <= x <= 0xDBFF {
        if k + 1 < n && 0xDC00 <= s[k + 1] <= 0xDFFF { k := k + 2; } else { return false; }
      } else if 0xDC00 <= x <= 0xDFFF { return false; }
      else { k := k + 1; }
    }
    return true;
  }

  lemma PrintBodySnoc(a: S, x: int) ensures PrintBody(a + [x]) == PrintBody(a) + PrintU(x) decreases |a|
  {
    if |a| == 0 { assert [x][1..] == []; }
    else { assert (a + [x])[1..] == a[1..] + [x]; PrintBodySnoc(a[1..], x); assert PrintBody(a) == PrintU(a[0]) + PrintBody(a[1..]); }
  }

  function HexLU(v: U16): U16 requires v < 16 { if v < 10 then 48 + v else 97 + (v - 10) }

  // the quoted, escaped string body (no quotes)
  method {:isolate_assertions} BodyM(s: seq<U16>, buf: array<U16>, n: N) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int && |s| < 0x20_0000_0000_0000
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> W(b2[..n2]) == W(old(buf[..n])) + PrintBody(W(s))
  {
    b2, n2 := buf, n;
    ghost var out0 := W(old(buf[..n]));
    var q: N := 0;
    var len := |s| as N;
    while q < len
      invariant q <= len && n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
      invariant W(b2[..n2]) == out0 + PrintBody(W(s[..q]))
      decreases len - q
    {
      var x := s[q];
      var r: bool;
      ghost var before := b2[..n2];
      if (b2.Length as N) - n2 < 6 {
        r, b2 := Room(b2, n2, 6);
        if !r { return false, b2, n2; }
      }
      // every branch writes e at [n0, n0 + |e|) and closes the slice equality on its own path (one 8-way VC was flaky)
      ghost var n0 := n2;
      assert b2[..n0] == before;
      ghost var e: seq<U16>;
      if x == 34 { b2[n2] := 92; b2[n2 + 1] := 34; n2 := n2 + 2; e := [92, 34]; assert b2[..n2] == before + e; }
      else if x == 92 { b2[n2] := 92; b2[n2 + 1] := 92; n2 := n2 + 2; e := [92, 92]; assert b2[..n2] == before + e; }
      else if x == 8 { b2[n2] := 92; b2[n2 + 1] := 98; n2 := n2 + 2; e := [92, 98]; assert b2[..n2] == before + e; }
      else if x == 12 { b2[n2] := 92; b2[n2 + 1] := 102; n2 := n2 + 2; e := [92, 102]; assert b2[..n2] == before + e; }
      else if x == 10 { b2[n2] := 92; b2[n2 + 1] := 110; n2 := n2 + 2; e := [92, 110]; assert b2[..n2] == before + e; }
      else if x == 13 { b2[n2] := 92; b2[n2 + 1] := 114; n2 := n2 + 2; e := [92, 114]; assert b2[..n2] == before + e; }
      else if x == 9 { b2[n2] := 92; b2[n2 + 1] := 116; n2 := n2 + 2; e := [92, 116]; assert b2[..n2] == before + e; }
      else if x < 0x20 {
        var h := HexLU(x / 16); var l := HexLU(x % 16);
        b2[n2] := 92; b2[n2 + 1] := 117; b2[n2 + 2] := 48; b2[n2 + 3] := 48; b2[n2 + 4] := h; b2[n2 + 5] := l;
        n2 := n2 + 6; e := [92, 117, 48, 48, h, l];
        assert b2[..n0] == before;
        assert b2[n0..n2] == e;
        assert b2[..n2] == b2[..n0] + b2[n0..n2];
        assert b2[..n2] == before + e;
        assert W(e) == PrintU(x as int) by { assert (x as int) / 16 == (x / 16) as int && (x as int) % 16 == (x % 16) as int; }
      } else { b2[n2] := x; n2 := n2 + 1; e := [x]; assert b2[..n2] == before + e; }
      assert b2[..n2] == before + e;
      assert W(e) == PrintU(x as int);
      WCat(before, e);
      assert s[..q + 1] == s[..q] + [x];
      WSnoc(s[..q], x);
      PrintBodySnoc(W(s[..q]), x as int);
      q := q + 1;
    }
    assert s[..q] == s;
    return true, b2, n2;
  }

  // ---- the canonical printer ----
  lemma PrintElemsSnoc(a: seq<J>, y: J)
    ensures PrintElems(a + [y]) == (if |a| == 0 then Print(y) else PrintElems(a) + [44] + Print(y))
    decreases |a|
  {
    if |a| == 0 { assert a + [y] == [y]; }
    else if |a| == 1 { assert (a + [y])[1..] == [y]; }
    else { assert (a + [y])[1..] == a[1..] + [y]; PrintElemsSnoc(a[1..], y); }
  }
  ghost function Mem(kv: KV): S { [34] + PrintBody(kv.k) + [34, 58] + Print(kv.v) }
  lemma PrintMembersSnoc(a: seq<KV>, y: KV)
    ensures PrintMembers(a + [y]) == (if |a| == 0 then Mem(y) else PrintMembers(a) + [44] + Mem(y))
    decreases |a|
  {
    if |a| == 0 { assert a + [y] == [y]; }
    else if |a| == 1 { assert (a + [y])[1..] == [y]; }
    else { assert (a + [y])[1..] == a[1..] + [y]; PrintMembersSnoc(a[1..], y); }
  }

  method PrintM(u: JU, d: N, buf: array<U16>, n: N) returns (st: St, b2: array<U16>, n2: N)
    requires 1 <= d <= 33 && n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures st.Done? ==> Valid(ToJ(u), d as int) && W(b2[..n2]) == W(old(buf[..n])) + Print(NormJ(ToJ(u)))
    ensures st.Bad? ==> !Valid(ToJ(u), d as int)
    decreases u, 1
  {
    ghost var out0 := W(old(buf[..n]));
    var ok: bool;
    match u {
      case UNull =>
        ok, b2, n2 := PutSeq(buf, n, [110, 117, 108, 108]);
        if ok { WCat(old(buf[..n]), [110, 117, 108, 108]); }
      case UBool(bv) =>
        if bv { ok, b2, n2 := PutSeq(buf, n, [116, 114, 117, 101]); if ok { WCat(old(buf[..n]), [116, 114, 117, 101]); } }
        else { ok, b2, n2 := PutSeq(buf, n, [102, 97, 108, 115, 101]); if ok { WCat(old(buf[..n]), [102, 97, 108, 115, 101]); } }
      case UInt(iv) =>
        ok, b2, n2 := IntM(iv, buf, n);
      case UBig(bv) =>
        if !(-MaxSafe <= bv <= MaxSafe) { return Bad, buf, n; }
        ok, b2, n2 := IntM(bv as I, buf, n);
      case UDec(neg, ip, fr) =>
        st, b2, n2 := DecM(neg, ip, fr, buf, n);
        return;
      case UStr(s) =>
        if |s| >= LIMIT as int { return Exh, buf, n; }
        var v16 := V16S(s);
        if !v16 { return Bad, buf, n; }
        ok, b2, n2 := Put1(buf, n, 34);
        if !ok { return Exh, b2, n2; }
        WCat(old(buf[..n]), [34]);
        ok, b2, n2 := BodyM(s, b2, n2);
        if !ok { return Exh, b2, n2; }
        ghost var mid := b2[..n2];
        ok, b2, n2 := Put1(b2, n2, 34);
        if ok { WCat(mid, [34]); }
      case UArr(a) =>
        st, b2, n2 := ArrPM(u, d, buf, n);
        return;
      case UObj(kv) =>
        st, b2, n2 := ObjPM(u, d, buf, n);
        return;
    }
    st := if ok then Done else Exh;
  }

  method IntM(iv: I, buf: array<U16>, n: N) returns (ok: bool, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures ok ==> W(b2[..n2]) == W(old(buf[..n])) + Print(Int(iv as int))
  {
    var a: N := if iv < 0 then (-iv) as N else iv as N;
    DigLenLe16(a);
    b2, n2 := buf, n;
    ok := true;
    if (buf.Length as N) - n < 17 {
      ok, b2 := Room(buf, n, 17);
      if !ok { return; }
    }
    ghost var B0 := b2[..n];
    assert B0 == old(buf[..n]);
    var m := n;
    if iv < 0 {
      b2[n] := 45;
      m := n + 1;
      assert b2[..m] == B0 + [45];
      WCat(B0, [45]);
    } else {
      assert b2[..m] == B0;
    }
    ghost var B1 := b2[..m];
    n2 := DigW(a, b2, m);
    assert W(b2[..n2]) == W(B1) + Dig(a as int);
  }

  method {:isolate_assertions} DecM(neg: bool, ip: N, fr: seq<U16>, buf: array<U16>, n: N) returns (st: St, b2: array<U16>, n2: N)
    requires n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures st.Done? ==> ValidDec(neg, ip as int, W(fr)) && W(b2[..n2]) == W(old(buf[..n])) + Print(Dec(neg, ip as int, W(fr)))
    ensures st.Bad? ==> !ValidDec(neg, ip as int, W(fr))
  {
    ghost var F := W(fr);
    if |fr| >= LIMIT as int { return Exh, buf, n; }
    var fl := |fr| as N;
    if fl == 0 { return Bad, buf, n; }
    // all fractional digits 0..9
    var q: N := 0;
    while q < fl && fr[q] <= 9
      modifies {}
      invariant q <= fl && forall w :: 0 <= w < q as int ==> 0 <= F[w] <= 9
      decreases fl - q
    { q := q + 1; }
    if q < fl { assert !Digits09(F) by { assert !(0 <= F[q] <= 9); } return Bad, buf, n; }
    assert Digits09(F);
    if fr[fl - 1] == 0 { return Bad, buf, n; }
    // significant digits and magnitude
    var sig: N;
    var magOk: bool;
    if ip > 0 {
      DigLenLe16(ip);
      sig := DigLen(ip) + fl;
      magOk := true;
    } else {
      var z: N := 0;
      while z < fl && fr[z] == 0
        modifies {}
        invariant z <= fl && LeadZeros(F) == z as int + LeadZeros(F[z..])
        invariant forall w :: 0 <= w < z as int ==> F[w] == 0
        decreases fl - z
      { LeadZerosStep(F, z as int); z := z + 1; }
      // z == fl would make the last digit 0, which was refused above
      assert F[fl as int - 1] == fr[fl - 1] as int != 0;
      if z == fl { assert F[fl as int - 1] == 0; }
      assert z < fl;
      assert |F| == fl as int;
      assert 0 <= z as int < |F|;
      assert F[z..][0] == F[z];
      assert LeadZeros(F[z..]) == 0;
      sig := fl - z;
      magOk := z < 6;
      assert magOk ==> MagOk(ip as int, F);
      assert MagOk(ip as int, F) ==> magOk by {
        if MagOk(ip as int, F) { var w :| 0 <= w < 6 && w < |F| && F[w] != 0; assert w >= z as int; }
      }
    }
    assert sig as int == Sig(ip as int, F);
    if sig > 15 || !magOk { return Bad, buf, n; }
    assert ValidDec(neg, ip as int, F);
    // print: [-] Dig(ip) . fr
    var ok: bool;
    ghost var pre: S := if neg then [45] else [];
    if neg {
      ok, b2, n2 := Put1(buf, n, 45);
      if !ok { return Exh, b2, n2; }
      WCat(old(buf[..n]), [45]);
      assert W(b2[..n2]) == W(old(buf[..n])) + pre;
    } else {
      b2, n2 := buf, n;
      assert b2[..n2] == old(buf[..n]);
      assert W(b2[..n2]) == W(old(buf[..n])) + pre;
    }
    ok, b2, n2 := DigM(ip, b2, n2);
    if !ok { return Exh, b2, n2; }
    ghost var mid := b2[..n2];
    ok, b2, n2 := Put1(b2, n2, 46);
    if !ok { return Exh, b2, n2; }
    WCat(mid, [46]);
    ghost var base := W(b2[..n2]);
    var r: bool;
    r, b2 := Room(b2, n2, 0);
    var i: N := 0;
    while i < fl
      invariant i <= fl && n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
      invariant W(b2[..n2]) == base + FrTxt(F[..i])
      decreases fl - i
    {
      ghost var before := b2[..n2];
      r, b2 := Room(b2, n2, 1);
      if !r { return Exh, b2, n2; }
      assert F[i] == fr[i] as int && 0 <= F[i] <= 9;
      b2[n2] := 48 + fr[i];
      assert b2[..n2 + 1] == before + [48 + fr[i]];
      WCat(before, [48 + fr[i]]);
      assert FrTxt(F[..i + 1]) == FrTxt(F[..i]) + [48 + F[i]];
      n2 := n2 + 1;
      i := i + 1;
    }
    assert F[..i] == F;
    return Done, b2, n2;
  }

  method ArrPM(u: JU, d: N, buf: array<U16>, n: N) returns (st: St, b2: array<U16>, n2: N)
    requires u.UArr? && 1 <= d <= 33 && n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures st.Done? ==> Valid(ToJ(u), d as int) && W(b2[..n2]) == W(old(buf[..n])) + Print(NormJ(ToJ(u)))
    ensures st.Bad? ==> !Valid(ToJ(u), d as int)
    decreases u, 0
  {
    var a := u.a;
    ghost var ja := seq(|a|, i requires 0 <= i < |a| => ToJ(a[i]));
    assert ToJ(u) == Arr(ja);
    if d > 32 { return Bad, buf, n; }
    if |a| >= LIMIT as int { return Exh, buf, n; }
    var len := |a| as N;
    var ok: bool;
    ok, b2, n2 := Put1(buf, n, 91);
    if !ok { return Exh, b2, n2; }
    WCat(old(buf[..n]), [91]);
    ghost var base := W(b2[..n2]);
    NormElemsIdx(ja);
    ghost var ne := NormElems(ja);
    var q: N := 0;
    while q < len
      invariant q <= len && n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
      invariant W(b2[..n2]) == base + PrintElems(ne[..q])
      invariant forall w :: 0 <= w < q as int ==> Valid(ja[w], d as int + 1)
      decreases len - q
    {
      ghost var before := W(b2[..n2]);
      if q > 0 {
        ghost var bb := b2[..n2];
        if (b2.Length as N) - n2 < 1 {
          ok, b2 := Room(b2, n2, 1);
          if !ok { return Exh, b2, n2; }
        }
        b2[n2] := 44;
        n2 := n2 + 1;
        assert b2[..n2] == bb + [44];
        WCat(bb, [44]);
      }
      var s: St;
      ghost var bb2 := b2[..n2];
      s, b2, n2 := PrintM(a[q], d + 1, b2, n2);
      if s.Bad? { assert !ValidElems(ja, d as int + 1) by { assert !Valid(ja[q], d as int + 1); } return Bad, b2, n2; }
      if s.Exh? { return Exh, b2, n2; }
      assert ne[..q + 1] == ne[..q] + [ne[q]];
      PrintElemsSnoc(ne[..q], ne[q]);
      q := q + 1;
    }
    assert ne[..q] == ne;
    ghost var mid := b2[..n2];
    ok, b2, n2 := Put1(b2, n2, 93);
    if !ok { return Exh, b2, n2; }
    WCat(mid, [93]);
    assert ValidElems(ja, d as int + 1);
    return Done, b2, n2;
  }

  // ---- object members: code points of the keys, merge sort, duplicate check ----
  ghost function WN(s: seq<N>): seq<int> { seq(|s|, i requires 0 <= i < |s| => s[i] as int) }
  datatype CP = CP(a: array?<N>, c: N)

  method CpsM(s: seq<U16>) returns (a: array<N>, c: N)
    requires |s| < LIMIT as int
    ensures fresh(a) && c as int <= a.Length && WN(a[..c]) == Cps(W(s))
  {
    ghost var S0 := W(s);
    var n := |s| as N;
    a := new N[n];
    c := 0;
    var q: N := 0;
    while q < n
      invariant q <= n && c <= q && WN(a[..c]) + Cps(S0[q..]) == Cps(S0)
      decreases n - q
    {
      var x := s[q];
      ghost var before := a[..c];
      if 0xD800 <= x <= 0xDBFF && q + 1 < n && 0xDC00 <= s[q + 1] <= 0xDFFF {
        var cp := 0x10000 + (x as N - 0xD800) * 0x400 + (s[q + 1] as N - 0xDC00);
        assert S0[q..][2..] == S0[q + 2..];
        a[c] := cp;
        assert a[..c + 1] == before + [cp];
        c := c + 1; q := q + 2;
      } else {
        assert S0[q..][1..] == S0[q + 1..];
        a[c] := x as N;
        assert a[..c + 1] == before + [x as N];
        c := c + 1; q := q + 1;
      }
    }
    assert S0[q..] == [];
  }

  // LexLess on two code point arrays
  method LessM(x: array<N>, xn: N, y: array<N>, yn: N) returns (r: bool)
    requires xn as int <= x.Length && yn as int <= y.Length
    ensures r == LexLess(WN(x[..xn]), WN(y[..yn]))
  {
    ghost var X := WN(x[..xn]);
    ghost var Y := WN(y[..yn]);
    var i: N := 0;
    while i < xn && i < yn && x[i] == y[i]
      invariant i <= xn && i <= yn && LexLess(X, Y) == LexLess(X[i..], Y[i..])
      decreases xn - i
    {
      assert X[i..][1..] == X[i + 1..] && Y[i..][1..] == Y[i + 1..];
      i := i + 1;
    }
    if i == yn { return false; }
    if i == xn { return true; }
    return x[i] < y[i];
  }

  ghost predicate CpsOk(cps: array<CP>, K: seq<seq<int>>)
    reads cps, set j | 0 <= j < cps.Length && cps[j].a != null :: cps[j].a
  { cps.Length == |K| && forall j :: 0 <= j < cps.Length ==> cps[j].a != null && cps[j].c as int <= cps[j].a.Length && WN(cps[j].a[..cps[j].c]) == K[j] }

  ghost predicate Le(K: seq<seq<int>>, x: N, y: N) requires x as int < |K| && y as int < |K| { !LexLess(K[y], K[x]) }
  ghost predicate SortedK(s: seq<N>, K: seq<seq<int>>)
  { (forall q :: 0 <= q < |s| ==> s[q] as int < |K|) && forall a, b :: 0 <= a < b < |s| ==> Le(K, s[a], s[b]) }

  lemma LeTrans(K: seq<seq<int>>, x: N, y: N, z: N)
    requires x as int < |K| && y as int < |K| && z as int < |K| && Le(K, x, y) && Le(K, y, z) ensures Le(K, x, z)
  {
    LexTotal(K[x], K[y]); LexTotal(K[y], K[z]);
    if LexLess(K[z], K[x]) {
      if K[x] == K[y] { } else { LexTrans(K[z], K[x], K[y]); }
    }
  }
  lemma LeTotal(K: seq<seq<int>>, x: N, y: N) requires x as int < |K| && y as int < |K| ensures Le(K, x, y) || Le(K, y, x)
  { if LexLess(K[y], K[x]) { LexAsym(K[y], K[x]); } }

  method {:isolate_assertions} Merge(p: array<N>, lo: N, mid: N, hi: N, tmp: array<N>, cps: array<CP>, ghost K: seq<seq<int>>)
    requires CpsOk(cps, K) && p != tmp && lo <= mid <= hi && hi as int <= p.Length && p.Length == tmp.Length
    requires forall j :: 0 <= j < cps.Length ==> cps[j].a != p && cps[j].a != tmp
    requires SortedK(p[lo..mid], K) && SortedK(p[mid..hi], K)
    modifies p, tmp
    ensures multiset(p[lo..hi]) == multiset(old(p[lo..hi])) && SortedK(p[lo..hi], K)
    ensures p[..lo] == old(p[..lo]) && p[hi..] == old(p[hi..]) && CpsOk(cps, K)
  {
    ghost var P0 := p[..];
    // absolute-index forms of the two sorted runs
    forall b | lo as int <= b < hi as int ensures P0[b] as int < |K| {
      if b < mid as int { assert p[lo..mid][b - lo as int] == p[b]; } else { assert p[mid..hi][b - mid as int] == p[b]; }
    }
    forall a, b | lo as int <= a < b < mid as int ensures Le(K, P0[a], P0[b]) { assert p[lo..mid][a - lo as int] == p[a] && p[lo..mid][b - lo as int] == p[b]; }
    forall a, b | mid as int <= a < b < hi as int ensures Le(K, P0[a], P0[b]) { assert p[mid..hi][a - mid as int] == p[a] && p[mid..hi][b - mid as int] == p[b]; }
    var i, j, k := lo, mid, lo;
    while k < hi
      invariant lo <= i <= mid <= j <= hi && k as int == lo as int + (i - lo) as int + (j - mid) as int
      invariant p[..] == P0 && CpsOk(cps, K)
      invariant multiset(tmp[lo..k]) == multiset(P0[lo..i]) + multiset(P0[mid..j])
      invariant forall a :: lo as int <= a < k as int ==> tmp[a] as int < |K|
      invariant forall a, b :: lo as int <= a < b < k as int ==> Le(K, tmp[a], tmp[b])
      invariant forall a, b :: lo as int <= a < k as int && i as int <= b < mid as int ==> Le(K, tmp[a], P0[b])
      invariant forall a, b :: lo as int <= a < k as int && j as int <= b < hi as int ==> Le(K, tmp[a], P0[b])
      decreases hi - k
    {
      var takeLeft: bool;
      if i == mid { takeLeft := false; }
      else if j == hi { takeLeft := true; }
      else {
        var cy := cps[p[j]]; var cx := cps[p[i]];
        var lt := LessM(cy.a, cy.c, cx.a, cx.c);
        takeLeft := !lt;
        if lt { LexAsym(K[P0[j]], K[P0[i]]); }
      }
      var x := if takeLeft then p[i] else p[j];
      assert x as int < |K|;
      forall b | (if takeLeft then i as int + 1 else i as int) <= b < mid as int ensures Le(K, x, P0[b]) {
        if takeLeft { } else { if b > i as int { LeTrans(K, x, P0[i], P0[b]); } }
      }
      forall b | (if takeLeft then j as int else j as int + 1) <= b < hi as int ensures Le(K, x, P0[b]) {
        if !takeLeft { } else { if b > j as int { LeTrans(K, x, P0[j], P0[b]); } }
      }
      ghost var before := tmp[lo..k];
      tmp[k] := x;
      assert tmp[lo..k + 1] == before + [x];
      if takeLeft {
        assert P0[lo..i + 1] == P0[lo..i] + [P0[i]];
        i := i + 1;
      } else {
        assert P0[mid..j + 1] == P0[mid..j] + [P0[j]];
        j := j + 1;
      }
      k := k + 1;
    }
    assert i == mid && j == hi;
    SliceSplit(P0, lo as int, mid as int, hi as int);
    ghost var T0 := tmp[lo..hi];
    forall a | 0 <= a < |T0| ensures T0[a] as int < |K| { assert T0[a] == tmp[lo as int + a]; }
    forall a, b | 0 <= a < b < |T0| ensures Le(K, T0[a], T0[b]) { assert T0[a] == tmp[lo as int + a] && T0[b] == tmp[lo as int + b]; }
    assert SortedK(T0, K);
    CopyBack(p, tmp, lo, hi);
  }

  lemma SliceSplit<X>(s: seq<X>, a: int, b: int, c: int)
    requires 0 <= a <= b <= c <= |s|
    ensures s[a..c] == s[a..b] + s[b..c]
  {
    forall q | 0 <= q < c - a ensures s[a..c][q] == (s[a..b] + s[b..c])[q] { if q < b - a { } else { } }
  }

  method CopyBack(p: array<N>, tmp: array<N>, lo: N, hi: N)
    requires p != tmp && lo <= hi && hi as int <= p.Length && p.Length == tmp.Length
    modifies p
    ensures p[lo..hi] == tmp[lo..hi] && p[..lo] == old(p[..lo]) && p[hi..] == old(p[hi..])
  {
    var w := lo;
    while w < hi
      invariant lo <= w <= hi
      invariant forall q :: lo as int <= q < w as int ==> p[q] == tmp[q]
      invariant forall q :: 0 <= q < lo as int || hi as int <= q < p.Length ==> p[q] == old(p[q])
      decreases hi - w
    { p[w] := tmp[w]; w := w + 1; }
  }

  method {:isolate_assertions} MSort(p: array<N>, lo: N, hi: N, tmp: array<N>, cps: array<CP>, ghost K: seq<seq<int>>)
    requires CpsOk(cps, K) && p != tmp && lo <= hi && hi as int <= p.Length && p.Length == tmp.Length
    requires forall j :: 0 <= j < cps.Length ==> cps[j].a != p && cps[j].a != tmp
    requires forall q :: lo as int <= q < hi as int ==> p[q] as int < |K|
    modifies p, tmp
    ensures multiset(p[lo..hi]) == multiset(old(p[lo..hi])) && SortedK(p[lo..hi], K)
    ensures p[..lo] == old(p[..lo]) && p[hi..] == old(p[hi..]) && CpsOk(cps, K)
    decreases hi - lo
  {
    if hi - lo <= 1 {
      forall a | 0 <= a < |p[lo..hi]| ensures p[lo..hi][a] as int < |K| { assert p[lo..hi][a] == p[lo as int + a]; }
      return;
    }
    var mid := lo + (hi - lo) / 2;
    ghost var P0 := p[..];
    MSort(p, lo, mid, tmp, cps, K);
    ghost var P1 := p[..];
    assert p[mid..hi] == P0[mid..hi] by { assert p[mid..] == P0[mid..]; assert p[mid..hi] == p[mid..][..hi - mid]; assert P0[mid..hi] == P0[mid..][..hi - mid]; }
    forall q | mid as int <= q < hi as int ensures p[q] as int < |K| {
      assert p[q] == p[mid..hi][q - mid as int] == P0[mid..hi][q - mid as int] == P0[q];
    }
    MSort(p, mid, hi, tmp, cps, K);
    ghost var P2 := p[..];
    assert p[lo..mid] == P1[lo..mid] by { assert p[..mid] == P1[..mid]; assert p[lo..mid] == p[..mid][lo..]; assert P1[lo..mid] == P1[..mid][lo..]; }
    assert p[..lo] == P0[..lo] by { assert p[..lo] == p[..mid][..lo]; assert P1[..lo] == P1[..mid][..lo]; }
    assert P1[mid..] == P0[mid..];
    assert P1[hi..] == P1[mid..][hi - mid..] && P0[hi..] == P0[mid..][hi - mid..];
    assert p[hi..] == P0[hi..];
    SliceSplit(P0, lo as int, mid as int, hi as int);
    SliceSplit(P2, lo as int, mid as int, hi as int);
    assert multiset(P2[mid..hi]) == multiset(P1[mid..hi]) == multiset(P0[mid..hi]);
    assert multiset(P2[lo..mid]) == multiset(P1[lo..mid]) == multiset(P0[lo..mid]);
    assert multiset(P2[lo..hi]) == multiset(P0[lo..hi]);
    Merge(p, lo, mid, hi, tmp, cps, K);
    assert multiset(p[lo..hi]) == multiset(P2[lo..hi]);
  }

  // ---- permutations and the canonical member order ----
  ghost function Range(n: nat): seq<N> requires n < 0x20_0000_0000_0000 { seq(n, i requires 0 <= i < n => i as N) }

  lemma DistinctCount<T>(s: seq<T>, x: T)
    requires forall a, b :: 0 <= a < b < |s| ==> s[a] != s[b]
    ensures multiset(s)[x] <= 1
    decreases |s|
  {
    if |s| > 0 {
      var h := s[..|s| - 1];
      assert s == h + [s[|s| - 1]];
      DistinctCount(h, x);
      if s[|s| - 1] == x { assert x !in h; }
    }
  }

  lemma DupCount<T>(s: seq<T>, a: int, b: int)
    requires 0 <= a < b < |s| && s[a] == s[b]
    ensures multiset(s)[s[a]] >= 2
  {
    assert s == s[..b] + s[b..];
    assert s[a] in s[..b];
    assert s[b] in s[b..];
  }

  lemma PermFacts(ord: seq<N>, n: nat)
    requires n < 0x20_0000_0000_0000 && multiset(ord) == multiset(Range(n))
    ensures |ord| == n
    ensures forall q :: 0 <= q < |ord| ==> ord[q] as int < n
    ensures forall i: N :: 0 <= i as int < n ==> i in ord
    ensures forall a, b :: 0 <= a < b < |ord| ==> ord[a] != ord[b]
  {
    assert |ord| == |multiset(ord)| == |multiset(Range(n))| == n;
    forall q | 0 <= q < |ord| ensures ord[q] as int < n { assert ord[q] in multiset(Range(n)); assert ord[q] in Range(n); }
    forall i: N | 0 <= i as int < n ensures i in ord {
      assert Range(n)[i] == i; assert i in multiset(Range(n)); assert i in multiset(ord);
    }
    forall a, b | 0 <= a < b < |ord| ensures ord[a] != ord[b] {
      if ord[a] == ord[b] { DupCount(ord, a, b); DistinctCount(Range(n), ord[a]); }
    }
  }

  ghost function MapS<B>(f: N -> B, x: seq<N>): seq<B> { seq(|x|, i requires 0 <= i < |x| => f(x[i])) }

  lemma MapMS<B>(f: N -> B, x: seq<N>, y: seq<N>)
    requires multiset(x) == multiset(y)
    ensures multiset(MapS(f, x)) == multiset(MapS(f, y))
    decreases |x|
  {
    if |x| == 0 { assert |y| == |multiset(y)| == 0; assert MapS(f, x) == [] && MapS(f, y) == []; }
    else {
      var a := x[0];
      assert a in multiset(y);
      var j :| 0 <= j < |y| && y[j] == a;
      var y' := y[..j] + y[j + 1..];
      assert y == y[..j] + [a] + y[j + 1..];
      assert x == [a] + x[1..];
      assert multiset(y) == multiset(y[..j]) + multiset{a} + multiset(y[j + 1..]);
      assert multiset(y') == multiset(y[..j]) + multiset(y[j + 1..]);
      assert multiset(x) == multiset{a} + multiset(x[1..]);
      forall e ensures multiset(x[1..])[e] == multiset(y')[e] {
        assert multiset(x)[e] == multiset{a}[e] + multiset(x[1..])[e];
        assert multiset(y)[e] == multiset(y[..j])[e] + multiset{a}[e] + multiset(y[j + 1..])[e];
      }
      assert multiset(x[1..]) == multiset(y');
      MapMS(f, x[1..], y');
      assert MapS(f, x) == [f(a)] + MapS(f, x[1..]);
      assert MapS(f, y) == MapS(f, y[..j]) + [f(a)] + MapS(f, y[j + 1..]);
      assert MapS(f, y') == MapS(f, y[..j]) + MapS(f, y[j + 1..]);
    }
  }

  ghost function Ordered(jkv: seq<KV>, ord: seq<N>): seq<KV>
    requires forall q :: 0 <= q < |ord| ==> ord[q] as int < |jkv|
  { seq(|ord|, q requires 0 <= q < |ord| => KV(jkv[ord[q]].k, NormJ(jkv[ord[q]].v))) }

  lemma AdjStrict(s: seq<KV>)
    requires forall q :: 0 <= q < |s| - 1 ==> KLess(s[q].k, s[q + 1].k)
    ensures StrictSorted(s)
  {
    forall a, b | 0 <= a < b < |s| ensures KLess(s[a].k, s[b].k) { AdjStrictFrom(s, a, b); }
  }
  lemma AdjStrictFrom(s: seq<KV>, a: int, b: int)
    requires forall q :: 0 <= q < |s| - 1 ==> KLess(s[q].k, s[q + 1].k)
    requires 0 <= a < b < |s|
    ensures KLess(s[a].k, s[b].k)
    decreases b - a
  { if b > a + 1 { AdjStrictFrom(s, a, b - 1); KLessTrans(s[a].k, s[b - 1].k, s[b].k); } }

  lemma OrderedDistinct(jkv: seq<KV>, ord: seq<N>)
    requires |jkv| < 0x20_0000_0000_0000 && multiset(ord) == multiset(Range(|jkv|))
    requires forall q :: 0 <= q < |ord| ==> ord[q] as int < |jkv|
    requires StrictSorted(Ordered(jkv, ord))
    ensures DistinctKeys(jkv)
  {
    var n := |jkv|;
    PermFacts(ord, n);
    var O := Ordered(jkv, ord);
    forall i, j | 0 <= i < j < n ensures jkv[i].k != jkv[j].k {
      assert (i as N) in ord && (j as N) in ord;
      var qi :| 0 <= qi < |ord| && ord[qi] == i as N;
      var qj :| 0 <= qj < |ord| && ord[qj] == j as N;
      assert O[qi].k == jkv[i].k && O[qj].k == jkv[j].k;
      KLessIrrefl(jkv[i].k);
      if qi < qj { assert KLess(O[qi].k, O[qj].k); } else { assert KLess(O[qj].k, O[qi].k); }
    }
  }

  lemma OrderedPerm(jkv: seq<KV>, ord: seq<N>)
    requires |jkv| < 0x20_0000_0000_0000 && multiset(ord) == multiset(Range(|jkv|))
    requires forall q :: 0 <= q < |ord| ==> ord[q] as int < |jkv|
    ensures multiset(Ordered(jkv, ord)) == multiset(NormMembers(jkv))
  {
    var n := |jkv|;
    var M := NormMembers(jkv);
    NormMembersIdx(jkv);
    var f: N -> KV := (i: N) => if i as int < n then M[i] else KV([], Null);
    MapMS(f, ord, Range(n));
    assert MapS(f, ord) == Ordered(jkv, ord);
    assert MapS(f, Range(n)) == M;
  }

  lemma ObjSorted(jkv: seq<KV>, K: seq<seq<int>>, ord: seq<N>)
    requires |K| == |jkv| < 0x20_0000_0000_0000 && forall i :: 0 <= i < |jkv| ==> Valid16(jkv[i].k) && K[i] == Cps(jkv[i].k)
    requires multiset(ord) == multiset(Range(|jkv|))
    requires forall q :: 0 <= q < |ord| ==> ord[q] as int < |jkv|
    requires forall q :: 0 <= q < |ord| - 1 ==> LexLess(K[ord[q]], K[ord[q + 1]])
    ensures DistinctKeys(jkv) && SortKV(NormMembers(jkv)) == Ordered(jkv, ord)
  {
    var O := Ordered(jkv, ord);
    forall q | 0 <= q < |O| - 1 ensures KLess(O[q].k, O[q + 1].k) { assert O[q].k == jkv[ord[q]].k && O[q + 1].k == jkv[ord[q + 1]].k; }
    AdjStrict(O);
    OrderedDistinct(jkv, ord);
    OrderedPerm(jkv, ord);
    var M := NormMembers(jkv);
    assert KeysValid(jkv);
    NormKeysDistinct(jkv);
    SortSorted(M);
    SortMultiset(M);
    SortedUnique(SortKV(M), O);
  }

  lemma ObjDup(jkv: seq<KV>, K: seq<seq<int>>, ord: seq<N>, q: int)
    requires |K| == |jkv| < 0x20_0000_0000_0000 && forall i :: 0 <= i < |jkv| ==> Valid16(jkv[i].k) && K[i] == Cps(jkv[i].k)
    requires multiset(ord) == multiset(Range(|jkv|)) && SortedK(ord, K)
    requires 0 <= q < |ord| - 1 && !LexLess(K[ord[q]], K[ord[q + 1]])
    ensures !DistinctKeys(jkv)
  {
    PermFacts(ord, |jkv|);
    assert ord[q] as int < |K| && ord[q + 1] as int < |K|;
    var a := ord[q] as int; var b := ord[q + 1] as int;
    assert Le(K, ord[q], ord[q + 1]);
    LexTotal(K[a], K[b]);
    assert K[a] == K[b];
    CpsInjective(jkv[a].k, jkv[b].k);
    assert a != b;
    if a < b { assert jkv[a].k == jkv[b].k; } else { assert jkv[b].k == jkv[a].k; }
  }

  method {:isolate_assertions} ObjPM(u: JU, d: N, buf: array<U16>, n: N) returns (st: St, b2: array<U16>, n2: N)
    requires u.UObj? && 1 <= d <= 33 && n as int <= buf.Length <= LIMIT as int
    modifies buf
    ensures n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
    ensures st.Done? ==> Valid(ToJ(u), d as int) && W(b2[..n2]) == W(old(buf[..n])) + Print(NormJ(ToJ(u)))
    ensures st.Bad? ==> !Valid(ToJ(u), d as int)
    decreases u, 0
  {
    var kv := u.kv;
    ghost var jkv := seq(|kv|, i requires 0 <= i < |kv| => KV(W(kv[i].k), ToJ(kv[i].v)));
    assert ToJ(u) == Obj(jkv);
    if d > 32 { return Bad, buf, n; }
    if |kv| >= LIMIT as int { return Exh, buf, n; }
    var cnt := |kv| as N;
    // keys: well-formed UTF-16, code points
    var cps := new CP[cnt];
    ghost var K: seq<seq<int>> := [];
    var i: N := 0;
    while i < cnt
      invariant i <= cnt && |K| == i as int
      invariant forall j :: 0 <= j < i as int ==> Valid16(jkv[j].k) && K[j] == Cps(jkv[j].k)
      invariant forall j :: 0 <= j < i as int ==> cps[j].a != null && cps[j].c as int <= cps[j].a.Length && WN(cps[j].a[..cps[j].c]) == K[j]
      invariant forall j :: 0 <= j < i as int ==> fresh(cps[j].a) && |kv[j].k| < LIMIT as int
      modifies cps
      decreases cnt - i
    {
      var key := kv[i].k;
      if |key| >= LIMIT as int { return Exh, buf, n; }
      var v16 := V16S(key);
      if !v16 { assert !ValidMembers(jkv, d as int + 1) by { assert !Valid16(jkv[i].k); } return Bad, buf, n; }
      var a, c := CpsM(key);
      cps[i] := CP(a, c);
      K := K + [Cps(W(key))];
      i := i + 1;
    }
    // sort member indices by key code points
    assert CpsOk(cps, K);
    var perm := new N[cnt];
    var tmp := new N[cnt];
    assert forall j :: 0 <= j < cps.Length ==> cps[j].a != perm && cps[j].a != tmp;
    i := 0;
    while i < cnt
      invariant i <= cnt && perm[..i] == Range(i as nat) && CpsOk(cps, K)
      invariant forall j :: 0 <= j < cps.Length ==> cps[j].a != perm && cps[j].a != tmp
      modifies perm
      decreases cnt - i
    { perm[i] := i; i := i + 1; }
    assert perm[..] == Range(cnt as nat);
    MSort(perm, 0, cnt, tmp, cps, K);
    assert perm[..cnt] == perm[..];
    ghost var ord := perm[..];
    assert multiset(ord) == multiset(Range(|jkv|));
    PermFacts(ord, |jkv|);
    assert SortedK(ord, K);
    // adjacent keys strictly increasing <=> no duplicate key
    i := 0;
    while i + 1 < cnt
      modifies {}
      invariant i <= cnt && cnt < LIMIT && (i < cnt || cnt == 0)
      invariant perm[..] == ord && CpsOk(cps, K)
      invariant forall q :: 0 <= q < i as int && q + 1 < cnt as int ==> LexLess(K[ord[q]], K[ord[q + 1]])
      decreases cnt - i
    {
      var x := cps[perm[i]]; var y := cps[perm[i + 1]];
      var lt := LessM(x.a, x.c, y.a, y.c);
      if !lt { ObjDup(jkv, K, ord, i as int); return Bad, buf, n; }
      i := i + 1;
    }
    ObjSorted(jkv, K, ord);
    ghost var O := Ordered(jkv, ord);
    // print: { members in key order }
    var ok: bool;
    ok, b2, n2 := Put1(buf, n, 123);
    if !ok { return Exh, b2, n2; }
    WCat(old(buf[..n]), [123]);
    ghost var base := W(b2[..n2]);
    var q: N := 0;
    while q < cnt
      invariant q <= cnt && n2 as int <= b2.Length <= LIMIT as int && (b2 == buf || fresh(b2))
      invariant perm[..] == ord
      invariant W(b2[..n2]) == base + PrintMembers(O[..q])
      invariant forall w :: 0 <= w < q as int ==> Valid(jkv[ord[w]].v, d as int + 1)
      decreases cnt - q
    {
      var idx := perm[q];
      ghost var before := W(b2[..n2]);
      ghost var bb := b2[..n2];
      if q > 0 {
        ok, b2, n2 := Put2(b2, n2, 44, 34);
        if !ok { return Exh, b2, n2; }
        WCat(bb, [44, 34]);
      } else {
        ok, b2, n2 := Put1(b2, n2, 34);
        if !ok { return Exh, b2, n2; }
        WCat(bb, [34]);
      }
      ok, b2, n2 := BodyM(kv[idx].k, b2, n2);
      if !ok { return Exh, b2, n2; }
      bb := b2[..n2];
      ok, b2, n2 := Put2(b2, n2, 34, 58);
      if !ok { return Exh, b2, n2; }
      WCat(bb, [34, 58]);
      var s: St;
      s, b2, n2 := PrintM(kv[idx].v, d + 1, b2, n2);
      if s.Bad? { assert !ValidMembers(jkv, d as int + 1) by { assert !Valid(jkv[idx].v, d as int + 1); } return Bad, b2, n2; }
      if s.Exh? { return Exh, b2, n2; }
      assert O[q] == KV(jkv[idx].k, NormJ(jkv[idx].v));
      assert O[..q + 1] == O[..q] + [O[q]];
      PrintMembersSnoc(O[..q], O[q]);
      q := q + 1;
    }
    assert O[..q] == O;
    ghost var mid := b2[..n2];
    ok, b2, n2 := Put1(b2, n2, 125);
    if !ok { return Exh, b2, n2; }
    WCat(mid, [125]);
    PermFacts(ord, |jkv|);
    assert NormJ(ToJ(u)) == Obj(O);
    assert Print(Obj(O)) == [123] + PrintMembers(O) + [125];
    assert W(b2[..n2]) == W(old(buf[..n])) + ([123] + PrintMembers(O) + [125]);
    assert ValidMembers(jkv, d as int + 1) by {
      forall x | 0 <= x < |jkv| ensures Valid16(jkv[x].k) && Valid(jkv[x].v, d as int + 1) {
        assert (x as N) in ord;
        var w :| 0 <= w < |ord| && ord[w] == x as N;
      }
    }
    return Done, b2, n2;
  }

  // ---- canonicalizeStrict, proved equal to the specification (Exh: the 2^40-unit output limit, no verdict) ----
  method CanonU(u: JU) returns (st: St, b: array<U16>, n: N)
    ensures st.Done? ==> n as int <= b.Length && CanonText(ToJ(u)) == Some(W(b[..n]))
    ensures st.Bad? ==> CanonText(ToJ(u)) == None
  {
    var buf := new U16[64];
    ghost var e := buf[..0];
    assert W(e) == [];
    st, b, n := PrintM(u, 1, buf, 0);
    if st.Done? { assert W(b[..n]) == W(e) + Print(NormJ(ToJ(u))); assert W(b[..n]) == Print(NormJ(ToJ(u))); assert Valid(ToJ(u), 1); }
  }
}

// Thin entry points compiled for the TypeScript adapter (ext-wire.ts).
module Api {
  import Utf
  import Json
  import B64
  import Fast
  import FastP

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

  // ---- compiled fast paths (modules Fast / FastP), each PROVED equal to the specification above ----
  // strictParse acceptance on native UTF-16 units. `seed` only salts the duplicate-key table's buckets.
  function ParseAcceptsU(t: seq<Fast.U16>, seed: Fast.N): bool { Fast.AcceptsU(t, seed) }
  lemma ParseAcceptsUSpec(t: seq<Fast.U16>, seed: Fast.N) ensures ParseAcceptsU(t, seed) == Json.ParseTop(Fast.W(t)).Some? {}

  // canonicalizeStrict on an imported value: Done -> b[..n] is the canonical text; Bad -> outside the profile;
  // Exh -> the output would pass 2^40 units (no verdict; the adapter treats it as resource exhaustion).
  method CanonicalOfValueU(u: FastP.JU) returns (st: FastP.St, b: array<Fast.U16>, n: Fast.N)
    ensures st.Done? ==> n as int <= b.Length && Json.CanonText(FastP.ToJ(u)) == Json.Some(Fast.W(b[..n]))
    ensures st.Bad? ==> Json.CanonText(FastP.ToJ(u)) == Json.None
  { st, b, n := FastP.CanonU(u); }

}
