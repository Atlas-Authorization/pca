// Regex.dfy - the linear-time budgeted regular-expression engine of the PCA verifier (packages/pca/src/safe-regex.ts) and the
// `re:` guard (isSafeRegexSource in predicates.ts), specified, implemented and PROVED here. STANDALONE (no includes).
// No assume / axiom / extern. Strings are sequences of UTF-16 code units, represented as seq<int> with every element in 0..65535
// (the adapter converts JS strings with charCodeAt).
//
// Layout
//   1. the supported subset as a datatype (Node) and the character-set algebra
//   2. the parser (pattern source -> Node or Refusal), mirroring the TypeScript grammar exactly
//   3. NFA size, the emitted instruction program (Thompson, same shapes as safe-regex.ts)
//   4. denotational semantics (Match) and the path semantics of the program, and the compile-correctness theorem
//   5. the Pike simulation (imperative, arrays) with its refinement to the semantics and its step bound
//   6. the guard (isSafeRegexSource) and the `re:` entry point
module Regex {
  datatype Option<T> = None | Some(v: T)

  const MAX_NFA_INSTRUCTIONS: int := 4096
  const MAX_REPEAT: int := 64
  const MAX_MATCH_STEPS: int := 2000000

  // ---------------------------------------------------------------- 1. character sets
  type Range = (int, int)

  function InRanges(rs: seq<Range>, c: int): bool
    decreases |rs|
  {
    if |rs| == 0 then false else (rs[0].0 <= c <= rs[0].1) || InRanges(rs[1..], c)
  }

  // A class item: a literal range, a positive escape class (\d \w \s) or a NEGATED escape class (\D \W \S) used inside [...].
  datatype Item = Rng(lo: int, hi: int) | In(rs: seq<Range>) | NotIn(rs: seq<Range>)

  function ItemHas(it: Item, c: int): bool {
    match it
    case Rng(lo, hi) => lo <= c <= hi
    case In(rs) => InRanges(rs, c)
    case NotIn(rs) => !InRanges(rs, c)
  }

  // A (possibly negated) union of items. `[]` = Cls([],false) matches nothing, `[^]` = Cls([],true) matches every code unit.
  datatype CharSet = Cls(items: seq<Item>, neg: bool)

  function AnyItem(items: seq<Item>, c: int): bool
    decreases |items|
  {
    if |items| == 0 then false else ItemHas(items[0], c) || AnyItem(items[1..], c)
  }

  function SetHas(cs: CharSet, c: int): bool { AnyItem(cs.items, c) != cs.neg }

  const DIGIT: seq<Range> := [(0x30, 0x39)]
  const WORD: seq<Range> := [(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)]
  const SPACE: seq<Range> := [(0x09, 0x0d), (0x20, 0x20), (0xa0, 0xa0), (0x1680, 0x1680), (0x2000, 0x200a), (0x2028, 0x2029),
                              (0x202f, 0x202f), (0x205f, 0x205f), (0x3000, 0x3000), (0xfeff, 0xfeff)]
  const LINE_TERMINATORS: seq<Range> := [(0x0a, 0x0a), (0x0d, 0x0d), (0x2028, 0x2029)]

  // ---------------------------------------------------------------- the supported subset (the type IS the subset)
  datatype Node =
    | Set(cs: CharSet)                       // consume one code unit in cs
    | Bol                                    // ^   (position 0 only)
    | Eol                                    // $   (position |s| only)
    | Cat(cat: NList)                        // concatenation (possibly empty)
    | Alt(alt: NList)                        // alternation (Valid: non-empty)
    | Rep(inner: Node, mn: int, mx: int)     // inner{mn,mx}; mx == -1 means unbounded
  datatype NList = Nil | Cons(hd: Node, tl: NList)

  predicate ValidN(n: Node)
    decreases n, 1
  {
    match n
    case Set(_) => true
    case Bol => true
    case Eol => true
    case Cat(l) => ValidL(l)
    case Alt(l) => l.Cons? && ValidL(l)
    case Rep(inner, mn, mx) => ValidN(inner) && 0 <= mn && (mx == -1 || mn <= mx) && !inner.Bol? && !inner.Eol?
  }
  predicate ValidL(l: NList)
    decreases l, 0
  {
    match l
    case Nil => true
    case Cons(h, t) => ValidN(h) && ValidL(t)
  }

  // every counted repetition obeys the parser's repeat cap
  predicate BoundedN(n: Node)
    decreases n, 1
  {
    match n
    case Set(_) => true
    case Bol => true
    case Eol => true
    case Cat(l) => BoundedL(l)
    case Alt(l) => BoundedL(l)
    case Rep(inner, mn, mx) => BoundedN(inner) && mn <= 64 && mx <= 64
  }
  predicate BoundedL(l: NList)
    decreases l, 0
  {
    match l
    case Nil => true
    case Cons(h, t) => BoundedN(h) && BoundedL(t)
  }

  // ---------------------------------------------------------------- 2. the parser
  // Mirrors class Parser in safe-regex.ts. Any deviation from the supported grammar is `PRef` (refusal), never a partial result.
  datatype PR<T> = POk(v: T, i: int) | PRef

  const BS: int := 0x5c       // backslash
  const LP: int := 0x28
  const RP: int := 0x29
  const LB: int := 0x5b
  const RB: int := 0x5d
  const LC: int := 0x7b
  const RC: int := 0x7d
  const BAR: int := 0x7c
  const STAR: int := 0x2a
  const PLUS: int := 0x2b
  const QM: int := 0x3f
  const DOT: int := 0x2e
  const CARET: int := 0x5e
  const DOLLAR: int := 0x24
  const DASH: int := 0x2d
  const COMMA: int := 0x2c
  const COLON: int := 0x3a

  predicate IsDigit(c: int) { 0x30 <= c <= 0x39 }
  predicate IsHex(c: int) { IsDigit(c) || (0x41 <= c <= 0x46) || (0x61 <= c <= 0x66) }
  predicate IsAlpha(c: int) { (0x41 <= c <= 0x5a) || (0x61 <= c <= 0x7a) }
  predicate IsAlnum(c: int) { IsDigit(c) || IsAlpha(c) }
  function HexVal(c: int): int
    requires IsHex(c)
  {
    if IsDigit(c) then c - 0x30 else if c <= 0x46 then c - 0x41 + 10 else c - 0x61 + 10
  }

  // maximal run of decimal digits starting at p (p <= |s|); returns the end index
  function DigitRun(s: seq<int>, p: int): int
    requires 0 <= p <= |s|
    decreases |s| - p
    ensures p <= DigitRun(s, p) <= |s|
    ensures forall k :: p <= k < DigitRun(s, p) ==> IsDigit(s[k])
    ensures DigitRun(s, p) == |s| || !IsDigit(s[DigitRun(s, p)])
  {
    if p < |s| && IsDigit(s[p]) then DigitRun(s, p + 1) else p
  }
  function DigitVal(s: seq<int>, p: int, q: int): int
    requires 0 <= p <= q <= |s|
    requires forall k :: p <= k < q ==> IsDigit(s[k])
    decreases q - p
    ensures DigitVal(s, p, q) >= 0
  {
    if p == q then 0 else (assert IsDigit(s[q - 1]); DigitVal(s, p, q - 1) * 10 + (s[q - 1] - 0x30))
  }

  // the result of looking for a quantifier after an atom
  datatype QR = NoQ | Q(mn: int, mx: int, k: int) | QBad

  // s[j] == '{' : /^\{(\d{1,4})(?:(,)(\d{0,4}))?\}/ , then the order check. mx == -1 is "{n,}".
  function ParseBrace(s: seq<int>, j: int): QR
    requires 0 <= j < |s| && s[j] == LC
    ensures ParseBrace(s, j).Q? ==> j < ParseBrace(s, j).k <= |s|
    ensures ParseBrace(s, j).Q? ==> 0 <= ParseBrace(s, j).mn && (ParseBrace(s, j).mx == -1 || ParseBrace(s, j).mn <= ParseBrace(s, j).mx)
  {
    var d1e := DigitRun(s, j + 1);
    var len1 := d1e - (j + 1);
    if len1 < 1 || len1 > 4 then QBad
    else
      var v1 := DigitVal(s, j + 1, d1e);
      if d1e < |s| && s[d1e] == RC then Q(v1, v1, d1e + 1)
      else if d1e < |s| && s[d1e] == COMMA then
        var d2e := DigitRun(s, d1e + 1);
        var len2 := d2e - (d1e + 1);
        if len2 > 4 || d2e >= |s| || s[d2e] != RC then QBad
        else
          var mx := if len2 == 0 then -1 else DigitVal(s, d1e + 1, d2e);
          if mx != -1 && mx < v1 then QBad else Q(v1, mx, d2e + 1)
      else QBad
  }

  datatype Esc = Esc(item: Item, cls: bool, ch: int)

  function Single(code: int): Esc { Esc(Rng(code, code), false, code) }

  // s[i] == '\\'. The escape outside (inClass=false) or inside a class.
  function EscapeInner(s: seq<int>, i: int, inClass: bool): PR<Esc>
    requires 0 <= i < |s| && s[i] == BS
    ensures EscapeInner(s, i, inClass).POk? ==> i + 2 <= EscapeInner(s, i, inClass).i <= |s|
  {
    if i + 1 >= |s| then PRef
    else
      var c := s[i + 1];
      var j := i + 2;
      if c == 0x64 then POk(Esc(In(DIGIT), true, -1), j)         // d
      else if c == 0x44 then POk(Esc(NotIn(DIGIT), true, -1), j) // D
      else if c == 0x77 then POk(Esc(In(WORD), true, -1), j)     // w
      else if c == 0x57 then POk(Esc(NotIn(WORD), true, -1), j)  // W
      else if c == 0x73 then POk(Esc(In(SPACE), true, -1), j)    // s
      else if c == 0x53 then POk(Esc(NotIn(SPACE), true, -1), j) // S
      else if c == 0x74 then POk(Single(9), j)                   // t
      else if c == 0x6e then POk(Single(10), j)                  // n
      else if c == 0x76 then POk(Single(11), j)                  // v
      else if c == 0x66 then POk(Single(12), j)                  // f
      else if c == 0x72 then POk(Single(13), j)                  // r
      else if c == 0x30 then                                     // 0 (not an octal escape)
        if j < |s| && IsDigit(s[j]) then PRef else POk(Single(0), j)
      else if c == 0x78 then                                     // xHH
        if j + 2 <= |s| && IsHex(s[j]) && IsHex(s[j + 1]) then POk(Single(HexVal(s[j]) * 16 + HexVal(s[j + 1])), j + 2) else PRef
      else if c == 0x75 then                                     // uHHHH
        if j + 4 <= |s| && IsHex(s[j]) && IsHex(s[j + 1]) && IsHex(s[j + 2]) && IsHex(s[j + 3])
        then POk(Single(((HexVal(s[j]) * 16 + HexVal(s[j + 1])) * 16 + HexVal(s[j + 2])) * 16 + HexVal(s[j + 3])), j + 4)
        else PRef
      else if c == 0x63 then                                     // cX
        if j < |s| && IsAlpha(s[j]) then POk(Single(s[j] % 32), j + 1) else PRef
      else if c == 0x62 then                                     // b : backspace in a class, an (unsupported) assertion outside
        if inClass then POk(Single(8), j) else PRef
      else if IsAlnum(c) || c == 0x5f then PRef                  // backrefs, \B, \k, \p, other letters/digits/underscore
      else POk(Single(c), j)
  }

  // one class atom: a literal code unit or an escape. Returns the items it contributes, its single code (if not a class escape).
  datatype CAtom = CAtom(it: Item, ch: int, cls: bool)
  function ReadAtom(s: seq<int>, i: int): PR<CAtom>
    requires 0 <= i <= |s|
    ensures ReadAtom(s, i).POk? ==> i < ReadAtom(s, i).i <= |s|
  {
    if i >= |s| then PRef
    else if s[i] == BS then
      match EscapeInner(s, i, true) {
        case PRef => PRef
        case POk(e, j) => POk(CAtom(e.item, e.ch, e.cls), j)
      }
    else POk(CAtom(Rng(s[i], s[i]), s[i], false), i + 1)
  }

  // after `[` (and the optional `^`): items up to the first unescaped `]`. Returns the position after `]`.
  function ParseClsBody(s: seq<int>, i: int): PR<seq<Item>>
    requires 0 <= i <= |s|
    decreases |s| - i
    ensures ParseClsBody(s, i).POk? ==> i < ParseClsBody(s, i).i <= |s|
  {
    if i >= |s| then PRef
    else if s[i] == RB then POk([], i + 1)
    else
      match ReadAtom(s, i) {
        case PRef => PRef
        case POk(a, j) =>
          if j < |s| && s[j] == DASH && j + 1 < |s| && s[j + 1] != RB then
            match ReadAtom(s, j + 1) {
              case PRef => PRef
              case POk(b, k) =>
                if a.cls || b.cls then
                  // Annex B: a class escape as a range endpoint makes '-' a literal
                  match ParseClsBody(s, k) { case PRef => PRef case POk(rest, e) => POk([a.it, Rng(DASH, DASH), b.it] + rest, e) }
                else if a.ch > b.ch then PRef
                else match ParseClsBody(s, k) { case PRef => PRef case POk(rest, e) => POk([Rng(a.ch, b.ch)] + rest, e) }
            }
          else
            match ParseClsBody(s, j) { case PRef => PRef case POk(rest, e) => POk([a.it] + rest, e) }
      }
  }

  function ParseCls(s: seq<int>, i: int): PR<Node>
    requires 0 <= i < |s| && s[i] == LB
    ensures ParseCls(s, i).POk? ==> i < ParseCls(s, i).i <= |s|
    ensures ParseCls(s, i).POk? ==> ValidN(ParseCls(s, i).v) && BoundedN(ParseCls(s, i).v)
  {
    var neg := i + 1 < |s| && s[i + 1] == CARET;
    var st := if neg then i + 2 else i + 1;
    match ParseClsBody(s, st) {
      case PRef => PRef
      case POk(items, e) => POk(Set(Cls(items, neg)), e)
    }
  }

  predicate IsQuantChar(c: int) { c == STAR || c == PLUS || c == QM || c == LC }

  // Rank order for the mutual recursion (all parse functions consume at least what the callee consumes):
  //   Alt(5) > AltTail(4) > Cat(3) > Quantified(2) > Atom(1) and Atom recurses into Alt on a strictly later index.
  function ParseAlt(s: seq<int>, i: int): PR<Node>
    requires 0 <= i <= |s|
    decreases |s| - i, 5
    ensures ParseAlt(s, i).POk? ==> i <= ParseAlt(s, i).i <= |s|
    ensures ParseAlt(s, i).POk? ==> ValidN(ParseAlt(s, i).v) && BoundedN(ParseAlt(s, i).v)
  {
    match ParseCat(s, i) {
      case PRef => PRef
      case POk(first, j) =>
        match ParseAltTail(s, j) {
          case PRef => PRef
          case POk(rest, k) => POk(if rest.Nil? then Cat(first) else Alt(Cons(Cat(first), rest)), k)
        }
    }
  }

  // ('|' cat)* : the further alternatives
  function ParseAltTail(s: seq<int>, j: int): PR<NList>
    requires 0 <= j <= |s|
    decreases |s| - j, 4
    ensures ParseAltTail(s, j).POk? ==> j <= ParseAltTail(s, j).i <= |s|
    ensures ParseAltTail(s, j).POk? ==> ValidL(ParseAltTail(s, j).v) && BoundedL(ParseAltTail(s, j).v)
  {
    if j < |s| && s[j] == BAR then
      match ParseCat(s, j + 1) {
        case PRef => PRef
        case POk(c, k) =>
          match ParseAltTail(s, k) {
            case PRef => PRef
            case POk(rest, e) => POk(Cons(Cat(c), rest), e)
          }
      }
    else POk(Nil, j)
  }

  // quantified* up to '|' , ')' or the end
  function ParseCat(s: seq<int>, i: int): PR<NList>
    requires 0 <= i <= |s|
    decreases |s| - i, 3
    ensures ParseCat(s, i).POk? ==> i <= ParseCat(s, i).i <= |s|
    ensures ParseCat(s, i).POk? ==> ValidL(ParseCat(s, i).v) && BoundedL(ParseCat(s, i).v)
  {
    if i >= |s| || s[i] == BAR || s[i] == RP then POk(Nil, i)
    else
      match ParseQuantified(s, i) {
        case PRef => PRef
        case POk(q, j) =>
          match ParseCat(s, j) {
            case PRef => PRef
            case POk(rest, k) => POk(Cons(q, rest), k)
          }
      }
  }

  function ParseQuantified(s: seq<int>, i: int): PR<Node>
    requires 0 <= i < |s|
    decreases |s| - i, 2
    ensures ParseQuantified(s, i).POk? ==> i < ParseQuantified(s, i).i <= |s|
    ensures ParseQuantified(s, i).POk? ==> ValidN(ParseQuantified(s, i).v) && BoundedN(ParseQuantified(s, i).v)
  {
    match ParseAtom(s, i) {
      case PRef => PRef
      case POk(atom, j) =>
        var q :=
          if j >= |s| then NoQ
          else if s[j] == STAR then Q(0, -1, j + 1)
          else if s[j] == PLUS then Q(1, -1, j + 1)
          else if s[j] == QM then Q(0, 1, j + 1)
          else if s[j] == LC then ParseBrace(s, j)
          else NoQ;
        match q {
          case NoQ => POk(atom, j)
          case QBad => PRef
          case Q(mn, mx, k) =>
            if atom.Bol? || atom.Eol? then PRef                                   // nothing to repeat (assertion)
            else if (mx != -1 && mx > MAX_REPEAT) || mn > MAX_REPEAT then PRef   // repeat bound too large
            else
              var k2 := if k < |s| && s[k] == QM then k + 1 else k;              // lazy modifier: no effect on a boolean full match
              if k2 < |s| && IsQuantChar(s[k2]) then PRef                         // nothing to repeat / '{' not a quantifier
              else POk(Rep(atom, mn, mx), k2)
        }
    }
  }

  function ParseAtom(s: seq<int>, i: int): PR<Node>
    requires 0 <= i < |s|
    decreases |s| - i, 1
    ensures ParseAtom(s, i).POk? ==> i < ParseAtom(s, i).i <= |s|
    ensures ParseAtom(s, i).POk? ==> ValidN(ParseAtom(s, i).v) && BoundedN(ParseAtom(s, i).v)
  {
    var c := s[i];
    if c == LP then
      var i1 := i + 1;
      var q := i1 < |s| && s[i1] == QM;
      if q && !(i1 + 1 < |s| && s[i1 + 1] == COLON) then PRef             // lookaround / named groups
      else
        var i2 := if q then i1 + 2 else i1;
        match ParseAlt(s, i2) {
          case PRef => PRef
          case POk(n, k) => if k < |s| && s[k] == RP then POk(n, k + 1) else PRef
        }
    else if c == LB then ParseCls(s, i)
    else if c == DOT then POk(Set(Cls([In(LINE_TERMINATORS)], true)), i + 1)
    else if c == CARET then POk(Bol, i + 1)
    else if c == DOLLAR then POk(Eol, i + 1)
    else if c == BS then
      match EscapeInner(s, i, false) {
        case PRef => PRef
        case POk(e, j) => POk(Set(Cls([e.item], false)), j)
      }
    else if c == STAR || c == PLUS || c == QM then PRef                    // nothing to repeat
    else if c == LC then PRef                                              // '{' is not a well-formed quantifier
    else POk(Set(Cls([Rng(c, c)], false)), i + 1)
  }

  // Parse(src): the whole source must be consumed (a stray ')' is "unbalanced )").
  function Parse(s: seq<int>): Option<Node>
    ensures Parse(s).Some? ==> ValidN(Parse(s).v) && BoundedN(Parse(s).v)
  {
    match ParseAlt(s, 0) {
      case PRef => None
      case POk(n, j) => if j < |s| then None else Some(n)
    }
  }

  // ---------------------------------------------------------------- 3. NFA size and the emitted program
  datatype Inst = ISet(cs: CharSet) | ISplit(x: int, y: int) | IJmp(x: int) | IBol | IEol | IMatch
  type Prog = seq<Inst>

  // Instruction count of the Thompson fragment of a node (exactly |Emit(n,a)|, see EmitLen).
  function Size(n: Node): int
    decreases n, 1
  {
    match n
    case Set(_) => 1
    case Bol => 1
    case Eol => 1
    case Cat(l) => SizeL(l)
    case Alt(l) => AltSize(l)
    case Rep(inner, mn, mx) =>
      mn * Size(inner) + (if mx == -1 then Size(inner) + 2 else (mx - mn) * (Size(inner) + 1))
  }
  function SizeL(l: NList): int
    decreases l, 0
  {
    match l
    case Nil => 0
    case Cons(h, t) => Size(h) + SizeL(t)
  }
  // an alternation of k branches costs the branches plus a split and a jump per non-last branch
  function AltSize(l: NList): int
    decreases l, 0
  {
    match l
    case Nil => 0
    case Cons(h, t) => if t.Nil? then Size(h) else Size(h) + 2 + AltSize(t)
  }

  // Emit(n, a): the instructions of n placed at absolute index a (jump targets are absolute, exactly like safe-regex.ts `emit`).
  function Emit(n: Node, a: int): seq<Inst>
    requires ValidN(n)
    decreases n, 2
  {
    match n
    case Set(cs) => [ISet(cs)]
    case Bol => [IBol]
    case Eol => [IEol]
    case Cat(l) => EmitL(l, a)
    case Alt(l) => EmitAlt(l, a)
    case Rep(inner, mn, mx) =>
      var S := Size(inner);
      var L := a + mn * S;
      EmitCopies(inner, a, mn) +
      (if mx == -1 then [ISplit(L + 1, L + S + 2)] + Emit(inner, L + 1) + [IJmp(L)]     // L: split body,end ; body ; jmp L
       else EmitChain(inner, L, mx - mn, L + (mx - mn) * (S + 1)))                       // (max-min) nested optionals
  }
  function EmitL(l: NList, a: int): seq<Inst>
    requires ValidL(l)
    decreases l, 1
  {
    match l
    case Nil => []
    case Cons(h, t) => Emit(h, a) + EmitL(t, a + Size(h))
  }
  // split L1,L2 ; L1: branch ; jmp end ; L2: ... ; last branch
  function EmitAlt(l: NList, a: int): seq<Inst>
    requires ValidL(l)
    decreases l, 1
  {
    match l
    case Nil => []
    case Cons(h, t) =>
      if t.Nil? then Emit(h, a)
      else [ISplit(a + 1, a + Size(h) + 2)] + Emit(h, a + 1) + [IJmp(a + AltSize(l))] + EmitAlt(t, a + Size(h) + 2)
  }
  function EmitCopies(inner: Node, a: int, t: int): seq<Inst>
    requires ValidN(inner) && t >= 0
    decreases inner, 3, t
  {
    if t == 0 then [] else Emit(inner, a) + EmitCopies(inner, a + Size(inner), t - 1)
  }
  // u optionals: split body,end ; body ; split body,end ; ...   (every split's second target is `end`)
  function EmitChain(inner: Node, L: int, u: int, end: int): seq<Inst>
    requires ValidN(inner) && u >= 0
    decreases inner, 3, u
  {
    if u == 0 then [] else [ISplit(L + 1, end)] + Emit(inner, L + 1) + EmitChain(inner, L + 1 + Size(inner), u - 1, end)
  }

  // Compile (safe-regex.ts compileSafeRegex after parsing): refuse when the program (incl. the final Match) exceeds 4096.
  // The TypeScript also aborts EARLY (an intermediate length > 4096); lengths only grow, so the final-size test is the same decision.
  function Compile(ast: Node): Option<Prog>
    requires ValidN(ast)
  {
    if Size(ast) + 1 > MAX_NFA_INSTRUCTIONS then None else Some(Emit(ast, 0) + [IMatch])
  }
  function CompileSrc(src: seq<int>): Option<Prog> {
    match Parse(src) {
      case None => None
      case Some(ast) => Compile(ast)
    }
  }

  // ---------------------------------------------------------------- instruction target discipline
  predicate InstTargetsIn(ins: Inst, pc: int, lo: int, hi: int) {
    match ins
    case ISet(_) => lo <= pc + 1 <= hi
    case ISplit(x, y) => lo <= x <= hi && lo <= y <= hi
    case IJmp(x) => lo <= x <= hi
    case IBol => lo <= pc + 1 <= hi
    case IEol => lo <= pc + 1 <= hi
    case IMatch => false   // a fragment never contains the final Match instruction
  }
  predicate TargetsIn(e: seq<Inst>, a: int, lo: int, hi: int) {
    forall k :: 0 <= k < |e| ==> InstTargetsIn(e[k], a + k, lo, hi)
  }
  lemma TargetsConcat(e1: seq<Inst>, e2: seq<Inst>, a: int, lo: int, hi: int)
    requires TargetsIn(e1, a, lo, hi) && TargetsIn(e2, a + |e1|, lo, hi)
    ensures TargetsIn(e1 + e2, a, lo, hi)
  {
    forall k | 0 <= k < |e1 + e2| ensures InstTargetsIn((e1 + e2)[k], a + k, lo, hi) {
      if k < |e1| { assert (e1 + e2)[k] == e1[k]; } else { assert (e1 + e2)[k] == e2[k - |e1|]; assert a + k == (a + |e1|) + (k - |e1|); }
    }
  }
  lemma TargetsMono(e: seq<Inst>, a: int, lo: int, hi: int, lo2: int, hi2: int)
    requires TargetsIn(e, a, lo, hi) && lo2 <= lo && hi <= hi2
    ensures TargetsIn(e, a, lo2, hi2)
  {}

  // ---------------------------------------------------------------- Emit: length and targets
  lemma EmitProps(n: Node, a: int)
    requires ValidN(n)
    ensures |Emit(n, a)| == Size(n) && Size(n) >= 0 && TargetsIn(Emit(n, a), a, a, a + Size(n))
    decreases n, 2
  {
    match n {
      case Set(cs) => {}
      case Bol => {}
      case Eol => {}
      case Cat(l) => EmitLProps(l, a);
      case Alt(l) => EmitAltProps(l, a);
      case Rep(inner, mn, mx) =>
        var S := Size(inner);
        EmitProps(inner, a);
        var L := a + mn * S;
        CopiesProps(inner, a, mn);
        assert S >= 0 && mn >= 0;
        assert mn * S >= 0 by { MulNonneg(mn, S); }
        if mx == -1 {
          EmitProps(inner, L + 1);
          var e1 := [ISplit(L + 1, L + S + 2)];
          var e2 := Emit(inner, L + 1);
          var e3 := [IJmp(L)];
          TargetsMono(e2, L + 1, L + 1, L + 1 + S, L, L + S + 2);
          assert TargetsIn(e1, L, L, L + S + 2);
          assert TargetsIn(e3, L + 1 + S, L, L + S + 2);
          TargetsConcat(e1, e2, L, L, L + S + 2);
          TargetsConcat(e1 + e2, e3, L, L, L + S + 2);
          TargetsMono(EmitCopies(inner, a, mn), a, a, L, a, L + S + 2);
          TargetsConcat(EmitCopies(inner, a, mn), e1 + e2 + e3, a, a, L + S + 2);
        } else {
          assert mx - mn >= 0;
          assert (mx - mn) * (S + 1) >= 0 by { MulNonneg(mx - mn, S + 1); }
          ChainProps(inner, L, mx - mn, L + (mx - mn) * (S + 1));
          TargetsMono(EmitCopies(inner, a, mn), a, a, L, a, L + (mx - mn) * (S + 1));
          TargetsConcat(EmitCopies(inner, a, mn), EmitChain(inner, L, mx - mn, L + (mx - mn) * (S + 1)), a, a, L + (mx - mn) * (S + 1));
        }
    }
  }
  lemma MulNonneg(x: int, y: int) requires x >= 0 && y >= 0 ensures x * y >= 0 {}

  lemma EmitLProps(l: NList, a: int)
    requires ValidL(l)
    ensures |EmitL(l, a)| == SizeL(l) && SizeL(l) >= 0 && TargetsIn(EmitL(l, a), a, a, a + SizeL(l))
    decreases l, 1
  {
    match l {
      case Nil => {}
      case Cons(h, t) =>
        EmitProps(h, a);
        EmitLProps(t, a + Size(h));
        TargetsMono(Emit(h, a), a, a, a + Size(h), a, a + SizeL(l));
        TargetsMono(EmitL(t, a + Size(h)), a + Size(h), a + Size(h), a + Size(h) + SizeL(t), a, a + SizeL(l));
        TargetsConcat(Emit(h, a), EmitL(t, a + Size(h)), a, a, a + SizeL(l));
    }
  }
  lemma EmitAltProps(l: NList, a: int)
    requires ValidL(l)
    ensures |EmitAlt(l, a)| == AltSize(l) && AltSize(l) >= 0 && TargetsIn(EmitAlt(l, a), a, a, a + AltSize(l))
    decreases l, 1
  {
    match l {
      case Nil => {}
      case Cons(h, t) =>
        if t.Nil? { EmitProps(h, a); }
        else {
          var Sh := Size(h);
          EmitProps(h, a + 1);
          EmitAltProps(t, a + Sh + 2);
          var end := a + AltSize(l);
          var e1 := [ISplit(a + 1, a + Sh + 2)];
          var e2 := Emit(h, a + 1);
          var e3 := [IJmp(end)];
          var e4 := EmitAlt(t, a + Sh + 2);
          assert TargetsIn(e1, a, a, end);
          TargetsMono(e2, a + 1, a + 1, a + 1 + Sh, a, end);
          assert TargetsIn(e3, a + 1 + Sh, a, end);
          TargetsMono(e4, a + Sh + 2, a + Sh + 2, a + Sh + 2 + AltSize(t), a, end);
          TargetsConcat(e1, e2, a, a, end);
          TargetsConcat(e1 + e2, e3, a, a, end);
          TargetsConcat(e1 + e2 + e3, e4, a, a, end);
        }
    }
  }
  lemma CopiesProps(inner: Node, a: int, t: int)
    requires ValidN(inner) && t >= 0
    ensures |EmitCopies(inner, a, t)| == t * Size(inner) && TargetsIn(EmitCopies(inner, a, t), a, a, a + t * Size(inner))
    decreases inner, 3, t
  {
    if t > 0 {
      var S := Size(inner);
      EmitProps(inner, a);
      CopiesProps(inner, a + S, t - 1);
      assert t * S == S + (t - 1) * S;
      TargetsMono(Emit(inner, a), a, a, a + S, a, a + t * S);
      TargetsMono(EmitCopies(inner, a + S, t - 1), a + S, a + S, a + S + (t - 1) * S, a, a + t * S);
      TargetsConcat(Emit(inner, a), EmitCopies(inner, a + S, t - 1), a, a, a + t * S);
    }
  }
  lemma ChainProps(inner: Node, L: int, u: int, end: int)
    requires ValidN(inner) && u >= 0 && end == L + u * (Size(inner) + 1)
    ensures |EmitChain(inner, L, u, end)| == u * (Size(inner) + 1) && TargetsIn(EmitChain(inner, L, u, end), L, L, end)
    decreases inner, 3, u
  {
    if u > 0 {
      var S := Size(inner);
      EmitProps(inner, L + 1);
      ChainProps(inner, L + 1 + S, u - 1, end);
      assert u * (S + 1) == (S + 1) + (u - 1) * (S + 1);
      var e1 := [ISplit(L + 1, end)];
      assert TargetsIn(e1, L, L, end);
      TargetsMono(Emit(inner, L + 1), L + 1, L + 1, L + 1 + S, L, end);
      TargetsMono(EmitChain(inner, L + 1 + S, u - 1, end), L + 1 + S, L + 1 + S, end, L, end);
      TargetsConcat(e1, Emit(inner, L + 1), L, L, end);
      TargetsConcat(e1 + Emit(inner, L + 1), EmitChain(inner, L + 1 + S, u - 1, end), L, L, end);
    }
  }

  // ---------------------------------------------------------------- 4. semantics and compile correctness
  // Denotational full-match semantics (position relation). i -> j means: n consumes s[i..j] (anchors look at absolute positions).
  ghost predicate Match(n: Node, s: seq<int>, i: int, j: int)
    decreases n, 0
  {
    match n
    case Set(cs) => 0 <= i < |s| && j == i + 1 && SetHas(cs, s[i])
    case Bol => i == 0 && j == 0
    case Eol => i == |s| && j == i
    case Cat(l) => MatchL(l, s, i, j)
    case Alt(l) => MatchAlt(l, s, i, j)
    case Rep(inner, mn, mx) => exists t: nat :: mn <= t && (mx == -1 || t <= mx) && Iter(inner, s, i, j, t)
  }
  ghost predicate MatchL(l: NList, s: seq<int>, i: int, j: int)
    decreases l, 0
  {
    match l
    case Nil => i == j
    case Cons(h, t) => exists k: int :: Match(h, s, i, k) && MatchL(t, s, k, j)
  }
  ghost predicate MatchAlt(l: NList, s: seq<int>, i: int, j: int)
    decreases l, 0
  {
    match l
    case Nil => false
    case Cons(h, t) => Match(h, s, i, j) || MatchAlt(t, s, i, j)
  }
  // t successive matches of inner
  ghost predicate Iter(inner: Node, s: seq<int>, i: int, j: int, t: nat)
    decreases inner, 1, t
  {
    if t == 0 then i == j else exists k: int :: Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1)
  }

  // "at most u iterations" (a named predicate so the quantifier is not restated inside other quantifiers)
  ghost predicate IterLe(inner: Node, s: seq<int>, i: int, j: int, u: nat) {
    exists t: nat :: t <= u && Iter(inner, s, i, j, t)
  }

  // Unfolding lemmas. The directional forms are proved by the solver directly; the iff forms are assembled from them
  // (an iff between two existentials over a recursive predicate is not found by the solver in one step).
  lemma IterF(inner: Node, s: seq<int>, i: int, j: int, t: nat)
    requires t > 0 && Iter(inner, s, i, j, t)
    ensures exists k: int :: Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1)
  {}
  lemma IterB(inner: Node, s: seq<int>, i: int, j: int, t: nat, k: int)
    requires t > 0 && Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1)
    ensures Iter(inner, s, i, j, t)
  {}
  lemma IterUnfold(inner: Node, s: seq<int>, i: int, j: int, t: nat)
    requires t > 0
    ensures Iter(inner, s, i, j, t) <==> exists k: int :: Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1)
  {
    if Iter(inner, s, i, j, t) { IterF(inner, s, i, j, t); }
    if exists k: int :: Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1) {
      var k :| Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1);
      IterB(inner, s, i, j, t, k);
    }
  }
  lemma MatchLF(l: NList, s: seq<int>, i: int, j: int)
    requires l.Cons? && MatchL(l, s, i, j)
    ensures exists k: int :: Match(l.hd, s, i, k) && MatchL(l.tl, s, k, j)
  {}
  lemma MatchLB(l: NList, s: seq<int>, i: int, j: int, k: int)
    requires l.Cons? && Match(l.hd, s, i, k) && MatchL(l.tl, s, k, j)
    ensures MatchL(l, s, i, j)
  {}
  lemma MatchLUnfold(l: NList, s: seq<int>, i: int, j: int)
    requires l.Cons?
    ensures MatchL(l, s, i, j) <==> exists k: int :: Match(l.hd, s, i, k) && MatchL(l.tl, s, k, j)
  {
    if MatchL(l, s, i, j) { MatchLF(l, s, i, j); }
    if exists k: int :: Match(l.hd, s, i, k) && MatchL(l.tl, s, k, j) {
      var k :| Match(l.hd, s, i, k) && MatchL(l.tl, s, k, j);
      MatchLB(l, s, i, j, k);
    }
  }
  lemma MatchAltUnfold(l: NList, s: seq<int>, i: int, j: int)
    requires l.Cons?
    ensures MatchAlt(l, s, i, j) <==> (Match(l.hd, s, i, j) || MatchAlt(l.tl, s, i, j))
  {}
  lemma MatchRepF(n: Node, s: seq<int>, i: int, j: int)
    requires n.Rep? && Match(n, s, i, j)
    ensures exists t: nat :: n.mn <= t && (n.mx == -1 || t <= n.mx) && Iter(n.inner, s, i, j, t)
  {}
  lemma MatchRepB(n: Node, s: seq<int>, i: int, j: int, t: nat)
    requires n.Rep? && n.mn <= t && (n.mx == -1 || t <= n.mx) && Iter(n.inner, s, i, j, t)
    ensures Match(n, s, i, j)
  {}
  lemma MatchRepUnfold(n: Node, s: seq<int>, i: int, j: int)
    requires n.Rep?
    ensures Match(n, s, i, j) <==> exists t: nat :: n.mn <= t && (n.mx == -1 || t <= n.mx) && Iter(n.inner, s, i, j, t)
  {
    if Match(n, s, i, j) { MatchRepF(n, s, i, j); }
    if exists t: nat :: n.mn <= t && (n.mx == -1 || t <= n.mx) && Iter(n.inner, s, i, j, t) {
      var t: nat :| n.mn <= t && (n.mx == -1 || t <= n.mx) && Iter(n.inner, s, i, j, t);
      MatchRepB(n, s, i, j, t);
    }
  }

  lemma IterAdd(inner: Node, s: seq<int>, i: int, j: int, t1: nat, t2: nat)
    ensures Iter(inner, s, i, j, t1 + t2) <==> exists k: int :: Iter(inner, s, i, k, t1) && Iter(inner, s, k, j, t2)
    decreases t1
  {
    if t1 == 0 {
      if Iter(inner, s, i, j, t2) { assert Iter(inner, s, i, i, 0); }
      if exists k: int :: Iter(inner, s, i, k, 0) && Iter(inner, s, k, j, t2) {
        var k :| Iter(inner, s, i, k, 0) && Iter(inner, s, k, j, t2);
        assert i == k;
      }
    } else {
      if Iter(inner, s, i, j, t1 + t2) {
        IterF(inner, s, i, j, t1 + t2);
        var k1 :| Match(inner, s, i, k1) && Iter(inner, s, k1, j, t1 - 1 + t2);
        IterAdd(inner, s, k1, j, t1 - 1, t2);
        var k :| Iter(inner, s, k1, k, t1 - 1) && Iter(inner, s, k, j, t2);
        IterB(inner, s, i, k, t1, k1);
        assert Iter(inner, s, i, k, t1) && Iter(inner, s, k, j, t2);
      }
      if exists k: int :: Iter(inner, s, i, k, t1) && Iter(inner, s, k, j, t2) {
        var k :| Iter(inner, s, i, k, t1) && Iter(inner, s, k, j, t2);
        IterF(inner, s, i, k, t1);
        var k1 :| Match(inner, s, i, k1) && Iter(inner, s, k1, k, t1 - 1);
        IterAdd(inner, s, k1, j, t1 - 1, t2);
        assert exists k2: int :: Iter(inner, s, k1, k2, t1 - 1) && Iter(inner, s, k2, j, t2) by {
          assert Iter(inner, s, k1, k, t1 - 1) && Iter(inner, s, k, j, t2);
        }
        IterB(inner, s, i, j, t1 + t2, k1);
      }
    }
  }

  // ---------------------------------------------------------------- path semantics of the program
  type Cfg = (int, int)   // (pc, position)

  ghost predicate StepR(P: Prog, s: seq<int>, c: Cfg, d: Cfg)
    requires 0 <= c.0 < |P|
  {
    match P[c.0]
    case ISet(cs) => c.1 < |s| && 0 <= c.1 && SetHas(cs, s[c.1]) && d == (c.0 + 1, c.1 + 1)
    case ISplit(x, y) => d.1 == c.1 && (d.0 == x || d.0 == y)
    case IJmp(x) => d == (x, c.1)
    case IBol => c.1 == 0 && d == (c.0 + 1, c.1)
    case IEol => c.1 == |s| && d == (c.0 + 1, c.1)
    case IMatch => false
  }
  // a path of exactly `len` steps from c to d, every step taken from a pc inside the window [a, b)
  ghost predicate WRn(P: Prog, s: seq<int>, a: int, b: int, c: Cfg, d: Cfg, len: nat)
    decreases len
  {
    if len == 0 then c == d
    else 0 <= a <= c.0 < b <= |P| && exists e: Cfg :: StepR(P, s, c, e) && WRn(P, s, a, b, e, d, len - 1)
  }
  ghost predicate WR(P: Prog, s: seq<int>, a: int, b: int, c: Cfg, d: Cfg) {
    exists len: nat :: WRn(P, s, a, b, c, d, len)
  }
  // every instruction in [a, b) only transfers control into [a, b]
  predicate ClosedW(P: Prog, a: int, b: int) {
    0 <= a && b <= |P| && forall pc :: a <= pc < b ==> InstTargetsIn(P[pc], pc, a, b)
  }
  predicate Embedded(P: Prog, e: seq<Inst>, a: int) {
    0 <= a && a + |e| <= |P| && forall k :: 0 <= k < |e| ==> P[a + k] == e[k]
  }

  lemma StepIn(P: Prog, s: seq<int>, c: Cfg, e: Cfg, lo: int, hi: int)
    requires 0 <= c.0 < |P| && StepR(P, s, c, e) && InstTargetsIn(P[c.0], c.0, lo, hi)
    ensures lo <= e.0 <= hi
  {}

  lemma WMono(P: Prog, s: seq<int>, a: int, b: int, a2: int, b2: int, c: Cfg, d: Cfg, len: nat)
    requires 0 <= a2 <= a && b <= b2 <= |P| && WRn(P, s, a, b, c, d, len)
    ensures WRn(P, s, a2, b2, c, d, len)
    decreases len
  {
    if len > 0 {
      var e :| StepR(P, s, c, e) && WRn(P, s, a, b, e, d, len - 1);
      WMono(P, s, a, b, a2, b2, e, d, len - 1);
    }
  }
  lemma WCat(P: Prog, s: seq<int>, a: int, b: int, c: Cfg, e: Cfg, d: Cfg, l1: nat, l2: nat)
    requires WRn(P, s, a, b, c, e, l1) && WRn(P, s, a, b, e, d, l2)
    ensures WRn(P, s, a, b, c, d, l1 + l2)
    decreases l1
  {
    if l1 > 0 {
      var m :| StepR(P, s, c, m) && WRn(P, s, a, b, m, e, l1 - 1);
      WCat(P, s, a, b, m, e, d, l1 - 1, l2);
    }
  }
  lemma WOut(P: Prog, s: seq<int>, a: int, b: int, c: Cfg, d: Cfg, len: nat)
    requires !(a <= c.0 < b) && WRn(P, s, a, b, c, d, len)
    ensures len == 0 && c == d
  {}
  // a path that leaves the closed piece [pa,pm) does so through the single point pm
  lemma SplitAt(P: Prog, s: seq<int>, wa: int, wb: int, pa: int, pm: int, c: Cfg, d: Cfg, len: nat)
    requires 0 <= wa <= pa <= pm <= wb <= |P| && ClosedW(P, pa, pm)
    requires pa <= c.0 <= pm && pm <= d.0 && WRn(P, s, wa, wb, c, d, len)
    ensures exists e: Cfg, l1: nat, l2: nat :: e.0 == pm && l1 + l2 == len && WRn(P, s, pa, pm, c, e, l1) && WRn(P, s, wa, wb, e, d, l2)
    decreases len
  {
    if c.0 == pm {
      assert WRn(P, s, pa, pm, c, c, 0);
    } else {
      assert len > 0;
      var e1 :| StepR(P, s, c, e1) && WRn(P, s, wa, wb, e1, d, len - 1);
      StepIn(P, s, c, e1, pa, pm);
      SplitAt(P, s, wa, wb, pa, pm, e1, d, len - 1);
      var e: Cfg, l1: nat, l2: nat :| e.0 == pm && l1 + l2 == len - 1 && WRn(P, s, pa, pm, e1, e, l1) && WRn(P, s, wa, wb, e, d, l2);
      assert WRn(P, s, pa, pm, c, e, l1 + 1);
    }
  }
  // confine a path that ends at wb to the later closed window [pm, wb)
  lemma Down(P: Prog, s: seq<int>, wa: int, wb: int, pm: int, c: Cfg, d: Cfg, len: nat)
    requires 0 <= wa <= pm <= wb <= |P| && ClosedW(P, pm, wb)
    requires pm <= c.0 <= wb && d.0 == wb && WRn(P, s, wa, wb, c, d, len)
    ensures WRn(P, s, pm, wb, c, d, len)
    decreases len
  {
    if len > 0 {
      var e1 :| StepR(P, s, c, e1) && WRn(P, s, wa, wb, e1, d, len - 1);
      StepIn(P, s, c, e1, pm, wb);
      Down(P, s, wa, wb, pm, e1, d, len - 1);
    }
  }
  lemma EmbTargets(P: Prog, e: seq<Inst>, a: int, lo: int, hi: int)
    requires Embedded(P, e, a) && TargetsIn(e, a, lo, hi)
    ensures forall pc :: a <= pc < a + |e| ==> InstTargetsIn(P[pc], pc, lo, hi)
  {
    forall pc | a <= pc < a + |e| ensures InstTargetsIn(P[pc], pc, lo, hi) {
      assert P[pc] == e[pc - a];
      assert InstTargetsIn(e[pc - a], a + (pc - a), lo, hi);
    }
  }
  lemma EmbClosed(P: Prog, e: seq<Inst>, a: int)
    requires Embedded(P, e, a) && TargetsIn(e, a, a, a + |e|)
    ensures ClosedW(P, a, a + |e|)
  { EmbTargets(P, e, a, a, a + |e|); }
  lemma EmbConcat(P: Prog, e1: seq<Inst>, e2: seq<Inst>, a: int)
    requires Embedded(P, e1 + e2, a)
    ensures Embedded(P, e1, a) && Embedded(P, e2, a + |e1|)
  {
    forall k | 0 <= k < |e2| ensures P[a + |e1| + k] == e2[k] { assert (e1 + e2)[|e1| + k] == e2[k]; }
    forall k | 0 <= k < |e1| ensures P[a + k] == e1[k] { assert (e1 + e2)[k] == e1[k]; }
  }
  lemma UseFrag(P: Prog, s: seq<int>, inner: Node, a: int)
    requires ValidN(inner) && FragAllP(P, s, inner) && Embedded(P, Emit(inner, a), a)
    ensures forall i: int, j: int :: (WR(P, s, a, a + Size(inner), (a, i), (a + Size(inner), j)) <==> Match(inner, s, i, j))
  {}
  lemma EmbConcatRev(P: Prog, e1: seq<Inst>, e2: seq<Inst>, a: int)
    requires Embedded(P, e1, a) && Embedded(P, e2, a + |e1|)
    ensures Embedded(P, e1 + e2, a)
  {
    forall k | 0 <= k < |e1 + e2| ensures P[a + k] == (e1 + e2)[k] {
      if k < |e1| { assert (e1 + e2)[k] == e1[k]; } else { assert (e1 + e2)[k] == e2[k - |e1|]; assert a + k == a + |e1| + (k - |e1|); }
    }
  }

  lemma ConcatWR(P: Prog, s: seq<int>, a: int, m: int, b: int, i: int, j: int)
    requires 0 <= a <= m <= b <= |P| && ClosedW(P, a, m) && ClosedW(P, m, b)
    ensures WR(P, s, a, b, (a, i), (b, j)) <==> exists k: int :: WR(P, s, a, m, (a, i), (m, k)) && WR(P, s, m, b, (m, k), (b, j))
  {
    if WR(P, s, a, b, (a, i), (b, j)) {
      var len: nat :| WRn(P, s, a, b, (a, i), (b, j), len);
      SplitAt(P, s, a, b, a, m, (a, i), (b, j), len);
      var e: Cfg, l1: nat, l2: nat :| e.0 == m && l1 + l2 == len && WRn(P, s, a, m, (a, i), e, l1) && WRn(P, s, a, b, e, (b, j), l2);
      Down(P, s, a, b, m, e, (b, j), l2);
      assert WR(P, s, a, m, (a, i), (m, e.1)) && WR(P, s, m, b, (m, e.1), (b, j));
    }
    if exists k: int :: WR(P, s, a, m, (a, i), (m, k)) && WR(P, s, m, b, (m, k), (b, j)) {
      var k: int :| WR(P, s, a, m, (a, i), (m, k)) && WR(P, s, m, b, (m, k), (b, j));
      var l1: nat :| WRn(P, s, a, m, (a, i), (m, k), l1);
      var l2: nat :| WRn(P, s, m, b, (m, k), (b, j), l2);
      WMono(P, s, a, m, a, b, (a, i), (m, k), l1);
      WMono(P, s, m, b, a, b, (m, k), (b, j), l2);
      WCat(P, s, a, b, (a, i), (m, k), (b, j), l1, l2);
    }
  }
  lemma OneStep(P: Prog, s: seq<int>, a: int, b: int, c: Cfg, e: Cfg, d: Cfg, len: nat)
    requires 0 <= a <= c.0 < b <= |P| && StepR(P, s, c, e) && WRn(P, s, a, b, e, d, len)
    ensures WRn(P, s, a, b, c, d, len + 1)
  {}
  lemma EmptyWindow(P: Prog, s: seq<int>, a: int, i: int, j: int)
    requires 0 <= a <= |P|
    ensures WR(P, s, a, a, (a, i), (a, j)) <==> i == j
  {
    if WR(P, s, a, a, (a, i), (a, j)) { var len: nat :| WRn(P, s, a, a, (a, i), (a, j), len); }
    if i == j { assert WRn(P, s, a, a, (a, i), (a, j), 0); }
  }

  // ---------------------------------------------------------------- fragment correctness (the compile theorem)
  ghost predicate FragAllP(P: Prog, s: seq<int>, n: Node)
    requires ValidN(n)
  {
    forall a: int :: Embedded(P, Emit(n, a), a) ==>
      forall i: int, j: int :: (WR(P, s, a, a + Size(n), (a, i), (a + Size(n), j)) <==> Match(n, s, i, j))
  }

  lemma FragAll(P: Prog, s: seq<int>, n: Node)
    requires ValidN(n)
    ensures FragAllP(P, s, n)
    decreases n, 3
  {
    forall a: int | Embedded(P, Emit(n, a), a)
      ensures forall i: int, j: int :: (WR(P, s, a, a + Size(n), (a, i), (a + Size(n), j)) <==> Match(n, s, i, j))
    { FragAt(P, s, n, a); }
  }

  lemma FragAt(P: Prog, s: seq<int>, n: Node, a: int)
    requires ValidN(n) && Embedded(P, Emit(n, a), a)
    ensures forall i: int, j: int :: (WR(P, s, a, a + Size(n), (a, i), (a + Size(n), j)) <==> Match(n, s, i, j))
    decreases n, 2
  {
    EmitProps(n, a);
    match n {
      case Set(cs) =>
        forall i: int, j: int ensures WR(P, s, a, a + 1, (a, i), (a + 1, j)) <==> Match(n, s, i, j) {
          assert Emit(n, a) == [ISet(cs)]; assert P[a + 0] == Emit(n, a)[0];
          assert P[a] == ISet(cs);
          if WR(P, s, a, a + 1, (a, i), (a + 1, j)) {
            var len: nat :| WRn(P, s, a, a + 1, (a, i), (a + 1, j), len);
            assert len > 0;
            var e :| StepR(P, s, (a, i), e) && WRn(P, s, a, a + 1, e, (a + 1, j), len - 1);
            WOut(P, s, a, a + 1, e, (a + 1, j), len - 1);
          }
          if Match(n, s, i, j) {
            assert StepR(P, s, (a, i), (a + 1, j));
            assert WRn(P, s, a, a + 1, (a + 1, j), (a + 1, j), 0);
            OneStep(P, s, a, a + 1, (a, i), (a + 1, j), (a + 1, j), 0);
          }
        }
      case Bol =>
        forall i: int, j: int ensures WR(P, s, a, a + 1, (a, i), (a + 1, j)) <==> Match(n, s, i, j) {
          assert Emit(n, a) == [IBol]; assert P[a + 0] == Emit(n, a)[0];
          assert P[a] == IBol;
          if WR(P, s, a, a + 1, (a, i), (a + 1, j)) {
            var len: nat :| WRn(P, s, a, a + 1, (a, i), (a + 1, j), len);
            assert len > 0;
            var e :| StepR(P, s, (a, i), e) && WRn(P, s, a, a + 1, e, (a + 1, j), len - 1);
            WOut(P, s, a, a + 1, e, (a + 1, j), len - 1);
          }
          if Match(n, s, i, j) {
            assert StepR(P, s, (a, i), (a + 1, j));
            assert WRn(P, s, a, a + 1, (a + 1, j), (a + 1, j), 0);
            OneStep(P, s, a, a + 1, (a, i), (a + 1, j), (a + 1, j), 0);
          }
        }
      case Eol =>
        forall i: int, j: int ensures WR(P, s, a, a + 1, (a, i), (a + 1, j)) <==> Match(n, s, i, j) {
          assert Emit(n, a) == [IEol]; assert P[a + 0] == Emit(n, a)[0];
          assert P[a] == IEol;
          if WR(P, s, a, a + 1, (a, i), (a + 1, j)) {
            var len: nat :| WRn(P, s, a, a + 1, (a, i), (a + 1, j), len);
            assert len > 0;
            var e :| StepR(P, s, (a, i), e) && WRn(P, s, a, a + 1, e, (a + 1, j), len - 1);
            WOut(P, s, a, a + 1, e, (a + 1, j), len - 1);
          }
          if Match(n, s, i, j) {
            assert StepR(P, s, (a, i), (a + 1, j));
            assert WRn(P, s, a, a + 1, (a + 1, j), (a + 1, j), 0);
            OneStep(P, s, a, a + 1, (a, i), (a + 1, j), (a + 1, j), 0);
          }
        }
      case Cat(l) => FragAtL(P, s, l, a);
      case Alt(l) => FragAtAlt(P, s, l, a);
      case Rep(inner, mn, mx) => FragAtRep(P, s, n, a);
    }
  }

  lemma FragAtL(P: Prog, s: seq<int>, l: NList, a: int)
    requires ValidL(l) && Embedded(P, EmitL(l, a), a)
    ensures forall i: int, j: int :: (WR(P, s, a, a + SizeL(l), (a, i), (a + SizeL(l), j)) <==> MatchL(l, s, i, j))
    decreases l, 1
  {
    EmitLProps(l, a);
    match l {
      case Nil =>
        forall i: int, j: int ensures WR(P, s, a, a, (a, i), (a, j)) <==> MatchL(l, s, i, j) { EmptyWindow(P, s, a, i, j); }
      case Cons(h, t) =>
        var m := a + Size(h);
        EmitProps(h, a);
        EmitLProps(t, m);
        EmbConcat(P, Emit(h, a), EmitL(t, m), a);
        FragAt(P, s, h, a);
        FragAtL(P, s, t, m);
        EmbClosed(P, Emit(h, a), a);
        EmbClosed(P, EmitL(t, m), m);
        forall i: int, j: int ensures WR(P, s, a, a + SizeL(l), (a, i), (a + SizeL(l), j)) <==> MatchL(l, s, i, j) {
          ConcatWR(P, s, a, m, a + SizeL(l), i, j);
          MatchLUnfold(l, s, i, j);
          if MatchL(l, s, i, j) {
            var k :| Match(h, s, i, k) && MatchL(t, s, k, j);
            assert WR(P, s, a, m, (a, i), (m, k)) by { assert Match(h, s, i, k); }
            assert WR(P, s, a, m, (a, i), (m, k)) && WR(P, s, m, a + SizeL(l), (m, k), (a + SizeL(l), j));
          }
          if WR(P, s, a, a + SizeL(l), (a, i), (a + SizeL(l), j)) {
            var k :| WR(P, s, a, m, (a, i), (m, k)) && WR(P, s, m, a + SizeL(l), (m, k), (a + SizeL(l), j));
            assert Match(h, s, i, k) && MatchL(t, s, k, j);
          }
        }
    }
  }

  lemma FragAtAlt(P: Prog, s: seq<int>, l: NList, a: int)
    requires ValidL(l) && l.Cons? && Embedded(P, EmitAlt(l, a), a)
    ensures forall i: int, j: int :: (WR(P, s, a, a + AltSize(l), (a, i), (a + AltSize(l), j)) <==> MatchAlt(l, s, i, j))
    decreases l, 1
  {
    EmitAltProps(l, a);
    var h := l.hd; var t := l.tl;
    if t.Nil? {
      FragAt(P, s, h, a);
    } else {
      var Sh := Size(h);
      var y := a + Sh + 2;
      var m := a + 1 + Sh;
      var end := a + AltSize(l);
      EmitProps(h, a + 1);
      EmitAltProps(t, y);
      assert end == y + AltSize(t);
      var e1 := [ISplit(a + 1, y)];
      var e2 := Emit(h, a + 1);
      var e3 := [IJmp(end)];
      var e4 := EmitAlt(t, y);
      assert EmitAlt(l, a) == e1 + e2 + e3 + e4;
      EmbConcat(P, e1 + e2 + e3, e4, a);
      EmbConcat(P, e1 + e2, e3, a);
      EmbConcat(P, e1, e2, a);
      assert P[a + 0] == e1[0];
      assert |e1 + e2| == 1 + Sh;
      assert P[a + |e1 + e2| + 0] == e3[0];
      assert P[a] == ISplit(a + 1, y);
      assert P[m] == IJmp(end);
      FragAt(P, s, h, a + 1);
      FragAtAlt(P, s, t, y);
      EmbClosed(P, e2, a + 1);
      EmbClosed(P, e4, y);
      forall i: int, j: int ensures WR(P, s, a, end, (a, i), (end, j)) <==> MatchAlt(l, s, i, j) {
        MatchAltUnfold(l, s, i, j);
        if WR(P, s, a, end, (a, i), (end, j)) {
          var len: nat :| WRn(P, s, a, end, (a, i), (end, j), len);
          assert len > 0;
          var f :| StepR(P, s, (a, i), f) && WRn(P, s, a, end, f, (end, j), len - 1);
          if f.0 == a + 1 {
            SplitAt(P, s, a, end, a + 1, m, f, (end, j), len - 1);
            var e: Cfg, l1: nat, l2: nat :| e.0 == m && l1 + l2 == len - 1 && WRn(P, s, a + 1, m, f, e, l1) && WRn(P, s, a, end, e, (end, j), l2);
            assert f == (a + 1, i);
            assert WR(P, s, a + 1, m, (a + 1, i), (m, e.1));
            assert Match(h, s, i, e.1);
            assert l2 > 0;
            var g :| StepR(P, s, e, g) && WRn(P, s, a, end, g, (end, j), l2 - 1);
            assert g == (end, e.1);
            WOut(P, s, a, end, g, (end, j), l2 - 1);
          } else {
            assert f == (y, i);
            Down(P, s, a, end, y, f, (end, j), len - 1);
            assert WR(P, s, y, end, (y, i), (end, j));
            assert MatchAlt(t, s, i, j);
          }
        }
        if MatchAlt(l, s, i, j) {
          if Match(h, s, i, j) {
            assert WR(P, s, a + 1, m, (a + 1, i), (m, j));
            var l1: nat :| WRn(P, s, a + 1, m, (a + 1, i), (m, j), l1);
            WMono(P, s, a + 1, m, a, end, (a + 1, i), (m, j), l1);
            assert StepR(P, s, (m, j), (end, j));
            assert WRn(P, s, a, end, (end, j), (end, j), 0);
            OneStep(P, s, a, end, (m, j), (end, j), (end, j), 0);
            WCat(P, s, a, end, (a + 1, i), (m, j), (end, j), l1, 1);
            assert StepR(P, s, (a, i), (a + 1, i));
            OneStep(P, s, a, end, (a, i), (a + 1, i), (end, j), l1 + 1);
          } else {
            assert WR(P, s, y, end, (y, i), (end, j));
            var l1: nat :| WRn(P, s, y, end, (y, i), (end, j), l1);
            WMono(P, s, y, end, a, end, (y, i), (end, j), l1);
            assert StepR(P, s, (a, i), (y, i));
            OneStep(P, s, a, end, (a, i), (y, i), (end, j), l1);
          }
        }
      }
    }
  }

  lemma CopiesFrag(P: Prog, s: seq<int>, inner: Node, a: int, t: nat)
    requires ValidN(inner) && Embedded(P, EmitCopies(inner, a, t), a) && FragAllP(P, s, inner)
    ensures forall i: int, j: int :: (WR(P, s, a, a + t * Size(inner), (a, i), (a + t * Size(inner), j)) <==> Iter(inner, s, i, j, t))
    decreases t
  {
    var S := Size(inner);
    EmitProps(inner, a);
    CopiesProps(inner, a, t);
    if t == 0 {
      forall i: int, j: int ensures WR(P, s, a, a, (a, i), (a, j)) <==> Iter(inner, s, i, j, 0) { EmptyWindow(P, s, a, i, j); }
    } else {
      assert t * S == S + (t - 1) * S;
      EmbConcat(P, Emit(inner, a), EmitCopies(inner, a + S, t - 1), a);
      CopiesFrag(P, s, inner, a + S, t - 1);
      EmbClosed(P, Emit(inner, a), a);
      CopiesProps(inner, a + S, t - 1);
      EmbClosed(P, EmitCopies(inner, a + S, t - 1), a + S);
      var b := a + t * S;
      forall i: int, j: int ensures WR(P, s, a, b, (a, i), (b, j)) <==> Iter(inner, s, i, j, t) {
        ConcatWR(P, s, a, a + S, b, i, j);
        if Iter(inner, s, i, j, t) {
          IterF(inner, s, i, j, t);
          var k :| Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1);
          assert WR(P, s, a, a + S, (a, i), (a + S, k)) && WR(P, s, a + S, b, (a + S, k), (b, j));
        }
        if WR(P, s, a, b, (a, i), (b, j)) {
          var k :| WR(P, s, a, a + S, (a, i), (a + S, k)) && WR(P, s, a + S, b, (a + S, k), (b, j));
          assert Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1);
        }
      }
    }
  }

  lemma LoopBwd(P: Prog, s: seq<int>, inner: Node, L: int, i: int, j: int, t: nat)
    requires ValidN(inner) && FragAllP(P, s, inner)
    requires Embedded(P, [ISplit(L + 1, L + Size(inner) + 2)] + Emit(inner, L + 1) + [IJmp(L)], L)
    requires Iter(inner, s, i, j, t)
    ensures WR(P, s, L, L + Size(inner) + 2, (L, i), (L + Size(inner) + 2, j))
    decreases t
  {
    var S := Size(inner);
    var E := L + S + 2;
    EmitProps(inner, L + 1);
    var e1 := [ISplit(L + 1, E)];
    var e2 := Emit(inner, L + 1);
    var e3 := [IJmp(L)];
    EmbConcat(P, e1 + e2, e3, L);
    EmbConcat(P, e1, e2, L);
    assert P[L + 0] == e1[0];
    assert |e1 + e2| == 1 + S;
    assert P[L + |e1 + e2| + 0] == e3[0];
    assert P[L] == ISplit(L + 1, E);
    assert P[L + 1 + S] == IJmp(L);
    if t == 0 {
      assert StepR(P, s, (L, i), (E, i));
      assert WRn(P, s, L, E, (E, i), (E, j), 0);
      OneStep(P, s, L, E, (L, i), (E, i), (E, j), 0);
    } else {
      var k :| Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1);
      LoopBwd(P, s, inner, L, k, j, t - 1);
      UseFrag(P, s, inner, L + 1);
      assert WR(P, s, L + 1, L + 1 + S, (L + 1, i), (L + 1 + S, k));
      var l1: nat :| WRn(P, s, L + 1, L + 1 + S, (L + 1, i), (L + 1 + S, k), l1);
      WMono(P, s, L + 1, L + 1 + S, L, E, (L + 1, i), (L + 1 + S, k), l1);
      var l2: nat :| WRn(P, s, L, E, (L, k), (E, j), l2);
      OneStep(P, s, L, E, (L + 1 + S, k), (L, k), (E, j), l2);
      WCat(P, s, L, E, (L + 1, i), (L + 1 + S, k), (E, j), l1, l2 + 1);
      assert StepR(P, s, (L, i), (L + 1, i));
      OneStep(P, s, L, E, (L, i), (L + 1, i), (E, j), l1 + (l2 + 1));
    }
  }
  lemma LoopFwd(P: Prog, s: seq<int>, inner: Node, L: int, i: int, j: int, len: nat)
    requires ValidN(inner) && FragAllP(P, s, inner)
    requires Embedded(P, [ISplit(L + 1, L + Size(inner) + 2)] + Emit(inner, L + 1) + [IJmp(L)], L)
    requires WRn(P, s, L, L + Size(inner) + 2, (L, i), (L + Size(inner) + 2, j), len)
    ensures exists t: nat :: Iter(inner, s, i, j, t)
    decreases len
  {
    var S := Size(inner);
    var E := L + S + 2;
    EmitProps(inner, L + 1);
    var e1 := [ISplit(L + 1, E)];
    var e2 := Emit(inner, L + 1);
    var e3 := [IJmp(L)];
    EmbConcat(P, e1 + e2, e3, L);
    EmbConcat(P, e1, e2, L);
    assert P[L + 0] == e1[0];
    assert |e1 + e2| == 1 + S;
    assert P[L + |e1 + e2| + 0] == e3[0];
    assert P[L] == ISplit(L + 1, E);
    assert P[L + 1 + S] == IJmp(L);
    assert len > 0;
    var f :| StepR(P, s, (L, i), f) && WRn(P, s, L, E, f, (E, j), len - 1);
    if f.0 == E {
      WOut(P, s, L, E, f, (E, j), len - 1);
      assert Iter(inner, s, i, j, 0);
    } else {
      assert f == (L + 1, i);
      EmbClosed(P, e2, L + 1);
      var m := L + 1 + S;
      SplitAt(P, s, L, E, L + 1, m, f, (E, j), len - 1);
      var e: Cfg, l1: nat, l2: nat :| e.0 == m && l1 + l2 == len - 1 && WRn(P, s, L + 1, m, f, e, l1) && WRn(P, s, L, E, e, (E, j), l2);
      UseFrag(P, s, inner, L + 1);
      assert WR(P, s, L + 1, L + 1 + S, (L + 1, i), (L + 1 + S, e.1));
      assert Match(inner, s, i, e.1);
      assert l2 > 0;
      var g :| StepR(P, s, e, g) && WRn(P, s, L, E, g, (E, j), l2 - 1);
      assert g == (L, e.1);
      LoopFwd(P, s, inner, L, e.1, j, l2 - 1);
      var t: nat :| Iter(inner, s, e.1, j, t);
      assert Iter(inner, s, i, j, t + 1);
    }
  }

  lemma ChainFrag0At(P: Prog, s: seq<int>, inner: Node, L: int, E: int, i: int, j: int)
    requires ValidN(inner) && 0 <= L <= |P| && E == L
    ensures WR(P, s, L, E, (L, i), (E, j)) <==> IterLe(inner, s, i, j, 0)
  {
    EmptyWindow(P, s, L, i, j);
    if i == j {
      assert Iter(inner, s, i, j, 0);
      assert IterLe(inner, s, i, j, 0);
    }
    if IterLe(inner, s, i, j, 0) {
      var t: nat :| t <= 0 && Iter(inner, s, i, j, t);
      assert t == 0;
      assert i == j;
    }
  }
  lemma ChainFragAt(P: Prog, s: seq<int>, inner: Node, L: int, u: nat, E: int, i: int, j: int)
    requires ValidN(inner) && FragAllP(P, s, inner) && E == L + u * (Size(inner) + 1)
    requires Embedded(P, EmitChain(inner, L, u, E), L)
    ensures WR(P, s, L, E, (L, i), (E, j)) <==> IterLe(inner, s, i, j, u)
    decreases u
  {
    var S := Size(inner);
    EmitProps(inner, L + 1);
    ChainProps(inner, L, u, E);
    if u == 0 {
      assert E == L;
      ChainFrag0At(P, s, inner, L, E, i, j);
    } else {
      var m := L + 1 + S;
      assert u * (S + 1) == (S + 1) + (u - 1) * (S + 1);
      assert E == m + (u - 1) * (S + 1);
      var e1 := [ISplit(L + 1, E)];
      var e2 := Emit(inner, L + 1);
      var e3 := EmitChain(inner, m, u - 1, E);
      assert EmitChain(inner, L, u, E) == e1 + e2 + e3;
      EmbConcat(P, e1 + e2, e3, L);
      EmbConcat(P, e1, e2, L);
      assert P[L + 0] == e1[0];
      assert P[L] == ISplit(L + 1, E);
      ChainProps(inner, m, u - 1, E);
      EmbClosed(P, e2, L + 1);
      assert ClosedW(P, m, E) by { EmbTargets(P, e3, m, m, E); }
      UseFrag(P, s, inner, L + 1);
      if WR(P, s, L, E, (L, i), (E, j)) {
        var len: nat :| WRn(P, s, L, E, (L, i), (E, j), len);
        assert len > 0;
        var f :| StepR(P, s, (L, i), f) && WRn(P, s, L, E, f, (E, j), len - 1);
        if f.0 == E {
          WOut(P, s, L, E, f, (E, j), len - 1);
          assert Iter(inner, s, i, j, 0);
          assert IterLe(inner, s, i, j, u);
        } else {
          assert f == (L + 1, i);
          SplitAt(P, s, L, E, L + 1, m, f, (E, j), len - 1);
          var e: Cfg, l1: nat, l2: nat :| e.0 == m && l1 + l2 == len - 1 && WRn(P, s, L + 1, m, f, e, l1) && WRn(P, s, L, E, e, (E, j), l2);
          assert WR(P, s, L + 1, m, (L + 1, i), (m, e.1));
          assert Match(inner, s, i, e.1);
          Down(P, s, L, E, m, e, (E, j), l2);
          assert WR(P, s, m, E, (m, e.1), (E, j));
          ChainFragAt(P, s, inner, m, u - 1, E, e.1, j);
          var t0: nat :| t0 <= u - 1 && Iter(inner, s, e.1, j, t0);
          IterB(inner, s, i, j, t0 + 1, e.1);
          assert IterLe(inner, s, i, j, u);
        }
      }
      if IterLe(inner, s, i, j, u) {
        var t: nat :| t <= u && Iter(inner, s, i, j, t);
        if t == 0 {
          assert StepR(P, s, (L, i), (E, i));
          assert WRn(P, s, L, E, (E, i), (E, j), 0);
          OneStep(P, s, L, E, (L, i), (E, i), (E, j), 0);
        } else {
          IterF(inner, s, i, j, t);
          var k :| Match(inner, s, i, k) && Iter(inner, s, k, j, t - 1);
          ChainFragAt(P, s, inner, m, u - 1, E, k, j);
          assert IterLe(inner, s, k, j, u - 1) by { assert t - 1 <= u - 1 && Iter(inner, s, k, j, t - 1); }
          assert WR(P, s, m, E, (m, k), (E, j));
          assert WR(P, s, L + 1, m, (L + 1, i), (m, k));
          var l1: nat :| WRn(P, s, L + 1, m, (L + 1, i), (m, k), l1);
          WMono(P, s, L + 1, m, L, E, (L + 1, i), (m, k), l1);
          var l2: nat :| WRn(P, s, m, E, (m, k), (E, j), l2);
          WMono(P, s, m, E, L, E, (m, k), (E, j), l2);
          WCat(P, s, L, E, (L + 1, i), (m, k), (E, j), l1, l2);
          assert StepR(P, s, (L, i), (L + 1, i));
          OneStep(P, s, L, E, (L, i), (L + 1, i), (E, j), l1 + l2);
        }
      }
    }
  }
  lemma ChainFrag(P: Prog, s: seq<int>, inner: Node, L: int, u: nat, E: int)
    requires ValidN(inner) && FragAllP(P, s, inner) && E == L + u * (Size(inner) + 1)
    requires Embedded(P, EmitChain(inner, L, u, E), L)
    ensures forall i: int, j: int :: (WR(P, s, L, E, (L, i), (E, j)) <==> IterLe(inner, s, i, j, u))
  {
    forall i: int, j: int { ChainFragAt(P, s, inner, L, u, E, i, j); }
  }

  lemma FragAtRep(P: Prog, s: seq<int>, n: Node, a: int)
    requires ValidN(n) && n.Rep? && Embedded(P, Emit(n, a), a)
    ensures forall i: int, j: int :: (WR(P, s, a, a + Size(n), (a, i), (a + Size(n), j)) <==> Match(n, s, i, j))
    decreases n, 1
  {
    var inner := n.inner; var mn := n.mn; var mx := n.mx;
    var S := Size(inner);
    var L := a + mn * S;
    EmitProps(inner, a);
    assert mn * S >= 0 by { MulNonneg(mn, S); }
    FragAll(P, s, inner);
    var C := EmitCopies(inner, a, mn);
    CopiesProps(inner, a, mn);
    var T := if mx == -1 then [ISplit(L + 1, L + S + 2)] + Emit(inner, L + 1) + [IJmp(L)]
             else EmitChain(inner, L, mx - mn, L + (mx - mn) * (S + 1));
    assert Emit(n, a) == C + T;
    EmbConcat(P, C, T, a);
    CopiesFrag(P, s, inner, a, mn);
    EmbClosed(P, C, a);
    var end := a + Size(n);
    if mx == -1 {
      EmitProps(inner, L + 1);
      assert end == L + S + 2;
      assert TargetsIn(T, L, L, end) by {
        var e1 := [ISplit(L + 1, L + S + 2)];
        var e2 := Emit(inner, L + 1);
        var e3 := [IJmp(L)];
        TargetsMono(e2, L + 1, L + 1, L + 1 + S, L, L + S + 2);
        TargetsConcat(e1, e2, L, L, L + S + 2);
        TargetsConcat(e1 + e2, e3, L, L, L + S + 2);
      }
      EmbClosed(P, T, L);
      forall i: int, j: int ensures WR(P, s, a, end, (a, i), (end, j)) <==> Match(n, s, i, j) {
        ConcatWR(P, s, a, L, end, i, j);
        MatchRepUnfold(n, s, i, j);
        if Match(n, s, i, j) {
          var t: nat :| mn <= t && Iter(inner, s, i, j, t);
          IterAdd(inner, s, i, j, mn, t - mn);
          var k :| Iter(inner, s, i, k, mn) && Iter(inner, s, k, j, t - mn);
          LoopBwd(P, s, inner, L, k, j, t - mn);
          assert WR(P, s, a, L, (a, i), (L, k)) && WR(P, s, L, end, (L, k), (end, j));
        }
        if WR(P, s, a, end, (a, i), (end, j)) {
          var k :| WR(P, s, a, L, (a, i), (L, k)) && WR(P, s, L, end, (L, k), (end, j));
          var len: nat :| WRn(P, s, L, end, (L, k), (end, j), len);
          LoopFwd(P, s, inner, L, k, j, len);
          var t0: nat :| Iter(inner, s, k, j, t0);
          assert WR(P, s, a, a + mn * S, (a, i), (a + mn * S, k));
          assert Iter(inner, s, i, k, mn);
          IterAdd(inner, s, i, j, mn, t0);
          assert Iter(inner, s, i, j, mn + t0);
          MatchRepB(n, s, i, j, mn + t0);
        }
      }
    } else {
      var u := mx - mn;
      assert end == L + u * (S + 1);
      ChainFrag(P, s, inner, L, u, end);
      ChainProps(inner, L, u, end);
      assert ClosedW(P, L, end) by { EmbTargets(P, T, L, L, end); }
      forall i: int, j: int ensures WR(P, s, a, end, (a, i), (end, j)) <==> Match(n, s, i, j) {
        ConcatWR(P, s, a, L, end, i, j);
        MatchRepUnfold(n, s, i, j);
        if Match(n, s, i, j) {
          var t: nat :| mn <= t <= mx && Iter(inner, s, i, j, t);
          IterAdd(inner, s, i, j, mn, t - mn);
          var k :| Iter(inner, s, i, k, mn) && Iter(inner, s, k, j, t - mn);
          assert WR(P, s, a, L, (a, i), (L, k)) && WR(P, s, L, end, (L, k), (end, j));
        }
        if WR(P, s, a, end, (a, i), (end, j)) {
          var k :| WR(P, s, a, L, (a, i), (L, k)) && WR(P, s, L, end, (L, k), (end, j));
          var t0: nat :| t0 <= u && Iter(inner, s, k, j, t0);
          assert WR(P, s, a, a + mn * S, (a, i), (a + mn * S, k));
          assert Iter(inner, s, i, k, mn);
          IterAdd(inner, s, i, j, mn, t0);
          assert Iter(inner, s, i, j, mn + t0);
          MatchRepB(n, s, i, j, mn + t0);
        }
      }
    }
  }

  // ---------------------------------------------------------------- compile correctness (top level)
  // The program accepts s iff some path from (0,0) reaches an IMatch instruction at the end of the subject.
  ghost predicate Accepts(P: Prog, s: seq<int>) {
    exists c: Cfg, len: nat :: WRn(P, s, 0, |P|, (0, 0), c, len) && c.1 == |s| && 0 <= c.0 < |P| && P[c.0].IMatch?
  }

  lemma TargetsNoMatch(e: seq<Inst>, a: int, lo: int, hi: int)
    requires TargetsIn(e, a, lo, hi)
    ensures forall k :: 0 <= k < |e| ==> !e[k].IMatch?
  {}

  lemma CompileCorrect(ast: Node, s: seq<int>, P: Prog)
    requires ValidN(ast) && Compile(ast) == Some(P)
    ensures Accepts(P, s) <==> Match(ast, s, 0, |s|)
  {
    var L := Size(ast);
    EmitProps(ast, 0);
    assert P == Emit(ast, 0) + [IMatch];
    assert |P| == L + 1;
    assert P[L] == IMatch;
    assert Embedded(P, Emit(ast, 0), 0);
    EmbClosed(P, Emit(ast, 0), 0);
    TargetsNoMatch(Emit(ast, 0), 0, 0, L);
    FragAt(P, s, ast, 0);
    if Match(ast, s, 0, |s|) {
      assert WR(P, s, 0, L, (0, 0), (L, |s|));
      var len: nat :| WRn(P, s, 0, L, (0, 0), (L, |s|), len);
      WMono(P, s, 0, L, 0, |P|, (0, 0), (L, |s|), len);
      assert WRn(P, s, 0, |P|, (0, 0), (L, |s|), len) && (L, |s|).1 == |s| && P[L].IMatch?;
    }
    if Accepts(P, s) {
      var c: Cfg, len: nat :| WRn(P, s, 0, |P|, (0, 0), c, len) && c.1 == |s| && 0 <= c.0 < |P| && P[c.0].IMatch?;
      assert c.0 == L by { if c.0 < L { assert P[c.0] == Emit(ast, 0)[c.0]; } }
      SplitAt(P, s, 0, |P|, 0, L, (0, 0), c, len);
      var e: Cfg, l1: nat, l2: nat :| e.0 == L && l1 + l2 == len && WRn(P, s, 0, L, (0, 0), e, l1) && WRn(P, s, 0, |P|, e, c, l2);
      if l2 > 0 { var f :| StepR(P, s, e, f); assert P[e.0] == IMatch; }
      assert l2 == 0 && e == c;
      assert WR(P, s, 0, L, (0, 0), (L, |s|));
    }
  }

  // Well-formed program: every control transfer lands inside the program (so the simulation never indexes out of range).
  predicate WFProg(P: Prog) {
    forall pc :: 0 <= pc < |P| ==> P[pc].IMatch? || InstTargetsIn(P[pc], pc, 0, |P| - 1)
  }
  lemma CompileWF(ast: Node, P: Prog)
    requires ValidN(ast) && Compile(ast) == Some(P)
    ensures WFProg(P) && |P| == Size(ast) + 1 && |P| <= MAX_NFA_INSTRUCTIONS && P[|P| - 1] == IMatch
  {
    var L := Size(ast);
    EmitProps(ast, 0);
    assert P == Emit(ast, 0) + [IMatch];
    forall pc | 0 <= pc < |P| ensures P[pc].IMatch? || InstTargetsIn(P[pc], pc, 0, |P| - 1) {
      if pc < L { assert P[pc] == Emit(ast, 0)[pc]; assert InstTargetsIn(Emit(ast, 0)[pc], 0 + pc, 0, L); }
    }
  }

  // ---------------------------------------------------------------- refusal lemmas (each unsupported construct class is refused)
  predicate HandledEscapeChar(c: int) {   // letters/digits that EscapeInner understands
    c in {0x64, 0x44, 0x77, 0x57, 0x73, 0x53, 0x74, 0x6e, 0x76, 0x66, 0x72, 0x30, 0x78, 0x75, 0x63, 0x62}
  }
  // any other letter, digit or underscore after a backslash is refused: back-references \1-\9, \B, \k, \p, \P, \_ ...
  lemma EscapeRefusesUnsupported(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s|
    requires (IsAlnum(s[i + 1]) || s[i + 1] == 0x5f) && !HandledEscapeChar(s[i + 1])
    ensures EscapeInner(s, i, inClass) == PRef
  {}
  lemma BackrefRefused(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s| && 0x31 <= s[i + 1] <= 0x39     // \1 .. \9
    ensures EscapeInner(s, i, inClass) == PRef
  { EscapeRefusesUnsupported(s, i, inClass); }
  lemma NamedBackrefRefused(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s| && s[i + 1] == 0x6b          // \k<name>
    ensures EscapeInner(s, i, inClass) == PRef
  { EscapeRefusesUnsupported(s, i, inClass); }
  lemma UnicodePropertyRefused(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s| && (s[i + 1] == 0x70 || s[i + 1] == 0x50)   // \p \P
    ensures EscapeInner(s, i, inClass) == PRef
  { EscapeRefusesUnsupported(s, i, inClass); }
  lemma NonWordBoundaryRefused(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s| && s[i + 1] == 0x42          // \B
    ensures EscapeInner(s, i, inClass) == PRef
  { EscapeRefusesUnsupported(s, i, inClass); }
  lemma WordBoundaryRefused(s: seq<int>, i: int)                                      // \b outside a class
    requires 0 <= i < |s| && s[i] == BS && i + 1 < |s| && s[i + 1] == 0x62
    ensures EscapeInner(s, i, false) == PRef
  {}
  lemma TrailingBackslashRefused(s: seq<int>, i: int, inClass: bool)
    requires 0 <= i < |s| && s[i] == BS && i + 1 == |s|
    ensures EscapeInner(s, i, inClass) == PRef
  {}
  lemma OctalEscapeRefused(s: seq<int>, i: int, inClass: bool)                         // \00 .. \09
    requires 0 <= i < |s| && s[i] == BS && i + 2 < |s| && s[i + 1] == 0x30 && IsDigit(s[i + 2])
    ensures EscapeInner(s, i, inClass) == PRef
  {}
  // lookahead (?= (?!, lookbehind (?<= (?<! and named groups (?<n>...) : a group opener `(?` not followed by `:` is refused
  lemma GroupExtensionRefused(s: seq<int>, i: int)
    requires 0 <= i < |s| && s[i] == LP && i + 1 < |s| && s[i + 1] == QM && !(i + 2 < |s| && s[i + 2] == COLON)
    ensures ParseAtom(s, i) == PRef
  {}
  // a quantifier with nothing to repeat
  lemma BareQuantifierRefused(s: seq<int>, i: int)
    requires 0 <= i < |s| && (s[i] == STAR || s[i] == PLUS || s[i] == QM || s[i] == LC)
    ensures ParseAtom(s, i) == PRef
  {}
  // a `{` after an atom that is not a well-formed {n} {n,} {n,m} (digits 1..4, ordered) is refused
  lemma MalformedBraceRefused(s: seq<int>, i: int)
    requires 0 <= i < |s| && ParseAtom(s, i).POk? && ParseAtom(s, i).i < |s| && s[ParseAtom(s, i).i] == LC
    requires ParseBrace(s, ParseAtom(s, i).i) == QBad
    ensures ParseQuantified(s, i) == PRef
  {}
  // a quantified anchor (^* $+ ^{2} ...) is refused
  lemma QuantifiedAssertionRefused(s: seq<int>, i: int)
    requires 0 <= i && i + 1 < |s| && (s[i] == CARET || s[i] == DOLLAR) && (s[i + 1] == STAR || s[i + 1] == PLUS || s[i + 1] == QM)
    ensures ParseQuantified(s, i) == PRef
  {}
  // an over-large repeat bound ({65} {0,65} {65,}) is refused
  lemma RepeatBoundRefused(s: seq<int>, i: int, k: int)
    requires 0 <= i < |s| && ParseAtom(s, i).POk? && ParseAtom(s, i).i < |s| && s[ParseAtom(s, i).i] == LC
    requires ParseBrace(s, ParseAtom(s, i).i).Q? && (ParseBrace(s, ParseAtom(s, i).i).mn > MAX_REPEAT || ParseBrace(s, ParseAtom(s, i).i).mx > MAX_REPEAT)
    requires !ParseAtom(s, i).v.Bol? && !ParseAtom(s, i).v.Eol?
    ensures ParseQuantified(s, i) == PRef
  {}
  // doubled quantifiers (a** a+* a{2}{3} a*+ ...) are refused
  lemma DoubledQuantifierRefused(s: seq<int>, i: int)
    requires 0 <= i < |s| && ParseAtom(s, i).POk? && ParseAtom(s, i).i < |s| && (s[ParseAtom(s, i).i] == STAR) && ParseAtom(s, i).i + 1 < |s|
    requires s[ParseAtom(s, i).i + 1] == STAR || s[ParseAtom(s, i).i + 1] == PLUS || s[ParseAtom(s, i).i + 1] == LC
    ensures ParseQuantified(s, i) == PRef
  {}
  // a stray `)` (unbalanced) can never be consumed by the top level
  lemma UnbalancedCloseRefused(s: seq<int>)
    requires |s| >= 1 && s[0] == RP
    ensures Parse(s) == None
  {
    assert ParseCat(s, 0) == POk(Nil, 0);
    assert ParseAltTail(s, 0) == POk(Nil, 0);
    assert ParseAlt(s, 0) == POk(Cat(Nil), 0);
  }
  // a refused first atom refuses the whole pattern (the refusal propagates through cat / quantified / alt)
  lemma TopRefuse(s: seq<int>)
    requires |s| >= 1 && s[0] != BAR && s[0] != RP && ParseAtom(s, 0) == PRef
    ensures Parse(s) == None
  {
    assert ParseQuantified(s, 0) == PRef;
    assert ParseCat(s, 0) == PRef;
    assert ParseAlt(s, 0) == PRef;
  }
  // whole-pattern forms: the refusal propagates to the top level
  lemma TopLevelRefusals(s: seq<int>)
    requires |s| >= 2
    ensures s[0] == LP && s[1] == QM && !(2 < |s| && s[2] == COLON) ==> Parse(s) == None
    ensures s[0] == BS && 0x31 <= s[1] <= 0x39 ==> Parse(s) == None
    ensures s[0] == BS && s[1] == 0x62 ==> Parse(s) == None
    ensures s[0] == BS && s[1] == 0x42 ==> Parse(s) == None
    ensures s[0] == BS && (s[1] == 0x70 || s[1] == 0x50) ==> Parse(s) == None
    ensures s[0] == BS && s[1] == 0x6b ==> Parse(s) == None
    ensures s[0] == STAR || s[0] == PLUS || s[0] == QM || s[0] == LC ==> Parse(s) == None
  {
    if s[0] == LP && s[1] == QM && !(2 < |s| && s[2] == COLON) { GroupExtensionRefused(s, 0); TopRefuse(s); }
    if s[0] == BS && 0x31 <= s[1] <= 0x39 { BackrefRefused(s, 0, false); assert ParseAtom(s, 0) == PRef; TopRefuse(s); }
    if s[0] == BS && s[1] == 0x62 { WordBoundaryRefused(s, 0); assert ParseAtom(s, 0) == PRef; TopRefuse(s); }
    if s[0] == BS && s[1] == 0x42 { NonWordBoundaryRefused(s, 0, false); assert ParseAtom(s, 0) == PRef; TopRefuse(s); }
    if s[0] == BS && (s[1] == 0x70 || s[1] == 0x50) { UnicodePropertyRefused(s, 0, false); assert ParseAtom(s, 0) == PRef; TopRefuse(s); }
    if s[0] == BS && s[1] == 0x6b { NamedBackrefRefused(s, 0, false); assert ParseAtom(s, 0) == PRef; TopRefuse(s); }
    if s[0] == STAR || s[0] == PLUS || s[0] == QM || s[0] == LC { BareQuantifierRefused(s, 0); TopRefuse(s); }
  }

  // The accepted language is exactly the subset: whatever Parse returns is a ValidN, repeat-bounded Node (the type is the subset),
  // and a source is compiled only if the program is within the 4096-instruction cap (fail closed on larger).
  lemma ParseSound(s: seq<int>)
    ensures Parse(s).Some? ==> ValidN(Parse(s).v) && BoundedN(Parse(s).v)
  {}
  lemma CompileCapFailsClosed(ast: Node)
    requires ValidN(ast) && Size(ast) + 1 > MAX_NFA_INSTRUCTIONS
    ensures Compile(ast) == None
  {}
  lemma CompileCapRespected(ast: Node, P: Prog)
    requires ValidN(ast) && Compile(ast) == Some(P)
    ensures |P| <= MAX_NFA_INSTRUCTIONS
  { EmitProps(ast, 0); }
  // Size is linear in the AST except for the (capped) multiplication of nested counted repeats; for a node without Rep it is
  // exactly the node count + 2 per extra alternative.
  lemma SizeOfSetIsOne(cs: CharSet) ensures Size(Set(cs)) == 1 {}

  // ---------------------------------------------------------------- 5. the Pike simulation
  // Reachability of a configuration from (0,0) in the whole program.
  ghost predicate Reachable(P: Prog, s: seq<int>, pc: int, k: int) {
    exists len: nat :: WRn(P, s, 0, |P|, (0, 0), (pc, k), len)
  }
  lemma WSnoc(P: Prog, s: seq<int>, c: Cfg, d: Cfg, e: Cfg, len: nat)
    requires WRn(P, s, 0, |P|, c, d, len) && 0 <= d.0 < |P| && StepR(P, s, d, e)
    ensures WRn(P, s, 0, |P|, c, e, len + 1)
    decreases len
  {
    if len == 0 {
      assert WRn(P, s, 0, |P|, e, e, 0);
      OneStep(P, s, 0, |P|, c, e, e, 0);
    } else {
      var c1 :| StepR(P, s, c, c1) && WRn(P, s, 0, |P|, c1, d, len - 1);
      WSnoc(P, s, c1, d, e, len - 1);
      OneStep(P, s, 0, |P|, c, c1, e, len);
    }
  }
  lemma ReachSnoc(P: Prog, s: seq<int>, pc: int, k: int, z: int, k2: int)
    requires Reachable(P, s, pc, k) && 0 <= pc < |P| && StepR(P, s, (pc, k), (z, k2))
    ensures Reachable(P, s, z, k2)
  {
    var len: nat :| WRn(P, s, 0, |P|, (0, 0), (pc, k), len);
    WSnoc(P, s, (0, 0), (pc, k), (z, k2), len);
  }
  lemma ReachStart(P: Prog, s: seq<int>)
    ensures Reachable(P, s, 0, 0)
  { assert WRn(P, s, 0, |P|, (0, 0), (0, 0), 0); }

  // ghost views of the simulation arrays
  ghost function VS(visited: array<bool>): set<int>
    reads visited
  {
    set pc | 0 <= pc < visited.Length && visited[pc]
  }
  lemma RangeCard(n: nat)
    ensures |set i | 0 <= i < n| == n
  {
    if n > 0 {
      RangeCard(n - 1);
      assert (set i | 0 <= i < n) == (set i | 0 <= i < n - 1) + {n - 1};
    }
  }
  lemma SubsetCard(a: set<int>, b: set<int>)
    requires a <= b
    ensures |a| <= |b|
  {
    assert b == a + (b - a);
    assert a * (b - a) == {};
  }
  lemma VSBound(visited: array<bool>)
    ensures |VS(visited)| <= visited.Length
  {
    RangeCard(visited.Length);
    SubsetCard(VS(visited), set i | 0 <= i < visited.Length);
  }

  // the visited set only contains configurations reachable at `pos`
  ghost predicate VisitedSound(P: Prog, s: seq<int>, pos: int, visited: array<bool>)
    reads visited
  {
    forall x :: 0 <= x < visited.Length && visited[x] ==> x < |P| && Reachable(P, s, x, pos)
  }
  // the visited set is closed under non-consuming steps at `pos`
  ghost predicate ClosedInv(P: Prog, s: seq<int>, pos: int, visited: array<bool>)
    reads visited
  {
    visited.Length == |P| &&
    forall x, z :: 0 <= x < |P| && visited[x] && StepR(P, s, (x, pos), (z, pos)) ==> 0 <= z < |P| && visited[z]
  }
  // list[0..cn) = exactly the visited ISet instructions, without repetition
  ghost predicate ListInv(P: Prog, visited: array<bool>, list: array<int>, cn: int)
    reads visited, list
  {
    visited.Length == |P| && list.Length == |P| && 0 <= cn <= |P| && cn <= |VS(visited)| &&
    (forall k :: 0 <= k < cn ==> 0 <= list[k] < |P| && visited[list[k]] && P[list[k]].ISet?) &&
    (forall k, l :: 0 <= k < l < cn ==> list[k] != list[l]) &&
    (forall x :: 0 <= x < |P| && visited[x] && P[x].ISet? ==> exists k :: 0 <= k < cn && list[k] == x)
  }
  ghost predicate MatchedInv(P: Prog, s: seq<int>, pos: int, visited: array<bool>, matched: bool)
    reads visited
  {
    visited.Length == |P| &&
    (matched <==> (pos == |s| && exists x :: 0 <= x < |P| && visited[x] && P[x].IMatch?))
  }
  ghost predicate {:opaque} PhaseInv(P: Prog, s: seq<int>, pos: int, visited: array<bool>, list: array<int>, cn: int, matched: bool)
    reads visited, list
  {
    0 <= pos <= |s| && visited.Length == |P| &&
    VisitedSound(P, s, pos, visited) && ClosedInv(P, s, pos, visited) &&
    ListInv(P, visited, list, cn) && MatchedInv(P, s, pos, visited, matched)
  }

  // ---------------------------------------------------------------- epsilon (non-consuming) reachability at a fixed position
  ghost predicate EpsN(P: Prog, s: seq<int>, pos: int, a: int, b: int, n: nat)
    decreases n
  {
    if n == 0 then a == b
    else 0 <= a < |P| && exists m: int :: StepR(P, s, (a, pos), (m, pos)) && EpsN(P, s, pos, m, b, n - 1)
  }
  ghost predicate Eps(P: Prog, s: seq<int>, pos: int, a: int, b: int) {
    exists n: nat :: EpsN(P, s, pos, a, b, n)
  }
  lemma EpsRefl(P: Prog, s: seq<int>, pos: int, a: int) ensures Eps(P, s, pos, a, a) { assert EpsN(P, s, pos, a, a, 0); }
  lemma EpsSnocN(P: Prog, s: seq<int>, pos: int, a: int, b: int, z: int, n: nat)
    requires EpsN(P, s, pos, a, b, n) && 0 <= b < |P| && StepR(P, s, (b, pos), (z, pos))
    ensures EpsN(P, s, pos, a, z, n + 1)
    decreases n
  {
    if n == 0 {
      assert EpsN(P, s, pos, z, z, 0);
    } else {
      var m :| StepR(P, s, (a, pos), (m, pos)) && EpsN(P, s, pos, m, b, n - 1);
      EpsSnocN(P, s, pos, m, b, z, n - 1);
    }
  }
  lemma EpsSnoc(P: Prog, s: seq<int>, pos: int, a: int, b: int, z: int)
    requires Eps(P, s, pos, a, b) && 0 <= b < |P| && StepR(P, s, (b, pos), (z, pos))
    ensures Eps(P, s, pos, a, z)
  {
    var n: nat :| EpsN(P, s, pos, a, b, n);
    EpsSnocN(P, s, pos, a, b, z, n);
  }
  ghost predicate SeedOK(P: Prog, s: seq<int>, pos: int, S: set<int>, x: int) {
    exists sd :: sd in S && Eps(P, s, pos, sd, x)
  }
  lemma SeedOKStep(P: Prog, s: seq<int>, pos: int, S: set<int>, pc: int, z: int)
    requires SeedOK(P, s, pos, S, pc) && 0 <= pc < |P| && StepR(P, s, (pc, pos), (z, pos))
    ensures SeedOK(P, s, pos, S, z)
  {
    var sd :| sd in S && Eps(P, s, pos, sd, pc);
    EpsSnoc(P, s, pos, sd, pc, z);
  }
  lemma SeedOKMono(P: Prog, s: seq<int>, pos: int, S: set<int>, S2: set<int>, x: int)
    requires SeedOK(P, s, pos, S, x) && S <= S2
    ensures SeedOK(P, s, pos, S2, x)
  {}
  lemma EpsStepFront(P: Prog, s: seq<int>, pos: int, a: int, b: int, m: int)
    requires Eps(P, s, pos, m, b) && 0 <= a < |P| && StepR(P, s, (a, pos), (m, pos))
    ensures Eps(P, s, pos, a, b)
  {
    var n: nat :| EpsN(P, s, pos, m, b, n);
    assert EpsN(P, s, pos, a, b, n + 1);
  }
  // a closed visited set containing a contains everything epsilon-reachable from a
  lemma ClosureContainsN(P: Prog, s: seq<int>, pos: int, visited: array<bool>, a: int, b: int, n: nat)
    requires ClosedInv(P, s, pos, visited) && 0 <= a < |P| && visited[a] && EpsN(P, s, pos, a, b, n)
    ensures 0 <= b < |P| && visited[b]
    decreases n
  {
    if n > 0 {
      var m :| StepR(P, s, (a, pos), (m, pos)) && EpsN(P, s, pos, m, b, n - 1);
      ClosureContainsN(P, s, pos, visited, m, b, n - 1);
    }
  }
  lemma ClosureContains(P: Prog, s: seq<int>, pos: int, visited: array<bool>, a: int, b: int)
    requires ClosedInv(P, s, pos, visited) && 0 <= a < |P| && visited[a] && Eps(P, s, pos, a, b)
    ensures 0 <= b < |P| && visited[b]
  {
    var n: nat :| EpsN(P, s, pos, a, b, n);
    ClosureContainsN(P, s, pos, visited, a, b, n);
  }
  lemma EpsReachable(P: Prog, s: seq<int>, pos: int, a: int, b: int, n: nat)
    requires WFProg(P) && Reachable(P, s, a, pos) && 0 <= a < |P| && EpsN(P, s, pos, a, b, n)
    ensures Reachable(P, s, b, pos) && 0 <= b < |P|
    decreases n
  {
    if n > 0 {
      var m :| StepR(P, s, (a, pos), (m, pos)) && EpsN(P, s, pos, m, b, n - 1);
      ReachSnoc(P, s, a, pos, m, pos);
      assert P[a].IMatch? || InstTargetsIn(P[a], a, 0, |P| - 1);
      assert 0 <= m < |P|;
      EpsReachable(P, s, pos, m, b, n - 1);
    }
  }

  // ---------------------------------------------------------------- decomposition of reachability
  lemma LastStep(P: Prog, s: seq<int>, c: Cfg, d: Cfg, len: nat)
    requires WRn(P, s, 0, |P|, c, d, len + 1)
    ensures exists e: Cfg :: 0 <= e.0 < |P| && WRn(P, s, 0, |P|, c, e, len) && StepR(P, s, e, d)
    decreases len
  {
    var m :| StepR(P, s, c, m) && WRn(P, s, 0, |P|, m, d, len);
    if len == 0 {
      assert m == d;
      assert WRn(P, s, 0, |P|, c, c, 0);
    } else {
      LastStep(P, s, m, d, len - 1);
      var e: Cfg :| 0 <= e.0 < |P| && WRn(P, s, 0, |P|, m, e, len - 1) && StepR(P, s, e, d);
      assert WRn(P, s, 0, |P|, c, e, len);
    }
  }
  lemma Decomp(P: Prog, s: seq<int>, z: int, q: int, len: nat)
    requires WRn(P, s, 0, |P|, (0, 0), (z, q), len)
    ensures q >= 0
    ensures q == 0 ==> Eps(P, s, 0, 0, z)
    ensures q > 0 ==> exists pc :: 0 <= pc < |P| && Reachable(P, s, pc, q - 1) && P[pc].ISet? && StepR(P, s, (pc, q - 1), (pc + 1, q)) && Eps(P, s, q, pc + 1, z)
    decreases len
  {
    if len == 0 {
      EpsRefl(P, s, 0, 0);
    } else {
      LastStep(P, s, (0, 0), (z, q), len - 1);
      var e: Cfg :| 0 <= e.0 < |P| && WRn(P, s, 0, |P|, (0, 0), e, len - 1) && StepR(P, s, e, (z, q));
      Decomp(P, s, e.0, e.1, len - 1);
      match P[e.0] {
        case ISet(cs) =>
          assert q == e.1 + 1 && z == e.0 + 1;
          assert Reachable(P, s, e.0, e.1);
          EpsRefl(P, s, q, z);
        case ISplit(_, _) => DecompNon(P, s, e, z, q);
        case IJmp(_) => DecompNon(P, s, e, z, q);
        case IBol => DecompNon(P, s, e, z, q);
        case IEol => DecompNon(P, s, e, z, q);
        case IMatch => assert false;
      }
    }
  }
  lemma DecompNon(P: Prog, s: seq<int>, e: Cfg, z: int, q: int)
    requires 0 <= e.0 < |P| && StepR(P, s, e, (z, q)) && q == e.1
    requires e.1 >= 0
    requires e.1 == 0 ==> Eps(P, s, 0, 0, e.0)
    requires e.1 > 0 ==> exists pc :: 0 <= pc < |P| && Reachable(P, s, pc, q - 1) && P[pc].ISet? && StepR(P, s, (pc, q - 1), (pc + 1, q)) && Eps(P, s, q, pc + 1, e.0)
    ensures q == 0 ==> Eps(P, s, 0, 0, z)
    ensures q > 0 ==> exists pc :: 0 <= pc < |P| && Reachable(P, s, pc, q - 1) && P[pc].ISet? && StepR(P, s, (pc, q - 1), (pc + 1, q)) && Eps(P, s, q, pc + 1, z)
  {
    if q == 0 {
      EpsSnoc(P, s, 0, 0, e.0, z);
    } else {
      var pc :| 0 <= pc < |P| && Reachable(P, s, pc, q - 1) && P[pc].ISet? && StepR(P, s, (pc, q - 1), (pc + 1, q)) && Eps(P, s, q, pc + 1, e.0);
      EpsSnoc(P, s, q, pc + 1, e.0, z);
    }
  }

  // Add one thread (pc0, pos) and everything reachable from it by non-consuming steps (the DFS of runSafeRegex.add).
  method Add(P: Prog, s: seq<int>, pos: int, pc0: int, visited: array<bool>, list: array<int>, cn0: int, stack: array<int>, matched0: bool)
    returns (cn: int, matched: bool, steps: int)
    requires WFProg(P) && 1 <= |P| && stack.Length >= 2 * |P| + 2 && list != stack && visited.Length == |P| && list.Length == |P| && 0 <= cn0 <= |P|
    requires PhaseInv(P, s, pos, visited, list, cn0, matched0)
    requires 0 <= pc0 < |P| && Reachable(P, s, pc0, pos)
    modifies visited, list, stack
    ensures PhaseInv(P, s, pos, visited, list, cn, matched)
    ensures visited.Length == |P| && list.Length == |P| && visited[pc0] && 0 <= cn <= |P|
    ensures forall x :: 0 <= x < |P| && old(visited[x]) ==> visited[x]
    ensures forall k :: 0 <= k < cn0 ==> list[k] == old(list[k])
    ensures cn0 <= cn
    ensures 0 <= steps <= 1 + 2 * (|VS(visited)| - |old(VS(visited))|)
  {
    reveal PhaseInv();
    cn := cn0; matched := matched0; steps := 0;
    var sp := 1;
    stack[0] := pc0;
    ghost var VS0 := VS(visited);
    ghost var visited0 := visited[..];
    var np := |P|;
    VSBound(visited);
    while sp > 0
      invariant 0 <= sp <= stack.Length && visited.Length == np && list.Length == np && 0 <= cn <= np && 0 <= pos <= |s|
      invariant VisitedSound(P, s, pos, visited)
      invariant ListInv(P, visited, list, cn) && MatchedInv(P, s, pos, visited, matched)
      invariant forall k :: 0 <= k < sp ==> 0 <= stack[k] < np && Reachable(P, s, stack[k], pos)
      invariant forall x, z :: 0 <= x < np && visited[x] && StepR(P, s, (x, pos), (z, pos)) ==>
                  (0 <= z < np && visited[z]) || (exists k :: 0 <= k < sp && stack[k] == z)
      invariant visited[pc0] || (exists k :: 0 <= k < sp && stack[k] == pc0)
      invariant VS0 <= VS(visited)
      invariant forall x :: 0 <= x < np && visited0[x] ==> visited[x]
      invariant forall k :: 0 <= k < cn0 ==> list[k] == old(list[k])
      invariant cn0 <= cn
      invariant steps + sp <= 1 + 2 * (|VS(visited)| - |VS0|)
      invariant |VS(visited)| <= np
      decreases np - |VS(visited)|, sp
    {
      VSBound(visited);
      ghost var stackOld := stack[..];
      ghost var visOld := visited[..];
      ghost var spOld := sp;
      ghost var listOld := list[..];
      ghost var cnOld := cn;
      sp := sp - 1;
      var pc := stack[sp];
      ghost var sb := sp;
      steps := steps + 1;
      assert 0 <= pc < np && Reachable(P, s, pc, pos);
      if !visited[pc] {
        ghost var vsBefore := VS(visited);
        assert pc !in vsBefore;
        visited[pc] := true;
        assert VS(visited) == vsBefore + {pc};
        assert |VS(visited)| == |vsBefore| + 1;
        VSBound(visited);
        match P[pc] {
          case ISet(cs) =>
            assert forall z :: !StepR(P, s, (pc, pos), (z, pos));
            // cn < np: cn <= |VS before| and |VS after| = |VS before| + 1 <= np
            VSBound(visited);
            assert cn <= |vsBefore|;
            assert cn < np;
            assert forall k :: 0 <= k < cn ==> visOld[list[k]] && list[k] != pc;
            assert forall x :: 0 <= x < np && visited[x] && P[x].ISet? && x != pc ==> visOld[x];
            list[cn] := pc;
            cn := cn + 1;
            assert forall k :: 0 <= k < cn - 1 ==> list[k] == listOld[k];
          case ISplit(x, y) =>
            assert 0 <= x < np && 0 <= y < np;
            assert StepR(P, s, (pc, pos), (x, pos)) && StepR(P, s, (pc, pos), (y, pos));
            ReachSnoc(P, s, pc, pos, x, pos);
            ReachSnoc(P, s, pc, pos, y, pos);
            assert forall z :: StepR(P, s, (pc, pos), (z, pos)) ==> z == x || z == y;
            stack[sp] := y; stack[sp + 1] := x; sp := sp + 2;
          case IJmp(x) =>
            assert 0 <= x < np;
            assert StepR(P, s, (pc, pos), (x, pos));
            ReachSnoc(P, s, pc, pos, x, pos);
            assert forall z :: StepR(P, s, (pc, pos), (z, pos)) ==> z == x;
            stack[sp] := x; sp := sp + 1;
          case IBol =>
            assert forall z :: StepR(P, s, (pc, pos), (z, pos)) ==> pos == 0 && z == pc + 1;
            if pos == 0 {
              assert pc + 1 < np;
              assert StepR(P, s, (pc, pos), (pc + 1, pos));
              ReachSnoc(P, s, pc, pos, pc + 1, pos);
              stack[sp] := pc + 1; sp := sp + 1;
            }
          case IEol =>
            assert forall z :: StepR(P, s, (pc, pos), (z, pos)) ==> pos == |s| && z == pc + 1;
            if pos == |s| {
              assert pc + 1 < np;
              assert StepR(P, s, (pc, pos), (pc + 1, pos));
              ReachSnoc(P, s, pc, pos, pc + 1, pos);
              stack[sp] := pc + 1; sp := sp + 1;
            }
          case IMatch =>
            assert forall z :: !StepR(P, s, (pc, pos), (z, pos));
            if pos == |s| { matched := true; }
        }
        assert ListInv(P, visited, list, cn);
        assert MatchedInv(P, s, pos, visited, matched);
        assert forall k :: 0 <= k < sb ==> stack[k] == stackOld[k];
        assert forall z :: StepR(P, s, (pc, pos), (z, pos)) ==> exists k :: sb <= k < sp && stack[k] == z by {
          match P[pc] {
            case ISet(_) => 
            case ISplit(x, y) => assert stack[sb] == y && stack[sb + 1] == x && sp == sb + 2;
            case IJmp(x) => assert stack[sb] == x && sp == sb + 1;
            case IBol => if pos == 0 { assert stack[sb] == pc + 1 && sp == sb + 1; }
            case IEol => if pos == |s| { assert stack[sb] == pc + 1 && sp == sb + 1; }
            case IMatch =>
          }
        }
      } else {
        assert forall k :: 0 <= k < sb ==> stack[k] == stackOld[k];
      }
      // closure: every successor of a visited pc is visited or still on the stack
      forall x, z | 0 <= x < np && visited[x] && StepR(P, s, (x, pos), (z, pos))
        ensures (0 <= z < np && visited[z]) || (exists k :: 0 <= k < sp && stack[k] == z)
      {
        if !visOld[pc] && x == pc {
          assert exists k :: 0 <= k < sp && stack[k] == z;
        } else if visOld[x] {
          // old invariant at (x, z): z visited, or on the old stack
          assert (0 <= z < np && visOld[z]) || (exists k :: 0 <= k < spOld && stackOld[k] == z);
          if !(0 <= z < np && visOld[z]) {
            var k :| 0 <= k < spOld && stackOld[k] == z;
            if k == spOld - 1 { assert z == pc; assert visited[pc]; } else { assert k < sb ; assert stack[k] == stackOld[k]; }
          }
        }
      }
    }
  }
  function sp1(spOld: int): int { spOld - 1 }

  // The thread list at position pos: exactly the reachable ISet instructions (distinctness is not needed, only cn <= |P|).
  ghost predicate {:opaque} Level(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int)
    reads list
  {
    list.Length == |P| && 0 <= cn <= |P| &&
    (forall k :: 0 <= k < cn ==> 0 <= list[k] < |P| && P[list[k]].ISet? && Reachable(P, s, list[k], pos)) &&
    (forall x :: 0 <= x < |P| && P[x].ISet? && Reachable(P, s, x, pos) ==> exists k :: 0 <= k < cn && list[k] == x)
  }

  lemma LevelEntry(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int, k: int)
    requires Level(P, s, pos, list, cn) && 0 <= k < cn
    ensures list.Length == |P| && 0 <= cn <= |P| && 0 <= list[k] < |P| && P[list[k]].ISet? && Reachable(P, s, list[k], pos)
  { reveal Level(); }
  lemma LevelBounds(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int)
    requires Level(P, s, pos, list, cn)
    ensures list.Length == |P| && 0 <= cn <= |P|
  { reveal Level(); }
  lemma LevelComplete(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int, x: int)
    requires Level(P, s, pos, list, cn) && 0 <= x < |P| && P[x].ISet? && Reachable(P, s, x, pos)
    ensures cn <= list.Length && exists k :: 0 <= k < cn && list[k] == x
  { reveal Level(); }

  ghost predicate {:opaque} SeedsOK(P: Prog, s: seq<int>, pos: int, seeds: array<int>, ns: int)
    reads seeds
  {
    0 <= ns <= seeds.Length && ns <= |P| &&
    (forall j :: 0 <= j < ns ==> 0 <= seeds[j] < |P| && Reachable(P, s, seeds[j], pos)) &&
    (forall z :: 0 <= z < |P| && Reachable(P, s, z, pos) ==> exists j :: 0 <= j < ns && Eps(P, s, pos, seeds[j], z))
  }

  // One position of the simulation: from a seed list (complete for the epsilon-frontier) compute the Level and the match flag.
  method Phase(P: Prog, s: seq<int>, pos: int, seeds: array<int>, ns: int)
    returns (list: array<int>, cn: int, matched: bool, work: int)
    requires WFProg(P) && 1 <= |P| && 0 <= pos <= |s| && SeedsOK(P, s, pos, seeds, ns)
    ensures fresh(list) && Level(P, s, pos, list, cn)
    ensures matched <==> (pos == |s| && exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, pos))
    ensures 0 <= work <= ns + 3 * |P|
  {
    reveal SeedsOK();
    var np := |P|;
    var visited := new bool[np](_ => false);
    list := new int[np];
    var stack := new int[2 * np + 2];
    cn := 0; matched := false; work := np;
    PhaseInit(P, s, pos, visited, list);
    var j := 0;
    ghost var pops := 0;
    while j < ns
      invariant 0 <= j <= ns && visited.Length == np && list.Length == np && stack.Length == 2 * np + 2
      invariant PhaseInv(P, s, pos, visited, list, cn, matched) && 0 <= cn <= np
      invariant forall j2 :: 0 <= j2 < j ==> visited[seeds[j2]]
      invariant 0 <= pops <= j + 2 * |VS(visited)| && |VS(visited)| <= np
      invariant work == np + pops
      invariant list != stack && seeds != list && seeds != stack
      invariant fresh(list)
    {
      ghost var vsOld := |VS(visited)|;
      var c2, m2, st := Add(P, s, pos, seeds[j], visited, list, cn, stack, matched);
      cn := c2; matched := m2;
      assert st <= 1 + 2 * (|VS(visited)| - vsOld);
      pops := pops + st;
      work := work + st;
      VSBound(visited);
      j := j + 1;
    }
    PhaseFinish(P, s, pos, seeds, ns, visited, list, cn, matched);
    VSBound(visited);
    assert pops <= ns + 2 * np;
  }

  lemma PhaseInit(P: Prog, s: seq<int>, pos: int, visited: array<bool>, list: array<int>)
    requires 0 <= pos <= |s| && visited.Length == |P| && list.Length == |P| && forall x :: 0 <= x < visited.Length ==> !visited[x]
    ensures PhaseInv(P, s, pos, visited, list, 0, false) && VS(visited) == {}
  {
    reveal PhaseInv();
    assert VS(visited) == {};
  }

  lemma PhaseFinish(P: Prog, s: seq<int>, pos: int, seeds: array<int>, ns: int, visited: array<bool>, list: array<int>, cn: int, matched: bool)
    requires WFProg(P) && 1 <= |P| && 0 <= ns <= seeds.Length
    requires visited.Length == |P| && PhaseInv(P, s, pos, visited, list, cn, matched)
    requires forall j :: 0 <= j < ns ==> 0 <= seeds[j] < |P| && visited[seeds[j]]
    requires forall z :: 0 <= z < |P| && Reachable(P, s, z, pos) ==> exists j :: 0 <= j < ns && Eps(P, s, pos, seeds[j], z)
    ensures Level(P, s, pos, list, cn)
    ensures matched <==> (pos == |s| && exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, pos))
  {
    reveal PhaseInv();
    reveal Level();
    forall x | 0 <= x < |P| && Reachable(P, s, x, pos) ensures visited[x] {
      var jj :| 0 <= jj < ns && Eps(P, s, pos, seeds[jj], x);
      ClosureContains(P, s, pos, visited, seeds[jj], x);
    }
    forall x | 0 <= x < |P| ensures visited[x] <==> Reachable(P, s, x, pos) {}
  }

  lemma Complete0(P: Prog, s: seq<int>, z: int)
    requires Reachable(P, s, z, 0)
    ensures Eps(P, s, 0, 0, z)
  {
    var len: nat :| WRn(P, s, 0, |P|, (0, 0), (z, 0), len);
    Decomp(P, s, z, 0, len);
  }
  lemma CompleteNext(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int, sarr: array<int>, ns: int, z: int)
    requires WFProg(P) && 0 <= pos < |s| && Level(P, s, pos, list, cn) && 0 <= ns <= sarr.Length
    requires cn <= list.Length
    requires forall k :: 0 <= k < cn && 0 <= list[k] < |P| && P[list[k]].ISet? && SetHas(P[list[k]].cs, s[pos]) ==> exists j :: 0 <= j < ns && sarr[j] == list[k] + 1
    requires Reachable(P, s, z, pos + 1)
    ensures exists j :: 0 <= j < ns && Eps(P, s, pos + 1, sarr[j], z)
  {
    var len: nat :| WRn(P, s, 0, |P|, (0, 0), (z, pos + 1), len);
    Decomp(P, s, z, pos + 1, len);
    reveal Level();
    var pc :| 0 <= pc < |P| && Reachable(P, s, pc, pos) && P[pc].ISet? && StepR(P, s, (pc, pos), (pc + 1, pos + 1)) && Eps(P, s, pos + 1, pc + 1, z);
    var k :| 0 <= k < cn && list[k] == pc;
    assert SetHas(P[pc].cs, s[pos]);
    var j :| 0 <= j < ns && sarr[j] == pc + 1;
  }
  lemma AcceptsIff(P: Prog, s: seq<int>)
    ensures Accepts(P, s) <==> exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, |s|)
  {
    if Accepts(P, s) {
      var c: Cfg, len: nat :| WRn(P, s, 0, |P|, (0, 0), c, len) && c.1 == |s| && 0 <= c.0 < |P| && P[c.0].IMatch?;
      assert Reachable(P, s, c.0, |s|);
    }
    if exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, |s|) {
      var x :| 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, |s|);
      var len: nat :| WRn(P, s, 0, |P|, (0, 0), (x, |s|), len);
    }
  }

  ghost predicate {:opaque} MatchedAt(P: Prog, s: seq<int>, pos: int, matched: bool) {
    matched <==> (pos == |s| && exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, pos))
  }
  lemma MatchedAtIntro(P: Prog, s: seq<int>, pos: int, matched: bool)
    requires matched <==> (pos == |s| && exists x :: 0 <= x < |P| && P[x].IMatch? && Reachable(P, s, x, pos))
    ensures MatchedAt(P, s, pos, matched)
  { reveal MatchedAt(); }
  lemma MatchedAtFinal(P: Prog, s: seq<int>, matched: bool)
    requires MatchedAt(P, s, |s|, matched)
    ensures matched <==> Accepts(P, s)
  { reveal MatchedAt(); AcceptsIff(P, s); }

  // Advance one input character: the seed list for position pos+1 from the thread list at pos.
  method Advance(P: Prog, s: seq<int>, pos: int, list: array<int>, cn: int) returns (sarr: array<int>, ns: int)
    requires WFProg(P) && 1 <= |P| && 0 <= pos < |s| && Level(P, s, pos, list, cn)
    ensures fresh(sarr) && sarr.Length == |P| && 0 <= ns <= |P|
    ensures SeedsOK(P, s, pos + 1, sarr, ns)
  {
    var np := |P|;
    LevelBounds(P, s, pos, list, cn);
    sarr := new int[np];
    ns := 0;
    var k := 0;
    while k < cn
      invariant 0 <= k <= cn <= np && 0 <= ns <= k && sarr.Length == np && Level(P, s, pos, list, cn) && list != sarr
      invariant forall j :: 0 <= j < ns ==> 0 <= sarr[j] < np && Reachable(P, s, sarr[j], pos + 1)
      invariant forall k2 :: 0 <= k2 < k && 0 <= list[k2] < np && P[list[k2]].ISet? && SetHas(P[list[k2]].cs, s[pos]) ==> exists j :: 0 <= j < ns && sarr[j] == list[k2] + 1
      decreases cn - k
    {
      LevelEntry(P, s, pos, list, cn, k);
      var pc := list[k];
      if SetHas(P[pc].cs, s[pos]) {
        assert StepR(P, s, (pc, pos), (pc + 1, pos + 1));
        ReachSnoc(P, s, pc, pos, pc + 1, pos + 1);
        ghost var nsOld := ns;
        ghost var sOld := sarr[..];
        sarr[ns] := pc + 1;
        assert forall j :: 0 <= j < nsOld ==> sarr[j] == sOld[j];
        ns := ns + 1;
        assert sarr[nsOld] == list[k] + 1;
      }
      assert forall k2 :: 0 <= k2 < k + 1 && 0 <= list[k2] < np && P[list[k2]].ISet? && SetHas(P[list[k2]].cs, s[pos]) ==> exists j :: 0 <= j < ns && sarr[j] == list[k2] + 1;
      k := k + 1;
    }
    forall z | 0 <= z < np && Reachable(P, s, z, pos + 1) ensures exists j :: 0 <= j < ns && Eps(P, s, pos + 1, sarr[j], z) {
      CompleteNext(P, s, pos, list, cn, sarr, ns, z);
    }
    reveal SeedsOK();
  }

  lemma StartSeeds(P: Prog, s: seq<int>, seeds0: array<int>)
    requires seeds0.Length == 1 && seeds0[0] == 0 && 1 <= |P|
    ensures SeedsOK(P, s, 0, seeds0, 1)
  {
    ReachStart(P, s);
    forall z | 0 <= z < |P| && Reachable(P, s, z, 0) ensures exists j :: 0 <= j < 1 && Eps(P, s, 0, seeds0[j], z) { Complete0(P, s, z); }
    reveal SeedsOK();
  }

  // The whole matcher: refuses (None) exactly when |program| x (|subject|+1) > MAX_MATCH_STEPS, otherwise decides acceptance.
  method Run(P: Prog, s: seq<int>) returns (r: Option<bool>, work: int)
    requires WFProg(P) && 1 <= |P|
    ensures |P| * (|s| + 1) > MAX_MATCH_STEPS ==> r.None?
    ensures |P| * (|s| + 1) <= MAX_MATCH_STEPS ==> r.Some? && (r.v <==> Accepts(P, s)) && 0 <= work <= 6 * |P| * (|s| + 1)
  {
    var np := |P|;
    var n := |s|;
    if np * (n + 1) > MAX_MATCH_STEPS { return None, 0; }
    var seeds0 := new int[1];
    seeds0[0] := 0;
    StartSeeds(P, s, seeds0);
    var list, cn, matched, w := Phase(P, s, 0, seeds0, 1);
    MatchedAtIntro(P, s, 0, matched);
    work := w + 1;
    var K := 6 * np;
    var pos := 0;
    ghost var bound := K;                     // K * (pos + 1)
    assert work <= bound;
    while pos < n
      invariant 0 <= pos <= n && Level(P, s, pos, list, cn) && np * (n + 1) <= MAX_MATCH_STEPS && K == 6 * np
      invariant bound == K * (pos + 1) && 0 <= work <= bound
      invariant MatchedAt(P, s, pos, matched)
      decreases n - pos
    {
      LevelBounds(P, s, pos, list, cn);
      var sarr, ns := Advance(P, s, pos, list, cn);
      var l2, c2, m2, w2 := Phase(P, s, pos + 1, sarr, ns);
      MatchedAtIntro(P, s, pos + 1, m2);
      LevelBounds(P, s, pos + 1, l2, c2);
      assert np + cn + w2 <= K;
      work := work + np + cn + w2;
      bound := bound + K;
      list := l2; cn := c2; matched := m2;
      pos := pos + 1;
    }
    assert work <= K * (n + 1);
    assert K * (n + 1) == 6 * np * (n + 1);
    MatchedAtFinal(P, s, matched);
    r := Some(matched);
  }

  // ---------------------------------------------------------------- 6. the guard (isSafeRegexSource) and the entry points
  const MAX_UNBOUNDED_QUANTIFIERS: int := 3
  const MAX_BOUNDED_REPEAT: int := 64
  const MAX_REGEX_COST_BITS: int := 22
  const UNBOUNDED_QUANTIFIER_BITS: int := 8

  datatype Fr = Fr(q: bool, a: bool)
  datatype Prev = PNone | PAtom | PFrame(q: bool, a: bool)

  function CeilLog2(n: int): int
    requires n >= 1
    decreases n
    ensures CeilLog2(n) >= 0
  {
    if n <= 1 then 0 else 1 + CeilLog2((n + 1) / 2)
  }

  // regex /^\{(\d+)(?:(,)(\d*))?\}/ at s[i] == '{'. mx == -1: unbounded. len = matched length.
  datatype GB = GBad | GQ(lo: int, hi: int, len: int)
  function GuardBrace(s: seq<int>, i: int): GB
    requires 0 <= i < |s| && s[i] == LC
    ensures GuardBrace(s, i).GQ? ==> GuardBrace(s, i).len >= 3 && i + GuardBrace(s, i).len <= |s|
  {
    var d1e := DigitRun(s, i + 1);
    if d1e == i + 1 then GBad
    else
      var lo := DigitVal(s, i + 1, d1e);
      if d1e < |s| && s[d1e] == RC then GQ(lo, lo, d1e + 1 - i)
      else if d1e < |s| && s[d1e] == COMMA then
        var d2e := DigitRun(s, d1e + 1);
        if d2e < |s| && s[d2e] == RC then
          (if d2e == d1e + 1 then GQ(lo, -1, d2e + 1 - i) else GQ(lo, DigitVal(s, d1e + 1, d2e), d2e + 1 - i))
        else GBad
      else GBad
  }

  // position after the class starting at s[i] == '[' ; -1 when unterminated (the JS loop: first unescaped ']').
  function ClassEnd(s: seq<int>, j: int): int
    requires 0 <= j
    decreases |s| - j
    ensures ClassEnd(s, j) == -1 || (j <= ClassEnd(s, j) < |s|)
  {
    if j >= |s| then -1
    else if s[j] == RB then j
    else if s[j] == BS then ClassEnd(s, j + 2)
    else ClassEnd(s, j + 1)
  }

  function GuardGo(s: seq<int>, i: int, prev: Prev, unb: int, bits: int, st: seq<Fr>): bool
    requires 0 <= i <= |s| && |st| >= 1 && 0 <= unb <= MAX_UNBOUNDED_QUANTIFIERS && 0 <= bits <= MAX_REGEX_COST_BITS
    decreases |s| - i
    ensures GuardGo(s, i, prev, unb, bits, st) ==> true
  {
    if i >= |s| then |st| == 1 && CompileSrc(s).Some?
    else
      var ch := s[i];
      if ch == BS then
        if i + 1 >= |s| then false
        else if (0x31 <= s[i + 1] <= 0x39) || s[i + 1] == 0x6b then false
        else GuardGo(s, i + 2, PAtom, unb, bits, st)
      else if ch == LB then
        var j0 := if i + 1 < |s| && s[i + 1] == CARET then i + 2 else i + 1;
        var e := ClassEnd(s, j0);
        if e < 0 then false else GuardGo(s, e + 1, PAtom, unb, bits, st)
      else if ch == LP then
        var nx :=
          if i + 1 < |s| && s[i + 1] == QM then (if i + 2 < |s| && s[i + 2] == COLON then i + 3 else -1) else i + 1;
        if nx < 0 then false else GuardGo(s, nx, PNone, unb, bits, st + [Fr(false, false)])
      else if ch == RP then
        if |st| < 2 then false
        else
          var f := st[|st| - 1];
          var par := st[|st| - 2];
          GuardGo(s, i + 1, PFrame(f.q, f.a), unb, bits, st[..|st| - 2] + [Fr(par.q || f.q, par.a || f.a)])
      else if ch == BAR then
        if bits + 1 > MAX_REGEX_COST_BITS then false
        else GuardGo(s, i + 1, PNone, unb, bits + 1, st[..|st| - 1] + [Fr(st[|st| - 1].q, true)])
      else if ch == STAR || ch == PLUS || ch == QM || ch == LC then
        // quantifier: (len, unbounded, max, options)
        var q: GB :=
          if ch == STAR || ch == PLUS then GQ(0, -1, 1)
          else if ch == QM then GQ(0, 1, 1)
          else GuardBrace(s, i);
        if q.GBad? then false
        else if ch == LC && q.hi != -1 && q.hi < q.lo then false
        else if prev.PNone? then false
        else if prev.PFrame? && (prev.q || prev.a) then false
        else
          var unbounded := q.hi == -1;
          if unbounded && unb + 1 > MAX_UNBOUNDED_QUANTIFIERS then false
          else if !unbounded && q.hi > MAX_BOUNDED_REPEAT then false
          else
            var add := if unbounded then UNBOUNDED_QUANTIFIER_BITS
                       else if q.hi - q.lo + 1 > 1 then CeilLog2(q.hi - q.lo + 1) else 0;
            if bits + add > MAX_REGEX_COST_BITS then false
            else
              var i2 := i + q.len;
              var i3 := if i2 < |s| && s[i2] == QM then i2 + 1 else i2;
              GuardGo(s, i3, PNone, if unbounded then unb + 1 else unb, bits + add, st[..|st| - 1] + [Fr(true, st[|st| - 1].a)])
      else GuardGo(s, i + 1, PAtom, unb, bits, st)
  }

  function IsSafeSource(s: seq<int>): bool {
    GuardGo(s, 0, PNone, 0, 0, [Fr(false, false)])
  }

  // The guard is a strict refinement of the engine: whatever it admits compiles (so the matcher can run it).
  lemma GuardImpliesCompiles(s: seq<int>)
    requires IsSafeSource(s)
    ensures CompileSrc(s).Some?
  { GuardTail(s, 0, PNone, 0, 0, [Fr(false, false)]); }
  lemma GuardTail(s: seq<int>, i: int, prev: Prev, unb: int, bits: int, st: seq<Fr>)
    requires 0 <= i <= |s| && |st| >= 1 && 0 <= unb <= MAX_UNBOUNDED_QUANTIFIERS && 0 <= bits <= MAX_REGEX_COST_BITS
    requires GuardGo(s, i, prev, unb, bits, st)
    ensures CompileSrc(s).Some?
    decreases |s| - i
  {
    if i < |s| {
      var ch := s[i];
      if ch == BS {
        GuardTail(s, i + 2, PAtom, unb, bits, st);
      } else if ch == LB {
        var j0 := if i + 1 < |s| && s[i + 1] == CARET then i + 2 else i + 1;
        var e := ClassEnd(s, j0);
        GuardTail(s, e + 1, PAtom, unb, bits, st);
      } else if ch == LP {
        var nx := if i + 1 < |s| && s[i + 1] == QM then i + 3 else i + 1;
        GuardTail(s, nx, PNone, unb, bits, st + [Fr(false, false)]);
      } else if ch == RP {
        var f := st[|st| - 1]; var par := st[|st| - 2];
        GuardTail(s, i + 1, PFrame(f.q, f.a), unb, bits, st[..|st| - 2] + [Fr(par.q || f.q, par.a || f.a)]);
      } else if ch == BAR {
        GuardTail(s, i + 1, PNone, unb, bits + 1, st[..|st| - 1] + [Fr(st[|st| - 1].q, true)]);
      } else if ch == STAR || ch == PLUS || ch == QM || ch == LC {
        var q: GB := if ch == STAR || ch == PLUS then GQ(0, -1, 1) else if ch == QM then GQ(0, 1, 1) else GuardBrace(s, i);
        var unbounded := q.hi == -1;
        var add := if unbounded then UNBOUNDED_QUANTIFIER_BITS else if q.hi - q.lo + 1 > 1 then CeilLog2(q.hi - q.lo + 1) else 0;
        var i2 := i + q.len;
        var i3 := if i2 < |s| && s[i2] == QM then i2 + 1 else i2;
        GuardTail(s, i3, PNone, if unbounded then unb + 1 else unb, bits + add, st[..|st| - 1] + [Fr(true, st[|st| - 1].a)]);
      } else {
        GuardTail(s, i + 1, PAtom, unb, bits, st);
      }
    }
  }

  // Resource-limit entry (predicates.ts resourceMatches for `re:` patterns): src <= 200, subject <= 512, guard, then the engine.
  const MAX_RE_SRC_LEN: int := 200
  const MAX_RE_RESOURCE_LEN: int := 512

  // Parse + compile + run. Fail-closed: None whenever the source is outside the subset, too large, or over the step budget.
  method FullMatch(src: seq<int>, subj: seq<int>) returns (r: Option<bool>)
    ensures r.Some? ==> exists ast :: Parse(src) == Some(ast) && ValidN(ast) && (r.v <==> Match(ast, subj, 0, |subj|))
    ensures Parse(src).None? ==> r.None?
    ensures CompileSrc(src).None? ==> r.None?
    ensures r.Some? ==> exists P :: CompileSrc(src) == Some(P) && |P| * (|subj| + 1) <= MAX_MATCH_STEPS && |P| <= MAX_NFA_INSTRUCTIONS
  {
    match Parse(src) {
      case None => return None;
      case Some(ast) =>
        match Compile(ast) {
          case None => return None;
          case Some(P) =>
            CompileWF(ast, P);
            CompileCorrect(ast, subj, P);
            var rr, work := Run(P, subj);
            r := rr;
        }
    }
  }

  method Compiles(src: seq<int>) returns (b: bool)
    ensures b <==> CompileSrc(src).Some?
  { b := CompileSrc(src).Some?; }

  method SafeSource(src: seq<int>) returns (b: bool)
    ensures b <==> IsSafeSource(src)
  { b := IsSafeSource(src); }

  // predicates.ts: `re:` resource matching. Returns whether the pattern permits `resource` (false on every refusal).
  method ReMatches(src: seq<int>, subj: seq<int>) returns (b: bool)
    ensures b ==> |src| <= MAX_RE_SRC_LEN && |subj| <= MAX_RE_RESOURCE_LEN && IsSafeSource(src)
    ensures b ==> exists ast :: Parse(src) == Some(ast) && Match(ast, subj, 0, |subj|)
  {
    if |src| > MAX_RE_SRC_LEN || |subj| > MAX_RE_RESOURCE_LEN { return false; }
    if !IsSafeSource(src) { return false; }
    var r := FullMatch(src, subj);
    b := r == Some(true);
  }
}
