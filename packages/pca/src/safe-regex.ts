import { regexCacheGet } from './regex-cache';
/**
 * A linear-time, budgeted regular-expression matcher for untrusted `re:` / `matches` patterns (R3-02).
 *
 * WHY: the previous defence validated a pattern with a hand-written scanner and then ran it on V8's BACKTRACKING engine.
 * Any parse differential between the scanner and V8 (the round-3 `[^](a+)+]` case: the scanner read `[^]` as the start
 * of a POSIX class, V8 as "any character") turned a "safe" pattern into exponential-time work on the single verifier
 * thread. This module removes the differential at the root: the pattern is parsed ONCE, by this parser, into a
 * Thompson NFA and run by a Pike-style simulation whose cost is O(|subject| x |NFA|) by construction. There is no
 * backtracking, so no pattern, however nested, can take exponential time, and a hard instruction budget bounds the
 * constant. V8's `RegExp` is never run on an untrusted pattern.
 *
 * SUBSET (anything else is REFUSED at compile time, fail closed): literals; `.` (not a line terminator); classes
 * `[...]` / `[^...]` incl. `[]` (matches nothing) and `[^]` (any char), ranges and `\d \D \w \W \s \S` inside them;
 * escapes `\d \D \w \W \s \S \t \n \v \f \r \0 \xHH \uHHHH \cX` and escaped punctuation; groups `( )` and `(?: )`;
 * alternation `|` (empty branches allowed); quantifiers `* + ? {n} {n,} {n,m}` with an optional lazy `?` (irrelevant to a
 * full-match boolean); anchors `^` `$`. REFUSED: backreferences, lookaround, named groups, `\b \B`, `\p`, flags,
 * a `{` that is not a well-formed quantifier, quantified assertions, and escapes of letters it does not know.
 * Matching is over UTF-16 code units, exactly like a flagless JS RegExp.
 *
 * `safeRegexFullMatch(src, subject)` is semantically `new RegExp('^(?:' + src + ')$').test(subject)` for every accepted
 * pattern (differentially fuzzed against V8, scripts/fuzz-safe-regex.mjs).
 */

/** Largest NFA (instruction count) a pattern may compile to. Bounds memory and the per-character cost. */
export const MAX_NFA_INSTRUCTIONS = 4096;
/** Largest `{n,m}` bound. */
export const MAX_REPEAT = 64;
/** Hard cap on (NFA size x (subject length + 1)): the matcher refuses rather than run longer. ~2M elementary steps. */
export const MAX_MATCH_STEPS = 2_000_000;

type Ranges = ReadonlyArray<readonly [number, number]>;

const enum Op {
  Set = 0, // consume one code unit that is in `set`
  Split = 1, // epsilon to x and y
  Jmp = 2, // epsilon to x
  Bol = 3, // assert position 0
  Eol = 4, // assert position n
  Match = 5,
}

interface Inst {
  op: Op;
  x: number;
  y: number;
  set?: CharSet;
}

/** A set of UTF-16 code units: sorted, merged ranges, optionally negated (negation is applied at test time). */
class CharSet {
  constructor(
    readonly ranges: Ranges,
    readonly negated: boolean,
  ) {}
  has(c: number): boolean {
    let lo = 0;
    let hi = this.ranges.length - 1;
    let inside = false;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const r = this.ranges[mid]!;
      if (c < r[0]) hi = mid - 1;
      else if (c > r[1]) lo = mid + 1;
      else {
        inside = true;
        break;
      }
    }
    return inside !== this.negated;
  }
}

const DIGIT: Ranges = [[0x30, 0x39]];
const WORD: Ranges = [
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x5f, 0x5f],
  [0x61, 0x7a],
];
const SPACE: Ranges = [
  [0x09, 0x0d],
  [0x20, 0x20],
  [0xa0, 0xa0],
  [0x1680, 0x1680],
  [0x2000, 0x200a],
  [0x2028, 0x2029],
  [0x202f, 0x202f],
  [0x205f, 0x205f],
  [0x3000, 0x3000],
  [0xfeff, 0xfeff],
];
const LINE_TERMINATORS: Ranges = [
  [0x0a, 0x0a],
  [0x0d, 0x0d],
  [0x2028, 0x2029],
];

function normalize(ranges: Array<[number, number]>): Ranges {
  const s = [...ranges].sort((a, b) => a[0] - b[0]);
  const out: Array<[number, number]> = [];
  for (const r of s) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push([r[0], r[1]]);
  }
  return out;
}

function complement(r: Ranges): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let next = 0;
  for (const [a, b] of normalize(r.map((x) => [x[0], x[1]] as [number, number]))) {
    if (a > next) out.push([next, a - 1]);
    next = b + 1;
  }
  if (next <= 0xffff) out.push([next, 0xffff]);
  return out;
}

// ---- AST ------------------------------------------------------------------------------------------------------------

type Node =
  | { k: 'set'; set: CharSet }
  | { k: 'bol' }
  | { k: 'eol' }
  | { k: 'cat'; items: Node[] }
  | { k: 'alt'; items: Node[] }
  | { k: 'rep'; node: Node; min: number; max: number }; // max = Infinity for unbounded

class Refuse extends Error {}
const refuse = (m: string): never => {
  throw new Refuse(m);
};

class Parser {
  i = 0;
  constructor(readonly s: string) {}

  parse(): Node {
    const n = this.alt();
    if (this.i < this.s.length) refuse('unbalanced )');
    return n;
  }

  private alt(): Node {
    const items: Node[] = [this.cat()];
    while (this.s[this.i] === '|') {
      this.i++;
      items.push(this.cat());
    }
    return items.length === 1 ? items[0]! : { k: 'alt', items };
  }

  private cat(): Node {
    const items: Node[] = [];
    while (this.i < this.s.length && this.s[this.i] !== '|' && this.s[this.i] !== ')') {
      items.push(this.quantified());
    }
    return { k: 'cat', items };
  }

  private quantified(): Node {
    const atom = this.atom();
    const c = this.s[this.i];
    let min = -1;
    let max = -1;
    if (c === '*') {
      min = 0;
      max = Infinity;
      this.i++;
    } else if (c === '+') {
      min = 1;
      max = Infinity;
      this.i++;
    } else if (c === '?') {
      min = 0;
      max = 1;
      this.i++;
    } else if (c === '{') {
      const m = /^\{(\d{1,4})(?:(,)(\d{0,4}))?\}/.exec(this.s.slice(this.i, this.i + 16));
      if (!m) return refuse('{ is not a well-formed quantifier');
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
      if (max < min) refuse('quantifier range out of order');
      this.i += m[0].length;
    } else {
      return atom;
    }
    if (atom.k === 'bol' || atom.k === 'eol') refuse('nothing to repeat (assertion)');
    if ((max !== Infinity && max > MAX_REPEAT) || min > MAX_REPEAT) refuse('repeat bound too large');
    if (this.s[this.i] === '?') this.i++; // lazy: no effect on a full-match boolean
    // A further quantifier char here (`a**`, `a{2}{3}`) needs no check of its own: the next `quantified()` call reaches
    // `atom()`, which refuses a leading `*` `+` `?` `{` (same verdict, null).
    return { k: 'rep', node: atom, min, max };
  }

  private atom(): Node {
    const c = this.s[this.i]!;
    switch (c) {
      case '(': {
        this.i++;
        if (this.s[this.i] === '?') {
          if (this.s[this.i + 1] !== ':') return refuse('lookaround / named groups are not supported');
          this.i += 2;
        }
        const n = this.alt();
        if (this.s[this.i] !== ')') refuse('unterminated group');
        this.i++;
        return n;
      }
      case '[':
        return this.cls();
      case '.':
        this.i++;
        return { k: 'set', set: new CharSet(LINE_TERMINATORS, true) };
      case '^':
        this.i++;
        return { k: 'bol' };
      case '$':
        this.i++;
        return { k: 'eol' };
      case '\\':
        return this.escape();
      case '*':
      case '+':
      case '?':
        return refuse('nothing to repeat');
      case '{':
        return refuse('{ is not a well-formed quantifier');
      default:
        this.i++;
        return { k: 'set', set: new CharSet([[c.charCodeAt(0), c.charCodeAt(0)]], false) };
    }
  }

  /** Parse an escape outside a class: returns a single-code-unit set. */
  private escape(): Node {
    const e = this.escapeInner(false);
    return { k: 'set', set: e.set };
  }

  /**
   * After `\`: returns the set it denotes and whether it is a class escape (\d etc., which cannot be a range endpoint).
   */
  private escapeInner(inClass: boolean): { set: CharSet; cls: boolean; ch?: number } {
    this.i++; // backslash
    const c = this.s[this.i];
    if (c === undefined) return refuse('trailing backslash');
    this.i++;
    const single = (code: number) => ({ set: new CharSet([[code, code]], false), cls: false, ch: code });
    switch (c) {
      case 'd':
        return { set: new CharSet(DIGIT, false), cls: true };
      case 'D':
        return { set: new CharSet(DIGIT, true), cls: true };
      case 'w':
        return { set: new CharSet(WORD, false), cls: true };
      case 'W':
        return { set: new CharSet(WORD, true), cls: true };
      case 's':
        return { set: new CharSet(SPACE, false), cls: true };
      case 'S':
        return { set: new CharSet(SPACE, true), cls: true };
      case 't':
        return single(9);
      case 'n':
        return single(10);
      case 'v':
        return single(11);
      case 'f':
        return single(12);
      case 'r':
        return single(13);
      case '0':
        if (this.s[this.i] !== undefined && this.s[this.i]! >= '0' && this.s[this.i]! <= '9') return refuse('octal escape');
        return single(0);
      case 'x': {
        const h = this.s.slice(this.i, this.i + 2);
        if (!/^[0-9a-fA-F]{2}$/.test(h)) return refuse('bad \\x escape');
        this.i += 2;
        return single(parseInt(h, 16));
      }
      case 'u': {
        const h = this.s.slice(this.i, this.i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(h)) return refuse('bad \\u escape');
        this.i += 4;
        return single(parseInt(h, 16));
      }
      case 'c': {
        const l = this.s[this.i];
        if (l === undefined || !/^[A-Za-z]$/.test(l)) return refuse('bad \\c escape');
        this.i++;
        return single(l.charCodeAt(0) % 32);
      }
      case 'b':
        if (inClass) return single(8); // [\b] is backspace
        return refuse('word-boundary assertions are not supported');
      default:
        // Back-references, \B, \k, \p, and any other letter/digit escape: not in the subset. Escaped punctuation
        // (and the other non-alphanumeric characters) is the character itself.
        if (/^[A-Za-z0-9]$/.test(c) || c === '_') return refuse(`escape \\${c} is not supported`);
        return single(c.charCodeAt(0));
    }
  }

  private cls(): Node {
    this.i++; // [
    let negated = false;
    if (this.s[this.i] === '^') {
      negated = true;
      this.i++;
    }
    const ranges: Array<[number, number]> = [];
    const readAtom = (): { ranges: Ranges; ch?: number; cls: boolean } => {
      const c = this.s[this.i]!; // both call sites have just checked this.s[this.i] is defined
      if (c === '\\') {
        const e = this.escapeInner(true);
        // a negated class escape (\D \W \S) contributes the complement as ranges
        const rs: Ranges = e.set.negated ? complement(e.set.ranges) : e.set.ranges;
        return { ranges: rs, ...(e.ch !== undefined ? { ch: e.ch } : {}), cls: e.cls };
      }
      this.i++;
      const code = c.charCodeAt(0);
      return { ranges: [[code, code]], ch: code, cls: false };
    };
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) return refuse('unterminated class');
      if (c === ']') {
        this.i++;
        break;
      }
      const a = readAtom();
      if (this.s[this.i] === '-' && this.s[this.i + 1] !== undefined && this.s[this.i + 1] !== ']') {
        // possible range
        this.i++;
        const b = readAtom();
        if (a.cls || b.cls) {
          // Annex B: a class escape as a range endpoint makes the '-' a literal
          for (const r of a.ranges) ranges.push([r[0], r[1]]);
          ranges.push([0x2d, 0x2d]);
          for (const r of b.ranges) ranges.push([r[0], r[1]]);
        } else {
          if (a.ch! > b.ch!) return refuse('class range out of order');
          ranges.push([a.ch!, b.ch!]);
        }
      } else {
        for (const r of a.ranges) ranges.push([r[0], r[1]]);
      }
    }
    return { k: 'set', set: new CharSet(normalize(ranges), negated) };
  }
}

// ---- compile ----------------------------------------------------------------------------------------------------------

export interface CompiledRegex {
  readonly program: ReadonlyArray<Inst>;
}

function emit(node: Node, prog: Inst[]): void {
  if (prog.length > MAX_NFA_INSTRUCTIONS) refuse('pattern too large');
  switch (node.k) {
    case 'set':
      prog.push({ op: Op.Set, x: 0, y: 0, set: node.set });
      return;
    case 'bol':
      prog.push({ op: Op.Bol, x: 0, y: 0 });
      return;
    case 'eol':
      prog.push({ op: Op.Eol, x: 0, y: 0 });
      return;
    case 'cat':
      for (const it of node.items) emit(it, prog);
      return;
    case 'alt': {
      // split L1, L2 ; L1: a ; jmp end ; L2: split ... ; last
      const jmps: number[] = [];
      for (let i = 0; i < node.items.length; i++) {
        if (i < node.items.length - 1) {
          const split = prog.length;
          prog.push({ op: Op.Split, x: split + 1, y: -1 });
          emit(node.items[i]!, prog);
          jmps.push(prog.length);
          prog.push({ op: Op.Jmp, x: -1, y: 0 });
          prog[split]!.y = prog.length;
        } else {
          emit(node.items[i]!, prog);
        }
      }
      for (const j of jmps) prog[j]!.x = prog.length;
      return;
    }
    case 'rep': {
      for (let i = 0; i < node.min; i++) emit(node.node, prog);
      if (node.max === Infinity) {
        // L: split body, end ; body ; jmp L
        const split = prog.length;
        prog.push({ op: Op.Split, x: split + 1, y: -1 });
        emit(node.node, prog);
        prog.push({ op: Op.Jmp, x: split, y: 0 });
        prog[split]!.y = prog.length;
      } else {
        // (max-min) nested optionals: split body, end ; body ; split body, end ; ...
        const splits: number[] = [];
        for (let i = node.min; i < node.max; i++) {
          splits.push(prog.length);
          prog.push({ op: Op.Split, x: prog.length + 1, y: -1 });
          emit(node.node, prog);
        }
        for (const sp of splits) prog[sp]!.y = prog.length;
      }
      if (prog.length > MAX_NFA_INSTRUCTIONS) refuse('pattern too large');
      return;
    }
  }
}

/** Compile `src` into an NFA, or return null when it is outside the supported subset or too large. Never throws. */
export function compileSafeRegex(src: string): CompiledRegex | null {
  try {
    if (typeof src !== 'string') return null;
    const ast = new Parser(src).parse();
    const prog: Inst[] = [];
    emit(ast, prog);
    prog.push({ op: Op.Match, x: 0, y: 0 });
    if (prog.length > MAX_NFA_INSTRUCTIONS) return null;
    return { program: prog };
  } catch {
    // Refuse, and RangeError (stack depth on absurd nesting), and anything else: refuse.
    return null;
  }
}

/**
 * Full-match `subject` against a compiled program: true / false, or null when the work budget would be exceeded
 * (callers treat null as "no match / unknown", never as a hang). O(|subject| x |program|), no backtracking.
 */
export function runSafeRegex(re: CompiledRegex, subject: string): boolean | null {
  const prog = re.program;
  const n = subject.length;
  if (prog.length * (n + 1) > MAX_MATCH_STEPS) return null;
  let clist = new Int32Array(prog.length);
  let nlist = new Int32Array(prog.length);
  let cn = 0;
  let nn = 0;
  const mark = new Int32Array(prog.length).fill(-1);
  let gen = 0;
  let matched = false;

  // add thread at pc (following epsilons) to the list for position `pos`
  const stack = new Int32Array(prog.length * 2 + 2);
  const add = (list: Int32Array, count: number, pc0: number, pos: number): number => {
    let sp = 0;
    stack[sp++] = pc0;
    while (sp > 0) {
      const pc = stack[--sp]!;
      if (mark[pc] === gen) continue;
      mark[pc] = gen;
      const ins = prog[pc]!;
      switch (ins.op) {
        case Op.Jmp:
          stack[sp++] = ins.x;
          break;
        case Op.Split:
          stack[sp++] = ins.y; // push y first so x is explored first (order is irrelevant for a boolean)
          stack[sp++] = ins.x;
          break;
        case Op.Bol:
          if (pos === 0) stack[sp++] = pc + 1;
          break;
        case Op.Eol:
          if (pos === n) stack[sp++] = pc + 1;
          break;
        case Op.Match:
          if (pos === n) matched = true;
          break;
        case Op.Set:
          list[count++] = pc;
          break;
      }
    }
    return count;
  };

  gen++;
  cn = add(clist, 0, 0, 0);
  for (let pos = 0; pos < n; pos++) {
    const c = subject.charCodeAt(pos);
    gen++;
    nn = 0;
    for (let k = 0; k < cn; k++) {
      const pc = clist[k]!;
      const ins = prog[pc]!;
      if (ins.set!.has(c)) nn = add(nlist, nn, pc + 1, pos + 1);
    }
    const t = clist;
    clist = nlist;
    nlist = t;
    cn = nn;
    if (cn === 0 && !matched) return false;
  }
  return matched;
}

/** Memory weight of a compiled program for the bounded cache: instructions plus character-class ranges. */
function compiledWeight(re: CompiledRegex | null): number {
  if (re === null) return 1;
  let w = re.program.length;
  for (const ins of re.program) if (ins.set) w += ins.set.ranges.length;
  return w;
}

/**
 * `compileSafeRegex` through the ONE bounded, per-source-admitted LRU (`regex-cache.ts`, R5-API-05/06). Never cleared
 * wholesale. Returns null for a pattern outside the subset (that verdict is cached too).
 */
export function compileSafeRegexCached(src: string): CompiledRegex | null {
  return regexCacheGet(src, compileSafeRegex, compiledWeight);
}

/**
 * `new RegExp('^(?:' + src + ')$').test(subject)` over the supported subset, in linear time. Returns null when `src` is
 * outside the subset (or too large) or the work budget is exceeded; the caller fails closed.
 */
export function safeRegexFullMatch(src: string, subject: string): boolean | null {
  const re = compileSafeRegexCached(src);
  if (re === null) return null;
  return runSafeRegex(re, subject);
}
