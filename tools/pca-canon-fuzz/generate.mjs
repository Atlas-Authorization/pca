#!/usr/bin/env node
// Adversarial float/string canonical-form corpus generator for the PCA cross-language convergence proof.
//
//   node generate.mjs <corpus.jsonl> [--seed N] [--count N]
//
// Emits `kind:"canon"` cases (the same line shape the pca-diff-fuzz drivers consume): {id, kind, raw, cls}.
// Each `raw` is a JSON TEXT fragment. Every verifier strict-parses it, canonicalizes, and must produce
// BYTE-IDENTICAL canonical output (or an identical rejection). The point is to hammer the exact places the
// crypto audit flagged as able to diverge across languages:
//
//   * Double -> shortest-round-trip decimal near the 15/16/17-significant-digit boundary (shortest-string
//     algorithms Grisu/Ryu/David-Gay must agree on the digits, AND the plain-decimal vs exponent formatting
//     threshold differs per language — JS String() switches at 1e-6/1e21, Python repr() at 1e-4/1e16, Ruby
//     Float#to_s similarly — so the [1e-6, 1e-3) band is the sharpest test).
//   * `-0`, subnormals, magnitude < 1e-6, >15 significant digits, exponent lexemes: all OUT of the strict
//     wire profile and MUST be rejected identically.
//   * Non-shortest-but-canonical <=15-digit lexemes: the lexeme-preserving verifiers (Go/PHP/.NET keep the
//     source lexeme) and the round-tripping ones (TS/Python/Ruby reparse to a double and reformat) can only
//     agree if every canonical lexeme already IS its double's shortest form. We mint candidates to prove it.
//   * Large integers around 2^53 (safe-integer boundary).
//   * Powers of two +/- 1 ulp.
//   * Hard strings: `/`, U+2028/U+2029, C0 controls (raw-escaped), DEL, non-BMP, and lone-surrogate rejects,
//     plus the same as OBJECT KEYS (escaping + bytewise key sort).
//
// Deterministic: a fixed seed yields a byte-identical corpus, so it doubles as a frozen regression gate.

import { writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
const outPath = args[0];
const seedArg = (() => { const i = args.indexOf('--seed'); return i >= 0 ? Number(args[i + 1]) : 0xC0FFEE; })();
const countArg = (() => { const i = args.indexOf('--count'); return i >= 0 ? Number(args[i + 1]) : 60000; })();
if (!outPath) { console.error('usage: node generate.mjs <corpus.jsonl> [--seed N] [--count N]'); process.exit(2); }

// --- deterministic PRNG (splitmix64 -> doubles & 64-bit words) ---------------------------------
let state = BigInt.asUintN(64, BigInt(seedArg) ^ 0x9e3779b97f4a7c15n);
function next64() {
  state = BigInt.asUintN(64, state + 0x9e3779b97f4a7c15n);
  let z = state;
  z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
  z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
  return BigInt.asUintN(64, z ^ (z >> 31n));
}
const rndFloat01 = () => Number(next64() >> 11n) / 2 ** 53; // [0,1)
const rndInt = (n) => Number(next64() % BigInt(n));

const cases = [];
const push = (cls, raw, id) => cases.push({ id: id ?? `${cls}-${cases.length}`, kind: 'canon', raw, cls });

// --- number helpers ---------------------------------------------------------------------------
const bufF = new ArrayBuffer(8);
const dvF = new DataView(bufF);
function doubleFromBits(hi32, lo32) { dvF.setUint32(0, hi32 >>> 0); dvF.setUint32(4, lo32 >>> 0); return dvF.getFloat64(0); }
function nextafter(x, dir) {
  if (!Number.isFinite(x)) return x;
  if (x === 0) return dir > 0 ? Number.MIN_VALUE : -Number.MIN_VALUE;
  dvF.setFloat64(0, x);
  let bits = dvF.getBigUint64(0);
  const up = dir > 0 ? x > 0 : x < 0;
  bits += up ? 1n : -1n;
  dvF.setBigUint64(0, BigInt.asUintN(64, bits));
  return dvF.getFloat64(0);
}
// The JS-canonical plain-decimal rendering the TS reference would emit for an in-profile double (String(v)
// never uses exponent inside [1e-6, 1e21)). We only use this to DECIDE whether a value is in the profile and
// as a convenient literal; the oracle recomputes the authoritative bytes.
function jsNum(v) { return String(v); }

// Feed a double as a raw number lexeme. We feed the *shortest* string the reference would print; this is the
// value that must round-trip identically. (Exponent/oversized strings are fed too — they test rejection.)
function pushDouble(cls, v) {
  if (Number.isNaN(v) || !Number.isFinite(v)) return;
  push(cls, jsNum(v));
}

// ---- class 1: random doubles across all magnitudes (incl. 16/17-digit shortest forms) ----------
for (let i = 0; i < countArg * 0.30; i++) {
  const hi = rndInt(0x100000000), lo = rndInt(0x100000000);
  const v = doubleFromBits(hi, lo);
  if (Number.isNaN(v) || !Number.isFinite(v)) continue;
  pushDouble('rand-bits', v);
}

// ---- class 2: doubles drawn uniformly in log-magnitude (dense near the profile band) ----------
for (let i = 0; i < countArg * 0.25; i++) {
  const exp = rndFloat01() * 48 - 24;           // 1e-24 .. 1e24
  const sign = rndInt(2) ? -1 : 1;
  const v = sign * Math.pow(10, exp) * (0.5 + rndFloat01());
  pushDouble('log-mag', v);
}

// ---- class 3: THE SHARP BAND [1e-6, 1e-3) where per-language exponent thresholds disagree -------
for (let i = 0; i < countArg * 0.15; i++) {
  const k = 1 + rndInt(15);                       // significant digits
  let d = '';
  d += 1 + rndInt(9);
  for (let j = 1; j < k; j++) d += rndInt(10);
  d = d.replace(/0+$/, '') || '1';
  const lead = 3 + rndInt(3);                      // 0.000ddd .. 0.00000ddd  (exp -4..-6 region)
  const sign = rndInt(2) ? '-' : '';
  push('sharp-band', `${sign}0.${'0'.repeat(lead)}${d}`);
}

// ---- class 4: exact 1e-6 / sub-1e-6 boundary (reject side), and just above ---------------------
for (const lex of ['0.000001', '-0.000001', '0.0000011', '0.000002', '0.0000009', '-0.0000009',
  '0.0000001', '0.00000099', '0.0000000001', '0.000001000001']) push('boundary-1e-6', lex);

// ---- class 5: powers of two +/- 1 ulp (the ulp step changes across the binade boundary) --------
for (let k = -20; k <= 52; k++) {
  const p = Math.pow(2, k);
  for (const v of [p, nextafter(p, +1), nextafter(p, -1), -p, nextafter(-p, +1)]) pushDouble('pow2-ulp', v);
}

// ---- class 6: subnormals & tiny (all < 1e-6 -> must reject identically) -------------------------
for (const v of [Number.MIN_VALUE, nextafter(0, +1), nextafter(Number.MIN_VALUE, +1), 2.2250738585072014e-308,
  nextafter(2.2250738585072014e-308, -1), 5e-308, 1e-310, -Number.MIN_VALUE]) pushDouble('subnormal', v);
// exponent-form literals: the strict parser must reject the lexeme itself
for (const lex of ['5e-324', '1e-7', '1.5e-10', '2.2250738585072014e-308', '1E10', '1e+21', '-3e-9', '1.0e0'])
  push('exp-literal', lex);

// ---- class 7: large integers around the 2^53 safe boundary --------------------------------------
for (const n of [
  '9007199254740990', '9007199254740991',               // safe
  '9007199254740992', '9007199254740993', '9007199254740994', '9007199254740995', // >= 2^53 -> reject
  '-9007199254740991', '-9007199254740992', '-9007199254740993',
  '99999999999999999', '18014398509481984',             // reject (too big)
  '0', '1', '-1', '42', '-0',                            // -0 must reject
]) push('int-boundary', n);
// random safe + unsafe integers
for (let i = 0; i < 2000; i++) {
  const n = next64() % 0x40000000000000n; // up to ~2^54
  const sign = rndInt(2) ? -1n : 1n;
  push('int-random', String(sign * n));
}

// ---- class 8: NON-SHORTEST-but-canonical <=15-digit lexemes (lexeme vs round-trip divergence hunt) --
// For a double v, build its 15-significant-digit decimal; if that lexeme is canonical (no trailing zero,
// in-profile) it is fed verbatim. If any such lexeme's double has a SHORTER shortest form, the
// lexeme-preserving and round-tripping verifiers will diverge. (We also try 16/17 digits -> reject.)
for (let i = 0; i < countArg * 0.15; i++) {
  const exp = rndFloat01() * 10 - 5;              // 1e-5 .. 1e5
  const sign = rndInt(2) ? -1 : 1;
  const v = sign * Math.pow(10, exp) * (0.5 + rndFloat01());
  for (const p of [15, 16, 17]) {
    let s = v.toPrecision(p);
    if (s.includes('e') || s.includes('E')) continue; // exponent lexeme can't be canonical; skip
    if (s.includes('.')) s = s.replace(/0+$/, '').replace(/\.$/, '');
    push(`nonshortest-p${p}`, s);
  }
}

// ---- class 9: hard STRINGS (fed as raw JSON string literals; escapes are deliberate) ------------
// [tag, rawJsonText]. The canonical form must agree on which bytes are escaped and which emitted raw.
const strCases = [
  ['solidus-raw', '"a/b/c"'],
  ['solidus-escaped', '"a\\/b\\/c"'],                 // \/ must decode to / and re-emit RAW as /
  ['line-sep-raw', '"x\u2028y"'],                     // U+2028 LINE SEPARATOR emitted raw
  ['para-sep-raw', '"x\u2029y"'],                     // U+2029 PARAGRAPH SEPARATOR emitted raw
  ['line-sep-escaped', '"x\\u2028y"'],
  ['para-sep-escaped', '"x\\u2029y"'],
  ['c0-null', '"\\u0000"'],
  ['c0-bell', '"\\u0007"'],
  ['c0-unit-sep', '"\\u001f"'],
  ['c0-all', '"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\u0008\\u0009\\u000a\\u000b\\u000c\\u000d\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f"'],
  ['named-escapes', '"\\b\\f\\n\\r\\t\\"\\\\"'],
  ['del-7f-raw', '"\u007f"'],                         // DEL: >= 0x20 -> emitted RAW by every impl
  ['del-7f-escaped', '"\\u007f"'],                    // escaped on input -> decodes to DEL -> emitted raw
  ['nbsp', '"\u00a0"'],
  ['nonbmp-emoji-raw', '"\u{1F600}\u{1F4A9}"'],       // surrogate pair in source -> 4-byte UTF-8 raw
  ['nonbmp-escaped', '"\\ud83d\\ude00"'],             // same via \u escapes
  ['nonbmp-plane2', '"\u{20000}"'],
  ['lone-high', '"\\ud800"'],                         // lone surrogate (as a \u escape) -> MUST reject identically
  ['lone-low', '"\\udc00"'],
  ['lone-mid', '"a\\ud834b"'],                        // lone high surrogate mid-string
  ['surrogate-reversed', '"\\udc00\\ud800"'],
  // NB: a *raw* lone surrogate as an actual source character is deliberately NOT emitted — it cannot be
  // encoded into a UTF-8 JSONL line, so it would corrupt the transport (the drivers' own JSON readers choke
  // on the outer line) rather than test canonicalization. The \u-escaped forms above are the real test.
  ['uppercase-hex-escape', '"\\u00AB"'],              // input hex case must not leak into output
  ['mixed', '"a\\u0001b/c\u2028d\u{1F680}e\\tf"'],
  ['empty', '""'],
  ['quote-only', '"\\""'],
  ['backslash-only', '"\\\\"'],
  ['high-codepoint-sort', '"\uffff"'],
];
for (const [tag, raw] of strCases) push(`str-${tag}`, raw);

// ---- class 10: adversarial OBJECT KEYS (escaping + bytewise UTF-8 sort across planes) ----------
const keyObjs = [
  '{"\\u0001":1,"\\u0000":2}',                        // control-char keys, must sort by byte
  '{"b":1,"a":2,"\u00e9":3,"A":4}',                   // ASCII vs latin-1 byte order
  '{"\u{1F600}":1,"\uffff":2,"~":3,"\u0080":4}',      // BMP vs non-BMP byte order (UTF-8)
  '{"\\ud83d\\ude00":1,"z":2}',
  '{"/":1,"\\/":2}',                                  // these two keys decode to the SAME key -> dup -> reject
  '{"\u2028":1,"\u2029":2,"\t":3}',
  '{"\\u0000key":1,"\u0000key":2}',                   // duplicate after decode -> reject
];
for (let i = 0; i < keyObjs.length; i++) push('keys', keyObjs[i], `keys-${i}`);

// ---- class 11: numbers EMBEDDED in objects/arrays (exercise the full serializer path) ----------
for (let i = 0; i < countArg * 0.15; i++) {
  const exp = rndFloat01() * 14 - 7;
  const sign = rndInt(2) ? -1 : 1;
  const v = sign * Math.pow(10, exp) * (0.5 + rndFloat01());
  const w = doubleFromBits(rndInt(0x100000000), rndInt(0x100000000));
  push('embedded', `{"z":${jsNum(v)},"a":[${jsNum(w)},${jsNum(v)}],"m":{"k":${jsNum(v)}}}`);
}

// ---- class 12: randomized hard strings (stress every escaper branch in combination) -----------
// Draw code points biased toward the escape boundaries: ASCII, C0 controls, quote/backslash/solidus,
// U+2028/U+2029, DEL, Latin-1 supplement, CJK, and non-BMP (as surrogate pairs). Emit as a JSON string
// literal using \u escapes for every unit, so the transport line is always valid UTF-8 and the parser must
// reconstruct the exact code points, then the escaper must agree byte-for-byte on the canonical form.
function esc4(u) { return '\\u' + u.toString(16).padStart(4, '0'); }
function randUnit() {
  const bucket = rndInt(10);
  if (bucket < 2) return rndInt(0x20);                       // C0 controls
  if (bucket < 3) return [0x22, 0x5c, 0x2f, 0x7f][rndInt(4)]; // " \ / DEL
  if (bucket < 4) return [0x2028, 0x2029, 0xa0, 0xfeff, 0x200b][rndInt(5)];
  if (bucket < 7) return 0x20 + rndInt(0x5f);                // printable ASCII
  if (bucket < 9) return 0x80 + rndInt(0x3000);              // BMP (incl. CJK), no surrogates
  return 0x10000 + rndInt(0x10000);                          // non-BMP (astral)
}
for (let i = 0; i < 4000; i++) {
  const len = rndInt(12);
  let raw = '"';
  for (let j = 0; j < len; j++) {
    const cp = randUnit();
    if (cp > 0xffff) { const c = cp - 0x10000; raw += esc4(0xd800 + (c >> 10)) + esc4(0xdc00 + (c & 0x3ff)); }
    else raw += esc4(cp);
  }
  raw += '"';
  push('str-random', raw);
}
// occasional deliberately-lone surrogate escapes (must reject identically everywhere)
for (let i = 0; i < 200; i++) {
  const hi = rndInt(2) === 0;
  push('str-random-lone', `"a${esc4(hi ? 0xd800 + rndInt(0x400) : 0xdc00 + rndInt(0x400))}b"`);
}

// de-dup by raw text (keep first id)
const seen = new Set();
const uniq = cases.filter((c) => (seen.has(c.raw) ? false : (seen.add(c.raw), true)));

writeFileSync(outPath, uniq.map((c) => JSON.stringify(c)).join('\n') + '\n');
const byCls = {};
for (const c of uniq) byCls[c.cls] = (byCls[c.cls] ?? 0) + 1;
console.error(`generated ${uniq.length} unique canon cases (seed=${seedArg}) -> ${outPath}`);
console.error('classes:', Object.entries(byCls).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}:${n}`).join(' '));
