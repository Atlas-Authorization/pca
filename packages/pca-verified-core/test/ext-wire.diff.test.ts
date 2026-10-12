/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential tests: the PROVED wire layer (Wire.dfy -> pca_wire.js, via src/ext-wire.ts) vs the production TypeScript
// (packages/pca/src/strict-json.ts, hash.ts). Counts: WIRE_FUZZ_N (default 6000 per family; the bulk run on a cloud box uses millions).
import { describe, expect, it } from 'vitest';
import { strictParse } from '../../pca/src/strict-json';
import { canonicalizeStrict, compareUtf8, decodeB64uStrict, b64u } from '../../pca/src/hash';
import { wireCanonicalOfText, wireCanonicalizeStrict, wireCompareUtf8, wireDecodeB64uStrict, wireB64uEncode, wireHexDecode, wireHexEncode } from '../src/ext-wire';
import { loadCorpus } from './support/corpus';

const N = Number(process.env.WIRE_FUZZ_N ?? 6000);
const SEED = Number(process.env.WIRE_FUZZ_SEED ?? 0x5eed);

function mulberry32(a: number): () => number {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
class R {
  constructor(public f: () => number) {}
  n(k: number) { return Math.floor(this.f() * k); }
  p(x: number) { return this.f() < x; }
  pick<T>(a: readonly T[]): T { return a[this.n(a.length)]!; }
}

const tsCanon = (text: string): string | undefined => { try { return canonicalizeStrict(strictParse(text)); } catch { return undefined; } };
const tsCanonVal = (v: unknown): string | undefined => { try { return canonicalizeStrict(v); } catch { return undefined; } };
const wCanonVal = (v: unknown): string | undefined => { try { return wireCanonicalizeStrict(v); } catch { return undefined; } };

describe('wire layer: proved code == production TS', () => {
  it.skipIf(!!process.env.WIRE_SKIP_CORPUS)('conformance corpus: every pcactn_json text and every pcactn/grant object', () => {
    const { core, adversarial } = loadCorpus();
    let texts = 0, values = 0, accepted = 0, skipped = 0;
    // the reference parser is a literal functional transcription (quadratic in the number of array/object members): cap the text length
    const CAP = Number(process.env.WIRE_CORPUS_CAP ?? 20000);
    for (const v of [...core, ...adversarial]) {
      const cands: string[] = [];
      if (typeof v.pcactn_json === 'string') cands.push(v.pcactn_json);
      if (v.pcactn !== undefined) cands.push(JSON.stringify(v.pcactn));
      if (v.grant !== undefined) cands.push(JSON.stringify(v.grant));
      for (const c of cands) {
        if (c.length > CAP) { skipped++; continue; }
        texts++;
        const a = tsCanon(c), b = wireCanonicalOfText(c);
        expect(b, c.slice(0, 120)).toBe(a);
        if (a !== undefined) accepted++;
      }
      for (const o of [v.pcactn, v.grant]) {
        if (o === undefined) continue;
        if (JSON.stringify(o).length > CAP) continue;
        values++;
        expect(wCanonVal(o)).toBe(tsCanonVal(o));
      }
    }
    console.log(`[wire corpus] texts=${texts} skipped(>${CAP} chars)=${skipped} accepted=${accepted} values=${values}`);
    expect(texts).toBeGreaterThan(3000);
    expect(accepted).toBeGreaterThan(1000);
  }, 7_200_000);

  // ---- random JSON texts: structured generator + mutations ----
  const STRS = ['', 'a', 'abc', 'é', ' ', '😀', '"', '\\', '/', '\n', '\u0000', '\u001f', '\u007f', '￿', 'a\tb', '__proto__', 'é́', 'z', 'Z', '퟿', ''];
  const NUMS = ['0', '-0', '1', '-1', '10', '100', '007', '0.1', '-0.5', '1.0', '1.50', '1e5', '1E5', '1e-7', '0.000001', '0.0000001', '0.000000999999999999999', '123456789012345', '1234567890123456', '9007199254740991', '9007199254740992', '-9007199254740991', '12345678901234.5', '123456789012345.6', '0.123456789012345', '0.1234567890123456', '.5', '5.', '+1', '1e', '1e+', '--1', '-', '99999999999999.9'];
  function genText(r: R, depth: number): string {
    const ws = () => (r.p(0.15) ? r.pick([' ', '\n', '\t', '\r', '  ', ' ', '\u000b', '﻿']) : '');
    const str = (): string => {
      let s = r.pick(STRS);
      if (r.p(0.3)) s += r.pick(STRS);
      let out = '"';
      for (const ch of s) {
        const c = ch.codePointAt(0)!;
        if (ch === '"') out += r.p(0.9) ? '\\"' : '"';
        else if (ch === '\\') out += '\\\\';
        else if (c < 0x20) out += r.p(0.5) ? '\\u' + c.toString(16).padStart(4, r.p(0.9) ? '0' : '0').toUpperCase() : r.p(0.5) ? ch : '\\u' + c.toString(16).padStart(4, '0');
        else if (r.p(0.15)) out += c > 0xffff ? '\\u' + (0xd800 + ((c - 0x10000) >> 10)).toString(16) + '\\u' + (0xdc00 + ((c - 0x10000) & 0x3ff)).toString(16) : '\\u' + c.toString(16).padStart(4, '0');
        else if (ch === '/' && r.p(0.3)) out += '\\/';
        else out += ch;
      }
      if (r.p(0.03)) out += r.pick(['\\x41', '\\ud800', '\\udc00', '\\u12', '\\q']);
      return out + '"';
    };
    const k = r.n(depth > 0 ? 9 : 5);
    if (k === 0) return 'null';
    if (k === 1) return r.p(0.5) ? 'true' : 'false';
    if (k === 2 || k === 3) return r.pick(NUMS);
    if (k === 4) return str();
    const n = r.n(4);
    const parts: string[] = [];
    if (k <= 6) {
      for (let i = 0; i < n; i++) parts.push(ws() + genText(r, depth - 1) + ws());
      return '[' + ws() + parts.join(',') + (r.p(0.02) ? ',' : '') + ']';
    }
    for (let i = 0; i < n; i++) parts.push(ws() + (r.p(0.2) ? str() : '"' + r.pick(['a', 'b', 'c', 'é', 'aa', '😀', '￿', 'Z', '\\u0061', '1', '10', '2'].map((x) => x)) + '"') + ws() + ':' + ws() + genText(r, depth - 1) + ws());
    return '{' + parts.join(',') + (r.p(0.02) ? ',' : '') + '}';
  }
  const TOK = ['"', '\\', '{', '}', '[', ']', ',', ':', ' ', '\n', '0', '1', '-', '.', 'e', 'E', '+', 'u', 'n', 't', 'f', '\ud800', '\udc00', '\ud83d', '\ude00', 'é', 'null', 'true', '\\u0041', '\\ud83d', '\\ude00'];
  function mutate(r: R, s: string): string {
    const m = r.n(4);
    for (let i = 0; i < m; i++) {
      const pos = r.n(s.length + 1);
      const op = r.n(3);
      if (op === 0) s = s.slice(0, pos) + r.pick(TOK) + s.slice(pos);
      else if (op === 1) s = s.slice(0, pos) + s.slice(pos + 1 + r.n(2));
      else s = s.slice(0, pos) + r.pick(TOK) + s.slice(pos + 1);
    }
    return s;
  }

  it(`random texts + mutations (${N})`, () => {
    const r = new R(mulberry32(SEED));
    let acc = 0, rej = 0;
    const bad: string[] = [];
    for (let i = 0; i < N; i++) {
      let t = genText(r, 4);
      if (r.p(0.5)) t = mutate(r, t);
      const a = tsCanon(t), b = wireCanonicalOfText(t);
      if (a !== b) { bad.push(JSON.stringify(t) + ' ts=' + JSON.stringify(a) + ' wire=' + JSON.stringify(b)); if (bad.length > 5) break; }
      if (a === undefined) rej++; else acc++;
    }
    console.log(`[wire texts] n=${N} accepted=${acc} rejected=${rej}`);
    expect(bad).toEqual([]);
    expect(acc).toBeGreaterThan(N / 50);
    expect(rej).toBeGreaterThan(N / 50);
  }, 7_200_000);

  it('pure random strings over the JSON alphabet', () => {
    const r = new R(mulberry32(SEED + 1));
    const bad: string[] = [];
    for (let i = 0; i < N; i++) {
      let t = '';
      const L = r.n(24);
      for (let k = 0; k < L; k++) t += r.pick(TOK);
      const a = tsCanon(t), b = wireCanonicalOfText(t);
      if (a !== b) { bad.push(JSON.stringify(t) + ' ts=' + JSON.stringify(a) + ' wire=' + JSON.stringify(b)); if (bad.length > 5) break; }
    }
    expect(bad).toEqual([]);
  }, 7_200_000);

  // ---- random JS values through canonicalizeStrict ----
  function genVal(r: R, depth: number): unknown {
    const k = r.n(depth > 0 ? 9 : 6);
    switch (k) {
      case 0: return null;
      case 1: return r.p(0.5);
      case 2: return r.pick([0, -0, 1, -1, 42, 2 ** 53 - 1, 2 ** 53, -(2 ** 53 - 1), 0.1, -0.5, 1e-6, 1e-7, 5e-7, 1.5e21, 1e21, 123456789012345.6, 99999999999999.9, 0.1 + 0.2, NaN, Infinity, -Infinity, 1 / 3, 0.000001234567890123, 4.35, 100.25, 1234.5678, 2 ** 60, 1e300, 0.30000000000000004]);
      case 3: return Math.floor((r.f() - 0.5) * 2 ** r.n(53)) ;
      case 4: case 5: return r.pick(STRS) + (r.p(0.2) ? r.pick(['\ud800', '\udc00', '\ud83d', '\ude00']) : '');
      case 6: case 7: return Array.from({ length: r.n(4) }, () => genVal(r, depth - 1));
      default: {
        const o: Record<string, unknown> = {};
        const n = r.n(5);
        for (let i = 0; i < n; i++) o[r.pick(['a', 'b', 'é', 'z', '😀', '￿', '', '퟿', 'A', '10', '2', '', 'ab', 'a\u0000', '__proto__x', '\ud800'])] = genVal(r, depth - 1);
        return o;
      }
    }
  }
  it(`random JS values: canonicalizeStrict (${N})`, () => {
    const rr = new R(mulberry32(SEED + 2));
    const bad: string[] = [];
    let ok = 0, thrown = 0;
    for (let i = 0; i < N; i++) {
      const v = genVal(rr, 4);
      const a = tsCanonVal(v), b = wCanonVal(v);
      if (a !== b) { bad.push(String(a) + ' | ' + String(b)); if (bad.length > 5) break; }
      if (a === undefined) thrown++; else ok++;
    }
    console.log(`[wire values] n=${N} ok=${ok} thrown=${thrown}`);
    expect(bad).toEqual([]);
    expect(ok).toBeGreaterThan(N / 20);
    expect(thrown).toBeGreaterThan(N / 50);
  }, 7_200_000);

  it('hand-picked edge cases (surrogate mixing, duplicates, numbers, whitespace, BOM)', () => {
    const cases = [
      '"\ud83d\ude00"', '"\ud83d\ude00"'.replace('\\ud83d', '\ud83d'), '"\ud83d\\ude00"', '"\\ud83d\ude00"', '"\\ud83d"', '"\\ude00"', '"\\ude00\\ud83d"', '"\ud83d"', '"\ude00"',
      '{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '[{"x":1},{"x":1}]', '{"\\u0061":1,"a":2}', '{"b":1,"a":2}', '{"\ud83d\ude00":1,"\uffff":2}',
      '\ufeff1', '1\u00a0', ' 1 ', '\t\n\r 1', '[1,]', '[,1]', '{"a":1,}', '{,}', '[]', '{}', '[ ]', '{ }', 'nul', 'nullx', 'truefalse', '[truefalse]',
      '-', '-0', '-0.0', '0.0', '0.5', '-0.5', '00', '01', '1.', '.1', '1e1', '1E+1', '1.5e', '1e', '9007199254740991', '9007199254740992', '-9007199254740992',
      '0.000001', '0.0000001', '0.000000999999999999999', '0.1234567890123456', '0.123456789012345', '12345678901234.5', '99999999999999.99', '1.10',
      '"\\u00zz"', '"\\u00"', '"\\u0041"', '"\\U0041"', '"\\/"', "\"\\'\"", '"\t"', '"a\nb"', '"\u0000"', '"\\u0000"', '"\\u001F"', '"\\u001f"', '"\\u007f"', '"\u007f"',
      '{"a":1}{"b":1}', '[1]x', '', ' ', '"', '"abc', '\\', '{"a"}', '{"a":}', '{1:2}', '{"a" 1}',
    ];
    for (const c of cases) expect(wireCanonicalOfText(c), JSON.stringify(c)).toBe(tsCanon(c));
  });

  it('depth boundary (32 ok, 33 rejected) and size boundary', () => {
    for (const depth of [30, 31, 32, 33, 34]) {
      const t = '['.repeat(depth) + ']'.repeat(depth);
      expect(wireCanonicalOfText(t)).toBe(tsCanon(t));
      const o = '{"a":'.repeat(depth) + '1' + '}'.repeat(depth);
      expect(wireCanonicalOfText(o)).toBe(tsCanon(o));
    }
    expect(wireCanonicalOfText('[' .repeat(32) + ']'.repeat(32))).toBeDefined();
    expect(wireCanonicalOfText('['.repeat(33) + ']'.repeat(33))).toBeUndefined();
  });

  it('UTF-8 key order: compareUtf8 on well-formed strings', () => {
    const r = new R(mulberry32(SEED + 3));
    const cp = (): number => r.pick([() => r.n(0x80), () => 0x80 + r.n(0x780), () => 0x800 + r.n(0xd800 - 0x800), () => 0xe000 + r.n(0x2000), () => 0x10000 + r.n(0x100000), () => 0xd7ff, () => 0xe000, () => 0xffff, () => 0x10000, () => 0x10ffff, () => 0x7f, () => 0x80, () => 0x7ff, () => 0x800])();
    const str = () => String.fromCodePoint(...Array.from({ length: r.n(5) }, cp));
    let bad = 0;
    for (let i = 0; i < N; i++) {
      const a = str(), b = r.p(0.2) ? a + str() : str();
      if (Math.sign(compareUtf8(a, b)) !== wireCompareUtf8(a, b)) bad++;
    }
    expect(bad).toBe(0);
  }, 7_200_000);

  it('strict base64url: decode (with and without fixed length) and encode', () => {
    const r = new R(mulberry32(SEED + 4));
    const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const EXTRA = ['=', '+', '/', ' ', '\n', 'é', '\u0000'];
    let acc = 0;
    for (let i = 0; i < N * 3; i++) {
      let s = '';
      const L = r.n(14);
      for (let k = 0; k < L; k++) s += r.p(0.03) ? r.pick(EXTRA) : ALPHA[r.n(64)];
      const len = r.p(0.4) ? undefined : r.n(11);
      const a = decodeB64uStrict(s, len), b = wireDecodeB64uStrict(s, len);
      if ((a === null) !== (b === null) || (a && b && Buffer.compare(Buffer.from(a), Buffer.from(b)) !== 0)) throw new Error('b64u decode mismatch ' + JSON.stringify(s) + ' len=' + len);
      if (a) acc++;
    }
    expect(acc).toBeGreaterThan(100);
    for (let i = 0; i < N; i++) {
      const bytes = Uint8Array.from({ length: r.n(40) }, () => r.n(256));
      if (wireB64uEncode(bytes) !== b64u(bytes)) throw new Error('b64u encode mismatch');
      if (Buffer.compare(Buffer.from(wireDecodeB64uStrict(b64u(bytes), bytes.length)!), Buffer.from(bytes)) !== 0) throw new Error('b64u round trip mismatch');
    }
    expect(wireDecodeB64uStrict(5 as any)).toBeNull();
  }, 7_200_000);

  it('canonical hex', () => {
    const r = new R(mulberry32(SEED + 5));
    const tsHex = (s: string): Uint8Array | null => (/^(?:[0-9a-f]{2})*$/.test(s) ? Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16)) : null);
    const CH = '0123456789abcdefABCDEFgG ';
    for (let i = 0; i < N; i++) {
      let s = '';
      const L = r.n(10);
      for (let k = 0; k < L; k++) s += CH[r.n(r.p(0.7) ? 16 : CH.length)];
      const a = tsHex(s), b = wireHexDecode(s);
      if ((a === null) !== (b === null) || (a && b && Buffer.compare(Buffer.from(a), Buffer.from(b)) !== 0)) throw new Error('hex mismatch ' + JSON.stringify(s));
    }
    const bytes = Uint8Array.from({ length: 33 }, (_, i) => (i * 37) & 255);
    expect(wireHexEncode(bytes)).toBe(Buffer.from(bytes).toString('hex'));
  }, 7_200_000);
});
