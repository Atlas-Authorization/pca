/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-wire.ts - typed adapter over the PROVED wire layer (formal/dafny/Wire.dfy -> generated/pca_wire.js):
// strict JSON parse + canonical printer, UTF-8 key order, strict base64url, canonical hex.
// Only this file touches Dafny runtime values; everything exported is plain JS (string / number / Uint8Array / null).
// strictParse acceptance (wireAcceptsText) and canonicalizeStrict (wireCanonicalizeStrict) run the compiled FAST PATHS (Wire.dfy
// modules Fast / FastP: native 16-bit units and indices, linear, each proved equal to the specification functions); the other
// entry points run the specification functions themselves (BigNumber per unit; quadratic on large inputs).
import { hardenDafnyRuntime } from './runtime';
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const W = require('../generated/pca_wire.js') as { _dafny: any; Utf: any; B64: any; Json: any; Fast: any; FastP: any; Api: any };
const D = hardenDafnyRuntime(W._dafny);
const Api = W.Api.__default;
const JU = W.FastP.JU;
const KU = W.FastP.KU;

const bn = (n: number | bigint | string): BigNumber => new BigNumber(n as any);

/** UTF-16 code units of a JS string as a Dafny seq<int>. */
function units(s: string): any {
  const q = D.Seq.of();
  for (let i = 0; i < s.length; i++) q.push(bn(s.charCodeAt(i)));
  return q;
}
/**
 * UTF-16 code units of a JS string as a Dafny seq of NATIVE numbers (the input of the compiled fast paths, modules Fast / FastP,
 * whose 16-bit unit type compiles to a plain number): one conversion per call, no BigNumber per unit.
 */
function units16(s: string): any {
  const q = new D.Seq();
  q.length = s.length; // sized once (a push per unit is ~10x slower on a 1 MiB text)
  for (let i = 0; i < s.length; i++) q[i] = s.charCodeAt(i);
  return q;
}
/** A fresh salt for the proved parser's duplicate-key table (the proof holds for every value; the salt only spreads its buckets). */
function seed(): number {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint32Array) => Uint32Array } }).crypto;
  if (c?.getRandomValues) return c.getRandomValues(new Uint32Array(1))[0]!;
  return Math.floor(Math.random() * 0x1_0000_0000);
}
function bytesSeq(b: Uint8Array): any {
  const q = D.Seq.of();
  for (let i = 0; i < b.length; i++) q.push(bn(b[i]!));
  return q;
}
function unitsToString(q: any): string {
  const n = q.length as number;
  let out = '';
  const CH = 4096;
  for (let i = 0; i < n; i += CH) {
    const part: number[] = [];
    for (let k = i; k < Math.min(n, i + CH); k++) part.push((q[k] as BigNumber).toNumber());
    out += String.fromCharCode(...part);
  }
  return out;
}
function seqToBytes(q: any): Uint8Array {
  const out = new Uint8Array(q.length as number);
  for (let i = 0; i < out.length; i++) out[i] = (q[i] as BigNumber).toNumber();
  return out;
}

/** Equivalent of `canonicalizeStrict(strictParse(text))` computed by the proved code; `undefined` where strictParse would throw. */
export function wireCanonicalOfText(text: string): string | undefined {
  const r = Api.CanonicalOfText(units(text));
  return r.is_Some ? unitsToString(r.dtor_v) : undefined;
}

/**
 * Does the proved strict-JSON profile accept `text`? (`Json.ParseTop(text).Some?`, i.e. `strictParse` would not throw.) Same
 * decision as `wireCanonicalOfText(text) !== undefined` (Wire.dfy `CanonicalOfTextTotalOnAccepted`: the canonical printer is total
 * on every accepted text) without running that printer, whose compiled form copies its accumulator once per character: a
 * maximum-size (1 MiB) string would take ~5 x 10^11 element copies to print, while the parse copies a run of plain characters once.
 */
export function wireAcceptsText(text: string): boolean {
  // Api.ParseAcceptsU == Json.ParseTop(text).Some? (Wire.dfy ParseAcceptsUSpec): the compiled fast path, linear in the text.
  return Api.ParseAcceptsU(units16(text), seed()) === true;
}

const SEEN_DEPTH_GUARD = 4096;
/**
 * JS value -> FastP.JU (glue; the profile checks themselves are made by the proved printer). Throws TypeError for unrepresentable
 * values. Strings become native code-unit sequences; a safe integer is UInt, any other integer UBig (never in the profile); a
 * non-integer is UDec with its plain decimal spelling (|v| < 2^52, so the integer part is a safe native number).
 */
function toJU(v: unknown, seen: Set<object>, depth: number): any {
  if (v === null) return JU.create_UNull();
  switch (typeof v) {
    case 'string':
      return JU.create_UStr(units16(v));
    case 'boolean':
      return JU.create_UBool(v);
    case 'number': {
      if (!Number.isFinite(v)) throw new TypeError('canonicalize: non-finite number');
      if (Object.is(v, -0)) throw new TypeError('canonicalize: negative zero');
      if (Number.isInteger(v)) return Number.isSafeInteger(v) ? JU.create_UInt(v) : JU.create_UBig(bn(v));
      const s = String(v);
      if (/e/i.test(s)) throw new TypeError('canonicalize: exponent form');
      const neg = s.startsWith('-');
      const [ip, fr] = (neg ? s.slice(1) : s).split('.') as [string, string];
      const frd = D.Seq.of();
      for (let i = 0; i < fr.length; i++) frd.push(fr.charCodeAt(i) - 48);
      return JU.create_UDec(neg, Number(ip), frd);
    }
    case 'object':
      break;
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof v}`);
  }
  const o = v as object;
  if (depth > SEEN_DEPTH_GUARD) throw new TypeError('canonicalize: nesting too deep');
  if (seen.has(o)) throw new TypeError('canonicalize: cycle');
  seen.add(o);
  try {
    if (Array.isArray(o)) {
      const q = D.Seq.of();
      for (let i = 0; i < o.length; i++) q.push(toJU(o[i], seen, depth + 1));
      return JU.create_UArr(q);
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('canonicalize: non-plain object');
    const rec = o as Record<string, unknown>;
    const q = D.Seq.of();
    for (const k of Object.keys(rec)) q.push(KU.create_KU(units16(k), toJU(rec[k], seen, depth + 1)));
    return JU.create_UObj(q);
  } finally {
    seen.delete(o);
  }
}

/** Native-number code units [0, n) of an output buffer -> string. */
function nativeUnitsToString(b: number[], n: number): string {
  let out = '';
  const CH = 4096;
  for (let i = 0; i < n; i += CH) out += String.fromCharCode.apply(null, b.slice(i, Math.min(n, i + CH)));
  return out;
}

/**
 * Equivalent of `canonicalizeStrict(value)` via the proved printer (Api.CanonicalOfValueU == Json.CanonText: sorted keys, strict
 * number/string/depth profile; linear apart from the O(m log m) key sort per object). Throws TypeError outside the profile, and a
 * RangeError if the output would pass 2^40 code units (resource exhaustion, no verdict; unreachable in practice).
 */
export function wireCanonicalizeStrict(value: unknown): string {
  const [st, b, n] = Api.CanonicalOfValueU(toJU(value, new Set(), 1)) as [any, number[], number];
  if (st.is_Done) return nativeUnitsToString(b, n);
  if (st.is_Bad) throw new TypeError('canonicalize: value outside the strict profile');
  throw new RangeError('canonicalize: output exceeds the verified printer limit');
}

/** compareUtf8 for WELL-FORMED strings: sign of the UTF-8 bytewise comparison (-1 | 0 | 1). */
export function wireCompareUtf8(a: string, b: string): -1 | 0 | 1 {
  return Api.CompareUtf8(units(a), units(b)).toNumber();
}

const NONE = (): any => W.B64.Option.create_None();
/** decodeB64uStrict(s, len?) -> bytes | null. */
export function wireDecodeB64uStrict(s: unknown, len?: number): Uint8Array | null {
  if (typeof s !== 'string') return null;
  const r = Api.B64Decode(units(s), len === undefined ? NONE() : W.B64.Option.create_Some(bn(len)));
  return r.is_Some ? seqToBytes(r.dtor_v) : null;
}
export function wireB64uEncode(b: Uint8Array): string {
  return unitsToString(Api.B64Encode(bytesSeq(b)));
}
/** Canonical (lower-case, even length) hex. */
export function wireHexDecode(s: string): Uint8Array | null {
  const r = Api.HexDecode(units(s));
  return r.is_Some ? seqToBytes(r.dtor_v) : null;
}
export function wireHexEncode(b: Uint8Array): string {
  return unitsToString(Api.HexEncode(bytesSeq(b)));
}
