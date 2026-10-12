/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-wire.ts - typed adapter over the PROVED wire layer (formal/dafny/Wire.dfy -> generated/pca_wire.js):
// strict JSON parse + canonical printer, UTF-8 key order, strict base64url, canonical hex.
// Only this file touches Dafny runtime values; everything exported is plain JS (string / number / Uint8Array / null).
// NOT wired into production (performance is quadratic on very large inputs; see docs/pca/security/verified-core.md, "Wire layer").
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const W = require('../generated/pca_wire.js') as { _dafny: any; Utf: any; B64: any; Json: any; Api: any };
const D = W._dafny;
const Api = W.Api.__default;
const J = W.Json.J;
const KV = W.Json.KV;

const bn = (n: number | bigint | string): BigNumber => new BigNumber(n as any);

/** UTF-16 code units of a JS string as a Dafny seq<int>. */
function units(s: string): any {
  const q = D.Seq.of();
  for (let i = 0; i < s.length; i++) q.push(bn(s.charCodeAt(i)));
  return q;
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

const SEEN_DEPTH_GUARD = 4096;
/** JS value -> Dafny J (glue; the profile checks themselves are made by the proved `Valid`). Throws TypeError for unrepresentable values. */
function toJ(v: unknown, seen: Set<object>, depth: number): any {
  if (v === null) return J.create_Null();
  switch (typeof v) {
    case 'string':
      return J.create_Str(units(v));
    case 'boolean':
      return J.create_Bool(v);
    case 'number': {
      if (!Number.isFinite(v)) throw new TypeError('canonicalize: non-finite number');
      if (Object.is(v, -0)) throw new TypeError('canonicalize: negative zero');
      if (Number.isInteger(v)) return J.create_Int(bn(v));
      const s = String(v);
      if (/e/i.test(s)) throw new TypeError('canonicalize: exponent form');
      const neg = s.startsWith('-');
      const [ip, fr] = (neg ? s.slice(1) : s).split('.') as [string, string];
      const frd = D.Seq.of();
      for (const c of fr) frd.push(bn(c.charCodeAt(0) - 48));
      return J.create_Dec(neg, bn(ip), frd);
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
      for (let i = 0; i < o.length; i++) q.push(toJ(o[i], seen, depth + 1));
      return J.create_Arr(q);
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('canonicalize: non-plain object');
    const rec = o as Record<string, unknown>;
    const q = D.Seq.of();
    for (const k of Object.keys(rec)) q.push(KV.create_KV(units(k), toJ(rec[k], seen, depth + 1)));
    return J.create_Obj(q);
  } finally {
    seen.delete(o);
  }
}

/** Equivalent of `canonicalizeStrict(value)` via the proved printer (sorted keys, strict number/string/depth profile). Throws TypeError otherwise. */
export function wireCanonicalizeStrict(value: unknown): string {
  const r = Api.CanonicalOfValue(toJ(value, new Set(), 1));
  if (!r.is_Some) throw new TypeError('canonicalize: value outside the strict profile');
  return unitsToString(r.dtor_v);
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
