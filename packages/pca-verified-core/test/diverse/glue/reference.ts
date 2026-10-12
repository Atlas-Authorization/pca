// Independent reference models for the glue contract (see tools/pca-trustbase/glue/glue-contract.json). NOTHING here imports @noble/*
// or any packages/pca/src module except through arguments: Ed25519 is a BigInt curve model + OpenSSL (node:crypto), ML-DSA/SLH-DSA
// are OpenSSL 3.5 (node:crypto), SHA-2 is node:crypto, base64url and canonical JSON are re-implemented from the wire spec.
import { createHash, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';
// @ts-expect-error - plain ESM helper shared with the primitives harness (independent BigInt Ed25519 arithmetic)
import { L, P, decodeLenient, fromLE, mul, TORSION } from '../../../../../tools/pca-trustbase/primitives/lib/ed-cases.mjs';

// ---------------------------------------------------------------- base64url (strict, no padding)
export function b64uStrictRef(s: unknown, len?: number): Uint8Array | null {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) return null; // non-zero trailing bits
  if (len !== undefined && b.length !== len) return null;
  return new Uint8Array(b);
}
const b64uEnc = (u: Uint8Array) => Buffer.from(u).toString('base64url');

// ---------------------------------------------------------------- Ed25519 (strict, torsion-free) reference
const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const edKeyCache = new Map<string, KeyObject>();
const tfCache = new Map<string, boolean>();
const MASK255 = (1n << 255n) - 1n;
const isId = (p: { x: bigint; y: bigint }) => p.x === 0n && p.y === 1n;

/** Returns decoded point iff the 32-byte encoding is canonical (y < p; not "negative zero") and on the curve. */
function canonicalPoint(u: Uint8Array): { x: bigint; y: bigint } | null {
  const y = fromLE(u) & MASK255;
  if (y >= P) return null;
  const pt = decodeLenient(u);
  if (!pt) return null;
  if (pt.x === 0n && (u[31]! & 0x80) !== 0) return null;
  return pt;
}

export function edVerifyRefBytes(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length !== 32 || sig.length !== 64) return false;
  if (fromLE(sig.subarray(32)) >= L) return false; // S < L
  const A = canonicalPoint(pk);
  const R = canonicalPoint(sig.subarray(0, 32));
  if (!A || !R) return false;
  if (isId(mul(A, 8n)) || isId(mul(R, 8n))) return false; // small order
  const hk = Buffer.from(pk).toString('hex');
  let key = edKeyCache.get(hk);
  if (!key) {
    key = createPublicKey({ key: Buffer.concat([ED_SPKI, pk]), format: 'der', type: 'spki' });
    if (edKeyCache.size > 2048) edKeyCache.clear();
    edKeyCache.set(hk, key);
  }
  let eq = false;
  try { eq = nodeVerify(null, msg, key, sig); } catch { eq = false; }
  if (!eq) return false; // OpenSSL: cofactorless RFC 8032 equation, compares the canonical encoding of R
  let tf = tfCache.get(hk);
  if (tf === undefined) { tf = isId(mul(A, L)); if (tfCache.size > 4096) tfCache.clear(); tfCache.set(hk, tf); }
  // R = [S]B - [k]A lies in the prime-order subgroup whenever A does, so R needs no separate torsion test.
  return tf;
}
export function edVerifyRef(pkB64: unknown, msg: Uint8Array, sigB64: unknown): boolean {
  const pk = b64uStrictRef(pkB64, 32), sg = b64uStrictRef(sigB64, 64);
  return pk !== null && sg !== null && edVerifyRefBytes(pk, msg, sg);
}
export const SMALL_ORDER_COUNT = TORSION.length;

// ---------------------------------------------------------------- PQ via OpenSSL 3.5 (node:crypto)
const tlv = (t: number, ...parts: Buffer[]) => { const body = Buffer.concat(parts); const n = body.length; const l = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]); return Buffer.concat([Buffer.from([t]), l, body]); };
const spki = (last: number, raw: Uint8Array) => tlv(0x30, tlv(0x30, tlv(0x06, Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last]))), tlv(0x03, Buffer.from([0]), Buffer.from(raw)));
interface PqSpec { oid: number; pk: number; sig: number }
const PQ: Record<string, PqSpec> = {
  'ml-dsa-65': { oid: 18, pk: 1952, sig: 3309 },
  'ml-dsa-87': { oid: 19, pk: 2592, sig: 4627 },
  'slh-dsa-sha2-128f': { oid: 21, pk: 32, sig: 17088 },
  'slh-dsa-sha2-256s': { oid: 24, pk: 64, sig: 29792 },
};
const pqCache = new Map<string, KeyObject>();
/** Optional observer of every PQ component verification the reference performs (used to dump traffic for multi-implementation replay). */
export const tap: { pq?: (kind: string, pk: Uint8Array, msg: Uint8Array, sig: Uint8Array) => void; ed?: (pk: Uint8Array, msg: Uint8Array, sig: Uint8Array) => void } = {};
export function pqVerifyRef(kind: keyof typeof PQ, pkB64: unknown, msg: Uint8Array, sigB64: unknown): boolean {
  const spec = PQ[kind]!;
  const pk = b64uStrictRef(pkB64, spec.pk), sg = b64uStrictRef(sigB64, spec.sig);
  if (!pk || !sg) return false;
  tap.pq?.(kind as string, pk, msg, sg);
  const ck = kind + Buffer.from(pk).toString('base64');
  let key = pqCache.get(ck);
  try {
    if (!key) { key = createPublicKey({ key: spki(spec.oid, pk), format: 'der', type: 'spki' }); if (pqCache.size > 256) pqCache.clear(); pqCache.set(ck, key); }
    return nodeVerify(null, msg, key, sg);
  } catch { return false; }
}

// ---------------------------------------------------------------- suite combinator (independent of pq.ts)
type SuiteShape = { ed: boolean; pq?: keyof typeof PQ; nested?: boolean };
const SUITES: Record<string, SuiteShape> = {
  'ed25519': { ed: true },
  'ml-dsa-65': { ed: false, pq: 'ml-dsa-65' },
  'hybrid-ed25519-ml-dsa-65': { ed: true, pq: 'ml-dsa-65' },
  'hybrid-nested-ed25519-ml-dsa-65': { ed: true, pq: 'ml-dsa-65', nested: true },
  'slh-dsa-sha2-128f': { ed: false, pq: 'slh-dsa-sha2-128f' },
  'hybrid-ed25519-slh-dsa-sha2-128f': { ed: true, pq: 'slh-dsa-sha2-128f' },
  'ml-dsa-87': { ed: false, pq: 'ml-dsa-87' },
  'hybrid-ed25519-ml-dsa-87': { ed: true, pq: 'ml-dsa-87' },
  'slh-dsa-sha2-256s': { ed: false, pq: 'slh-dsa-sha2-256s' },
  'hybrid-ed25519-slh-dsa-sha2-256s': { ed: true, pq: 'slh-dsa-sha2-256s' },
};
export const SUITE_NAMES = Object.keys(SUITES);

/** undefined = this alg is outside the monitor (FN-DSA / LESS backends). */
export function suiteRef(alg: unknown, keys: { edPub?: unknown; pq?: { b64u?: unknown } | undefined } | undefined, msg: Uint8Array, s: { sig?: unknown; pq_sig?: unknown } | undefined, isPinned: (x: unknown) => boolean): boolean | undefined {
  const name = alg === undefined ? 'ed25519' : typeof alg === 'string' ? alg : null;
  if (name === null) return false;
  if (!(name in SUITES)) return /^(fn-dsa|less|hybrid-ed25519-less)/.test(name) ? undefined : false;
  const sh = SUITES[name]!;
  const pqk = keys?.pq;
  if (pqk !== undefined && !isPinned(pqk)) return false;
  const sig = s?.sig;
  const edOk = !sh.ed ? true : typeof sig === 'string' && typeof keys?.edPub === 'string' && edVerifyRef(keys.edPub, msg, sig);
  if (!sh.pq) return edOk;
  // pure PQ: the PQ signature is `sig`; hybrids: it is `pq_sig`
  const pqSigField = sh.ed ? s?.pq_sig : sig;
  let pqMsg = msg;
  if (sh.nested) {
    const edBytes = b64uStrictRef(sig, 64);
    if (edBytes === null) return false;
    pqMsg = Buffer.concat([msg, edBytes]);
  }
  const pqOk = typeof pqSigField === 'string' && pqVerifyRef(sh.pq, keys?.pq?.b64u, pqMsg, pqSigField);
  return edOk && pqOk;
}

// ---------------------------------------------------------------- canonical JSON (strict profile) + hash
const utf8cmp = (a: string, b: string) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
const hasLone = (s: string) => { for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c >= 0xd800 && c <= 0xdbff) { const d = s.charCodeAt(i + 1); if (d >= 0xdc00 && d <= 0xdfff) { i++; continue; } return true; } if (c >= 0xdc00 && c <= 0xdfff) return true; } return false; };
function escStr(s: string): string {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') o += '\\"'; else if (ch === '\\') o += '\\\\'; else if (c === 8) o += '\\b'; else if (c === 12) o += '\\f'; else if (c === 10) o += '\\n'; else if (c === 13) o += '\\r'; else if (c === 9) o += '\\t';
    else if (c < 0x20) o += '\\u' + c.toString(16).padStart(4, '0'); else o += ch;
  }
  return o + '"';
}
function numRef(v: number): string {
  if (!Number.isFinite(v) || Object.is(v, -0)) throw new TypeError('num');
  if (Number.isInteger(v)) { if (Math.abs(v) > Number.MAX_SAFE_INTEGER) throw new TypeError('int'); return String(v); }
  if (Math.abs(v) < 1e-6) throw new TypeError('small');
  const s = String(v);
  if (/e/i.test(s)) throw new TypeError('exp');
  if (s.replace('-', '').replace('.', '').replace(/^0+/, '').length > 15) throw new TypeError('digits');
  return s;
}
export function canonRef(v: unknown, depth = 1, seen: object[] = []): string {
  if (v === null) return 'null';
  if (typeof v === 'string') { if (hasLone(v)) throw new TypeError('surrogate'); return escStr(v); }
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return numRef(v);
  if (typeof v !== 'object') throw new TypeError('type');
  if (depth > 32) throw new TypeError('depth');
  if (seen.includes(v as object)) throw new TypeError('cycle');
  seen.push(v as object);
  try {
    if (Array.isArray(v)) return '[' + v.map((x) => canonRef(x, depth + 1, seen)).join(',') + ']';
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('plain');
    const keys = Object.keys(v as object).sort(utf8cmp);
    return '{' + keys.map((k) => { if (hasLone(k)) throw new TypeError('keysurrogate'); return escStr(k) + ':' + canonRef((v as Record<string, unknown>)[k], depth + 1, seen); }).join(',') + '}';
  } finally { seen.pop(); }
}
export function hashRef(bytes: Uint8Array, suite: 'sha256' | 'sha384' = 'sha256'): string { return b64uEnc(createHash(suite).update(bytes).digest()); }
export const sha2Hex = (alg: 'sha256' | 'sha384' | 'sha512', d: Uint8Array) => createHash(alg).update(d).digest('hex');
