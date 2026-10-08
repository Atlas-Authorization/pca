import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { sha384 as nobleSha384 } from '@noble/hashes/sha512';
import { base64urlnopad } from '@scure/base';

const enc = new TextEncoder();

/** Encode a UTF-8 string. */
export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return nobleSha256(bytes);
}

export function sha384(bytes: Uint8Array): Uint8Array {
  return nobleSha384(bytes);
}

// ---- hash-suite agility (P4) ------------------------------------------------------------------
//
// HONEST RATIONALE — margin, NOT a fix. SHA-256 (the DEFAULT, and the only suite the whole existing
// corpus uses) is ALREADY post-quantum adequate for every digest in this protocol: Grover's algorithm
// reduces a 256-bit PREIMAGE search to ~2^128 quantum work, and the best known quantum COLLISION attack
// (Brassard-Hoyer-Tapp) leaves ~2^128 work — both far outside any foreseeable adversary. SHA-384 is
// offered here purely as an OPTIONAL, stronger-margin variant (a ~2^192 preimage / ~2^192 collision
// floor under the same quantum models) for deployments that want extra headroom or a longer-dated
// commitment. It is cryptographic AGILITY and defense-in-depth margin — it is NOT a response to any
// vulnerability in SHA-256, which remains the recommended default. Choosing it has real costs (larger
// 48-byte digests; cross-SDK verifiers must opt in), so it is never selected implicitly.
//
// NON-BREAKING by construction: `'sha256'` is the DEFAULT everywhere the suite is threaded, and the
// ABSENCE of any `hash_suite` field MUST be read as `'sha256'`. Every pre-existing digest, Merkle root,
// inclusion proof and signed body is therefore BYTE-IDENTICAL to before this change.

/** Hash-suite selector for canonical digests and the Merkle tree. See the agility note above. */
export type HashSuite = 'sha256' | 'sha384';

/** The DEFAULT suite. Absence of an explicit `hash_suite` MUST be interpreted as this (back-compat). */
export const DEFAULT_HASH_SUITE: HashSuite = 'sha256';

/** Digest byte length per suite (SHA-256 => 32, SHA-384 => 48). */
export const HASH_LEN: Record<HashSuite, number> = { sha256: 32, sha384: 48 };

/** Narrowing guard: true iff `s` is a known {@link HashSuite}. Anything else MUST fail closed at the caller. */
export function isHashSuite(s: unknown): s is HashSuite {
  return s === 'sha256' || s === 'sha384';
}

/** Dispatch a raw-byte hash over the selected suite (DEFAULT sha256 => byte-identical to a bare {@link sha256}). */
export function hashWithSuite(bytes: Uint8Array, suite: HashSuite = DEFAULT_HASH_SUITE): Uint8Array {
  return suite === 'sha384' ? sha384(bytes) : sha256(bytes);
}

export function b64u(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

export function unb64u(s: string): Uint8Array {
  return base64urlnopad.decode(s);
}

// ---- strict base64url (normative wire rule) ---------------------------------------------------

const B64U_ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * STRICT base64url (RFC 4648 §5, NO padding): only `[A-Za-z0-9_-]`, no whitespace, no `=`, length mod 4
 * != 1, and the unused trailing bits of the last character MUST be zero (i.e. `b64u(decode(s)) === s`).
 * Returns the bytes, or null for ANY deviation (never throws). When `len` is given the DECODED length must
 * equal it (fixed-length fields: 32-byte hashes/keys, 64-byte signatures).
 */
export function decodeB64uStrict(s: unknown, len?: number): Uint8Array | null {
  if (typeof s !== 'string' || !B64U_ALPHABET.test(s) || s.length % 4 === 1) return null;
  if (len !== undefined && s.length !== b64uLen(len)) return null;
  try {
    const bytes = unb64u(s);
    if (b64u(bytes) !== s) return null; // non-canonical trailing bits
    if (len !== undefined && bytes.length !== len) return null;
    return bytes;
  } catch {
    return null;
  }
}

/** Encoded (unpadded) length of `n` bytes. */
export function b64uLen(n: number): number {
  return Math.ceil((n * 4) / 3);
}

/** True iff `s` is canonical base64url (optionally of an exact decoded byte length). */
export function isCanonicalB64u(s: unknown, len?: number): boolean {
  return decodeB64uStrict(s, len) !== null;
}

// ---- canonical JSON ---------------------------------------------------------------------------

/** UTF-8 bytewise comparison of two strings (== Unicode code point order). */
export function compareUtf8(a: string, b: string): number {
  if (a === b) return 0;
  const x = enc.encode(a);
  const y = enc.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i]! - y[i]!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export const hasLoneSurrogate = (s: string): boolean => LONE_SURROGATE.test(s);

/** Max significant decimal digits of a non-integer number in the canonical wire form. */
export const MAX_DECIMAL_DIGITS = 15;

/**
 * Deterministic serialization: object keys sorted BYTEWISE over their UTF-8 encoding (== Unicode code point
 * order, recursively), no whitespace, JSON string/number escaping. Rejects undefined, functions, symbols,
 * bigint, non-finite numbers, non-plain objects and cycles — anything that has no stable encoding.
 *
 * This is the LENIENT form: any finite JS number is serialized with ECMAScript `Number::toString`.
 *
 * SERVER-ONLY. It is NOT language-portable (it tolerates exponent / >15-significant-digit numbers that the
 * strict wire profile forbids), so it MUST NEVER feed a protocol digest — capability/grant hashes (`capHash`),
 * goal commitments, Merkle leaves, ledger commits, revocation roots, the threshold signer-set, or the signed
 * PCActn body. Every one of those uses {@link canonicalizeStrict}. The deliberately ugly name exists so a wrong
 * import (which would silently produce a non-portable digest no language verifier can reproduce) is obvious at
 * the call site.
 */
export function __canonicalizeLenientServerOnly(value: unknown): string {
  return ser(value, new Set(), false);
}

/**
 * @deprecated Renamed to {@link __canonicalizeLenientServerOnly} to make its SERVER-ONLY, non-portable nature
 * obvious at every call site: it MUST NEVER feed a protocol digest (capHash, goal commitments, Merkle leaves,
 * ledger commits, revocation roots, the threshold signer-set, or the signed PCActn body) — those use
 * {@link canonicalizeStrict}. This alias is kept only so existing importers keep working; do not add new uses.
 */
export const canonicalize = __canonicalizeLenientServerOnly;

/**
 * The STRICT, language-portable canonical form of a signed PCActn body (wire format v2). On top of
 * {@link canonicalize}:
 *  - integer-valued numbers MUST be safe integers (|n| <= 2^53-1) and `-0` is rejected;
 *  - non-integer numbers are written in plain decimal (never an exponent), have at most 15 significant
 *    digits, and no trailing fractional zero (so every language reproduces the same bytes by parsing to an
 *    IEEE-754 double and printing the shortest round-trip decimal);
 *  - strings (and object keys) MUST NOT contain lone surrogates;
 *  - nesting depth is bounded ({@link MAX_JSON_DEPTH}).
 * THROWS a TypeError on any violation.
 */
export function canonicalizeStrict(value: unknown): string {
  return ser(value, new Set(), true, 1);
}

/** Maximum container nesting depth accepted by the strict JSON profile (and by `canonicalizeStrict`). */
export const MAX_JSON_DEPTH = 32;

/** Strict-profile check of one JS number. Returns an error string or null. */
export function strictNumberError(v: number): string | null {
  if (!Number.isFinite(v)) return 'non-finite number';
  if (Object.is(v, -0)) return 'negative zero';
  if (Number.isInteger(v)) return Number.isSafeInteger(v) ? null : 'integer outside the safe range (|n| > 2^53-1)';
  if (Math.abs(v) < 1e-6) return 'non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)';
  const s = String(v);
  if (/e/i.test(s)) return 'non-integer number needs an exponent form (not representable in the canonical decimal form)';
  const digits = s.replace('-', '').replace('.', '').replace(/^0+/, '');
  if (digits.length > MAX_DECIMAL_DIGITS) return `non-integer number has more than ${MAX_DECIMAL_DIGITS} significant digits`;
  return null;
}

function ser(v: unknown, seen: Set<object>, strict: boolean, depth = 1): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string':
      if (strict && hasLoneSurrogate(v)) throw new TypeError('canonicalize: lone surrogate in string');
      return JSON.stringify(v);
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number': {
      if (!Number.isFinite(v)) throw new TypeError('canonicalize: non-finite number');
      if (strict) {
        const e = strictNumberError(v);
        if (e) throw new TypeError(`canonicalize: ${e}`);
        return String(v);
      }
      return Object.is(v, -0) ? '0' : JSON.stringify(v);
    }
    case 'object':
      break;
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof v}`);
  }
  const o = v as object;
  if (strict && depth > MAX_JSON_DEPTH) throw new TypeError('canonicalize: nesting too deep');
  if (seen.has(o)) throw new TypeError('canonicalize: cycle');
  seen.add(o);
  try {
    if (Array.isArray(o)) {
      return '[' + o.map((x) => ser(x, seen, strict, depth + 1)).join(',') + ']';
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError('canonicalize: non-plain object');
    }
    const rec = o as Record<string, unknown>;
    const keys = Object.keys(rec).sort(compareUtf8);
    return (
      '{' +
      keys
        .map((k) => {
          if (strict && hasLoneSurrogate(k)) throw new TypeError('canonicalize: lone surrogate in key');
          return JSON.stringify(k) + ':' + ser(rec[k], seen, strict, depth + 1);
        })
        .join(',') +
      '}'
    );
  } finally {
    seen.delete(o);
  }
}

// All DIGEST/HASH inputs use the STRICT canonical form so the whole reference —
// capability/grant hashes (capHash), goal commitments, Merkle leaves, ledger
// commits, revocation roots and the threshold signer-set — matches the strict
// language verifiers byte-for-byte (no looser/strict split). Strict and looser
// produce identical bytes on in-profile data; out-of-profile inputs (already
// rejected at mint / on the wire) now throw here too, instead of hashing.
export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(canonicalizeStrict(value));
}

/** Alias of {@link canonicalBytes} — both are strict. Kept for call-site clarity. */
export function canonicalBytesStrict(value: unknown): Uint8Array {
  return utf8(canonicalizeStrict(value));
}

/**
 * base64url(H(strictCanonical(value))) under `suite`. The DEFAULT `'sha256'` is BYTE-IDENTICAL to the
 * original one-argument form, so every existing protocol digest is unchanged; `'sha384'` is the optional
 * stronger-margin variant (see the hash-suite agility note above — margin, not a fix).
 */
export function hashCanonical(value: unknown, suite: HashSuite = DEFAULT_HASH_SUITE): string {
  return b64u(hashWithSuite(canonicalBytes(value), suite));
}

// LENIENT variants for SERVER-ONLY digests that are never recomputed by the
// language verifiers and legitimately carry high-precision floats (e.g. the
// objective-risk calibration scores, resource-graph harm weights, evidence
// inputs). These are not wire/cross-language contracts, so they use the looser
// canonical form that tolerates exponent/>15-digit numbers. NEVER use these for
// a protocol hash (capHash, goalCommit, Merkle, ledger, revocation, PCActn).
export function canonicalBytesLenient(value: unknown): Uint8Array {
  return utf8(__canonicalizeLenientServerOnly(value));
}

/** base64url(sha256(canonicalize(value))) — lenient; SERVER-ONLY digests only. */
export function hashCanonicalLenient(value: unknown): string {
  return b64u(sha256(canonicalBytesLenient(value)));
}
