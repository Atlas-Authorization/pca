import { strictParse } from './strict-json';

/**
 * CANONICAL compact-JWS gate. Third-party JOSE libraries (e.g. `jose` 5.x) accept many encodings of ONE
 * signature/segment — non-zero trailing bits in the last base64url character, `=` padding, standard-alphabet
 * `+` `/`, embedded whitespace/newlines — so a token string has many accepted spellings. Anything keyed on the
 * token string or its hash (dedupe, replay caches, ledger entries, binding hashes) is bypassable by
 * re-encoding. Run this gate BEFORE the JOSE library: it accepts exactly one spelling per token.
 *
 * Requires: exactly `parts` dot-separated segments (3 = JWS, 5 = JWE); each segment non-empty (optionally
 * the empty-allowed ones, see options) over the strictly UNPADDED base64url alphabet `[A-Za-z0-9_-]`;
 * decode-then-re-encode equals the segment (kills trailing-bit aliases); no whitespace/control characters;
 * total length bounded; the protected header (and, unless `payload: 'any'`, the payload) decode to UTF-8
 * WITHOUT a BOM and parse as STRICT JSON objects (no duplicate keys — see `strictParse`).
 */
export type CanonicalJwsReason =
  | 'not-a-string'
  | 'too-long'
  | 'bad-segment-count'
  | 'bad-character'
  | 'empty-segment'
  | 'non-canonical-base64url'
  | 'bad-utf8'
  | 'bom'
  | 'bad-json'
  | 'not-an-object';

export class CanonicalJwsError extends Error {
  constructor(public readonly reason: CanonicalJwsReason, detail?: string) {
    super(`non-canonical compact JWS: ${reason}${detail ? ` (${detail})` : ''}`);
    this.name = 'CanonicalJwsError';
  }
}

export interface CanonicalJwsOptions {
  /** Expected number of dot-separated segments (3 = JWS, 5 = JWE). Default 3. */
  parts?: 3 | 5;
  /** Upper bound on the whole token length in bytes (ASCII). Default 64 KiB. */
  maxBytes?: number;
  /** `'json'` (default): payload must be a strict-JSON object. `'any'`: payload only needs canonical base64url. */
  payload?: 'json' | 'any';
}

export interface CanonicalJws {
  segments: string[];
  header: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export const DEFAULT_MAX_JWS_BYTES = 64 * 1024;
const B64U = /^[A-Za-z0-9_-]*$/;

/** Decode one strictly canonical unpadded base64url segment (throws {@link CanonicalJwsError}). */
export function decodeCanonicalBase64url(seg: string): Buffer {
  if (!B64U.test(seg)) throw new CanonicalJwsError('bad-character');
  // A 1-mod-4 length can never be valid base64 (6 bits of data cannot make a byte).
  if (seg.length % 4 === 1) throw new CanonicalJwsError('non-canonical-base64url', 'impossible length');
  const bytes = Buffer.from(seg, 'base64url');
  if (bytes.toString('base64url') !== seg) throw new CanonicalJwsError('non-canonical-base64url');
  return bytes;
}

/** Decode a canonical base64url segment holding a strict-JSON document (any JSON type); used for SD-JWT disclosures. */
export function decodeCanonicalJsonSegment(seg: string): unknown {
  return parseJsonBytes(decodeCanonicalBase64url(seg));
}

function parseJsonBytes(bytes: Buffer): unknown {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new CanonicalJwsError('bom');
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new CanonicalJwsError('bad-utf8');
  }
  try {
    return strictParse(text);
  } catch (e) {
    throw new CanonicalJwsError('bad-json', e instanceof Error ? e.message : undefined);
  }
}

function asObject(v: unknown): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new CanonicalJwsError('not-an-object');
  return v as Record<string, unknown>;
}

/** Throws {@link CanonicalJwsError} unless `token` is the one canonical spelling of a compact JWS/JWE. */
export function assertCanonicalCompactJws(token: unknown, opts: CanonicalJwsOptions = {}): CanonicalJws {
  const parts = opts.parts ?? 3;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_JWS_BYTES;
  if (typeof token !== 'string') throw new CanonicalJwsError('not-a-string');
  if (token.length > maxBytes) throw new CanonicalJwsError('too-long');
  const segments = token.split('.');
  if (segments.length !== parts) throw new CanonicalJwsError('bad-segment-count', `${segments.length} != ${parts}`);
  const bytes: Buffer[] = [];
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i] as string;
    // JWE (5 parts) may have an empty encrypted-key segment (direct encryption); JWS segments may not be empty.
    if (seg.length === 0) {
      if (parts === 5 && i === 1) {
        bytes.push(Buffer.alloc(0));
        continue;
      }
      throw new CanonicalJwsError('empty-segment', `segment ${i}`);
    }
    bytes.push(decodeCanonicalBase64url(seg));
  }
  const header = asObject(parseJsonBytes(bytes[0] as Buffer));
  const out: CanonicalJws = { segments, header };
  if (parts === 3 && (opts.payload ?? 'json') === 'json') out.payload = asObject(parseJsonBytes(bytes[1] as Buffer));
  return out;
}

/**
 * Canonical gate for the PROTECTED + SIGNATURE segments of a flattened / detached JWS (A2A / AgentCard
 * signatures, GNAP detached-JWS), where the payload is supplied out of band. Same rules as the compact form.
 */
export function assertCanonicalJwsSegments(protectedB64u: unknown, signatureB64u: unknown, opts: { maxBytes?: number } = {}): Record<string, unknown> {
  if (typeof protectedB64u !== 'string' || typeof signatureB64u !== 'string') throw new CanonicalJwsError('not-a-string');
  const max = opts.maxBytes ?? DEFAULT_MAX_JWS_BYTES;
  if (protectedB64u.length + signatureB64u.length > max) throw new CanonicalJwsError('too-long');
  if (protectedB64u.length === 0 || signatureB64u.length === 0) throw new CanonicalJwsError('empty-segment');
  const header = asObject(parseJsonBytes(decodeCanonicalBase64url(protectedB64u)));
  decodeCanonicalBase64url(signatureB64u);
  return header;
}

export function isCanonicalCompactJws(token: unknown, opts: CanonicalJwsOptions = {}): boolean {
  try {
    assertCanonicalCompactJws(token, opts);
    return true;
  } catch {
    return false;
  }
}

/**
 * Test/conformance helper: derive the alias spellings of a valid compact JWS that a lenient JOSE library may
 * still accept (padding, trailing-bit flip, standard alphabet, surrounding whitespace, duplicate header key).
 * Every variant MUST be rejected by a verifier that gates on {@link assertCanonicalCompactJws}; the original
 * must pass. Variants that cannot be built for this token (e.g. no spare bits) are omitted.
 */
export function compactJwsAliases(token: string): Array<{ name: string; token: string }> {
  const out: Array<{ name: string; token: string }> = [];
  const [h, p, s] = token.split('.') as [string, string, string];
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  out.push({ name: 'padded signature', token: `${h}.${p}.${s}${'='.repeat((4 - (s.length % 4)) % 4 || 1)}` });
  if (s.length % 4 === 2 || s.length % 4 === 3) {
    const spare = s.length % 4 === 2 ? 4 : 2;
    const idx = A.indexOf(s[s.length - 1] as string);
    const alt = (idx & ~((1 << spare) - 1)) | (((idx & ((1 << spare) - 1)) + 1) & ((1 << spare) - 1));
    out.push({ name: 'altered trailing bits', token: `${h}.${p}.${s.slice(0, -1)}${A[alt]}` });
  }
  const std = (x: string) => x.replace(/-/g, '+').replace(/_/g, '/');
  for (const [name, t] of [
    ['standard alphabet header', `${std(h)}.${p}.${s}`],
    ['standard alphabet payload', `${h}.${std(p)}.${s}`],
    ['standard alphabet signature', `${h}.${p}.${std(s)}`],
  ] as const) {
    if (t !== token) out.push({ name, token: t });
  }
  out.push({ name: 'trailing newline', token: `${token}\n` });
  out.push({ name: 'trailing space', token: `${token} ` });
  out.push({ name: 'leading space', token: ` ${token}` });
  out.push({ name: 'interior newline', token: `${h}\n.${p}.${s}` });
  try {
    const hj = Buffer.from(h, 'base64url').toString('utf8');
    const k = /^\{\s*("(?:[^"\\]|\\.)*")\s*:/.exec(hj)?.[1];
    const dup = k === undefined ? hj : hj.replace(/^\{/, `{${k}:0,`); // the same key twice (first value differs)
    if (k !== undefined) out.push({ name: 'duplicate header key', token: `${Buffer.from(dup).toString('base64url')}.${p}.${s}` });
  } catch {
    /* unreachable for a valid token */
  }
  return out;
}
