import { createHash } from 'node:crypto';

/**
 * RFC 9530 (Digest Fields) `Content-Digest` — a published IETF RFC. The field is a Structured Field Dictionary
 * (RFC 8941) whose keys are hash algorithm names from the IANA "Hash Algorithms for HTTP Digest Fields" registry and
 * whose values are Byte Sequences (`:base64:`) of the digest over the message CONTENT (the body bytes after any
 * content coding, before transfer coding). Only the two algorithms the RFC marks "Active", `sha-256` and `sha-512`,
 * are produced or accepted here; the deprecated ones (md5, sha, unixsum, …) are never accepted.
 *
 * Use with RFC 9421: cover `content-digest` in the signature (`coverHeaders: ['content-digest']`) so the signature
 * protects the request body too; {@link verifyContentDigest} then checks the body against the covered field.
 * Verification FAILS CLOSED: a malformed field, a mismatching digest for any supported algorithm, or no supported
 * algorithm at all returns `{ valid: false, reason }`; it never throws.
 */

export type ContentDigestAlg = 'sha-256' | 'sha-512';
export const CONTENT_DIGEST_ALGS: readonly ContentDigestAlg[] = ['sha-256', 'sha-512'];
export const CONTENT_DIGEST_HEADER = 'Content-Digest';

const NODE_ALG: Record<ContentDigestAlg, string> = { 'sha-256': 'sha256', 'sha-512': 'sha512' };

function bytesOf(body: Uint8Array | string): Buffer {
  return typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
}

/** The raw digest bytes of `body` under `alg`. */
export function contentDigestBytes(body: Uint8Array | string, alg: ContentDigestAlg): Uint8Array {
  return new Uint8Array(createHash(NODE_ALG[alg]).update(bytesOf(body)).digest());
}

/** Build the `Content-Digest` field value, e.g. `sha-256=:X48E9q...=:` (members in the given order). */
export function contentDigestHeader(body: Uint8Array | string, algs: readonly ContentDigestAlg[] = ['sha-256']): string {
  if (algs.length === 0) throw new Error('contentDigestHeader: name at least one algorithm');
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const alg of algs) {
    if (!CONTENT_DIGEST_ALGS.includes(alg)) throw new Error(`contentDigestHeader: unsupported algorithm ${String(alg)}`);
    if (seen.has(alg)) continue;
    seen.add(alg);
    parts.push(`${alg}=:${Buffer.from(contentDigestBytes(body, alg)).toString('base64')}:`);
  }
  return parts.join(', ');
}

/** Parse the dictionary: key -> byte sequence. Throws on anything that is not `key=:base64:` (parameters refused). */
export function parseContentDigest(value: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const raw of value.split(',')) {
    const member = raw.trim();
    if (member.length === 0) throw new Error('empty dictionary member');
    const m = /^([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):$/.exec(member);
    if (m === null) throw new Error(`malformed Content-Digest member "${member}"`);
    const key = m[1]!;
    const b64 = m[2]!;
    if (b64.length % 4 !== 0) throw new Error(`member "${key}" is not canonical base64`);
    const bytes = Buffer.from(b64, 'base64');
    if (bytes.toString('base64') !== b64) throw new Error(`member "${key}" is not canonical base64`);
    // RFC 8941: a repeated key overrides the earlier one; a digest field with two values for one algorithm is
    // ambiguous, so it is refused here.
    if (out.has(key)) throw new Error(`member "${key}" appears twice`);
    out.set(key, new Uint8Array(bytes));
  }
  return out;
}

export interface VerifyContentDigestOptions {
  /** Algorithms that MUST be present (and match). Default: none, but at least one supported algorithm must match. */
  require?: readonly ContentDigestAlg[];
}

export interface ContentDigestResult {
  valid: boolean;
  reason?: string;
  /** The supported algorithms that were checked and matched. */
  matched?: ContentDigestAlg[];
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/**
 * Check `body` against a `Content-Digest` field value. Every supported member present must match (one mismatch fails
 * the whole field); unsupported members are ignored, as RFC 9530 §2 allows; at least one supported member must be
 * present; and every algorithm in `require` must be among the matched ones.
 */
export function verifyContentDigest(header: string | undefined, body: Uint8Array | string, opts: VerifyContentDigestOptions = {}): ContentDigestResult {
  try {
    if (header === undefined || header.trim() === '') return { valid: false, reason: 'missing Content-Digest' };
    const members = parseContentDigest(header);
    const matched: ContentDigestAlg[] = [];
    for (const alg of CONTENT_DIGEST_ALGS) {
      const got = members.get(alg);
      if (got === undefined) continue;
      if (!equalBytes(got, contentDigestBytes(body, alg))) return { valid: false, reason: `${alg} digest does not match the content` };
      matched.push(alg);
    }
    if (matched.length === 0) return { valid: false, reason: 'no supported digest algorithm (sha-256 or sha-512)' };
    for (const alg of opts.require ?? []) if (!matched.includes(alg)) return { valid: false, reason: `required ${alg} digest is absent` };
    return { valid: true, matched };
  } catch (e) {
    return { valid: false, reason: `malformed Content-Digest: ${(e as Error).message}` };
  }
}
