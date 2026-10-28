import { createHash } from 'node:crypto';

// Canonical JSON for the Goal IR, byte-identical to @atlasauth/pca `canonicalizeStrict` on in-profile data: object keys in UTF-8 byte
// order, no whitespace, integers only (safe range), strings escape `"`, `\`, \b \t \n \f \r and the other controls < 0x20 as \u00xx
// (lowercase hex). Every language port implements exactly this.
export function canon(v: unknown): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw new TypeError('canon: integers only');
    return String(v);
  }
  if (typeof v === 'string') return str(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const ks = Object.keys(o).filter((k) => o[k] !== undefined).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return '{' + ks.map((k) => str(k) + ':' + canon(o[k])).join(',') + '}';
  }
  throw new TypeError('canon: unsupported');
}
const SHORT: Record<number, string> = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' }; // JSON.stringify's escapes, as @atlasauth/pca strict canonical
function str(s: string): string {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c >= 0xd800 && c <= 0xdfff) throw new TypeError('canon: lone surrogate');
    if (ch === '"') o += '\\"';
    else if (ch === '\\') o += '\\\\';
    else if (c < 0x20) o += SHORT[c] ?? '\\u' + c.toString(16).padStart(4, '0');
    else o += ch;
  }
  return o + '"';
}
export const bytesCmp = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));
export function digest(kind: string, v: unknown): string {
  return createHash('sha256').update('pca-goal:v1:' + kind + ':' + canon(v), 'utf8').digest('base64url');
}
/** b64u(sha256(strictCanonical(x))): the shape of `hashCanonical` in @atlasauth/pca. */
export const hashCanon = (v: unknown): string => createHash('sha256').update(canon(v), 'utf8').digest('base64url');
/** The Goal IR digest, as `goalDigest` in pca-goal: hashCanonical({d: 'atlas-pca/goal-ir/v1', goal}). */
export const goalDigest = (goal: unknown): string => hashCanon({ d: 'atlas-pca/goal-ir/v1', goal });
