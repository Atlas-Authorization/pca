// idpattern.ts - the restricted resource id grammar. Containment between two patterns is decidable and cheap
// (the semantic diff in A4 must prove "the new pattern is no wider than the old one"), which arbitrary regex is not.

import { ID_CLASSES, type IdClass, type IdPattern } from './def';

const range = (a: string, b: string): string[] => {
  const out: string[] = [];
  for (let c = a.charCodeAt(0); c <= b.charCodeAt(0); c++) out.push(String.fromCharCode(c));
  return out;
};
const DIGITS = range('0', '9');
const HEXLC = [...DIGITS, ...range('a', 'f')];
const ALNUM = [...DIGITS, ...range('a', 'z'), ...range('A', 'Z')];
const SLUG = [...DIGITS, ...range('a', 'z'), '-', '_'];
const ANY_SAFE = [...ALNUM, '.', '_', '-', ':', '/'];
const UUID = [...HEXLC, '-'];

/** The character set of each id class. */
export const ID_CLASS_CHARS: Readonly<Record<IdClass, ReadonlySet<string>>> = {
  digits: new Set(DIGITS), hex: new Set(HEXLC), alnum: new Set(ALNUM), slug: new Set(SLUG), uuid: new Set(UUID), any_safe: new Set(ANY_SAFE),
};

/** A uuid-class id is exactly the canonical 36 character lowercase form. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const MAX_ID_LEN = 128;
const inClass = (s: string, c: IdClass): boolean => {
  const set = ID_CLASS_CHARS[c];
  for (const ch of s) if (!set.has(ch)) return false;
  return true;
};

/** Null if the pattern is well formed. */
export function idPatternError(p: unknown): string | null {
  if (p === '*') return null;
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return "resource.id must be '*', {exact} or {prefix, class, len}";
  const o = p as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  if (keys === 'exact') {
    return typeof o.exact === 'string' && o.exact.length >= 1 && o.exact.length <= MAX_ID_LEN && inClass(o.exact, 'any_safe') ? null : 'resource.id.exact must be 1..128 safe characters';
  }
  if (keys !== 'class,len,prefix') return "resource.id must be '*', {exact} or {prefix, class, len}";
  if (typeof o.prefix !== 'string' || o.prefix.length > 32 || !inClass(o.prefix, 'any_safe')) return 'resource.id.prefix must be up to 32 safe characters';
  if (!(ID_CLASSES as readonly unknown[]).includes(o.class)) return 'resource.id.class is not an id class';
  const len = o.len;
  if (!Array.isArray(len) || len.length !== 2 || !len.every((n) => Number.isSafeInteger(n) && n >= 1 && n <= MAX_ID_LEN)) return 'resource.id.len must be [min, max] in 1..128';
  if ((len[0] as number) > (len[1] as number)) return 'resource.id.len: min > max';
  if (o.class === 'uuid' && (o.prefix !== '' || len[0] !== 36 || len[1] !== 36)) return 'a uuid id has no prefix and length exactly [36, 36]';
  return null;
}

/** Does `id` (the id part of a resource, without the type) match the pattern? */
export function idMatches(p: IdPattern, id: string): boolean {
  if (p === '*') return id.length > 0 && id.length <= MAX_ID_LEN && inClass(id, 'any_safe');
  if ('exact' in p) return id === p.exact;
  if (!id.startsWith(p.prefix)) return false;
  const rest = id.slice(p.prefix.length);
  if (rest.length < p.len[0] || rest.length > p.len[1]) return false;
  if (p.class === 'uuid') return UUID_RE.test(rest);
  return inClass(rest, p.class);
}

const classSubset = (a: IdClass, b: IdClass): boolean => {
  for (const ch of ID_CLASS_CHARS[a]) if (!ID_CLASS_CHARS[b].has(ch)) return false;
  return true;
};

/**
 * Is every id matched by `inner` also matched by `outer`? Decidable: prefix extension, class inclusion, and length arithmetic
 * (exact ids are checked by matching; a pattern is never contained in an exact id unless it is a single-value pattern, which
 * this grammar cannot express, so that case is false).
 */
export function idPatternContains(outer: IdPattern, inner: IdPattern): boolean {
  if (outer === '*') return true;
  if (inner === '*') return false;
  if ('exact' in outer) return 'exact' in inner && inner.exact === outer.exact;
  if ('exact' in inner) return idMatches(outer, inner.exact);
  if (!inner.prefix.startsWith(outer.prefix)) return false;
  const r = inner.prefix.slice(outer.prefix.length);
  if (!inClass(r, outer.class)) return false;
  if (outer.class === 'uuid') return inner.class === 'uuid' && r === '';
  if (!classSubset(inner.class, outer.class)) return false;
  return r.length + inner.len[0] >= outer.len[0] && r.length + inner.len[1] <= outer.len[1];
}
