import { describe, expect, it } from 'vitest';
import { compactJwsAliases, CanonicalJwsError, assertCanonicalCompactJws, decodeCanonicalJsonSegment, isCanonicalCompactJws } from './strict-jws';

const b = (s: string) => Buffer.from(s).toString('base64url');
const sig = Buffer.alloc(64, 7).toString('base64url'); // 64 bytes -> 86 chars, last char has 4 spare bits
const tok = `${b('{"alg":"EdDSA"}')}.${b('{"a":1}')}.${sig}`;
const reason = (t: unknown, o = {}) => {
  try {
    assertCanonicalCompactJws(t, o);
  } catch (e) {
    expect(e).toBeInstanceOf(CanonicalJwsError);
    return (e as CanonicalJwsError).reason;
  }
  return 'ACCEPTED';
};

describe('assertCanonicalCompactJws', () => {
  it('accepts the canonical form', () => {
    expect(assertCanonicalCompactJws(tok).header.alg).toBe('EdDSA');
    expect(isCanonicalCompactJws(tok)).toBe(true);
  });
  it('rejects padding, trailing-bit alias, +/ alphabet, whitespace', () => {
    expect(reason(`${tok}=`)).toBe('bad-character');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = tok[tok.length - 1] as string;
    const t2 = tok.slice(0, -1) + (alphabet[alphabet.indexOf(last) + 1] as string); // sets a spare low bit
    expect(reason(t2)).toBe('non-canonical-base64url');
    expect(reason(tok.replace(/-/, '+').replace(/_/, '/') + '+')).toBe('bad-character');
    expect(reason(`${tok}\n`)).toBe('bad-character');
    expect(reason(` ${tok}`)).toBe('bad-character');
  });
  it('rejects wrong segment count, empty segment, over-long, non-string', () => {
    expect(reason(`${tok}.x`)).toBe('bad-segment-count');
    expect(reason(`${b('{}')}..${sig}`)).toBe('empty-segment');
    expect(reason(tok, { maxBytes: 10 })).toBe('too-long');
    expect(reason(42)).toBe('not-a-string');
  });
  it('rejects duplicate header keys, BOM, bad utf8, non-object', () => {
    expect(reason(`${b('{"alg":"A","alg":"B"}')}.${b('{}')}.${sig}`)).toBe('bad-json');
    expect(reason(`${Buffer.from('﻿{}').toString('base64url')}.${b('{}')}.${sig}`)).toBe('bom');
    expect(reason(`${Buffer.from([0x7b, 0xff, 0x7d]).toString('base64url')}.${b('{}')}.${sig}`)).toBe('bad-utf8');
    expect(reason(`${b('[]')}.${b('{}')}.${sig}`)).toBe('not-an-object');
    expect(reason(`${b('{}')}.${b('{"a":1,"a":2}')}.${sig}`)).toBe('bad-json');
    expect(reason(`${b('{}')}.${b('"s"')}.${sig}`)).toBe('not-an-object');
  });
  it('payload any / 5-part', () => {
    expect(reason(`${b('{}')}.${b('raw bytes')}.${sig}`, { payload: 'any' })).toBe('ACCEPTED');
    const jwe = [b('{"enc":"A"}'), '', b('iv'), b('ct'), b('tag')].join('.');
    expect(reason(jwe, { parts: 5 })).toBe('ACCEPTED');
  });
  it('decodeCanonicalJsonSegment', () => {
    expect(decodeCanonicalJsonSegment(b('["s","n",1]'))).toEqual(['s', 'n', 1]);
    expect(() => decodeCanonicalJsonSegment(`${b('[1]')}=`)).toThrow(CanonicalJwsError);
  });
  it('every alias variant of a valid token is rejected', () => {
    const v = compactJwsAliases(tok);
    expect(v.length).toBeGreaterThanOrEqual(7);
    for (const a of v) expect(isCanonicalCompactJws(a.token), a.name).toBe(false);
    expect(v.map((x) => x.name)).toContain('altered trailing bits');
  });
});
