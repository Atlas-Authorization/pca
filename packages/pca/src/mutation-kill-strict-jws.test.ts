/**
 * Mutation-kill tests for strict-jws.ts: every refusal by its exact reason AND message, every boundary on both sides,
 * the detached-segments gate, and the alias generator's exact output (fixtures reviewed by hand: padding count per
 * length class, the +1 trailing-bit flip keeps the decoded bytes, standard-alphabet swaps only where '-'/'_' occur,
 * the duplicate-key alias only when the header starts with '{' followed by a quoted key).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CanonicalJwsError, DEFAULT_MAX_JWS_BYTES, assertCanonicalCompactJws, assertCanonicalJwsSegments, compactJwsAliases, decodeCanonicalBase64url,
  decodeCanonicalJsonSegment, isCanonicalCompactJws,
} from './strict-jws';

const fixtures = JSON.parse(readFileSync(join(__dirname, 'mutation-kill-strict-jws.fixtures.json'), 'utf8')) as Array<{ hj: string; pj: string; n: number; token: string; aliases: Array<{ name: string; token: string }> }>;
const b = (s: string | Uint8Array) => Buffer.from(s).toString('base64url');
const H = b('{"alg":"EdDSA"}');
const P = b('{"a":1}');
const S = b(new Uint8Array(64).fill(7));
const TOKEN = `${H}.${P}.${S}`;
const err = (f: () => unknown): CanonicalJwsError => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(CanonicalJwsError);
    return e as CanonicalJwsError;
  }
  throw new Error('expected a CanonicalJwsError');
};

describe('CanonicalJwsError', () => {
  it('message with and without detail; name', () => {
    expect(new CanonicalJwsError('bom').message).toBe('non-canonical compact JWS: bom');
    expect(new CanonicalJwsError('bad-json', 'x').message).toBe('non-canonical compact JWS: bad-json (x)');
    expect(new CanonicalJwsError('bom').name).toBe('CanonicalJwsError');
    expect(new CanonicalJwsError('bom').reason).toBe('bom');
  });
});

describe('decodeCanonicalBase64url', () => {
  it('a 1-mod-4 length is refused as an impossible length (detail in the message)', () => {
    for (const s of ['A', 'AAAAA']) {
      const e = err(() => decodeCanonicalBase64url(s));
      expect(e.reason).toBe('non-canonical-base64url');
      expect(e.message).toBe('non-canonical compact JWS: non-canonical-base64url (impossible length)');
    }
    expect(err(() => decodeCanonicalBase64url('AB')).message).toBe('non-canonical compact JWS: non-canonical-base64url');
  });
});

describe('BOM and UTF-8 in JSON segments', () => {
  const seg = (...bytes: number[]) => b(new Uint8Array(bytes));
  it('a BOM (alone or before JSON) is "bom"', () => {
    expect(err(() => decodeCanonicalJsonSegment(seg(0xef, 0xbb, 0xbf))).reason).toBe('bom');
    expect(err(() => decodeCanonicalJsonSegment(seg(0xef, 0xbb, 0xbf, 0x7b, 0x7d))).reason).toBe('bom');
  });
  it('a partial BOM pattern is invalid UTF-8, not "bom"', () => {
    for (const bytes of [[0x61, 0xbb, 0xbf], [0xef, 0x61, 0xbf], [0xef, 0xbb, 0x61], [0x61, 0x62, 0xbf]]) {
      expect(err(() => decodeCanonicalJsonSegment(seg(...bytes))).reason, bytes.join(',')).toBe('bad-utf8');
    }
  });
  it('JSON null is not an object', () => {
    expect(err(() => assertCanonicalCompactJws(`${b('null')}.${P}.${S}`)).reason).toBe('not-an-object');
  });
});

describe('assertCanonicalCompactJws boundaries and messages', () => {
  it('maxBytes is inclusive', () => {
    expect(assertCanonicalCompactJws(TOKEN, { maxBytes: TOKEN.length }).header).toEqual({ alg: 'EdDSA' });
    expect(err(() => assertCanonicalCompactJws(TOKEN, { maxBytes: TOKEN.length - 1 })).reason).toBe('too-long');
  });
  it('segment count detail', () => {
    expect(err(() => assertCanonicalCompactJws(`${H}.${P}`)).message).toBe('non-canonical compact JWS: bad-segment-count (2 != 3)');
  });
  it('JWE: only segment 1 may be empty; the empty-segment detail names the index', () => {
    expect(assertCanonicalCompactJws(`${H}..${S}.${S}.${S}`, { parts: 5 }).header).toEqual({ alg: 'EdDSA' });
    expect(err(() => assertCanonicalCompactJws(`${H}.${S}..${S}.${S}`, { parts: 5 })).message).toBe('non-canonical compact JWS: empty-segment (segment 2)');
    expect(err(() => assertCanonicalCompactJws(`${H}..${S}`)).message).toBe('non-canonical compact JWS: empty-segment (segment 1)');
  });
});

describe('assertCanonicalJwsSegments (detached)', () => {
  it('returns the header of canonical segments', () => {
    expect(assertCanonicalJwsSegments(H, S)).toEqual({ alg: 'EdDSA' });
  });
  it('either segment not a string', () => {
    expect(err(() => assertCanonicalJwsSegments(1, S)).reason).toBe('not-a-string');
    expect(err(() => assertCanonicalJwsSegments(H, null)).reason).toBe('not-a-string');
    expect(err(() => assertCanonicalJwsSegments(undefined, undefined)).message).toBe('non-canonical compact JWS: not-a-string');
  });
  it('the length bound is on the SUM and inclusive; default 64 KiB', () => {
    const sum = H.length + S.length;
    expect(assertCanonicalJwsSegments(H, S, { maxBytes: sum })).toEqual({ alg: 'EdDSA' });
    expect(err(() => assertCanonicalJwsSegments(H, S, { maxBytes: sum - 1 })).message).toBe('non-canonical compact JWS: too-long');
    // the difference would fit, only the sum does not
    expect(err(() => assertCanonicalJwsSegments(H, S, { maxBytes: S.length })).reason).toBe('too-long');
    const big = 'A'.repeat(DEFAULT_MAX_JWS_BYTES);
    expect(err(() => assertCanonicalJwsSegments(H, big)).reason).toBe('too-long');
  });
  it('either segment empty', () => {
    expect(err(() => assertCanonicalJwsSegments('', S)).message).toBe('non-canonical compact JWS: empty-segment');
    expect(err(() => assertCanonicalJwsSegments(H, '')).reason).toBe('empty-segment');
  });
  it('the signature segment must be canonical too', () => {
    expect(err(() => assertCanonicalJwsSegments(H, 'A')).reason).toBe('non-canonical-base64url');
    expect(err(() => assertCanonicalJwsSegments(H, `${S}=`)).reason).toBe('bad-character');
  });
});

describe('compactJwsAliases', () => {
  it('exact alias list per length class / header shape, and every alias is refused while the original passes', () => {
    for (const f of fixtures) {
      expect(f.token).toBe(`${b(f.hj)}.${b(f.pj)}.${b(new Uint8Array(f.n).fill(0xfb))}`);
      expect(compactJwsAliases(f.token)).toEqual(f.aliases);
      if (f.hj.startsWith('{')) expect(isCanonicalCompactJws(f.token)).toBe(true);
    }
  });
  it('the altered-trailing-bits alias decodes to the same bytes', () => {
    for (const f of fixtures) {
      const alt = f.aliases.find((a) => a.name === 'altered trailing bits');
      if (!alt) continue;
      const s = f.token.split('.')[2]!;
      const s2 = alt.token.split('.')[2]!;
      expect(s2).not.toBe(s);
      expect(Buffer.from(s2, 'base64url')).toEqual(Buffer.from(s, 'base64url'));
    }
  });
  it('the trailing-bit flip increments the spare-bit field modulo 2^spare (4 spare bits at length 2 mod 4, 2 at 3 mod 4)', () => {
    const alt = (sig: string) => compactJwsAliases(`${H}.${P}.${sig}`).find((a) => a.name === 'altered trailing bits')!.token.split('.')[2]!;
    const s86 = b(new Uint8Array(64).fill(0xfb)).slice(0, -1);
    const s43 = b(new Uint8Array(32).fill(0xfb)).slice(0, -1);
    expect(alt(`${s86}z`)).toBe(`${s86}0`); // z = 110011: spare 0011 -> 0100
    expect(alt(`${s43}v`)).toBe(`${s43}s`); // v = 101111: spare 11 -> 00
  });
});
