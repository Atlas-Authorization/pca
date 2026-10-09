/**
 * Strings that feed a HASH or COMMITMENT are ordered by UTF-8 byte order (== code point order), never by JavaScript's default
 * UTF-16 code-unit order — the two disagree for characters above U+FFFF versus U+E000..U+FFFF, and other implementations
 * (the Rust zkVM canonicalizer, the SDKs) use byte order. The distinguishing pair is U+FFFD (UTF-16: 0xFFFD) and U+1F600
 * (UTF-16: 0xD83D 0xDE00): UTF-16 puts U+1F600 FIRST, UTF-8 puts it LAST.
 */
import { describe, expect, it } from 'vitest';
import { hashCanonical, compareUtf8 } from './hash';
import { approveClass } from './approvals';
import { describeEnvelope } from './agent-native';
import { encodeKey, generateKeyPair } from './keys';
import { mintGrant } from './envelope';
import { DEFAULT_RISK_POLICY as P } from './risk';

const ASTRAL = '\u{1F600}';
const BMP_HIGH = '�';
const UTF8_ORDER = ['a', BMP_HIGH, ASTRAL]; // by UTF-8 bytes / code point
const UTF16_ORDER = ['a', ASTRAL, BMP_HIGH]; // what a bare .sort() would give

describe('premise: the two orders really differ for this pair', () => {
  it('compareUtf8 sorts the astral char AFTER U+FFFD; the default sort sorts it BEFORE', () => {
    expect([ASTRAL, BMP_HIGH, 'a'].sort(compareUtf8)).toEqual(UTF8_ORDER);
    expect([ASTRAL, BMP_HIGH, 'a'].sort()).toEqual(UTF16_ORDER);
  });
});

describe('class-approval id is committed over UTF-8-ordered verbs', () => {
  const now = 1_700_000_000_000;
  it('equals the hash over the UTF-8 order, not the UTF-16 order, and is permutation-invariant', () => {
    const mk = (verbs: string[]) => approveClass(verbs, { ttlMs: 60_000, by: 'principal', now, resource: '/r' }).id;
    const expected = (verbs: string[]) => hashCanonical({ d: 'atlas-pca/class-approval/v1', verbs, resource: '/r', grantedAt: now, by: 'principal' });
    const id = mk([ASTRAL, 'a', BMP_HIGH]);
    expect(id).toBe(expected(UTF8_ORDER));
    expect(id).not.toBe(expected(UTF16_ORDER));
    expect(mk([BMP_HIGH, ASTRAL, 'a'])).toBe(id);
    expect(mk(['a', BMP_HIGH, ASTRAL])).toBe(id);
  });
});

describe('authority envelope lists are UTF-8 ordered', () => {
  it('verbs and resources come out in code point order', () => {
    const p = generateKeyPair(), a = generateKeyPair();
    const root = mintGrant({
      principalSecret: p.secretKey, principalPublic: encodeKey(p.publicKey), holder: encodeKey(a.publicKey), goal: 'g',
      envelope: {
        predicates: [
          { verb: [ASTRAL, BMP_HIGH, 'a'], resource: `/${ASTRAL}` },
          { verb: [ASTRAL, BMP_HIGH, 'a'], resource: `/${BMP_HIGH}` },
          { verb: [ASTRAL, BMP_HIGH, 'a'], resource: '/a' },
        ],
        caveats: [{ type: 'expires', at: 10_000 }],
        agent_binding: {},
        risk_policy: P,
      },
    }).grant;
    const env = describeEnvelope([root], 1_000);
    expect(env.ok).toBe(true);
    expect(env.verbs).toEqual(UTF8_ORDER);
    expect(env.resources).toEqual(['/a', `/${BMP_HIGH}`, `/${ASTRAL}`]);
  });
});
