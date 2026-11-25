/**
 * 0.5 hardening: the RSA public-key rule (H1) and the OID size caps (H2) in x509-strict.ts. Boundaries are pinned with
 * synthetic KeyObject-shaped values (the rule reads only asymmetricKeyType / modulusLength / publicExponent) plus real keys
 * generated at test load (no key material is committed).
 */
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { tlv, seq, octets, integer, oid, ctx } from './test-support/forge-x509';
import { certVerifiedUnder, parseTbsExtensions, rsaKeyOk } from './x509-strict';

const fake = (type: string, modulusLength?: number, publicExponent?: bigint): KeyObject =>
  ({ asymmetricKeyType: type, asymmetricKeyDetails: modulusLength === undefined ? undefined : { modulusLength, publicExponent } }) as unknown as KeyObject;

describe('rsaKeyOk', () => {
  it('modulus bounds are 512..16384 bits inclusive', () => {
    expect(rsaKeyOk(fake('rsa', 512, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa', 511, 65537n))).toBe(false);
    expect(rsaKeyOk(fake('rsa', 256, 65537n))).toBe(false);
    expect(rsaKeyOk(fake('rsa', 2048, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa', 16384, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa', 16385, 65537n))).toBe(false);
    expect(rsaKeyOk(fake('rsa', 17000, 65537n))).toBe(false);
  });
  it('the exponent must be odd, at least 3 and at most 32 bits', () => {
    for (const e of [1n, 0n, 2n, 4n, 65536n, 2n ** 32n, 2n ** 33n + 1n, 2n ** 40n + 1n]) expect(rsaKeyOk(fake('rsa', 2048, e)), String(e)).toBe(false);
    for (const e of [3n, 5n, 17n, 65537n, 2n ** 31n + 1n, 2n ** 32n - 1n]) expect(rsaKeyOk(fake('rsa', 2048, e)), String(e)).toBe(true);
  });
  it('rsa-pss keys follow the same rule', () => {
    expect(rsaKeyOk(fake('rsa-pss', 4096, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa-pss', 4096, 1n))).toBe(false);
    expect(rsaKeyOk(fake('rsa-pss', 256, 65537n))).toBe(false);
  });
  it('a key whose details are missing is unusable; other key types are not this rule\'s business', () => {
    expect(rsaKeyOk(fake('rsa'))).toBe(false);
    expect(rsaKeyOk(fake('rsa', 2048))).toBe(false); // no exponent
    expect(rsaKeyOk(fake('rsa-pss'))).toBe(false);
    expect(rsaKeyOk(fake('ec'))).toBe(true);
    expect(rsaKeyOk(fake('ed25519'))).toBe(true);
  });
  it('real keys: RSA 2048 e=65537, e=3 and an EC key pass; a 1024-bit key passes, a 256-bit modulus is unusable', () => {
    expect(rsaKeyOk(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey)).toBe(true);
    expect(rsaKeyOk(generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 3 }).publicKey)).toBe(true);
    expect(rsaKeyOk(generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).publicKey)).toBe(true);
    expect(rsaKeyOk(generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey)).toBe(true);
    expect(rsaKeyOk(generateKeyPairSync('ed25519').publicKey)).toBe(true);
  });
});

describe('certVerifiedUnder', () => {
  it('does not call verify for an unusable RSA key, and passes the verify result through for a usable one', () => {
    let calls = 0;
    const cert = { verify: () => (calls++, true) };
    expect(certVerifiedUnder(cert, fake('rsa', 2048, 1n))).toBe(false);
    expect(calls).toBe(0);
    expect(certVerifiedUnder(cert, fake('rsa', 2048, 65537n))).toBe(true);
    expect(calls).toBe(1);
    expect(certVerifiedUnder({ verify: () => false }, fake('rsa', 2048, 65537n))).toBe(false);
    expect(certVerifiedUnder({ verify: () => true }, fake('ec'))).toBe(true);
  });
});

// ------------------------------------------------------------------------------------------------ OID caps
const tbsWith = (oidTlv: Uint8Array) => seq(ctx(0, integer(2)), integer(1), tlv(0xa3, seq(seq(oidTlv, octets(new Uint8Array([5, 0]))))));
const oidOf = (content: number[]) => tlv(0x06, Uint8Array.from(content));
const reason = (f: () => unknown) => {
  try {
    f();
    return 'OK';
  } catch (e) {
    return (e as Error).message;
  }
};

describe('extension OID caps (decoded before any BigInt work)', () => {
  it('ordinary OIDs decode, including a 2.25.<uuid> arc', () => {
    expect([...parseTbsExtensions(tbsWith(oid('2.5.29.19'))).keys()]).toEqual(['2.5.29.19']);
    // 2.25.<128-bit>: 19 base-128 groups
    const uuid = [0x69, ...Array(18).fill(0xff).map((_, i) => (i === 0 ? 0x83 : 0xff)), 0x7f];
    expect([...parseTbsExtensions(tbsWith(oidOf(uuid))).keys()][0]).toMatch(/^2\.25\.\d+$/);
  });
  it('content of exactly 256 bytes is accepted, 257 is "too long"', () => {
    const ok = Array(256).fill(0x2a); // 256 single-group arcs
    expect(parseTbsExtensions(tbsWith(oidOf(ok))).size).toBe(1);
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf([...ok, 0x2a]))))).toBe('extension OID is too long');
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf(Array(300).fill(0x81).fill(0x01, 299)))))).toBe('extension OID is too long');
  });
  it('an arc of exactly 64 groups is accepted, 65 is "oversized"', () => {
    const arc = (groups: number) => [0x2a, ...Array(groups - 1).fill(0x81), 0x01];
    expect(parseTbsExtensions(tbsWith(oidOf(arc(64)))).size).toBe(1);
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf(arc(65)))))).toBe('extension OID has an oversized arc');
    // the group counter restarts per arc: two 64-group arcs are fine
    expect(parseTbsExtensions(tbsWith(oidOf([0x2a, ...Array(63).fill(0x81), 0x01, ...Array(63).fill(0x81), 0x01]))).size).toBe(1);
  });
  it('the 65-group arc inside the first arc (the head) is oversized too', () => {
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf([...Array(64).fill(0x81), 0x01]))))).toBe('extension OID has an oversized arc');
  });
  it('an oversized OID is refused fast (no quadratic decimal decode)', () => {
    const big = tlv(0x06, Uint8Array.from([...Array(100_000).fill(0xff), 0x7f]));
    const t0 = performance.now();
    expect(reason(() => parseTbsExtensions(tbsWith(big)))).toBe('extension OID is too long');
    expect(performance.now() - t0).toBeLessThan(500);
  });
  it('the existing refusals keep their texts and precedence: empty, non-minimal arc, truncated', () => {
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf([])))) ).toBe('extension OID is malformed');
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf([0x2a, 0x80, 0x01]))))).toBe('extension OID has a non-minimal arc');
    expect(reason(() => parseTbsExtensions(tbsWith(oidOf([0x2a, 0x81]))))).toBe('extension OID is truncated');
  });
});
