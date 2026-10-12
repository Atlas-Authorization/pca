import { describe, expect, it } from 'vitest';
import {
  Ap2Error,
  assertP256Jwk,
  b64uDecode,
  b64uEncode,
  disclosureBuilder,
  generateAp2KeyPair,
  jwkThumbprint,
  parseJson,
  parseSdJwtHop,
  processDisclosures,
  sdDigest,
  signSdJwt,
  verifyHopSignature,
  type JsonObject,
} from './index';
import { counterSalt } from './testkit';

const ALG = 'sha-256' as const;

describe('base64url + JSON strictness', () => {
  it('b64uDecode accepts only canonical unpadded base64url', () => {
    expect(b64uDecode(b64uEncode('hello'), 'x').toString()).toBe('hello');
    for (const bad of ['aGVsbG8=', 'aGVs bG8', 'aGVsbG8+', 'aGVsbG9', 'a']) expect(() => b64uDecode(bad, 'x'), bad).toThrow(Ap2Error);
  });

  it('parseJson rejects duplicate keys at any depth but accepts float spellings the official SDK emits', () => {
    expect(() => parseJson('{"a":1,"a":2}', 't')).toThrow(/duplicate key "a"/);
    expect(() => parseJson('{"a":{"b":1,"b":2}}', 't')).toThrow(/duplicate key "b"/);
    expect(() => parseJson('[{"a":1},{"a":2}]', 't')).not.toThrow();
    expect(() => parseJson('{"a":"x\\",\\"a\\":1"}', 't')).not.toThrow(); // keys inside strings are not keys
    expect(parseJson('{"max": 1000.0, "n": 1e3}', 't')).toEqual({ max: 1000, n: 1000 });
    expect(() => parseJson('{"a":', 't')).toThrow(Ap2Error);
  });
});

describe('disclosure processing (RFC 9901)', () => {
  const salt = counterSalt();
  const build = (f: (b: ReturnType<typeof disclosureBuilder>) => JsonObject): { payload: JsonObject; discs: string[] } => {
    const b = disclosureBuilder(ALG, salt);
    const payload = f(b);
    return { payload, discs: b.disclosures };
  };

  it('resolves property and array-element disclosures, drops decoys and withheld elements', () => {
    const { payload, discs } = build((b) => ({ _sd: [b.property('a', 1), 'decoy-digest'], list: [b.element('x'), { '...': 'decoy' }, 'plain'], _sd_alg: ALG }));
    expect(processDisclosures(payload, discs, ALG)).toEqual({ a: 1, list: ['x', 'plain'] });
    // withholding the element disclosure removes it from the processed claims
    expect(processDisclosures(payload, discs.filter((d) => !b64uDecode(d, 'd').toString().includes('"x"')), ALG)).toEqual({ a: 1, list: ['plain'] });
  });

  it('rejects an unreferenced disclosure', () => {
    const { payload, discs } = build((b) => {
      b.property('orphan', 1);
      return { v: 1 };
    });
    expect(() => processDisclosures(payload, discs, ALG)).toThrow(/not referenced/);
  });

  it('rejects duplicate disclosures and a digest referenced twice', () => {
    const { payload, discs } = build((b) => ({ _sd: [b.property('a', 1)] }));
    expect(() => processDisclosures(payload, [...discs, ...discs], ALG)).toThrow(/duplicate disclosure/);
    const d = discs[0] as string;
    const twice = { _sd: [sdDigest(d, ALG), sdDigest(d, ALG)] };
    expect(() => processDisclosures(twice, discs, ALG)).toThrow(/more than once/);
  });

  it('rejects a disclosed claim colliding with an existing claim', () => {
    const { payload, discs } = build((b) => ({ a: 0, _sd: [b.property('a', 1)] }));
    expect(() => processDisclosures(payload, discs, ALG)).toThrow(/collides/);
  });

  it('rejects a property disclosure in an array position and vice versa', () => {
    const b = disclosureBuilder(ALG, salt);
    const prop = b.property('a', 1);
    const el = b.element(2)['...'];
    expect(() => processDisclosures({ list: [{ '...': prop }] }, b.disclosures, ALG)).toThrow(/position/);
    expect(() => processDisclosures({ _sd: [el] }, b.disclosures, ALG)).toThrow(/position/);
  });

  it('rejects reserved names, malformed placeholders and malformed disclosures', () => {
    const raw = (v: unknown): string => b64uEncode(JSON.stringify(v));
    const named = raw(['s', '_sd', 1]);
    expect(() => processDisclosures({ _sd: [sdDigest(named, ALG)] }, [named], ALG)).toThrow(/reserved/);
    expect(() => processDisclosures({ l: [{ '...': 'x', extra: 1 }] }, [], ALG)).toThrow(/malformed array digest/);
    expect(() => processDisclosures({ '...': 'x' }, [], ALG)).toThrow(/only valid as the sole key/);
    for (const bad of [raw({ not: 'array' }), raw(['only-salt']), raw(['', 1]), raw([1, 'name', 2]), raw(['s', 'a', 'b', 'c'])]) {
      expect(() => processDisclosures({}, [bad], ALG), bad).toThrow(Ap2Error);
    }
  });

  it('supports sha-384 and sha-512 as _sd_alg', () => {
    for (const alg of ['sha-384', 'sha-512'] as const) {
      const b = disclosureBuilder(alg, salt);
      const payload = { _sd: [b.property('a', 1)] };
      expect(processDisclosures(payload, b.disclosures, alg)).toEqual({ a: 1 });
      expect(() => processDisclosures(payload, b.disclosures, 'sha-256')).toThrow(/not referenced/);
    }
  });
});

describe('SD-JWT hops and ES256', () => {
  const key = generateAp2KeyPair('k1');
  const issue = (disclosures: string[] = []): string => signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'k1' }, payload: { a: 1, _sd_alg: ALG }, disclosures, privateKey: key.privateKey });

  it('round-trips and verifies; the wrong key and a flipped signature do not', () => {
    const hop = parseSdJwtHop(issue());
    expect(verifyHopSignature(hop, key.publicJwk)).toBe(true);
    expect(verifyHopSignature(hop, generateAp2KeyPair().publicJwk)).toBe(false);
    const bad = parseSdJwtHop(issue().replace(/\.[^.~]+~$/, (m) => `.${m[1] === 'A' ? 'B' : 'A'}${m.slice(2)}`));
    expect(verifyHopSignature(bad, key.publicJwk)).toBe(false);
  });

  it('refuses alg other than ES256 (none, HS256) and non-canonical input', () => {
    const hop = parseSdJwtHop(issue());
    const forge = (alg: string): string => {
      const [, p, s] = hop.jwt.split('.') as [string, string, string];
      const header = b64uEncode(JSON.stringify({ ...hop.header, alg }));
      return `${header}.${p}.${s}~`;
    };
    expect(verifyHopSignature(parseSdJwtHop(forge('none')), key.publicJwk)).toBe(false);
    expect(verifyHopSignature(parseSdJwtHop(forge('HS256')), key.publicJwk)).toBe(false);
    expect(() => parseSdJwtHop(issue().slice(0, -1))).toThrow(/end with "~"/); // missing trailing ~ (or a KB-JWT)
    expect(() => parseSdJwtHop(`~${issue()}`)).toThrow(Ap2Error);
    expect(() => parseSdJwtHop(issue().replace('~', '~~'))).toThrow(/empty disclosure/);
    expect(() => parseSdJwtHop('')).toThrow(Ap2Error);
    expect(() => parseSdJwtHop('a.b~')).toThrow(/header.payload.signature/);
  });

  it('rejects an unsupported _sd_alg and a short signature', () => {
    const [h, , s] = parseSdJwtHop(issue()).jwt.split('.') as [string, string, string];
    expect(() => parseSdJwtHop(`${h}.${b64uEncode(JSON.stringify({ _sd_alg: 'md5' }))}.${s}~`)).toThrow(/unsupported _sd_alg/);
    const short = parseSdJwtHop(`${h}.${b64uEncode(JSON.stringify({ a: 1 }))}.${b64uEncode(new Uint8Array(63))}~`);
    expect(verifyHopSignature(short, key.publicJwk)).toBe(false);
  });
});

describe('JWK handling', () => {
  it('accepts a P-256 point and refuses private material, other curves and off-curve points', () => {
    const k = generateAp2KeyPair();
    expect(assertP256Jwk(k.publicJwk, 't')).toBeDefined();
    expect(() => assertP256Jwk({ ...k.publicJwk, d: 'x' }, 't')).toThrow(/private/);
    expect(() => assertP256Jwk({ ...k.publicJwk, crv: 'P-384' }, 't')).toThrow(/P-256/);
    expect(() => assertP256Jwk({ ...k.publicJwk, y: k.publicJwk.x }, 't')).toThrow(/valid P-256 point/);
    expect(() => assertP256Jwk({ ...k.publicJwk, x: 'short' }, 't')).toThrow(/bad JWK x/);
    expect(() => assertP256Jwk({ ...k.publicJwk, alg: 'RS256' }, 't')).toThrow(/alg/);
    expect(() => assertP256Jwk(null, 't')).toThrow(Ap2Error);
  });

  it('thumbprint is order-independent and URL-safe (the independent-implementation check is in crosscheck.test.ts)', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'QpSyxPQHy38xckyvDr54gZ3T42zj9iLtV4koyb5U27c', y: '37HLd7JJinxjJIn8J7HijssoecBlfhdW-gUL7feI9lw' } as const;
    expect(jwkThumbprint(jwk)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jwkThumbprint({ ...jwk })).toBe(jwkThumbprint({ y: jwk.y, x: jwk.x, crv: jwk.crv, kty: jwk.kty }));
  });
});
