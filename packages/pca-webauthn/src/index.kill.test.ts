import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { b64u } from '@atlasauth/pca';
import { type Assertion, type CredentialPublicKey, type VerifyExpectations, buildStepUpChallenge, coseKeyToJwk, spcPaymentError, verifyAssertion } from './index';

const RP_ID = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const enc = new TextEncoder();
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

const concat = (...p: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const authData = (signCount: number, size = 37): Uint8Array => {
  const out = new Uint8Array(size);
  out.set(sha256(enc.encode(RP_ID)), 0);
  out[32] = 0x05;
  new DataView(out.buffer).setUint32(33, signCount, false);
  return out;
};
const clientData = (pad = 0): Uint8Array => {
  const base = { type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false };
  const len = enc.encode(JSON.stringify({ ...base, pad: '' })).length;
  return enc.encode(JSON.stringify(pad > 0 ? { ...base, pad: 'a'.repeat(pad - len) } : base));
};
const expectations = (o: Partial<VerifyExpectations> = {}): VerifyExpectations => ({
  expectedChallenge: CHALLENGE,
  rpId: RP_ID,
  origins: [ORIGIN],
  requireUV: true,
  storedSignCount: 0,
  ...o,
});

const skFrom = (n: number): Uint8Array => {
  const sk = new Uint8Array(32);
  new DataView(sk.buffer).setUint32(28, n + 1000, false);
  return sk;
};
const es = (n = 1) => {
  const sk = skFrom(n);
  const pub = p256.getPublicKey(sk, false);
  return { sk, x: pub.slice(1, 33), y: pub.slice(33, 65) };
};
const signEs = (sk: Uint8Array, ad: Uint8Array, cd: Uint8Array, format: 'der' | 'compact' = 'der'): Uint8Array => {
  const sig = p256.sign(sha256(concat(ad, sha256(cd))), sk);
  return format === 'der' ? sig.toDERRawBytes() : sig.toCompactRawBytes();
};
const esAssertion = (jwk: CredentialPublicKey, n = 1, o: { ad?: Uint8Array; cd?: Uint8Array; sig?: Uint8Array } = {}): Assertion => {
  const { sk } = es(n);
  const ad = o.ad ?? authData(1);
  const cd = o.cd ?? clientData();
  return { authenticatorData: ad, clientDataJSON: cd, signature: o.sig ?? signEs(sk, ad, cd), publicKey: jwk };
};
const jwkOf = (n = 1) => {
  const k = es(n);
  return { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(k.x), y: b64u(k.y) };
};
const unresolved = (m: string) => ({ ok: false, reason: `public key could not be resolved: ${m}` });

describe('base64url key coordinates (tolerant decode)', () => {
  it('accepts the key as is', () => {
    expect(verifyAssertion(esAssertion(jwkOf()), expectations()).ok).toBe(true);
  });
  it('accepts trailing padding of any length and the standard alphabet', () => {
    const j = jwkOf();
    expect(verifyAssertion(esAssertion({ ...j, x: j.x + '==' }), expectations()).ok).toBe(true);
    expect(verifyAssertion(esAssertion({ ...j, y: j.y + '=' }), expectations()).ok).toBe(true);
    for (const ch of ['-', '_']) {
      let found = 0;
      for (let n = 1; n < 400 && !found; n++) {
        const k = jwkOf(n);
        if (!(k.x + k.y).includes(ch)) continue;
        found = n;
        const std = (s: string) => s.replace(/-/g, '+').replace(/_/g, '/');
        expect(verifyAssertion(esAssertion({ ...k, x: std(k.x), y: std(k.y) }, n), expectations()).ok).toBe(true);
      }
      expect(found).toBeGreaterThan(0);
    }
  });
  it('rejects padding that is not at the end', () => {
    const j = jwkOf();
    const mid = j.x.slice(0, 10) + '=' + j.x.slice(10);
    expect(verifyAssertion(esAssertion({ ...j, x: mid }), expectations())).toEqual(unresolved('resolveKey: invalid EC JWK coordinates'));
  });
  it('rejects a coordinate that is not a string, is missing, or is the wrong length (each on its own)', () => {
    const j = jwkOf();
    const bad = [
      { ...j, x: 5 as unknown as string },
      { ...j, y: undefined as unknown as string },
      { ...j, x: b64u(es().x.slice(0, 31)) },
      { ...j, y: b64u(es().y.slice(0, 31)) },
      { ...j, x: '' },
    ];
    for (const k of bad) expect(verifyAssertion(esAssertion(k), expectations())).toEqual(unresolved('resolveKey: invalid EC JWK coordinates'));
  });
  it('rejects an Ed25519 key that is missing or the wrong length', () => {
    const sk = ed25519.utils.randomPrivateKey();
    const x = ed25519.getPublicKey(sk);
    const a = { ...esAssertion(jwkOf()), publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(x.slice(0, 31)) } as CredentialPublicKey };
    expect(verifyAssertion(a, expectations())).toEqual(unresolved('resolveKey: invalid OKP JWK public key'));
    const b = { ...a, publicKey: { kty: 'OKP', crv: 'Ed25519' } as unknown as CredentialPublicKey };
    expect(verifyAssertion(b, expectations())).toEqual(unresolved('resolveKey: invalid OKP JWK public key'));
  });
});

describe('verifyAssertion boundaries and reasons', () => {
  it('accepts the largest allowed authenticatorData and clientDataJSON, refuses one byte more', () => {
    const k = jwkOf();
    const ad = authData(1, 4096);
    expect(verifyAssertion(esAssertion(k, 1, { ad }), expectations()).ok).toBe(true);
    const cd = clientData(8192);
    expect(cd.length).toBe(8192);
    expect(verifyAssertion(esAssertion(k, 1, { cd }), expectations()).ok).toBe(true);
    expect(verifyAssertion(esAssertion(k, 1, { ad: authData(1, 4097) }), expectations())).toEqual({ ok: false, reason: 'authenticatorData is too large' });
    expect(verifyAssertion(esAssertion(k, 1, { cd: clientData(8193) }), expectations())).toEqual({ ok: false, reason: 'clientDataJSON is too large' });
  });
  it('a 1024-byte signature is read (and fails to verify); 1025 bytes is too large', () => {
    const k = jwkOf();
    expect(verifyAssertion(esAssertion(k, 1, { sig: new Uint8Array(1024).fill(7) }), expectations())).toEqual({ ok: false, reason: 'assertion signature did not verify' });
    expect(verifyAssertion(esAssertion(k, 1, { sig: new Uint8Array(1025).fill(7) }), expectations())).toEqual({ ok: false, reason: 'signature is too large' });
  });
  it('a non-string rpId is refused', () => {
    expect(verifyAssertion(esAssertion(jwkOf()), expectations({ rpId: 123 as unknown as string }))).toEqual({ ok: false, reason: 'rpId is required' });
  });
  it('a compact signature whose first byte is 0x30 is still read as compact', () => {
    const { sk } = es();
    const k = jwkOf();
    let sig: Uint8Array | undefined;
    let ad: Uint8Array | undefined;
    for (let c = 1; c < 20000 && !sig; c++) {
      const a = authData(c);
      const s = signEs(sk, a, clientData(), 'compact');
      if (s[0] === 0x30) {
        sig = s;
        ad = a;
      }
    }
    expect(sig).toBeDefined();
    expect(verifyAssertion(esAssertion(k, 1, { ad, sig }), expectations()).ok).toBe(true);
  });
  it('the stored counter bound is inclusive at 0xffffffff and refused above it', () => {
    const k = jwkOf();
    const a = esAssertion(k, 1, { ad: authData(5) });
    expect(verifyAssertion(a, expectations({ storedSignCount: 0xffffffff }))).toEqual({ ok: false, reason: 'signCount did not increase (possible cloned authenticator)' });
    expect(verifyAssertion(a, expectations({ storedSignCount: 0x100000000 }))).toEqual({ ok: false, reason: 'storedSignCount is not a uint32' });
  });
  it('reports non-Error throws as "unknown"', () => {
    const k = jwkOf();
    const hostileKey = { get kty(): string { throw 'boom'; } } as unknown as CredentialPublicKey;
    expect(verifyAssertion({ ...esAssertion(k), publicKey: hostileKey }, expectations())).toEqual(unresolved('unknown'));
    const hostile = { get authenticatorData(): Uint8Array { throw 'boom'; } } as unknown as Assertion;
    expect(verifyAssertion(hostile, expectations())).toEqual({ ok: false, reason: 'verification error (fail closed): unknown' });
  });
  it.each([['null'], ['[]'], ['5'], ['"s"']])('clientDataJSON %s is not a JSON object', (text) => {
    expect(verifyAssertion(esAssertion(jwkOf(), 1, { cd: enc.encode(text) }), expectations())).toEqual({ ok: false, reason: 'clientDataJSON is not a JSON object' });
  });
});

describe('spcPaymentError', () => {
  const e = { topOrigin: 'https://top.example', total: { currency: 'USD', value: '1.00' }, payeeName: 'Shop' };
  const good = { rpId: RP_ID, topOrigin: 'https://top.example', total: { currency: 'USD', value: '1.00' }, payeeName: 'Shop' };
  it('accepts an exact match', () => {
    expect(spcPaymentError(good, e, RP_ID)).toBeNull();
  });
  it('is missing for anything that is not a plain object', () => {
    for (const p of [undefined, null, 5, 'x', []]) expect(spcPaymentError(p, e, RP_ID)).toBe('clientData.payment is missing');
  });
  it('refuses an expectation that names no payee', () => {
    const { payeeName: _n, ...none } = e;
    void _n;
    expect(spcPaymentError(good, none, RP_ID)).toBe('the expectation names no payee (refused: a payment approval must bind the payee)');
  });
  it('a payeeOrigin-only expectation is accepted when it matches', () => {
    const { payeeName: _n, ...rest } = e;
    void _n;
    expect(spcPaymentError({ ...good, payeeOrigin: 'https://shop.example' }, { ...rest, payeeOrigin: 'https://shop.example' }, RP_ID)).toBeNull();
    expect(spcPaymentError({ ...good, payeeOrigin: 'https://evil.example' }, { ...rest, payeeOrigin: 'https://shop.example' }, RP_ID)).toBe('clientData.payment.payeeOrigin does not equal the canonical render');
  });
  it('only the payee fields the expectation names are compared', () => {
    expect(spcPaymentError({ ...good, payeeOrigin: 'https://anything.example' }, e, RP_ID)).toBeNull();
    expect(spcPaymentError({ ...good, payeeName: 'Other' }, e, RP_ID)).toBe('clientData.payment.payeeName does not equal the canonical render');
  });
  it('total must be a plain object that equals the expectation', () => {
    for (const total of [undefined, null, 5, []]) expect(spcPaymentError({ ...good, total }, e, RP_ID)).toBe('clientData.payment.total does not equal the canonical render');
  });
});

describe('buildStepUpChallenge digest forms', () => {
  it('refuses raw digests that are not 32 bytes, with the exact message', () => {
    for (const n of [31, 33]) expect(() => buildStepUpChallenge(new Uint8Array(n))).toThrow('buildStepUpChallenge: digest bytes must be 32 bytes');
  });
  it('returns a copy of raw digest bytes', () => {
    const d = Uint8Array.from({ length: 32 }, (_, i) => i);
    const out = buildStepUpChallenge(d);
    expect(out).toEqual(d);
    out[0] = 99;
    expect(d[0]).toBe(0);
  });
  it('refuses a string that is not a canonical 32-byte base64url digest', () => {
    for (const s of ['abc', b64u(new Uint8Array(31)), `${b64u(new Uint8Array(32))}=`]) {
      expect(() => buildStepUpChallenge(s)).toThrow('buildStepUpChallenge: digest is not a canonical base64url 32-byte value');
    }
  });
});

// ---- COSE_Key reader -------------------------------------------------------------------------------------------
const head = (major: number, arg: number, ai?: 24 | 25 | 26): number[] => {
  const m = major << 5;
  if (ai === undefined) {
    if (arg < 24) return [m | arg];
    if (arg < 256) return [m | 24, arg];
    return [m | 25, arg >> 8, arg & 255];
  }
  if (ai === 24) return [m | 24, arg];
  if (ai === 25) return [m | 25, (arg >> 8) & 255, arg & 255];
  return [m | 26, (arg >>> 24) & 255, (arg >>> 16) & 255, (arg >>> 8) & 255, arg & 255];
};
const bstr = (b: Uint8Array, ai?: 24 | 25 | 26): number[] => [...head(2, b.length, ai), ...b];
const nint = (n: number): number[] => head(1, -1 - n);
const cmap = (count: number, ...parts: number[][]): Uint8Array => Uint8Array.from([...head(5, count), ...parts.flat()]);
const X = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const Y = Uint8Array.from({ length: 32 }, (_, i) => i + 101);
const ec2 = (o: { crv?: number; x?: Uint8Array; y?: Uint8Array } = {}): Uint8Array => {
  const parts: number[][] = [[0x01, 0x02]];
  if (o.crv !== undefined) parts.push([...nint(-1), ...head(0, o.crv)]);
  if (o.x) parts.push([...nint(-2), ...bstr(o.x)]);
  if (o.y) parts.push([...nint(-3), ...bstr(o.y)]);
  return cmap(parts.length, ...parts);
};
const okp = (o: { crv?: number; x?: Uint8Array } = {}): Uint8Array => {
  const parts: number[][] = [[0x01, 0x01]];
  if (o.crv !== undefined) parts.push([...nint(-1), ...head(0, o.crv)]);
  if (o.x) parts.push([...nint(-2), ...bstr(o.x)]);
  return cmap(parts.length, ...parts);
};

describe('coseKeyToJwk', () => {
  it('reads EC2 P-256 and OKP Ed25519 keys', () => {
    expect(coseKeyToJwk(ec2({ crv: 1, x: X, y: Y }))).toEqual({ kty: 'EC', crv: 'P-256', x: b64u(X), y: b64u(Y), alg: 'ES256' });
    expect(coseKeyToJwk(okp({ crv: 6, x: X }))).toEqual({ kty: 'OKP', crv: 'Ed25519', x: b64u(X), alg: 'EdDSA' });
  });
  it('reads past unrelated entries encoded with 1-, 2- and 4-byte arguments', () => {
    const extra = Uint8Array.from({ length: 300 }, (_, i) => i & 255);
    const big = new Uint8Array(65537);
    const key = Uint8Array.from([
      ...head(5, 6),
      ...head(0, 100, 24), ...bstr(extra, 25),
      ...head(0, 101, 26), ...head(0, 300, 25),
      ...head(0, 102, 25), ...bstr(big, 26),
      0x01, 0x01, ...nint(-1), ...head(0, 6), ...nint(-2), ...bstr(X),
    ]);
    expect(coseKeyToJwk(key)).toEqual({ kty: 'OKP', crv: 'Ed25519', x: b64u(X), alg: 'EdDSA' });
  });
  it('refuses 8-byte and indefinite-length arguments with the exact message', () => {
    const m = 'cose: unsupported CBOR argument encoding (8-byte or indefinite length)';
    expect(() => coseKeyToJwk(Uint8Array.from([0xa1, 0x1b, 0, 0, 0, 0, 0, 0, 0, 1, 0x01]))).toThrow(m);
    expect(() => coseKeyToJwk(Uint8Array.from([0xbf, 0xff]))).toThrow(m);
  });
  it('refuses a byte string longer than the input, a non-integer key and an unsupported major type', () => {
    expect(() => coseKeyToJwk(Uint8Array.from([0xa1, 0x01, 0x58, 0xff, 0x00]))).toThrow('cose: byte string length out of range');
    expect(() => coseKeyToJwk(Uint8Array.from([0xa1, 0x41, 0x00, 0x01]))).toThrow('cose: non-integer map key');
    expect(() => coseKeyToJwk(Uint8Array.from([0xa1, 0x61, 0x41, 0x01]))).toThrow('cose: unsupported CBOR major type 3');
  });
  it('refuses input that is not bytes or not a map', () => {
    expect(() => coseKeyToJwk('abc' as unknown as Uint8Array)).toThrow('coseKeyToJwk: expected a Uint8Array');
    expect(() => coseKeyToJwk(Uint8Array.of(0x01))).toThrow('coseKeyToJwk: COSE_Key is not a CBOR map');
  });
  it('refuses an EC2 key that is not P-256, lacks a coordinate or has a short coordinate', () => {
    expect(() => coseKeyToJwk(ec2({ crv: 2, x: X, y: Y }))).toThrow('coseKeyToJwk: EC2 key is not P-256 (crv != 1)');
    expect(() => coseKeyToJwk(ec2({ x: X, y: Y }))).toThrow('coseKeyToJwk: EC2 key is not P-256 (crv != 1)');
    expect(() => coseKeyToJwk(ec2({ crv: 1, y: Y }))).toThrow('coseKeyToJwk: EC2 key missing an x/y coordinate');
    expect(() => coseKeyToJwk(ec2({ crv: 1, x: X }))).toThrow('coseKeyToJwk: EC2 key missing an x/y coordinate');
    expect(() => coseKeyToJwk(ec2({ crv: 1, x: X.slice(0, 31), y: Y }))).toThrow('coseKeyToJwk: EC2 coordinate is not 32 bytes');
    expect(() => coseKeyToJwk(ec2({ crv: 1, x: X, y: Y.slice(0, 31) }))).toThrow('coseKeyToJwk: EC2 coordinate is not 32 bytes');
  });
  it('refuses an OKP key that is not Ed25519, lacks its key or has a short key', () => {
    expect(() => coseKeyToJwk(okp({ crv: 7, x: X }))).toThrow('coseKeyToJwk: OKP key is not Ed25519 (crv != 6)');
    expect(() => coseKeyToJwk(okp({ x: X }))).toThrow('coseKeyToJwk: OKP key is not Ed25519 (crv != 6)');
    expect(() => coseKeyToJwk(okp({ crv: 6 }))).toThrow('coseKeyToJwk: OKP key missing its public key');
    expect(() => coseKeyToJwk(okp({ crv: 6, x: X.slice(0, 31) }))).toThrow('coseKeyToJwk: Ed25519 public key is not 32 bytes');
  });
});
