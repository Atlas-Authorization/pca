import { afterEach, describe, expect, it, vi } from 'vitest';
import { SignJWT, decodeProtectedHeader, importJWK } from 'jose';
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { actDepth, fromTransactionToken as fromTransactionTokenReal, subActChain, toTransactionToken as toTransactionTokenReal } from './index';

// The package defaults are draft-11 + a required replay store; these tests exercise the legacy profile
// unless a test passes its own options, so the shared defaults are pinned here once.
const fromTransactionToken: typeof fromTransactionTokenReal = (jwt, key, opts = {}) =>
  fromTransactionTokenReal(jwt, key, { profile: 'legacy', replayCheck: 'unchecked', ...opts });
const toTransactionToken: typeof toTransactionTokenReal = (args) => toTransactionTokenReal({ profile: 'legacy', ...args });


const ACTION = { verb: 'v.x', resource: 'r:1', aud: 'aud1' };
const chainOf = (...hs: string[]) => hs.map((h, i) => ({ issuer: i === 0 ? 'P' : hs[i - 1], holder: h })) as never;
const tts = generateKeyPair();

async function priv() {
  return importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(tts.publicKey), d: b64u(tts.secretKey) }, 'EdDSA');
}
async function forge(payload: Record<string, unknown>, typ = 'txn_token+jwt', exp = Math.floor(Date.now() / 1000) + 60) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ }).setExpirationTime(exp).sign(await priv());
}
const good = { sub: 'P', tctx: { verb: 'v', resource: 'r', aud: 'a' } };

afterEach(() => vi.useRealTimers());

describe('subActChain guards', () => {
  it('non-array / empty chain', () => {
    expect(() => subActChain(null as never)).toThrow('subActChain: chain must be a non-empty CapabilityChain');
    expect(() => subActChain({} as never)).toThrow(TypeError);
    expect(() => subActChain([])).toThrow('subActChain: chain must be a non-empty CapabilityChain');
  });
  it('holder checks name the hop index and take priority over issuer', () => {
    expect(() => subActChain([{ issuer: 'P', holder: 'a' }, { issuer: 'a', holder: '' }] as never)).toThrow('subActChain: hop 1 has no holder');
    expect(() => subActChain([{ issuer: 'P', holder: 5 }] as never)).toThrow('subActChain: hop 0 has no holder');
    expect(() => subActChain([{ issuer: '', holder: '' }] as never)).toThrow('hop 0 has no holder');
    expect(() => subActChain([{ issuer: 'P', holder: '' }, { issuer: 'a', holder: '' }] as never)).toThrow('hop 1 has no holder');
  });
  it('issuer checks', () => {
    expect(() => subActChain([{ issuer: '', holder: 'a' }] as never)).toThrow('subActChain: root hop has no issuer (principal)');
    expect(() => subActChain([{ issuer: 7, holder: 'a' }] as never)).toThrow(TypeError);
    expect(() => subActChain([{ issuer: undefined, holder: 'a' }] as never)).toThrow('root hop has no issuer');
  });
  it('exact shape: sub is root issuer, act nests holders without extra keys', () => {
    expect(subActChain(chainOf('a'))).toStrictEqual({ sub: 'P', act: { sub: 'a' } });
    expect(subActChain(chainOf('a', 'b', 'c'))).toStrictEqual({ sub: 'P', act: { sub: 'a', act: { sub: 'b', act: { sub: 'c' } } } });
  });
});

describe('actDepth', () => {
  it('guards and counting', () => {
    for (const bad of [null, undefined, 'x', 5]) expect(() => actDepth(bad as never)).toThrow('actDepth: expected a sub/act claim object');
    expect(actDepth({ sub: 'a' })).toBe(0);
    expect(actDepth({ sub: 'a', act: { sub: 'b' } })).toBe(1);
    expect(actDepth({ sub: 'a', act: { sub: 'b', act: { sub: 'c', act: { sub: 'd' } } } })).toBe(3);
  });
});

describe('toTransactionToken', () => {
  const base = { chain: chainOf('a', 'b'), action: ACTION, issuerKey: tts.secretKey, issuer: 'iss' };
  it('validation order and messages', async () => {
    await expect(toTransactionToken({ ...base, issuer: '' })).rejects.toThrow('toTransactionToken: `issuer` is required');
    await expect(toTransactionToken({ ...base, issuer: 3 as never })).rejects.toThrow('`issuer` is required');
    // issuer is checked before action and chain
    await expect(toTransactionToken({ ...base, issuer: '', action: null as never, chain: [] })).rejects.toThrow('`issuer` is required');
    const msg = 'toTransactionToken: `action` must have string verb, resource and aud';
    await expect(toTransactionToken({ ...base, action: null as never })).rejects.toThrow(msg);
    await expect(toTransactionToken({ ...base, action: 'x' as never })).rejects.toThrow(msg);
    for (const k of ['verb', 'resource', 'aud'] as const) {
      await expect(toTransactionToken({ ...base, action: { ...ACTION, [k]: 1 } as never })).rejects.toThrow(msg);
      await expect(toTransactionToken({ ...base, action: { ...ACTION, [k]: undefined } as never })).rejects.toThrow(msg);
    }
    // a function with string members is not a plain action object
    const fnAction = Object.assign(() => 0, ACTION);
    await expect(toTransactionToken({ ...base, action: fnAction as never })).rejects.toThrow(msg);
    // empty strings are allowed for action fields
    await expect(toTransactionToken({ ...base, action: { verb: '', resource: '', aud: '' } })).resolves.toBeTypeOf('string');
    // action before chain
    await expect(toTransactionToken({ ...base, action: null as never, chain: [] })).rejects.toThrow('`action` must have');
    await expect(toTransactionToken({ ...base, chain: [] })).rejects.toThrow('non-empty');
  });
  it('ttl validation', async () => {
    for (const t of [0, -1, NaN, Infinity, -Infinity]) {
      await expect(toTransactionToken({ ...base, ttlSec: t })).rejects.toThrow(new RangeError('toTransactionToken: ttlSec must be > 0'));
    }
    await expect(toTransactionToken({ ...base, ttlSec: 0.5 })).resolves.toBeTypeOf('string');
    // ttl is validated before the key is imported
    await expect(toTransactionToken({ ...base, ttlSec: 0, issuerKey: new Uint8Array(3) })).rejects.toThrow('ttlSec');
  });
  it('key length: exactly 32', async () => {
    for (const n of [0, 31, 33, 64]) {
      await expect(toTransactionToken({ ...base, issuerKey: new Uint8Array(n) })).rejects.toThrow('toTransactionToken: a raw Ed25519 secret key must be 32 bytes');
    }
  });
  it('header, claims, clock', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_999);
    const jwt = await toTransactionToken({ ...base, ttlSec: 7 });
    const h = decodeProtectedHeader(jwt);
    expect(h).toStrictEqual({ alg: 'EdDSA', typ: 'txn_token+jwt' });
    const p = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());
    expect(Object.keys(p).sort()).toEqual(['act', 'aud', 'exp', 'iat', 'iss', 'jti', 'sub', 'tctx']);
    expect(p.iat).toBe(1_700_000_000);
    expect(p.exp).toBe(1_700_000_007);
    expect(p.iss).toBe('iss');
    expect(p.sub).toBe('P');
    expect(p.aud).toBe('aud1');
    expect(p.act).toStrictEqual({ sub: 'a', act: { sub: 'b' } });
    expect(p.tctx).toStrictEqual(ACTION);
    expect(p.jti).toMatch(/^[0-9a-f-]{36}$/);
    const jwt2 = await toTransactionToken({ ...base });
    const p2 = JSON.parse(Buffer.from(jwt2.split('.')[1]!, 'base64url').toString());
    expect(p2.exp - p2.iat).toBe(120);
    expect(p2.jti).not.toBe(p.jti);
  });
  it('tctx drops extra action fields; single-hop chain still has act', async () => {
    const jwt = await toTransactionToken({ ...base, chain: chainOf('a'), action: { ...ACTION, extra: 1 } as never });
    const p = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());
    expect(p.tctx).toStrictEqual(ACTION);
    expect(p.act).toStrictEqual({ sub: 'a' });
  });
});

describe('fromTransactionToken', () => {
  const act1 = { sub: 'a' };
  it('key length and non-canonical gate ordering', async () => {
    const jwt = await forge({ ...good, act: act1 });
    for (const n of [0, 31, 33]) {
      await expect(fromTransactionToken(jwt, new Uint8Array(n))).rejects.toThrow('fromTransactionToken: a raw Ed25519 public key must be 32 bytes');
    }
    // canonical gate runs before the key is looked at
    const err = await fromTransactionToken(jwt + '=', new Uint8Array(3)).catch((e: Error) => e);
    expect((err as Error).message).not.toContain('32 bytes');
    await expect(fromTransactionToken('a.b', tts.publicKey)).rejects.toThrow();
  });
  it('happy path returns exact normalized shapes', async () => {
    const jwt = await forge({ ...good, tctx: { verb: 'v', resource: 'r', aud: 'a', extra: 1 }, act: { sub: 'a', junk: 1, act: { sub: 'b', junk: 2 } } });
    const r = await fromTransactionToken(jwt, tts.publicKey);
    expect(r.chain).toStrictEqual({ sub: 'P', act: { sub: 'a', act: { sub: 'b' } } });
    expect(r.action).toStrictEqual({ verb: 'v', resource: 'r', aud: 'a' });
    expect(r.claims.sub).toBe('P');
    expect(r.claims.act).toBeDefined();
    const noAct = await fromTransactionToken(await forge(good), tts.publicKey);
    expect(noAct.chain).toStrictEqual({ sub: 'P' });
    expect('act' in noAct.chain).toBe(false);
  });
  it('typ is enforced', async () => {
    await expect(fromTransactionToken(await forge(good, 'JWT'), tts.publicKey)).rejects.toThrow();
    await expect(fromTransactionToken(await forge(good, 'txn_token+jwt'), tts.publicKey)).resolves.toBeDefined();
  });
  it('expired tokens are rejected', async () => {
    await expect(fromTransactionToken(await forge(good, 'txn_token+jwt', 1000), tts.publicKey)).rejects.toThrow();
  });
  it('sub checks', async () => {
    for (const sub of [undefined, '', 5]) {
      await expect(fromTransactionToken(await forge({ ...good, sub }), tts.publicKey)).rejects.toThrow('transaction token: missing `sub` (root principal)');
    }
  });
  it('tctx checks', async () => {
    const msg = 'transaction token: missing or malformed `tctx`';
    for (const tctx of [undefined, null, 'x', 5, true]) {
      await expect(fromTransactionToken(await forge({ sub: 'P', tctx }), tts.publicKey)).rejects.toThrow(msg);
    }
    for (const k of ['verb', 'resource', 'aud']) {
      const t = { verb: 'v', resource: 'r', aud: 'a', [k]: 1 };
      await expect(fromTransactionToken(await forge({ sub: 'P', tctx: t }), tts.publicKey)).rejects.toThrow(msg);
      const m = { verb: 'v', resource: 'r', aud: 'a' } as Record<string, unknown>;
      delete m[k];
      await expect(fromTransactionToken(await forge({ sub: 'P', tctx: m }), tts.publicKey)).rejects.toThrow(msg);
    }
    // empty strings are accepted
    await expect(fromTransactionToken(await forge({ sub: 'P', tctx: { verb: '', resource: '', aud: '' } }), tts.publicKey)).resolves.toBeDefined();
    // sub is checked before tctx
    await expect(fromTransactionToken(await forge({ sub: '', tctx: 1 }), tts.publicKey)).rejects.toThrow('missing `sub`');
  });
  it('act checks (including nested)', async () => {
    const malformed = 'transaction token: malformed `act` claim';
    for (const act of [null, 'x', 5, [], [{ sub: 'a' }]]) {
      await expect(fromTransactionToken(await forge({ ...good, act }), tts.publicKey)).rejects.toThrow(malformed);
    }
    const subMsg = 'transaction token: `act.sub` must be a non-empty string';
    for (const act of [{}, { sub: '' }, { sub: 3 }]) {
      await expect(fromTransactionToken(await forge({ ...good, act }), tts.publicKey)).rejects.toThrow(subMsg);
    }
    await expect(fromTransactionToken(await forge({ ...good, act: { sub: 'a', act: null } }), tts.publicKey)).rejects.toThrow(malformed);
    await expect(fromTransactionToken(await forge({ ...good, act: { sub: 'a', act: { sub: '' } } }), tts.publicKey)).rejects.toThrow(subMsg);
    await expect(fromTransactionToken(await forge({ ...good, act: { sub: 'a', act: { sub: 'b', act: [] } } }), tts.publicKey)).rejects.toThrow(malformed);
  });
  it('round trip via raw keys and jose key', async () => {
    const jwt = await toTransactionToken({ chain: chainOf('a'), action: ACTION, issuerKey: tts.secretKey, issuer: 'i' });
    const pub = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(tts.publicKey) }, 'EdDSA');
    expect((await fromTransactionToken(jwt, pub)).chain).toStrictEqual({ sub: 'P', act: { sub: 'a' } });
    const other = generateKeyPair();
    await expect(fromTransactionToken(jwt, other.publicKey)).rejects.toThrow();
  });
});
