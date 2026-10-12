/**
 * Mutation-kill tests for the SD-JWT issuer / presenter / verifier. SD-JWTs are hand-assembled so that every disclosure rule,
 * every key-binding check and every error reason can be driven independently.
 */
import { createHash } from 'node:crypto';
import { SignJWT, decodeProtectedHeader, exportJWK, generateKeyPair as joseGen, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import type { PCActn } from '@atlasauth/pca';
import {
  PCA_CAPABILITY_CLAIMS,
  ed25519PublicJwk,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  issuePcaSdJwt,
  present,
  verifyPcaSdJwt,
} from './index';

const b64u = (s: string | Uint8Array) => Buffer.from(s).toString('base64url');
const sha = (s: string) => createHash('sha256').update(s, 'ascii').digest().toString('base64url');
const disc = (...parts: unknown[]) => b64u(JSON.stringify(parts));
const dig = (encoded: string) => sha(encoded);
const decodePayload = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1] as string, 'base64url').toString());
const NOW = 1_800_000_000; // seconds

type JoseKeyPair = Awaited<ReturnType<typeof joseGen>>;
let ISS: JoseKeyPair;
let HOLD: JoseKeyPair & { jwk: JWK };
beforeAll(async () => {
  ISS = await joseGen('EdDSA', { extractable: true });
  const h = await joseGen('EdDSA', { extractable: true });
  HOLD = { privateKey: h.privateKey, publicKey: h.publicKey, jwk: await exportJWK(h.publicKey) };
});

/** Sign an issuer JWT with the given payload (defaults to a valid, non-expired one) and assemble the SD-JWT. */
async function mk(payloadOver: Record<string, unknown>, discs: string[] = [], header: Record<string, unknown> = {}): Promise<{ sd: string; jwt: string }> {
  const payload = { iss: 'https://iss', aud: 'rs', iat: NOW, exp: NOW + 3600, _sd_alg: 'sha-256', ...payloadOver };
  const jwt = await new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'pca+sd-jwt', ...header } as never).sign(ISS.privateKey);
  return { sd: [jwt, ...discs].join('~') + '~', jwt };
}
const vopts = (o: Record<string, unknown> = {}) => ({ issuerKey: ISS.publicKey, now: NOW * 1000, ...o }) as never;
const fails = async (sd: string, o: Record<string, unknown> = {}) => {
  const r = await verifyPcaSdJwt(sd, vopts(o));
  if (r.ok) throw new Error('expected failure, got ok');
  return r.reason;
};
const passes = async (sd: string, o: Record<string, unknown> = {}) => {
  const r = await verifyPcaSdJwt(sd, vopts(o));
  if (!r.ok) throw new Error(`expected ok, got: ${r.reason}`);
  return r;
};

describe('key helpers', () => {
  it('length checks with exact messages', () => {
    for (const n of [0, 31, 33]) {
      expect(() => ed25519PublicJwk(new Uint8Array(n))).toThrow('pca-sdjwt: Ed25519 public key must be 32 bytes');
      expect(() => importEd25519PublicKey(new Uint8Array(n))).toThrow('pca-sdjwt: Ed25519 public key must be 32 bytes');
      expect(() => importEd25519PrivateKey(new Uint8Array(n))).toThrow('pca-sdjwt: Ed25519 private seed must be 32 bytes');
    }
    expect(ed25519PublicJwk(new Uint8Array(32).fill(7))).toStrictEqual({ kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(7)) });
    expect(importEd25519PublicKey(new Uint8Array(32).fill(7)).type).toBe('public');
    expect(importEd25519PrivateKey(new Uint8Array(32).fill(7)).type).toBe('private');
  });
});

const chainOf = (holder: unknown, issuer: unknown = 'ISSUER-KEY') => [{ issuer, holder }] as never;
const act = (over: Record<string, unknown> = {}): PCActn =>
  ({
    ver: 'pca/1',
    aud: 'rs.example',
    iat: 1_700_000_000_000,
    exp: 1_700_000_300_000,
    cap_chain: chainOf(b64u(new Uint8Array(32).fill(9))),
    action: { verb: 'v', resource: 'r' },
    grant_ref: 'g1',
    counter: 3,
    sig: 'SIG',
    ...over,
  }) as unknown as PCActn;
const issue = (a: PCActn, o: Record<string, unknown> = {}) => issuePcaSdJwt(a, { issuerKey: ISS.privateKey, ...o } as never);
const rejects = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error('no rejection');
};

describe('issuePcaSdJwt', () => {
  it('input validation messages', async () => {
    expect(await rejects(issue(null as never))).toBe('pca-sdjwt: pcActn must be an object');
    expect(await rejects(issue([] as never))).toBe('pca-sdjwt: pcActn must be an object');
    expect(await rejects(issue(new Uint8Array(3) as never))).toBe('pca-sdjwt: pcActn must be an object');
    for (const cap_chain of [undefined, 'x', [], {}]) expect(await rejects(issue(act({ cap_chain })))).toBe('pca-sdjwt: pcActn.cap_chain must be a non-empty array');
    expect(await rejects(issue(act({ cap_chain: [null] })))).toBe('pca-sdjwt: cap_chain root issuer is missing');
    expect(await rejects(issue(act({ cap_chain: chainOf('h', 5) })))).toBe('pca-sdjwt: cap_chain root issuer is missing');
    expect(await rejects(issue(act({ cap_chain: [{ issuer: 'i', holder: 'h' }, null] })))).toBe('pca-sdjwt: cap_chain leaf holder is missing');
    expect(await rejects(issue(act({ cap_chain: chainOf(5) })))).toBe('pca-sdjwt: cap_chain leaf holder is missing');
    for (const aud of [undefined, '', 5]) expect(await rejects(issue(act({ aud })))).toBe('pca-sdjwt: pcActn.aud is required');
    for (const [k, label] of [['iat', 'iat'], ['exp', 'exp']] as const) {
      for (const v of [undefined, '5', NaN, Infinity]) expect(await rejects(issue(act({ [k]: v })))).toBe(`pca-sdjwt: PCActn.${label} must be a finite number (epoch ms)`);
    }
  });
  it('maps standard claims: iss/sub default to root issuer / leaf holder, iat floors, exp ceils and stays after iat', async () => {
    const holder = b64u(new Uint8Array(32).fill(9));
    const p = decodePayload((await issue(act({ iat: 1_700_000_000_999, exp: 1_700_000_300_001 }))).split('~')[0] as string);
    expect(p).toMatchObject({ iss: 'ISSUER-KEY', sub: holder, aud: 'rs.example', iat: 1_700_000_000, exp: 1_700_000_301, ver: 'pca/1', _sd_alg: 'sha-256' });
    const same = decodePayload((await issue(act({ iat: 2000, exp: 2000 }))).split('~')[0] as string);
    expect([same.iat, same.exp]).toEqual([2, 3]);
    const before = decodePayload((await issue(act({ iat: 5000, exp: 1000 }))).split('~')[0] as string);
    expect([before.iat, before.exp]).toEqual([5, 6]);
    const ok = decodePayload((await issue(act({ iat: 2000, exp: 3000 }))).split('~')[0] as string);
    expect([ok.iat, ok.exp]).toEqual([2, 3]);
    const sub = decodePayload((await issue(act(), { iss: 'me', sub: 'you' })).split('~')[0] as string);
    expect([sub.iss, sub.sub]).toEqual(['me', 'you']);
    const lt = decodePayload((await issue(act({ iat: 2000, exp: 2999 }))).split('~')[0] as string);
    expect(lt.exp).toBe(3);
    const iatOnly = decodePayload((await issue(act({ iat: 2999, exp: 4000 }))).split('~')[0] as string);
    expect(iatOnly.iat).toBe(2);
  });
  it('capability claims become disclosures by default; the clear set and header are configurable', async () => {
    const a = act({ rationale_commitment: undefined, custom: { x: 1 } });
    const sd = await issue(a);
    const segs = sd.split('~');
    expect(segs[segs.length - 1]).toBe('');
    const jwt = segs[0] as string;
    const discs = segs.slice(1, -1);
    const parsed = discs.map((d) => JSON.parse(Buffer.from(d, 'base64url').toString()) as [string, string, unknown]);
    const names = parsed.map((p) => p[1]).sort();
    expect(names).toEqual(['action', 'cap_chain', 'counter', 'grant_ref', 'sig']);
    for (const p of parsed) expect(p[0]).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(new Set(parsed.map((p) => p[0])).size).toBe(parsed.length);
    const payload = decodePayload(jwt);
    expect(payload._sd.slice().sort()).toEqual(discs.map(dig).sort());
    expect(payload.custom).toEqual({ x: 1 }); // not in PCA_CAPABILITY_CLAIMS: clear
    expect('action' in payload).toBe(false);
    expect('rationale_commitment' in payload).toBe(false);
    expect(parsed.find((p) => p[1] === 'action')?.[2]).toEqual({ verb: 'v', resource: 'r' });
    expect(decodeProtectedHeader(jwt)).toMatchObject({ alg: 'EdDSA', typ: 'pca+sd-jwt' });
    expect(PCA_CAPABILITY_CLAIMS).toContain('cap_chain');
    const only = await issue(a, { disclosable: ['action'], typ: 'custom+jwt', signingAlg: 'EdDSA' });
    const [j2, ...d2] = only.split('~');
    expect(d2.length).toBe(1 + 1); // one disclosure + trailing ''
    expect(decodePayload(j2 as string).grant_ref).toBe('g1');
    expect(decodePayload(j2 as string).counter).toBe(3);
    expect(decodeProtectedHeader(j2 as string).typ).toBe('custom+jwt');
    const none = await issue(a, { disclosable: [] });
    const np = decodePayload(none.split('~')[0] as string);
    expect('_sd' in np).toBe(false);
    expect(none.endsWith('~')).toBe(true);
    expect(none.split('~')).toHaveLength(2);
  });
  it('the cnf claim: leaf holder (default), raw key, JWK; errors for anything else', async () => {
    const raw = new Uint8Array(32).fill(5);
    const jwk = ed25519PublicJwk(raw);
    const cnf = async (kb: unknown, a = act()) => decodePayload((await issue(a, { keyBinding: kb })).split('~')[0] as string).cnf;
    expect(await cnf({})).toStrictEqual({ jwk: ed25519PublicJwk(new Uint8Array(32).fill(9)) });
    expect(await cnf({ holderPublicKey: raw })).toStrictEqual({ jwk });
    expect(await cnf({ holderPublicKey: jwk })).toStrictEqual({ jwk });
    expect(await cnf({ holderPublicKey: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } })).toStrictEqual({ jwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } });
    const msg = 'pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key';
    for (const bad of [null, 'k', 5, [], { x: 'a' }, { kty: 5 }]) expect(await rejects(issue(act(), { keyBinding: { holderPublicKey: bad } }))).toBe(msg);
    expect(await rejects(issue(act(), { keyBinding: { holderPublicKey: new Uint8Array(31) } }))).toBe('pca-sdjwt: Ed25519 public key must be 32 bytes');
    expect(await rejects(issue(act({ cap_chain: chainOf('') }), { keyBinding: {} }))).toBe('pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing');
    expect('cnf' in decodePayload((await issue(act())).split('~')[0] as string)).toBe(false);
  });
});

describe('present', () => {
  const dA = disc('sA', 'a', { x: 1, _sd: [] });
  const dX = disc('sX', 'x', 5);
  const dAn = disc('sA2', 'an', { inner: 1, _sd: [dig(dX)] }); // 'an' carries a nested digest
  const dB = disc('sB', 'b', 2);
  const dE = disc('sE', 'elem'); // array-element disclosure
  const dDeep = disc('sD', 'deep', { lvl1: { lvl2: [{ _sd: [dig(dX)] }] } });
  const dTwo = disc('sT', 'two'); // two-part disclosure referenced from _sd (malformed)
  const decoy = sha('decoy');

  it('keeps exactly the selected disclosures and the digests they nest', async () => {
    const { sd } = await mk({ _sd: [dig(dA), dig(dAn), dig(dB), decoy, 5 as never] }, [dA, dAn, dB, dX]);
    const heads = async (sel: string[]) => (await present(sd, sel)).split('~');
    expect((await heads([])).slice(1)).toEqual(['']);
    expect((await heads(['a'])).slice(1)).toEqual([dA, '']);
    expect((await heads(['b'])).slice(1)).toEqual([dB, '']);
    expect((await heads(['b', 'a'])).slice(1)).toEqual([dA, dB, '']); // original order, not selection order
    expect((await heads(['an'])).slice(1)).toEqual([dAn, dX, '']); // nested digest pulled in
    expect((await heads(['x'])).slice(1)).toEqual(['']); // nested claims are not selectable by themselves
    expect((await heads(['zzz'])).slice(1)).toEqual(['']);
    expect((await heads(['_sd'])).slice(1)).toEqual(['']);
    expect((await present(sd, ['a'])).startsWith(`${sd.split('~')[0]}~`)).toBe(true);
  });
  it('digests in clear claims and arrays are followed only when the claim is selected', async () => {
    const { sd } = await mk({ clear: { list: [{ '...': dig(dE) }, { _sd: [dig(dX)] }], _sd: [dig(dDeep)], other: 1 }, other2: [1] }, [dE, dX, dDeep]);
    expect((await present(sd, [])).split('~').slice(1)).toEqual(['']);
    expect((await present(sd, ['other2'])).split('~').slice(1)).toEqual(['']);
    const got = (await present(sd, ['clear'])).split('~').slice(1);
    expect(got).toEqual([dE, dX, dDeep, '']);
    const inner = await present((await mk({ _sd: [dig(dDeep)] }, [dDeep, dX])).sd, ['deep']);
    expect(inner.split('~').slice(1)).toEqual([dDeep, dX, '']);
  });
  it('a two-part disclosure referenced from _sd is never selected by name; a repeated digest is kept once', async () => {
    const { sd } = await mk({ _sd: [dig(dTwo), dig(dB)], c: { '...': dig(dB) }, d: { '...': dig(dB) } }, [dTwo, dB]);
    expect((await present(sd, ['two'])).split('~').slice(1)).toEqual(['']);
    expect((await present(sd, ['b', 'c', 'd'])).split('~').slice(1)).toEqual([dB, '']);
    expect((await present(sd, ['c'])).split('~').slice(1)).toEqual([dB, '']);
  });
  it('non-string array digests and non-string entries are ignored while collecting', async () => {
    const dNest = disc('sN', 'nest', { _sd: [dig(dX), 7, null, { y: 1 }], '...': 9, deeper: { '...': dig(dB) }, arr: [[{ _sd: [dig(dE)] }]] });
    const { sd } = await mk({ _sd: [dig(dNest)] }, [dNest, dX, dB, dE]);
    expect((await present(sd, ['nest'])).split('~').slice(1)).toEqual([dNest, dX, dB, dE, '']);
  });
  it('rejects broken input with specific messages', async () => {
    expect(await rejects(present('', []))).toBe('pca-sdjwt: empty SD-JWT');
    expect(await rejects(present('abc', []))).toBe('pca-sdjwt: malformed SD-JWT (missing ~ separator)');
    expect(await rejects(present('~x~', []))).toBe('pca-sdjwt: empty issuer JWT');
    const { jwt } = await mk({});
    expect(await rejects(present(`${jwt}~~`, []))).toBe('pca-sdjwt: empty disclosure segment');
  });
  it('malformed referenced disclosures are rejected while selecting', async () => {
    const notArr = b64u(JSON.stringify({ a: 1 }));
    const four = disc('s', 'n', 1, 2);
    const noSalt = disc(5, 'n', 1);
    for (const [d, msg] of [
      [notArr, 'pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair'],
      [four, 'pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair'],
      [disc('only'), 'pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair'],
      [noSalt, 'pca-sdjwt: disclosure salt must be a string'],
      [b64u('not json'), 'pca-sdjwt: disclosure is not canonical base64url strict JSON'],
    ] as [string, string][]) {
      const { sd } = await mk({ _sd: [dig(d)] }, [d]);
      expect(await rejects(present(sd, ['n']))).toBe(msg);
    }
  });
  it('key binding: a KB-JWT over the exact presentation head with audience, nonce and iat', async () => {
    const { sd } = await mk({ _sd: [dig(dB)], cnf: { jwk: HOLD.jwk } }, [dB]);
    const out = await present(sd, ['b'], { keyBinding: { holderKey: HOLD.privateKey as never, audience: 'rs', nonce: 'n-1', iat: NOW } });
    const kb = out.slice(out.lastIndexOf('~') + 1);
    const head = out.slice(0, out.lastIndexOf('~') + 1);
    expect(decodeProtectedHeader(kb)).toMatchObject({ alg: 'EdDSA', typ: 'kb+jwt' });
    expect(decodePayload(kb)).toStrictEqual({ iat: NOW, aud: 'rs', sd_hash: sha(head), nonce: 'n-1' });
    const noNonce = await present(sd, ['b'], { keyBinding: { holderKey: HOLD.privateKey as never, audience: 'rs' } });
    const p2 = decodePayload(noNonce.slice(noNonce.lastIndexOf('~') + 1));
    expect('nonce' in p2).toBe(false);
    expect(Math.abs(p2.iat - Date.now() / 1000)).toBeLessThan(10);
    const alg = await present(sd, [], { keyBinding: { holderKey: HOLD.privateKey as never, audience: 'rs', alg: 'EdDSA', iat: 5 } });
    expect(decodePayload(alg.slice(alg.lastIndexOf('~') + 1)).iat).toBe(5);
    expect((await present(sd, ['b'])).endsWith('~')).toBe(true);
  });
});

describe('verifyPcaSdJwt: issuer JWT and disclosure processing', () => {
  const dName = disc('s1', 'name', 'Ada');
  const dX = disc('s2', 'x', 1);
  it('a plain valid SD-JWT: result structure, claims exclude reserved names, disclosed only top-level', async () => {
    const dIss = disc('s3', 'inner', { _sd: [dig(disc('s4', 'iss', 'nested-ok'))] });
    const nested = disc('s4', 'iss', 'nested-ok');
    const { sd } = await mk({ _sd: [dig(dName), dig(dIss)], ver: 'pca/1', keep: 1, nbf: NOW - 1 }, [dName, dIss, nested]);
    const r = await passes(sd);
    expect(r.disclosed).toStrictEqual({ name: 'Ada', inner: { iss: 'nested-ok' } });
    expect(r.claims).toStrictEqual({ ver: 'pca/1', keep: 1, nbf: NOW - 1, name: 'Ada', inner: { iss: 'nested-ok' } });
    expect(r.processed).toMatchObject({ iss: 'https://iss', aud: 'rs', name: 'Ada' });
    expect('_sd' in r.processed).toBe(false);
    expect('_sd_alg' in r.processed).toBe(false);
    expect(Array.isArray(r.payload._sd)).toBe(true);
    expect(r.protectedHeader).toMatchObject({ alg: 'EdDSA', typ: 'pca+sd-jwt' });
    expect(r.keyBinding).toStrictEqual({ presented: false, verified: false });
    expect((await passes((await mk({})).sd)).claims).toStrictEqual({});
  });
  it('structural errors', async () => {
    expect(await fails('')).toBe('pca-sdjwt: empty SD-JWT');
    expect(await fails('abc')).toBe('pca-sdjwt: malformed SD-JWT (missing ~ separator)');
    expect(await fails('~')).toBe('pca-sdjwt: empty issuer JWT');
    expect(await fails(123 as never)).toBe('pca-sdjwt: empty SD-JWT');
    const { jwt } = await mk({});
    expect(await fails(`${jwt}~~`)).toBe('pca-sdjwt: empty disclosure segment');
    expect(await fails(`${jwt}~${dName}~~`)).toBe('pca-sdjwt: empty disclosure segment');
    expect(await fails(`${jwt}~!!`)).toMatch(/./);
  });
  it('signature, audience, algorithm, expiry', async () => {
    const { sd } = await mk({});
    const other = (await joseGen('EdDSA')).publicKey;
    expect(await fails(sd, { issuerKey: other })).toMatch(/signature/i);
    await passes(sd, { expectedAudience: 'rs' });
    expect(await fails(sd, { expectedAudience: 'other' })).toMatch(/aud/i);
    expect(await fails(sd, { algorithms: ['ES256'] })).toMatch(/alg/i);
    await passes(sd, { algorithms: ['EdDSA'] });
    expect(await fails(sd, { now: (NOW + 3600 + 1) * 1000 })).toMatch(/exp/i);
    await passes(sd, { now: (NOW + 3600 - 1) * 1000 });
    // with no `now` option the real clock decides (the fixture expired in 2027)
    const stale = await mk({ iat: 1000, exp: 2000 });
    const r = await verifyPcaSdJwt(stale.sd, { issuerKey: ISS.publicKey } as never);
    expect(r.ok).toBe(false);
    expect(await fails(stale.sd, { now: 2500 * 1000 })).toMatch(/exp/i);
    await passes(stale.sd, { now: 2500 * 1000, clockToleranceSec: 600 });
    expect(await fails(stale.sd, { now: 2500 * 1000, clockToleranceSec: 100 })).toMatch(/exp/i);
  });
  it('_sd_alg', async () => {
    expect(await fails((await mk({ _sd_alg: 'sha-512' })).sd)).toBe('unsupported _sd_alg (require "sha-256")');
    const { sd } = await mk({ _sd_alg: undefined });
    await passes(sd);
  });
  it('disclosure errors', async () => {
    const m = (extra: Record<string, unknown>, discs: string[]) => mk(extra, discs).then((x) => x.sd);
    expect(await fails(await m({ _sd: [dig(dName)] }, [dName, dName]))).toBe('duplicate disclosure');
    expect(await fails(await m({ _sd: [dig(dName)] }, [dName, dX]))).toBe('a presented disclosure does not match any _sd digest (tampered)');
    expect(await fails(await m({ _sd: [dig(dName), dig(dName)] }, [dName]))).toBe('a digest appears more than once in the payload');
    expect(await fails(await m({ _sd: 'x' }, []))).toBe('_sd must be an array of strings');
    expect(await fails(await m({ _sd: [dig(dName), 5] }, [dName]))).toBe('_sd must be an array of strings');
    expect(await fails(await m({ _sd: {} }, []))).toBe('_sd must be an array of strings');
    expect(await fails(await m({ _sd: [dig(disc('s', 'n'))] }, [disc('s', 'n')]))).toBe('an object-property disclosure must be [salt, name, value]');
    expect(await fails(await m({ _sd: [dig(disc('s', 5, 1))] }, [disc('s', 5, 1)]))).toBe('disclosure claim name must be a string');
    for (const n of ['_sd', '...']) expect(await fails(await m({ _sd: [dig(disc('s', n, 1))] }, [disc('s', n, 1)]))).toBe(`disclosure claim name '${n}' is reserved`);
    expect(await fails(await m({ _sd: [dig(disc('s', 'keep', 1))], keep: 2 }, [disc('s', 'keep', 1)]))).toBe("disclosure claim 'keep' collides with an existing claim");
    for (const n of ['iss', 'aud', 'exp', 'nbf', 'cnf', 'status']) {
      expect(await fails(await m({ _sd: [dig(disc('s', n, 1))], ...(n === 'iss' || n === 'aud' || n === 'exp' ? { [n]: undefined } : {}) }, [disc('s', n, 1)]))).toBe(`'${n}' is security-critical and must not be selectively disclosable`);
    }
    // sub / iat / jti-like names are not critical
    const sub = disc('s', 'sub', 'x');
    await passes(await m({ _sd: [dig(sub)] }, [sub]));
    expect((await passes(await m({ _sd: [dig(sub)] }, [sub]))).disclosed).toStrictEqual({ sub: 'x' });
  });
  it('array element disclosures', async () => {
    const e1 = disc('e1', 'one');
    const eBad = disc('e2', 'n', 'v');
    const ok = await passes((await mk({ list: [{ '...': dig(e1) }, 'plain', { '...': sha('decoy') }, { a: 1 }] }, [e1])).sd);
    expect(ok.processed.list).toEqual(['one', 'plain', { a: 1 }]);
    expect(ok.disclosed).toStrictEqual({});
    expect(await fails((await mk({ list: [{ '...': dig(eBad) }] }, [eBad])).sd)).toBe('an array-element disclosure must be [salt, value]');
    expect(await fails((await mk({ list: [{ '...': 5 }] })).sd)).toBe("an array '...' entry must reference a string digest");
    // an object with '...' plus other keys is an ordinary object, not a digest reference
    const mixed = await passes((await mk({ list: [{ '...': 'x', other: 1 }] })).sd);
    expect(mixed.processed.list).toEqual([{ '...': 'x', other: 1 }]);
    // nested disclosure inside an array element value
    const inner = disc('i', 'k', 'v');
    const e3 = disc('e3', { _sd: [dig(inner)] });
    const nested = await passes((await mk({ list: [{ '...': dig(e3) }] }, [e3, inner])).sd);
    expect(nested.processed.list).toEqual([{ k: 'v' }]);
    expect(nested.disclosed).toStrictEqual({});
    // a digest used twice, once in an array and once in _sd
    expect(await fails((await mk({ _sd: [dig(e1)], list: [{ '...': dig(e1) }] }, [e1])).sd)).toBe('a digest appears more than once in the payload');
  });
  it('requiredDisclosures counts only top-level disclosed claims', async () => {
    const { sd } = await mk({ _sd: [dig(dName)], clear: 1 }, [dName]);
    await passes(sd, { requiredDisclosures: ['name'] });
    await passes(sd, { requiredDisclosures: [] });
    expect(await fails(sd, { requiredDisclosures: ['name', 'age'] })).toBe("required disclosure 'age' was not presented");
    expect(await fails(sd, { requiredDisclosures: ['clear'] })).toBe("required disclosure 'clear' was not presented");
    expect(await fails(sd, { requiredDisclosures: ['toString'] })).toBe("required disclosure 'toString' was not presented");
  });
  it('a nested disclosure is not reported as a top-level one', async () => {
    const inner = disc('i', 'deep', 1);
    const outer = disc('o', 'wrap', { _sd: [dig(inner)] });
    const r = await passes((await mk({ _sd: [dig(outer)] }, [outer, inner])).sd, { requiredDisclosures: ['wrap'] });
    expect(Object.keys(r.disclosed)).toEqual(['wrap']);
    expect(await fails((await mk({ _sd: [dig(outer)] }, [outer, inner])).sd, { requiredDisclosures: ['deep'] })).toBe("required disclosure 'deep' was not presented");
  });
});

describe('verifyPcaSdJwt: key binding', () => {
  const dB = disc('sb', 'b', 2);
  const kbSign = async (payload: Record<string, unknown>, header: Record<string, unknown> = {}, key: unknown = HOLD.privateKey) =>
    new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt', ...header } as never).sign(key as never);
  /** SD-JWT with cnf = HOLD and a KB-JWT whose payload can be overridden. */
  async function withKb(kbOver: Record<string, unknown> = {}, o: { cnf?: unknown; header?: Record<string, unknown>; key?: unknown; head?: string } = {}) {
    const { sd } = await mk({ _sd: [dig(dB)], ...(o.cnf === null ? {} : { cnf: o.cnf ?? { jwk: HOLD.jwk } }) }, [dB]);
    const payload = { iat: NOW, aud: 'rs', sd_hash: sha(o.head ?? sd), nonce: 'n1', ...kbOver };
    for (const k of Object.keys(payload)) if ((payload as Record<string, unknown>)[k] === undefined) delete (payload as Record<string, unknown>)[k];
    return sd + (await kbSign(payload, o.header, o.key));
  }
  it('a good key binding verifies and reports aud / nonce', async () => {
    const r = await passes(await withKb(), { expectedAudience: 'rs', expectedNonce: 'n1', requireKeyBinding: true });
    expect(r.keyBinding).toStrictEqual({ presented: true, verified: true, aud: 'rs', nonce: 'n1' });
    const noNonce = await passes(await withKb({ nonce: undefined }));
    expect(noNonce.keyBinding).toStrictEqual({ presented: true, verified: true, aud: 'rs' });
    const arrAud = await passes(await withKb({ aud: ['rs', 'x'] }));
    expect(arrAud.keyBinding).toStrictEqual({ presented: true, verified: true, nonce: 'n1' });
    expect('aud' in arrAud.keyBinding).toBe(false);
    const numNonce = await passes(await withKb({ nonce: 5 }));
    expect('nonce' in numNonce.keyBinding).toBe(false);
  });
  it('presence rules', async () => {
    const { sd } = await mk({ _sd: [dig(dB)], cnf: { jwk: HOLD.jwk } }, [dB]);
    expect(await fails(sd, { requireKeyBinding: true })).toBe('key binding required but no KB-JWT was presented');
    expect(await fails(sd, { keyBindingKey: HOLD.publicKey })).toBe('key binding required but no KB-JWT was presented');
    await passes(sd, { requireKeyBinding: false });
    expect(await fails(await withKb({}, { cnf: null }))).toBe('KB-JWT presented but issuer JWT has no cnf key');
    expect(await fails(await withKb({}, { cnf: {} }))).toBe('KB-JWT presented but issuer JWT has no cnf key');
    expect(await fails(await withKb({}, { cnf: 'x' }))).toBe('KB-JWT presented but issuer JWT has no cnf key');
    expect(await fails(await withKb({}, { cnf: { jwk: 'x' } }))).toBe('KB-JWT presented but issuer JWT has no cnf key');
    expect(await fails(await withKb({}, { cnf: { jwk: { x: 'a' } } }))).toBe('KB-JWT presented but issuer JWT has no cnf key');
  });
  it('keyBindingKey must match the cnf key, whatever its representation', async () => {
    const kb = await withKb();
    const x = HOLD.jwk.x as string;
    await passes(kb, { keyBindingKey: HOLD.publicKey });
    await passes(kb, { keyBindingKey: HOLD.jwk });
    await passes(kb, { keyBindingKey: new Uint8Array(Buffer.from(x, 'base64url')) });
    const other = await joseGen('EdDSA', { extractable: true });
    const msg = 'cnf key does not match the expected keyBindingKey';
    expect(await fails(kb, { keyBindingKey: other.publicKey })).toBe(msg);
    expect(await fails(kb, { keyBindingKey: await exportJWK(other.publicKey) })).toBe(msg);
    expect(await fails(kb, { keyBindingKey: new Uint8Array(32) })).toBe(msg);
    expect(await fails(kb, { keyBindingKey: { kty: 'oct', k: 'AAAA' } })).toBe(msg);
    // a cnf key without x can never match
    expect(await fails(await withKb({}, { cnf: { jwk: { kty: 'OKP', crv: 'Ed25519' } } }), { keyBindingKey: HOLD.jwk })).toMatch(/./);
  });
  it('KB-JWT claims: signature, typ, iat, aud, sd_hash, nonce', async () => {
    const other = await joseGen('EdDSA');
    expect(await fails(await withKb({}, { key: other.privateKey }))).toMatch(/^KB-JWT signature\/claims invalid: /);
    expect(await fails(await withKb({}, { header: { typ: 'JWT' } }))).toBe('KB-JWT typ must be "kb+jwt"');
    expect(await fails(await withKb({ iat: undefined }))).toBe('KB-JWT iat is required');
    expect(await fails(await withKb({ iat: '5' }))).toMatch(/^KB-JWT signature\/claims invalid: |^KB-JWT iat is required/);
    expect(await fails(await withKb({ aud: undefined }))).toBe('KB-JWT aud is required');
    expect(await fails(await withKb({ aud: 5 }))).toMatch(/KB-JWT/);
    expect(await fails(await withKb({ sd_hash: sha('x') }))).toBe('KB-JWT sd_hash does not cover this presentation');
    expect(await fails(await withKb({ sd_hash: undefined }))).toBe('KB-JWT sd_hash does not cover this presentation');
    expect(await fails(await withKb(), { expectedNonce: 'zzz' })).toBe('KB-JWT nonce does not match');
    expect(await fails(await withKb({ nonce: undefined }), { expectedNonce: 'n1' })).toBe('KB-JWT nonce does not match');
    await passes(await withKb({ nonce: undefined }));
  });
  it('the KB-JWT must cover the exact presentation (head including every disclosure)', async () => {
    const { sd } = await mk({ _sd: [dig(dB)], cnf: { jwk: HOLD.jwk } }, [dB]);
    const kb = await kbSign({ iat: NOW, aud: 'rs', sd_hash: sha(sd) });
    await passes(sd + kb);
    expect(await fails(sd.replace(`${dB}~`, '') + kb)).toMatch(/KB-JWT sd_hash|disclosure/);
  });
  it('audience: expectedKbAudience wins over expectedAudience; both are enforced on the KB-JWT', async () => {
    const kb = await withKb({ aud: 'verifier-2' });
    expect(await fails(kb, { expectedAudience: 'rs' })).toMatch(/^KB-JWT signature\/claims invalid: .*aud/i);
    await passes(kb, { expectedAudience: 'rs', expectedKbAudience: 'verifier-2' });
    expect(await fails(kb, { expectedAudience: 'rs', expectedKbAudience: 'verifier-3' })).toMatch(/^KB-JWT signature\/claims invalid/);
    await passes(await withKb({ aud: 'anything' }));
  });
  it('time windows: kbMaxAgeSec and future iat are inclusive at the edge; clock tolerance applies', async () => {
    const at = (iat: number) => withKb({ iat });
    await passes(await at(NOW - 100), { kbMaxAgeSec: 100 });
    expect(await fails(await at(NOW - 101), { kbMaxAgeSec: 100 })).toBe('KB-JWT is older than the accepted window');
    await passes(await at(NOW - 5000)); // no window configured
    await passes(await at(NOW), { kbMaxAgeSec: 0 });
    expect(await fails(await at(NOW + 1), { kbMaxAgeSec: 100 })).toBe('KB-JWT iat is in the future');
    await passes(await at(NOW + 2), { kbMaxAgeSec: 100, clockToleranceSec: 2 });
    expect(await fails(await at(NOW + 3), { kbMaxAgeSec: 100, clockToleranceSec: 2 })).toBe('KB-JWT iat is in the future');
    // without a window a future iat is not checked here
    await passes(await at(NOW + 5000), { clockToleranceSec: 10000 });
    // with no explicit `now` the real clock is used for the window
    const nowSec = Math.floor(Date.now() / 1000);
    const live = (iat: number, o: Record<string, unknown> = {}) => verifyPcaSdJwt(iat === 0 ? '' : '', { issuerKey: ISS.publicKey, ...o } as never);
    void live;
    const kbReal = async (age: number) => verifyPcaSdJwt(await at(nowSec - age), { issuerKey: ISS.publicKey, kbMaxAgeSec: 60 } as never);
    expect((await kbReal(10)).ok).toBe(true);
    expect((await kbReal(1000)).ok).toBe(false);
  });
});

describe('remaining boundaries', () => {
  it('the clear discriminator `ver` stays in the clear even when listed as disclosable', async () => {
    const sd = await issue(act(), { disclosable: ['ver', 'action'] });
    const [jwt, ...d] = sd.split('~');
    expect(decodePayload(jwt as string).ver).toBe('pca/1');
    const names = d.filter(Boolean).map((x) => (JSON.parse(Buffer.from(x, 'base64url').toString()) as string[])[1]);
    expect(names).toEqual(['action']);
  });
  const dB = disc('sb', 'b', 2);
  const dIss = disc('si', 'iss', 'inner-iss');
  it('only "..." references (with string digests) are followed in clear claims', async () => {
    const { sd } = await mk({ _sd: [dig(dB)], keepme: { note: dig(dB), other: [dig(dB)] } }, [dB]);
    expect((await present(sd, ['keepme'])).split('~').slice(1)).toEqual(['']);
  });
  it('unknown digests nested in a selected value are ignored', async () => {
    const dNest = disc('sn', 'nest', { _sd: [sha('nothing')], '...': sha('also nothing'), arr: [{ '...': sha('x') }] });
    const { sd } = await mk({ _sd: [dig(dNest)], clear: { _sd: [sha('zz')], deep: [{ '...': sha('qq') }] } }, [dNest]);
    expect((await present(sd, ['nest', 'clear'])).split('~').slice(1)).toEqual([dNest, '']);
  });
  it('security-critical names are only protected at the top level', async () => {
    const r1 = await passes((await mk({ wrap: { _sd: [dig(dIss)] } }, [dIss])).sd);
    expect(r1.processed.wrap).toEqual({ iss: 'inner-iss' });
    expect(r1.disclosed).toStrictEqual({});
    const r2 = await passes((await mk({ list: [{ _sd: [dig(dIss)] }] }, [dIss])).sd);
    expect(r2.processed.list).toEqual([{ iss: 'inner-iss' }]);
    const r3 = await passes((await mk({ a: { b: { _sd: [dig(dIss)] } } }, [dIss])).sd);
    expect(r3.processed.a).toEqual({ b: { iss: 'inner-iss' } });
  });
  it('clock options reach the KB-JWT verification as well', async () => {
    const kbAt = async (kbExtra: Record<string, unknown>) => {
      const { sd } = await mk({ cnf: { jwk: HOLD.jwk } });
      return sd + (await new SignJWT({ iat: NOW, aud: 'rs', sd_hash: sha(sd), ...kbExtra }).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' }).sign(HOLD.privateKey));
    };
    const kb = await kbAt({ exp: NOW + 10 });
    await passes(kb, { now: (NOW + 5) * 1000 });
    expect(await fails(kb, { now: (NOW + 500) * 1000 })).toMatch(/^KB-JWT signature\/claims invalid: .*exp/i);
    // tolerance applies to both JWTs: issuer exp is NOW+3600, KB exp is NOW+10
    await passes(kb, { now: (NOW + 15) * 1000, clockToleranceSec: 10 });
    expect(await fails(kb, { now: (NOW + 15) * 1000, clockToleranceSec: 1 })).toMatch(/^KB-JWT signature\/claims invalid/);
    expect(await fails(kb, { now: (NOW + 15) * 1000 })).toMatch(/^KB-JWT signature\/claims invalid/);
    const nbf = await kbAt({ nbf: NOW + 100 });
    expect(await fails(nbf, { now: NOW * 1000 })).toMatch(/^KB-JWT signature\/claims invalid/);
    await passes(nbf, { now: NOW * 1000, clockToleranceSec: 200 });
  });
  it('a KB-JWT is not rejected for a future iat when no age window is configured', async () => {
    const { sd } = await mk({ cnf: { jwk: HOLD.jwk } });
    const kb = await new SignJWT({ iat: NOW + 5000, aud: 'rs', sd_hash: sha(sd) }).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' }).sign(HOLD.privateKey);
    await passes(sd + kb);
    expect(await fails(sd + kb, { kbMaxAgeSec: 100 })).toBe('KB-JWT iat is in the future');
  });
  it('a missing x on both sides can never satisfy keyBindingKey', async () => {
    const { sd } = await mk({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519' } } });
    const kb = await new SignJWT({ iat: NOW, aud: 'rs', sd_hash: sha(sd) }).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' }).sign(HOLD.privateKey);
    expect(await fails(sd + kb, { keyBindingKey: { kty: 'oct', k: 'AAAA' } })).toBe('cnf key does not match the expected keyBindingKey');
    expect(await fails(sd + kb, { keyBindingKey: new Uint8Array(32) })).toBe('cnf key does not match the expected keyBindingKey');
  });
  it('kbAlgorithms selects the algorithm the cnf key is imported for', async () => {
    const ec = await joseGen('ES256', { extractable: true });
    const ecJwk = await exportJWK(ec.publicKey);
    const { sd } = await mk({ cnf: { jwk: ecJwk } });
    const kb = await new SignJWT({ iat: NOW, aud: 'rs', sd_hash: sha(sd) }).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(ec.privateKey);
    const r = await passes(sd + kb, { kbAlgorithms: ['ES256'] });
    expect(r.keyBinding.verified).toBe(true);
    expect(await fails(sd + kb)).toMatch(/./); // default EdDSA rejects an ES256 holder
    const p = await present(sd, [], { keyBinding: { holderKey: ec.privateKey as never, audience: 'rs', alg: 'ES256', iat: NOW } });
    await passes(p, { kbAlgorithms: ['ES256'] });
  });
});

describe('KB-JWT expiry uses the real clock when no `now` is given', () => {
  it('an expired KB-JWT is refused', async () => {
    const { sd } = await mk({ cnf: { jwk: HOLD.jwk } });
    const kb = await new SignJWT({ iat: 1000, exp: 2000, aud: 'rs', sd_hash: sha(sd) }).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' }).sign(HOLD.privateKey);
    const r = await verifyPcaSdJwt(sd + kb, { issuerKey: ISS.publicKey } as never);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/^KB-JWT signature\/claims invalid: .*exp/i);
  });
});
