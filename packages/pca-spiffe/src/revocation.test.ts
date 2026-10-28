/**
 * Revocation (C-115): a revoked SVID is refused, and a revocation source that is missing, stale, failing or
 * malformed refuses instead of admitting. Every outcome is asserted whole (code and message).
 */
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SignJWT, generateKeyPair, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  SpiffeError,
  createRevocationSource,
  svidToHolder,
  verifyJwtSvid,
  verifyX509Svid,
  type JwtRevocationSubject,
  type RevocationList,
  type X509RevocationSubject,
} from './index';

const pki = (name: string): string => readFileSync(resolve(__dirname, '..', 'fixtures', 'generated', `${name}.pem`), 'utf8');
const NOW = new Date('2027-06-01T00:00:00Z');
const ID = 'spiffe://example.org/workload/db';
const LEAF = pki('leaf');
const INTER = pki('inter0');
const base = { trustDomain: 'example.org', roots: [pki('root')], now: NOW };
const leafCert = new X509Certificate(LEAF);
const interCert = new X509Certificate(INTER);

interface Outcome {
  code: string;
  message: string;
}
function sErr(fn: () => unknown): Outcome {
  try {
    fn();
  } catch (e) {
    if (e instanceof SpiffeError) return { code: e.code, message: e.message };
    throw e;
  }
  throw new Error('expected a SpiffeError, but nothing was thrown');
}
async function sErrAsync(fn: () => Promise<unknown>): Promise<Outcome> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof SpiffeError) return { code: e.code, message: e.message };
    throw e;
  }
  throw new Error('expected a SpiffeError, but nothing was thrown');
}
function clock(start = 1_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => void (t += ms) };
}
interface Minted {
  token: string;
  key: KeyLike;
  exp: number;
}
async function mint(claims: Record<string, unknown> = {}, sub = ID): Promise<Minted> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const token = await new SignJWT({ sub, ...claims })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .setAudience('rs')
    .setExpirationTime('1h')
    .sign(privateKey);
  const payload: unknown = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'));
  const exp = (payload as { exp: number }).exp;
  return { token, key: publicKey as KeyLike, exp };
}
const jwtOpts = (m: Minted) => ({ audience: 'rs', trustDomain: 'example.org', key: m.key });

describe('X.509-SVID revocation hook', () => {
  it('asks about every certificate of the chain, leaf first, and admits when all answer false', () => {
    const seen: X509RevocationSubject[] = [];
    const svid = verifyX509Svid([LEAF, INTER], {
      ...base,
      revocation: (s) => {
        seen.push(s);
        return false;
      },
    });
    expect(svid.spiffeId.id).toBe(ID);
    expect(seen).toEqual([
      { spiffeId: ID, serialNumber: leafCert.serialNumber, fingerprint256: leafCert.fingerprint256, position: 0, isLeaf: true },
      { spiffeId: ID, serialNumber: interCert.serialNumber, fingerprint256: interCert.fingerprint256, position: 1, isLeaf: false },
    ]);
  });

  it('refuses a revoked leaf with svid_revoked', () => {
    expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, revocation: (s) => s.isLeaf }))).toEqual({
      code: 'svid_revoked',
      message: `X.509-SVID for ${ID} is revoked`,
    });
  });

  it('refuses a revoked signing certificate with chain_revoked', () => {
    expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, revocation: (s) => s.position === 1 }))).toEqual({
      code: 'chain_revoked',
      message: 'signing certificate #1 of the chain is revoked',
    });
  });

  it('refuses when the check throws', () => {
    expect(
      sErr(() =>
        verifyX509Svid([LEAF, INTER], {
          ...base,
          revocation: () => {
            throw new Error('crl endpoint down');
          },
        }),
      ),
    ).toEqual({ code: 'revocation_unavailable', message: 'revocation check failed: crl endpoint down' });
    expect(
      sErr(() =>
        verifyX509Svid([LEAF, INTER], {
          ...base,
          revocation: () => {
            throw 'plain string'; // eslint-disable-line @typescript-eslint/only-throw-error
          },
        }),
      ),
    ).toEqual({ code: 'revocation_unavailable', message: 'revocation check failed: plain string' });
  });

  it('refuses any answer that is not exactly a boolean (undefined, "false", 0, null, a Promise)', () => {
    for (const bad of [undefined, 'false', 0, null, Promise.resolve(false)]) {
      expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, revocation: (() => bad) as never }))).toEqual({
        code: 'revocation_unavailable',
        message: 'revocation check did not return a boolean',
      });
    }
  });

  it('refuses a revocation option that is not a function, before looking at the chain', () => {
    for (const bad of [null, 'yes', 1, {}]) {
      expect(sErr(() => verifyX509Svid([], { ...base, revocation: bad as never }))).toEqual({
        code: 'revocation_unavailable',
        message: 'revocation must be a function',
      });
    }
  });

  it('is not consulted for a chain that failed another check', () => {
    let calls = 0;
    const revocation = (): boolean => {
      calls++;
      return false;
    };
    expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, now: new Date('2040-01-01T00:00:00Z'), revocation })).code).toBe('chain_expired');
    expect(sErr(() => verifyX509Svid([LEAF], { ...base, revocation })).code).toBe('chain_untrusted_root');
    expect(calls).toBe(0);
  });

  it('without a revocation option nothing is checked (expiry is the only bound)', () => {
    expect(verifyX509Svid([LEAF, INTER], base).spiffeId.id).toBe(ID);
  });

  it('a revoked SVID never yields a holder: the verifier throws, so svidToHolder has nothing to bind', () => {
    const revoked = (): unknown => verifyX509Svid([LEAF, INTER], { ...base, revocation: () => true });
    expect(sErr(revoked).code).toBe('svid_revoked');
    expect(sErr(() => svidToHolder({} as never)).code).toBe('unverified_svid');
  });
});

describe('JWT-SVID revocation hook', () => {
  it('passes the subject (spiffeId, expiresAt, tokenHash, jti when present) and admits on false', async () => {
    const plain = await mint();
    const seen: JwtRevocationSubject[] = [];
    const svid = await verifyJwtSvid(plain.token, {
      ...jwtOpts(plain),
      revocation: (s) => {
        seen.push(s);
        return false;
      },
    });
    expect(svid.spiffeId.id).toBe(ID);
    expect(seen).toEqual([{ spiffeId: ID, expiresAt: plain.exp, tokenHash: createHash('sha256').update(plain.token).digest('base64url') }]);

    const withJti = await mint({ jti: 'tok-1' });
    const seen2: JwtRevocationSubject[] = [];
    await verifyJwtSvid(withJti.token, {
      ...jwtOpts(withJti),
      revocation: async (s) => {
        seen2.push(s);
        return false;
      },
    });
    expect(seen2).toEqual([
      { spiffeId: ID, jti: 'tok-1', expiresAt: withJti.exp, tokenHash: createHash('sha256').update(withJti.token).digest('base64url') },
    ]);
  });

  it('a non-string jti is not passed on', async () => {
    const m = await mint({ jti: 7 });
    const seen: JwtRevocationSubject[] = [];
    await verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: (s) => (seen.push(s), false) });
    expect('jti' in (seen[0] ?? {})).toBe(false);
  });

  it('refuses a revoked token with svid_revoked', async () => {
    const m = await mint();
    expect(await sErrAsync(() => verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: () => true }))).toEqual({
      code: 'svid_revoked',
      message: `JWT-SVID for ${ID} is revoked`,
    });
  });

  it('refuses when the check throws or rejects', async () => {
    const m = await mint();
    expect(
      await sErrAsync(() =>
        verifyJwtSvid(m.token, {
          ...jwtOpts(m),
          revocation: () => {
            throw new Error('db down');
          },
        }),
      ),
    ).toEqual({ code: 'revocation_unavailable', message: 'revocation check failed: db down' });
    expect(await sErrAsync(() => verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: () => Promise.reject(new Error('timeout')) }))).toEqual({
      code: 'revocation_unavailable',
      message: 'revocation check failed: timeout',
    });
  });

  it('refuses any answer that is not exactly a boolean', async () => {
    const m = await mint();
    for (const bad of [undefined, 'false', 0, null]) {
      expect(await sErrAsync(() => verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: (() => bad) as never }))).toEqual({
        code: 'revocation_unavailable',
        message: 'revocation check did not return a boolean',
      });
    }
  });

  it('refuses a revocation option that is not a function, before verifying the token', async () => {
    for (const bad of [null, 'yes', 1]) {
      expect(await sErrAsync(() => verifyJwtSvid('not-a-token', { audience: 'rs', trustDomain: 'example.org', key: new Uint8Array(1), revocation: bad as never }))).toEqual({
        code: 'revocation_unavailable',
        message: 'revocation must be a function',
      });
    }
  });

  it('is not consulted for a token that failed another check', async () => {
    const m = await mint();
    let calls = 0;
    const revocation = (): boolean => {
      calls++;
      return false;
    };
    await expect(verifyJwtSvid(m.token, { ...jwtOpts(m), audience: 'other', revocation })).rejects.toThrow();
    expect((await sErrAsync(() => verifyJwtSvid(m.token, { ...jwtOpts(m), trustDomain: 'other.org', revocation }))).code).toBe('trust_domain_mismatch');
    expect(calls).toBe(0);
  });
});

describe('createRevocationSource', () => {
  const list = (l: RevocationList) => async (): Promise<RevocationList> => l;
  const fp = leafCert.fingerprint256;

  it('refuses a missing fetch and bad timings at construction', () => {
    const e = (o: unknown): Outcome => sErr(() => createRevocationSource(o as never));
    expect(e({ refreshMs: 1, maxStaleMs: 1 })).toEqual({ code: 'revocation_unavailable', message: 'createRevocationSource requires `fetch`' });
    expect(e(undefined)).toEqual({ code: 'revocation_unavailable', message: 'createRevocationSource requires `fetch`' });
    const timing = { code: 'revocation_unavailable', message: 'refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)' };
    expect(e({ fetch: list({}), refreshMs: 0, maxStaleMs: 10 })).toEqual(timing);
    expect(e({ fetch: list({}), refreshMs: -1, maxStaleMs: 10 })).toEqual(timing);
    expect(e({ fetch: list({}), refreshMs: 10, maxStaleMs: 9 })).toEqual(timing);
    expect(e({ fetch: list({}), refreshMs: Number.NaN, maxStaleMs: 10 })).toEqual(timing);
    expect(e({ fetch: list({}), refreshMs: 1, maxStaleMs: Number.POSITIVE_INFINITY })).toEqual(timing);
    expect(e({ fetch: list({}), refreshMs: Number.POSITIVE_INFINITY, maxStaleMs: Number.POSITIVE_INFINITY })).toEqual(timing);
    expect(() => createRevocationSource({ fetch: list({}), refreshMs: 10, maxStaleMs: 10 })).not.toThrow();
  });

  it('refuses every check before the first successful fetch', async () => {
    const src = createRevocationSource({ fetch: list({}), refreshMs: 10, maxStaleMs: 100 });
    expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, revocation: src.x509 }))).toEqual({
      code: 'revocation_unavailable',
      message: 'revocation check failed: no revocation snapshot available',
    });
  });

  it('matches by fingerprint (colons and case ignored), serial (leading zeros ignored), SPIFFE ID, jti and token hash', async () => {
    const c = clock();
    const m = await mint({ jti: 'j-9' });
    const hash = createHash('sha256').update(m.token).digest('base64url');
    const subjectOf = (over: Partial<X509RevocationSubject>): X509RevocationSubject => ({
      spiffeId: ID,
      serialNumber: leafCert.serialNumber,
      fingerprint256: fp,
      position: 0,
      isLeaf: true,
      ...over,
    });
    const check = async (l: RevocationList, x?: Partial<X509RevocationSubject>) => {
      const src = createRevocationSource({ fetch: list(l), refreshMs: 10, maxStaleMs: 100, now: c.now });
      await src.refresh();
      return src.x509(subjectOf(x ?? {}));
    };
    expect(await check({})).toBe(false);
    expect(await check({ fingerprints: [fp] })).toBe(true);
    expect(await check({ fingerprints: [fp.replace(/:/g, '').toLowerCase()] })).toBe(true);
    expect(await check({ fingerprints: ['AA:BB'] })).toBe(false);
    expect(await check({ serials: [leafCert.serialNumber] })).toBe(true);
    expect(await check({ serials: ['000' + leafCert.serialNumber.toLowerCase()] })).toBe(true);
    expect(await check({ serials: ['0'] })).toBe(false);
    expect(await check({ spiffeIds: [ID] })).toBe(true);
    expect(await check({ spiffeIds: ['spiffe://example.org/other'] })).toBe(false);
    expect(await check({ jtis: ['j-9'], tokenHashes: [hash] })).toBe(false); // JWT-only fields do not revoke certificates

    const jwtCheck = async (l: RevocationList) => {
      const src = createRevocationSource({ fetch: list(l), refreshMs: 10, maxStaleMs: 100, now: c.now });
      return src.jwt({ spiffeId: ID, jti: 'j-9', expiresAt: m.exp, tokenHash: hash });
    };
    expect(await jwtCheck({})).toBe(false);
    expect(await jwtCheck({ jtis: ['j-9'] })).toBe(true);
    expect(await jwtCheck({ jtis: ['j-8'] })).toBe(false);
    expect(await jwtCheck({ tokenHashes: [hash] })).toBe(true);
    expect(await jwtCheck({ spiffeIds: [ID] })).toBe(true);
    expect(await jwtCheck({ fingerprints: [fp], serials: [leafCert.serialNumber] })).toBe(false); // certificate-only fields do not revoke tokens
  });

  it('works end to end with both verifiers', async () => {
    const c = clock();
    const m = await mint();
    const src = createRevocationSource({ fetch: list({ fingerprints: [fp] }), refreshMs: 10, maxStaleMs: 100, now: c.now });
    await src.ensureFresh();
    expect(sErr(() => verifyX509Svid([LEAF, INTER], { ...base, revocation: src.x509 })).code).toBe('svid_revoked');
    const clean = createRevocationSource({ fetch: list({}), refreshMs: 10, maxStaleMs: 100, now: c.now });
    await clean.ensureFresh();
    expect(verifyX509Svid([LEAF, INTER], { ...base, revocation: clean.x509 }).spiffeId.id).toBe(ID);
    expect((await verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: clean.jwt })).spiffeId.id).toBe(ID);
    const revoked = createRevocationSource({ fetch: list({ spiffeIds: [ID] }), refreshMs: 10, maxStaleMs: 100, now: c.now });
    expect((await sErrAsync(() => verifyJwtSvid(m.token, { ...jwtOpts(m), revocation: revoked.jwt }))).code).toBe('svid_revoked');
  });

  it('refreshes at refreshMs (not before) and replaces the snapshot instead of merging', async () => {
    const c = clock();
    let n = 0;
    const lists: RevocationList[] = [{ spiffeIds: [ID] }, {}];
    const src = createRevocationSource({
      fetch: async () => {
        n++;
        return lists[Math.min(n - 1, 1)]!;
      },
      refreshMs: 10,
      maxStaleMs: 100,
      now: c.now,
    });
    const subject = { spiffeId: ID, expiresAt: 1, tokenHash: 'h' };
    expect(await src.jwt(subject)).toBe(true);
    c.advance(9);
    expect(await src.jwt(subject)).toBe(true);
    expect(n).toBe(1);
    c.advance(1);
    expect(await src.jwt(subject)).toBe(false); // fetched again at exactly refreshMs, and the old entry is gone
    expect(n).toBe(2);
  });

  it('shares one fetch between concurrent callers', async () => {
    let n = 0;
    const src = createRevocationSource({
      fetch: async () => {
        n++;
        await Promise.resolve();
        return {};
      },
      refreshMs: 10,
      maxStaleMs: 100,
    });
    const subject = { spiffeId: ID, expiresAt: 1, tokenHash: 'h' };
    await Promise.all([src.jwt(subject), src.jwt(subject), src.ensureFresh(), src.refresh()]);
    expect(n).toBe(1);
  });

  it('keeps the last good snapshot through a failed refresh until maxStaleMs, then refuses with the failure', async () => {
    const c = clock();
    let fail = false;
    const src = createRevocationSource({
      fetch: async () => {
        if (fail) throw new Error('source down');
        return { spiffeIds: [ID] };
      },
      refreshMs: 10,
      maxStaleMs: 100,
      now: c.now,
    });
    const subject = { spiffeId: ID, expiresAt: 1, tokenHash: 'h' };
    expect(await src.jwt(subject)).toBe(true);
    fail = true;
    c.advance(50);
    expect(await src.jwt(subject)).toBe(true); // stale but inside maxStaleMs: last good snapshot still answers
    c.advance(50);
    expect(await src.jwt(subject)).toBe(true); // exactly maxStaleMs old is still usable
    c.advance(1);
    expect(await sErrAsync(() => src.jwt(subject))).toEqual({ code: 'revocation_unavailable', message: 'revocation fetch failed: source down' });
    expect(sErr(() => src.x509({ spiffeId: ID, serialNumber: '1', fingerprint256: 'AA', position: 0, isLeaf: true })).code).toBe('revocation_unavailable');
    expect(await sErrAsync(() => src.refresh())).toEqual({ code: 'revocation_unavailable', message: 'revocation fetch failed: source down' });
    expect(await sErrAsync(() => src.ensureFresh())).toEqual({ code: 'revocation_unavailable', message: 'revocation fetch failed: source down' });
  });

  it('a snapshot older than maxStaleMs with a working source is replaced, not refused', async () => {
    const c = clock();
    const src = createRevocationSource({ fetch: list({}), refreshMs: 10, maxStaleMs: 100, now: c.now });
    const subject = { spiffeId: ID, expiresAt: 1, tokenHash: 'h' };
    expect(await src.jwt(subject)).toBe(false);
    c.advance(10_000);
    expect(await src.jwt(subject)).toBe(false);
  });

  it('rejects a malformed snapshot and keeps refusing until a good one arrives', async () => {
    const bad: unknown[] = [null, 'x', 7, [], { fingerprints: 'AA' }, { serials: [1] }, { spiffeIds: {} }, { jtis: [null] }, { tokenHashes: 5 }];
    for (const b of bad) {
      const src = createRevocationSource({ fetch: (async () => b) as never, refreshMs: 10, maxStaleMs: 100 });
      const out = await sErrAsync(() => src.refresh());
      expect(out.code).toBe('revocation_unavailable');
      expect(await sErrAsync(() => src.jwt({ spiffeId: ID, expiresAt: 1, tokenHash: 'h' }))).toEqual(out);
    }
    expect(await sErrAsync(() => createRevocationSource({ fetch: (async () => null) as never, refreshMs: 10, maxStaleMs: 100 }).refresh())).toEqual({
      code: 'revocation_unavailable',
      message: 'revocation list must be an object',
    });
    expect(await sErrAsync(() => createRevocationSource({ fetch: (async () => ({ jtis: 'x' })) as never, refreshMs: 10, maxStaleMs: 100 }).refresh())).toEqual({
      code: 'revocation_unavailable',
      message: 'revocation list field "jtis" must be an array of strings',
    });
  });

  it('an empty snapshot is valid and revokes nothing', async () => {
    const src = createRevocationSource({ fetch: list({}), refreshMs: 10, maxStaleMs: 100 });
    await expect(src.refresh()).resolves.toBeUndefined();
    expect(src.x509({ spiffeId: ID, serialNumber: leafCert.serialNumber, fingerprint256: fp, position: 0, isLeaf: true })).toBe(false);
  });
});
