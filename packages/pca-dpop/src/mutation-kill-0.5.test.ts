/** Kills for the in-memory replay store, the conformance runner, the nonce issuer and the hostile-header checks. */
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DPOP_CLOCK_SKEW_SEC,
  DpopVerificationError,
  createDpopNonceIssuer,
  createInMemoryDpopReplayStore,
  dpopAlgMatchesJwk,
  runDpopReplayStoreConformance,
  verifyDpopProof,
  type DpopReplayStore,
} from './index';

const URL1 = 'https://api.example/v1/x';
const NOW = 1_800_000_000;
const SECRET = new Uint8Array(32).fill(9);

describe('dpopAlgMatchesJwk requires the right key type, not only the curve', () => {
  it('a matching curve under the wrong kty is refused for every curve-bound alg', () => {
    expect(dpopAlgMatchesJwk('EdDSA', { kty: 'EC', crv: 'Ed25519' })).toBe(false);
    expect(dpopAlgMatchesJwk('EdDSA', { kty: 'EC', crv: 'Ed448' })).toBe(false);
    expect(dpopAlgMatchesJwk('ES256', { kty: 'OKP', crv: 'P-256' })).toBe(false);
    expect(dpopAlgMatchesJwk('ES384', { kty: 'OKP', crv: 'P-384' })).toBe(false);
    expect(dpopAlgMatchesJwk('ES512', { kty: 'OKP', crv: 'P-521' })).toBe(false);
    expect(dpopAlgMatchesJwk('ES256', { kty: 'EC', crv: 'P-256' })).toBe(true);
    expect(dpopAlgMatchesJwk('ES384', { kty: 'EC', crv: 'P-384' })).toBe(true);
    expect(dpopAlgMatchesJwk('ES512', { kty: 'EC', crv: 'P-521' })).toBe(true);
    expect(dpopAlgMatchesJwk('EdDSA', { kty: 'OKP', crv: 'Ed25519' })).toBe(true);
  });
});

describe('runDpopReplayStoreConformance reports the exact failed checks', () => {
  it('a store that always admits fails the replay checks', async () => {
    const always: DpopReplayStore = { addIfAbsent: () => true };
    expect(await runDpopReplayStoreConformance(() => always)).toEqual([
      'second sight of the same key returns false',
      'still seen one second before expiry',
      '16 concurrent adds of one key: exactly one wins (got 16)',
    ]);
  });
  it('a store that never admits fails the admission checks', async () => {
    const never: DpopReplayStore = { addIfAbsent: () => false };
    expect(await runDpopReplayStoreConformance(() => never)).toEqual([
      'first sight of a key returns true',
      'a different key is independent',
      'an expired entry may be added again (nowSec >= expiresAtSec)',
      '16 concurrent adds of one key: exactly one wins (got 0)',
    ]);
  });
  it('a conformant store passes, including one that refuses empty keys', async () => {
    expect(await runDpopReplayStoreConformance(() => createInMemoryDpopReplayStore())).toEqual([]);
    const strict = (): DpopReplayStore => {
      const inner = createInMemoryDpopReplayStore();
      return {
        addIfAbsent(key, exp, now) {
          if (key === '') throw new Error('empty key');
          return inner.addIfAbsent(key, exp, now);
        },
      };
    };
    expect(await runDpopReplayStoreConformance(strict)).toEqual([]);
  });
});

describe('createInMemoryDpopReplayStore capacity', () => {
  it('refuses a new key when full of live entries, reclaims expired ones, and lets a held key be re-added', async () => {
    const s = createInMemoryDpopReplayStore({ maxEntries: 2 });
    expect(await s.addIfAbsent('a', 200, 100)).toBe(true);
    expect(await s.addIfAbsent('b', 300, 100)).toBe(true);
    expect(() => s.addIfAbsent('c', 400, 100)).toThrow('replay store is full');
    expect(await s.addIfAbsent('a', 200, 100)).toBe(false);
    expect(await s.addIfAbsent('c', 400, 250)).toBe(true); // a expired: reclaimed
    expect(await s.addIfAbsent('b', 500, 300)).toBe(true); // b expired exactly now: may be added again
    expect(() => s.addIfAbsent('d', 600, 301)).toThrow('replay store is full');
  });
});

describe('createDpopNonceIssuer', () => {
  it('rejects a missing options object and bad config with the misconfigured code', () => {
    const code = (f: () => unknown) => {
      try {
        f();
      } catch (e) {
        return e instanceof DpopVerificationError ? e.code : `other:${String(e)}`;
      }
      return 'none';
    };
    expect(code(() => createDpopNonceIssuer(undefined as never))).toBe('misconfigured');
    expect(code(() => createDpopNonceIssuer({ secret: new Uint8Array(31) }))).toBe('misconfigured');
    expect(code(() => createDpopNonceIssuer({ secret: SECRET, ttlSec: 0 }))).toBe('misconfigured');
  });
  it('mints timestamp || HMAC-SHA256(secret, "dpop-nonce\\0" || timestamp)[0..16]', () => {
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(NOW));
    const mac = createHmac('sha256', SECRET).update('dpop-nonce\0').update(ts).digest().subarray(0, 16);
    expect(createDpopNonceIssuer({ secret: SECRET }).issue(NOW)).toBe(Buffer.concat([ts, mac]).toString('base64url'));
  });
  it('uses the real clock by default for both issue and check', () => {
    const i = createDpopNonceIssuer({ secret: SECRET });
    expect(i.check(i.issue())).toBe(true);
    const now = Math.floor(Date.now() / 1000);
    expect(i.check(i.issue(now + 10_000))).toBe(false);
  });
  it('accepts a nonce issued exactly the clock skew in the future, not one second more', () => {
    const i = createDpopNonceIssuer({ secret: SECRET, ttlSec: 300 });
    expect(i.check(i.issue(NOW + DPOP_CLOCK_SKEW_SEC), NOW)).toBe(true);
    expect(i.check(i.issue(NOW + DPOP_CLOCK_SKEW_SEC + 1), NOW)).toBe(false);
  });
});

describe('hostile proof headers', () => {
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = (alg: string, jwk: unknown): string =>
    `${b64({ typ: 'dpop+jwt', alg, jwk })}.${b64({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })}.${Buffer.alloc(64).toString('base64url')}`;
  const opts = { method: 'POST', url: URL1, maxAgeSec: 60, nowSec: NOW, requireReplayStore: false };
  const codeOf = async (proof: string): Promise<string> => {
    try {
      await verifyDpopProof(proof, opts);
    } catch (e) {
      if (e instanceof DpopVerificationError) return e.code;
      throw e;
    }
    return 'accepted';
  };
  const ec = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' };

  it.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'])('a header jwk carrying private member %s is refused', async (m) => {
    expect(await codeOf(unsigned('ES256', { ...ec, [m]: 'AAAA' }))).toBe('private_jwk');
  });
  it.each([['a string', 'abc'], ['null', null], ['a number', 7]])('a non-object header jwk (%s) is refused by the signature step, never by a TypeError', async (_n, jwk) => {
    expect(await codeOf(unsigned('ES999', jwk))).toBe('signature');
  });
  it('a proof of exactly the size limit is parsed (not oversize); one more byte is oversize', async () => {
    expect(await codeOf('a'.repeat(8192))).toBe('malformed');
    expect(await codeOf('a'.repeat(8193))).toBe('oversize');
  });
  it('a header without alg skips the alg/jwk match and is judged by the signature', async () => {
    const h = b64({ typ: 'dpop+jwt', jwk: ec });
    const p = `${h}.${b64({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })}.${Buffer.alloc(64).toString('base64url')}`;
    expect(await codeOf(p)).toBe('signature');
  });
});
