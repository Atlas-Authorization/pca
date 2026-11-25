/** Replay store, nonce issuer, private-jwk, oversize and the requireReplayStore fail-closed switch. */
import { SignJWT, exportJWK, generateKeyPair as joseGen } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DpopVerificationError,
  createDpopNonceIssuer,
  createDpopProof,
  createInMemoryDpopReplayStore,
  jwkThumbprint,
  runDpopReplayStoreConformance,
  verifyDpopProof as verifyDpopProofRaw,
  type DpopReplayStore,
} from './index';

// 0.5: a replay store is required by default; these suites mostly exercise other checks, so they opt out explicitly.
const verifyDpopProof: typeof verifyDpopProofRaw = (p, o) => verifyDpopProofRaw(p, { requireReplayStore: false, ...o });

const URL1 = 'https://api.example/v1/x';
const NOW = 1_800_000_000;
const SECRET = new Uint8Array(32).fill(7);

async function key() {
  const { privateKey, publicKey } = await joseGen('ES256', { extractable: true });
  return { privateKey, privateJwk: await exportJWK(privateKey), publicJwk: await exportJWK(publicKey) };
}
const base = (o: Record<string, unknown> = {}) => ({ method: 'POST', url: URL1, maxAgeSec: 60, nowSec: NOW, ...o });

/** Verify and return {code,message} of the refusal, or {ok:true}. */
async function settle(proof: string, o: Record<string, unknown>) {
  try {
    await verifyDpopProof(proof, base(o) as Parameters<typeof verifyDpopProof>[1]);
    return { ok: true as const };
  } catch (e) {
    if (!(e instanceof DpopVerificationError)) throw e;
    return { ok: false as const, code: e.code, message: e.message };
  }
}
async function proofFor(k: Awaited<ReturnType<typeof key>>, over: Record<string, unknown> = {}) {
  return createDpopProof({ method: 'POST', url: URL1, privateKey: k.privateJwk, publicJwk: k.publicJwk, iat: NOW, jti: 'j1', ...over });
}

describe('replayStore', () => {
  it('first use passes, the same proof again is a replay', async () => {
    const k = await key();
    const store = createInMemoryDpopReplayStore();
    const p = await proofFor(k);
    expect(await settle(p, { replayStore: store })).toEqual({ ok: true });
    expect(await settle(p, { replayStore: store })).toEqual({ ok: false, code: 'jti_replay', message: "jti 'j1' has already been seen" });
  });

  it('is keyed by jkt + jti with expiry iat + maxAge + skew, using the verifier clock', async () => {
    const k = await key();
    const calls: unknown[] = [];
    const store: DpopReplayStore = { addIfAbsent: (...a) => (calls.push(a), true) };
    await settle(await proofFor(k), { replayStore: store });
    expect(calls).toEqual([[`${await jwkThumbprint(k.publicJwk)}.j1`, NOW + 60 + 5, NOW]]);
  });

  it('another key holder reusing the same jti does not burn it', async () => {
    const [a, b] = [await key(), await key()];
    const store = createInMemoryDpopReplayStore();
    expect(await settle(await proofFor(a), { replayStore: store })).toEqual({ ok: true });
    expect(await settle(await proofFor(b), { replayStore: store })).toEqual({ ok: true });
  });

  it('a proof that fails another check does not consume its jti', async () => {
    const k = await key();
    const store = createInMemoryDpopReplayStore();
    const p = await proofFor(k);
    expect((await settle(p, { replayStore: store, expectedJkt: 'wrong' })).ok).toBe(false);
    expect(await settle(p, { replayStore: store })).toEqual({ ok: true });
  });

  it('a throwing store denies', async () => {
    const k = await key();
    const store: DpopReplayStore = { addIfAbsent: () => Promise.reject(new Error('db down')) };
    expect(await settle(await proofFor(k), { replayStore: store })).toEqual({ ok: false, code: 'replay_store_error', message: 'replay store failed: db down' });
  });

  it('a store answering anything but true denies', async () => {
    const k = await key();
    const store = { addIfAbsent: () => undefined } as unknown as DpopReplayStore;
    expect((await settle(await proofFor(k), { replayStore: store })).ok).toBe(false);
  });

  it('requireReplayStore with neither store refuses; either store satisfies it', async () => {
    const k = await key();
    const p = await proofFor(k);
    expect(await settle(p, { requireReplayStore: true })).toEqual({ ok: false, code: 'replay_store_required', message: 'no replay store configured; replay cannot be detected' });
    expect(await settle(p, { requireReplayStore: true, seenJti: new Set<string>() })).toEqual({ ok: true });
    expect(await settle(await proofFor(k, { jti: 'j2' }), { requireReplayStore: true, replayStore: createInMemoryDpopReplayStore() })).toEqual({ ok: true });
  });
});

describe('replay store conformance suite', () => {
  it('the in-memory double passes', async () => {
    expect(await runDpopReplayStoreConformance(createInMemoryDpopReplayStore)).toEqual([]);
  });
  it('catches racy, never-expiring and forgetful stores', async () => {
    const racy = (): DpopReplayStore => {
      const seen = new Set<string>();
      return { async addIfAbsent(j) { const had = seen.has(j); await Promise.resolve(); seen.add(j); return !had; } };
    };
    const forever = (): DpopReplayStore => {
      const seen = new Set<string>();
      return { addIfAbsent(j) { if (seen.has(j)) return false; seen.add(j); return true; } };
    };
    expect(await runDpopReplayStoreConformance(racy)).toEqual(['an expired entry may be added again (nowSec >= expiresAtSec)', '16 concurrent adds of one key: exactly one wins (got 16)']);
    expect(await runDpopReplayStoreConformance(forever)).toEqual(['an expired entry may be added again (nowSec >= expiresAtSec)']);
    expect((await runDpopReplayStoreConformance(() => ({ addIfAbsent: () => true }))).length).toBe(3);
  });
});

describe('nonce issuer', () => {
  const issuer = createDpopNonceIssuer({ secret: SECRET, ttlSec: 100 });
  it('accepts a fresh nonce through verifyDpopProof; boundary ttl inclusive', async () => {
    const k = await key();
    const nonce = issuer.issue(NOW - 100);
    expect(await settle(await proofFor(k, { nonce }), { nonceIssuer: issuer })).toEqual({ ok: true });
  });
  it.each([
    ['expired (ttl + 1)', () => issuer.issue(NOW - 101)],
    ['from the future beyond skew', () => issuer.issue(NOW + 6)],
    ['minted with another secret', () => createDpopNonceIssuer({ secret: new Uint8Array(32).fill(8) }).issue(NOW)],
    ['garbage', () => 'AAAA'],
    ['padded spelling', () => issuer.issue(NOW) + '='],
  ])('refused when %s', async (_n, mk) => {
    const k = await key();
    expect(await settle(await proofFor(k, { nonce: mk() }), { nonceIssuer: issuer })).toEqual({ ok: false, code: 'nonce', message: 'proof nonce is missing, forged or expired' });
  });
  it('a proof with no nonce is refused', async () => {
    const k = await key();
    expect((await settle(await proofFor(k), { nonceIssuer: issuer })).ok).toBe(false);
  });
  it('rejects a short secret and a non-positive ttl; non-string nonce is false', () => {
    expect(() => createDpopNonceIssuer({ secret: new Uint8Array(31) })).toThrow('nonce secret must be at least 32 bytes');
    expect(() => createDpopNonceIssuer({ secret: SECRET, ttlSec: 0 })).toThrow('nonce ttlSec must be positive');
    expect(issuer.check(undefined, NOW)).toBe(false);
    expect(issuer.check(42, NOW)).toBe(false);
  });
});

describe('hostile proofs', () => {
  it('a header jwk carrying a private member is refused before verification', async () => {
    const k = await key();
    const p = await new SignJWT({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: k.privateJwk })
      .sign(k.privateKey);
    expect(await settle(p, {})).toEqual({ ok: false, code: 'private_jwk', message: 'proof header jwk contains private key material' });
  });
  it('oversize and non-string input', async () => {
    expect(await settle('a'.repeat(8193), {})).toEqual({ ok: false, code: 'oversize', message: 'proof is not a string or exceeds 8192 bytes' });
    expect((await settle(undefined as unknown as string, {})).code).toBe('oversize');
  });
  it('HS256 and alg none with an embedded jwk are refused', async () => {
    const k = await key();
    const hs = await new SignJWT({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'HS256', jwk: k.publicJwk })
      .sign(new Uint8Array(32));
    expect((await settle(hs, {})).ok).toBe(false);
    const h = Buffer.from(JSON.stringify({ typ: 'dpop+jwt', alg: 'none', jwk: k.publicJwk })).toString('base64url');
    const b = Buffer.from(JSON.stringify({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })).toString('base64url');
    expect((await settle(`${h}.${b}.`, {})).ok).toBe(false);
  });
});
