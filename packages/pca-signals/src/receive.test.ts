import { SignJWT, generateKeyPair, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  EVENT_TYPES,
  createInMemorySetReplayStore,
  createRevocationState,
  isRevoked,
  receiveSET,
  runSetReplayStoreConformance,
  type ReceiveSetOptions,
  type SetReplayStore,
} from './index';

const ISS = 'https://transmitter.example';
const AUD = 'https://rs.example';
const NOW = 1_800_000_000;

async function keys() {
  return generateKeyPair('EdDSA');
}

/** Sign an arbitrary claim set as a SET with a pinned clock (buildSET stamps the real time). */
async function sign(key: KeyLike, claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'EdDSA', typ: 'secevent+jwt' }) {
  return new SignJWT(claims).setProtectedHeader(header as { alg: string }).sign(key);
}

const grant = (ref: string) => ({ [EVENT_TYPES.grantRevoked]: { grant_ref: ref, reason: 'r', event_timestamp: NOW } });
const claims = (over: Record<string, unknown> = {}) => ({ iss: ISS, aud: AUD, iat: NOW, jti: 'jti-1', events: grant('g1'), ...over });

function opts(over: Partial<ReceiveSetOptions> = {}): ReceiveSetOptions {
  return { issuer: ISS, audience: AUD, replayStore: createInMemorySetReplayStore(), state: createRevocationState(), maxAgeSec: 3600, nowSec: NOW, ...over };
}

/** Run receiveSET and return the verdict with the (unserialisable) parsed token reduced to its jti. */
async function settle(set: string, key: KeyLike, o: ReceiveSetOptions) {
  const r = await receiveSET(set, key, o);
  return r.ok ? { ok: true as const, jti: r.parsed.jti } : r;
}

describe('receiveSET: accept path', () => {
  it('verifies, records the jti and folds the revocation into state', async () => {
    const { publicKey, privateKey } = await keys();
    const o = opts();
    expect(await settle(await sign(privateKey, claims()), publicKey, o)).toEqual({ ok: true, jti: 'jti-1' });
    expect(isRevoked(o.state, 'g1')).toBe(true);
  });
});

describe('receiveSET: failure modes (exact verdicts, state untouched)', () => {
  it('replay: the second delivery of the same SET is refused and nothing is re-applied', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await sign(privateKey, claims());
    const o = opts();
    await receiveSET(set, publicKey, o);
    const o2 = opts({ replayStore: o.replayStore });
    expect(await settle(set, publicKey, o2)).toEqual({ ok: false, code: 'replay', reason: "jti 'jti-1' has already been received" });
    expect(isRevoked(o2.state, 'g1')).toBe(false);
  });

  it('a forged token cannot burn the real SET jti (jti recorded only after verification)', async () => {
    const { publicKey, privateKey } = await keys();
    const { privateKey: evil } = await keys();
    const o = opts();
    const forged = await settle(await sign(evil, claims()), publicKey, o);
    expect(forged.ok).toBe(false);
    expect(await settle(await sign(privateKey, claims()), publicKey, o)).toEqual({ ok: true, jti: 'jti-1' });
  });

  it.each([
    ['bad signature (wrong key)', async (k: { privateKey: KeyLike }) => sign((await keys()).privateKey, claims()), 'verify_failed'],
    ['wrong aud', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ aud: 'https://other' })), 'verify_failed'],
    ['wrong iss', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ iss: 'https://other' })), 'verify_failed'],
    ['missing typ', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims(), { alg: 'EdDSA' }), 'verify_failed'],
    ['wrong typ (an access-token lookalike)', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims(), { alg: 'EdDSA', typ: 'JWT' }), 'verify_failed'],
    ['missing jti', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ jti: undefined })), 'verify_failed'],
    ['missing events', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ events: undefined })), 'verify_failed'],
    ['empty events', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ events: {} })), 'verify_failed'],
    ['events payload not an object', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ events: { x: 1 } })), 'verify_failed'],
    ['expired exp', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ exp: NOW - 1 })), 'verify_failed'],
    ['missing iat', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ iat: undefined })), 'iat_missing'],
    ['iat in the future', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ iat: NOW + 61 })), 'iat_future'],
    ['iat too old', async (k: { privateKey: KeyLike }) => sign(k.privateKey, claims({ iat: NOW - 3601 })), 'iat_stale'],
  ] as const)('%s -> %s', async (_name, make, code) => {
    const k = await keys();
    const r = await receiveSET(await make({ privateKey: k.privateKey }), k.publicKey, opts());
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe(code);
  });

  it('iat boundaries: +60 s skew and exactly maxAge are accepted', async () => {
    const { publicKey, privateKey } = await keys();
    expect((await settle(await sign(privateKey, claims({ iat: NOW + 60, jti: 'a' })), publicKey, opts())).ok).toBe(true);
    expect((await settle(await sign(privateKey, claims({ iat: NOW - 3600, jti: 'b' })), publicKey, opts())).ok).toBe(true);
  });

  it('alg confusion: HS256 and alg none are refused', async () => {
    const { publicKey } = await keys();
    const hs = await new SignJWT(claims()).setProtectedHeader({ alg: 'HS256', typ: 'secevent+jwt' }).sign(new TextEncoder().encode('0123456789abcdef0123456789abcdef'));
    expect((await settle(hs, publicKey, opts())).ok).toBe(false);
    const none = ['eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0', Buffer.from(JSON.stringify(claims())).toString('base64url'), ''].join('.');
    expect((await settle(none, publicKey, opts())).ok).toBe(false);
  });

  it('oversize and non-canonical input', async () => {
    const { publicKey } = await keys();
    expect(await settle('a'.repeat(17000), publicKey, opts())).toEqual({ ok: false, code: 'oversize', reason: 'SET is not a string or exceeds maxBytes' });
    expect((await settle('not.a.jws!', publicKey, opts())).ok).toBe(false);
    expect(((await settle('x'.repeat(10), publicKey, opts())) as { code: string }).code).toBe('malformed');
  });

  it('a throwing replay store denies and does not apply the SET', async () => {
    const { publicKey, privateKey } = await keys();
    const store: SetReplayStore = {
      addIfAbsent() {
        throw new Error('db down');
      },
    };
    const o = opts({ replayStore: store });
    expect(await settle(await sign(privateKey, claims()), publicKey, o)).toEqual({ ok: false, code: 'replay_store_error', reason: 'db down' });
    expect(isRevoked(o.state, 'g1')).toBe(false);
  });

  it.each([
    ['replayStore', { replayStore: undefined }],
    ['state', { state: undefined }],
    ['issuer', { issuer: undefined }],
    ['audience', { audience: undefined }],
    ['maxAgeSec', { maxAgeSec: undefined }],
    ['maxAgeSec <= 0', { maxAgeSec: 0 }],
  ])('missing %s -> misconfigured (deny, never downgrade)', async (_n, over) => {
    const { publicKey, privateKey } = await keys();
    const r = await receiveSET(await sign(privateKey, claims()), publicKey, { ...opts(), ...over } as unknown as ReceiveSetOptions);
    expect(r).toEqual({ ok: false, code: 'misconfigured', reason: 'issuer, audience, replayStore, state and a positive maxAgeSec are all required' });
  });
});

describe('receiveSET: replay-store contract', () => {
  it('records the jti with expiry iat + maxAgeSec + skew and the receiver clock', async () => {
    const { publicKey, privateKey } = await keys();
    const calls: unknown[] = [];
    const store: SetReplayStore = { addIfAbsent: (...a) => (calls.push(a), true) };
    await receiveSET(await sign(privateKey, claims()), publicKey, opts({ replayStore: store, clockSkewSec: 7 }));
    expect(calls).toEqual([['jti-1', NOW + 3600 + 7, NOW]]);
  });
  it('a store answering anything but true is a replay', async () => {
    const { publicKey, privateKey } = await keys();
    const store = { addIfAbsent: () => undefined } as unknown as SetReplayStore;
    expect(await settle(await sign(privateKey, claims()), publicKey, opts({ replayStore: store }))).toEqual({ ok: false, code: 'replay', reason: "jti 'jti-1' has already been received" });
  });
});

describe('SetReplayStore conformance', () => {
  it('the in-memory double passes the suite', async () => {
    expect(await runSetReplayStoreConformance(createInMemorySetReplayStore)).toEqual([]);
  });
  it('the suite catches a non-atomic / non-expiring / forgetful store', async () => {
    const racy = (): SetReplayStore => {
      const seen = new Set<string>();
      return { async addIfAbsent(j) { const had = seen.has(j); await Promise.resolve(); seen.add(j); return !had; } };
    };
    const forever = (): SetReplayStore => {
      const seen = new Set<string>();
      return { addIfAbsent(j) { if (seen.has(j)) return false; seen.add(j); return true; } };
    };
    const forgetful = (): SetReplayStore => ({ addIfAbsent: () => true });
    expect(await runSetReplayStoreConformance(racy)).toEqual(['an expired entry may be added again (nowSec >= expiresAtSec)', '16 concurrent adds of one jti: exactly one wins (got 16)']);
    expect(await runSetReplayStoreConformance(forever)).toEqual(['an expired entry may be added again (nowSec >= expiresAtSec)']);
    expect((await runSetReplayStoreConformance(forgetful)).length).toBe(3);
  });
});
