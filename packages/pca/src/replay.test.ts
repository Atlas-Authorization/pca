import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { commitPlan } from './merkle';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS, buildPCActn, type PCActn } from './pcactn';
import { InMemoryReplayStore, REPLAY_MIN_RETENTION_MS, guardPCActnReplay, replayKey, type CounterStore, type ReplayStore } from './replay';

const NOW = 1_800_000_000_000;

function fixture(aud = 'inst_A') {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const plan = [{ id: 'n1', verb: 'read', resource: 'acct', reversibility_class: 'R0' }];
  const act = (o: { nonce?: string; counter?: number; iat?: number; exp?: number; aud?: string; grantOverride?: typeof grant } = {}): PCActn =>
    buildPCActn({
      aud: o.aud ?? aud,
      grant: o.grantOverride ?? grant,
      chain: [o.grantOverride ?? grant],
      plan,
      nodeId: 'n1',
      counter: o.counter ?? 1,
      signerSecret: A.secretKey,
      iat: o.iat ?? NOW,
      exp: o.exp ?? NOW + 60_000,
      ...(o.nonce !== undefined ? { nonce: o.nonce } : {}),
    });
  const other = () => fixture(aud);
  return { act, grant, other, P, A, plan, commit: commitPlan(plan) };
}

describe('replayKey', () => {
  it('is injective across part boundaries (length-prefixed)', () => {
    expect(replayKey('ns', 'ab', 'c')).not.toBe(replayKey('ns', 'a', 'bc'));
    expect(replayKey('ns', 'a', '')).not.toBe(replayKey('ns', '', 'a'));
    expect(replayKey('ns1', 'x')).not.toBe(replayKey('ns2', 'x'));
  });
});

describe('guardPCActnReplay: single store', () => {
  it('accepts once, then rejects the same nonce', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const a = f.act({ nonce: 'n-1' });
    expect(await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW })).toEqual({ ok: true });
    expect(await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'replay' });
  });

  it('N=200 concurrent submissions of one nonce: exactly one accepted', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const a = f.act({ nonce: 'race' });
    const res = await Promise.all(Array.from({ length: 200 }, () => guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW })));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect(res.filter((r) => !r.ok && r.code === 'replay')).toHaveLength(199);
  });

  it('two verifier objects sharing ONE store behave as one (multi-instance shape)', async () => {
    const f = fixture();
    const shared = new InMemoryReplayStore();
    const a = f.act({ nonce: 'x' });
    const [r1, r2] = await Promise.all([
      guardPCActnReplay(shared, a, { aud: 'inst_A', now: NOW }),
      guardPCActnReplay(shared, a, { aud: 'inst_A', now: NOW }),
    ]);
    expect([r1.ok, r2.ok].filter(Boolean)).toHaveLength(1);
  });

  it('same nonce under a different grant / holder / audience does not collide', async () => {
    const f1 = fixture();
    const f2 = fixture();
    const store = new InMemoryReplayStore();
    expect((await guardPCActnReplay(store, f1.act({ nonce: 'same' }), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect((await guardPCActnReplay(store, f2.act({ nonce: 'same' }), { aud: 'inst_A', now: NOW })).ok).toBe(true); // other grant+holder
    const f3 = fixture('inst_B');
    expect((await guardPCActnReplay(store, f3.act({ nonce: 'same' }), { aud: 'inst_B', now: NOW })).ok).toBe(true); // other audience
    // and the originals are still consumed
    expect((await guardPCActnReplay(store, f1.act({ nonce: 'same', counter: 2 }), { aud: 'inst_A', now: NOW })).ok).toBe(false);
  });

  it('an action for another audience is refused before anything is consumed', async () => {
    const f = fixture('inst_B');
    const store = new InMemoryReplayStore();
    const a = f.act({ nonce: 'k' });
    expect(await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'audience' });
    expect(store.size).toBe(0);
  });

  it('Unicode: nonces are byte-exact, so NFC and NFD forms are DIFFERENT nonces (no normalization); malformed ones are refused', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const nfc = 'é'; // e-acute, one code point
    const nfd = 'é'; // e + combining acute: renders identically
    expect(nfc).not.toBe(nfd);
    expect(nfc.normalize('NFC')).toBe(nfd.normalize('NFC'));
    expect((await guardPCActnReplay(store, f.act({ nonce: nfc, counter: 1 }), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect((await guardPCActnReplay(store, f.act({ nonce: nfd, counter: 2 }), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect((await guardPCActnReplay(store, f.act({ nonce: nfc, counter: 3 }), { aud: 'inst_A', now: NOW })).ok).toBe(false);
    expect((await guardPCActnReplay(store, f.act({ nonce: nfd, counter: 4 }), { aud: 'inst_A', now: NOW })).ok).toBe(false);
    // lone surrogate is not valid UTF-8
    expect(await guardPCActnReplay(store, { ...f.act({ nonce: 'ok', counter: 5 }), nonce: 'a\ud800' } as PCActn, { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'malformed' });
  });

  it('nonce length is bounded in UTF-8 BYTES (128), empty refused, missing refused unless requireNonce=false', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    expect((await guardPCActnReplay(store, f.act({ nonce: 'a'.repeat(128) }), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect(await guardPCActnReplay(store, f.act({ nonce: 'a'.repeat(129) }), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'malformed' });
    // 43 x 3-byte chars = 129 bytes but only 43 code units
    expect(await guardPCActnReplay(store, f.act({ nonce: '€'.repeat(43) }), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'malformed' });
    expect(await guardPCActnReplay(store, f.act({ nonce: '' }), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'malformed' });
    expect(await guardPCActnReplay(store, f.act(), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'malformed' });
    expect((await guardPCActnReplay(store, f.act(), { aud: 'inst_A', now: NOW, requireNonce: false })).ok).toBe(true);
  });

  it('clock skew, both directions, and the exp boundary instant', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const a = (n: string, iat: number, exp: number) => f.act({ nonce: n, iat, exp });
    // iat in the future within skew: accepted; beyond skew: refused
    expect((await guardPCActnReplay(store, a('f1', NOW + PCACTN_MAX_SKEW_MS, NOW + 120_000), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect(await guardPCActnReplay(store, a('f2', NOW + PCACTN_MAX_SKEW_MS + 1, NOW + 120_000), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'not_yet_valid' });
    // a refused action must not have consumed its nonce
    expect((await guardPCActnReplay(store, a('f2', NOW, NOW + 60_000), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    // exp boundary: valid AT exp, expired one ms later
    expect((await guardPCActnReplay(store, a('b1', NOW - 60_000, NOW), { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect(await guardPCActnReplay(store, a('b2', NOW - 60_000, NOW), { aud: 'inst_A', now: NOW + 1 })).toMatchObject({ ok: false, code: 'expired' });
    // a verifier with a slow clock (skew behind) still rejects the already-consumed nonce at exp
    expect((await guardPCActnReplay(store, a('b1', NOW - 60_000, NOW), { aud: 'inst_A', now: NOW - PCACTN_MAX_SKEW_MS })).ok).toBe(false);
  });

  it('TTL pruning never frees a still-valid nonce (retention >= exp + skew)', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const a = f.act({ nonce: 'keep', iat: NOW, exp: NOW + PCACTN_MAX_LIFETIME_MS });
    expect((await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW })).ok).toBe(true);
    // prune at every instant up to the end of validity + skew: nothing is freed, so replay stays denied
    for (const t of [NOW, NOW + 1, NOW + PCACTN_MAX_LIFETIME_MS - 1, NOW + PCACTN_MAX_LIFETIME_MS, NOW + PCACTN_MAX_LIFETIME_MS + PCACTN_MAX_SKEW_MS]) {
      expect(store.prune(t)).toBe(0);
      expect(store.size).toBe(1);
    }
    expect(await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW + PCACTN_MAX_LIFETIME_MS })).toMatchObject({ ok: false, code: 'replay' });
    // only once the whole window (incl. skew) elapsed is it freed, and by then the action itself is expired
    expect(store.prune(NOW + PCACTN_MAX_LIFETIME_MS + PCACTN_MAX_SKEW_MS + 1)).toBe(1);
    expect(await guardPCActnReplay(store, a, { aud: 'inst_A', now: NOW + PCACTN_MAX_LIFETIME_MS + PCACTN_MAX_SKEW_MS + 1 })).toMatchObject({ ok: false, code: 'expired' });
    expect(REPLAY_MIN_RETENTION_MS).toBeGreaterThanOrEqual(PCACTN_MAX_LIFETIME_MS + PCACTN_MAX_SKEW_MS);
  });

  it('a "restart" (fresh in-memory store) DOES resurrect a nonce: the documented limit of the reference store', async () => {
    const f = fixture();
    const a = f.act({ nonce: 'r' });
    expect((await guardPCActnReplay(new InMemoryReplayStore(), a, { aud: 'inst_A', now: NOW })).ok).toBe(true);
    expect((await guardPCActnReplay(new InMemoryReplayStore(), a, { aud: 'inst_A', now: NOW })).ok).toBe(true);
  });
});

describe('guardPCActnReplay: counters + fail-closed', () => {
  it('counter stream: strictly increasing, N=200 concurrent same counter => one winner; distinct streams independent', async () => {
    const f = fixture();
    const g = fixture();
    const store = new InMemoryReplayStore();
    const opts = { aud: 'inst_A', now: NOW, counters: store, requireNonce: false } as const;
    const res = await Promise.all(Array.from({ length: 200 }, () => guardPCActnReplay(store, f.act({ counter: 7 }), opts)));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect((await guardPCActnReplay(store, f.act({ counter: 7 }), opts)).ok).toBe(false);
    expect((await guardPCActnReplay(store, f.act({ counter: 6 }), opts)).ok).toBe(false); // reorder
    expect((await guardPCActnReplay(store, f.act({ counter: 8 }), opts)).ok).toBe(true);
    expect((await guardPCActnReplay(store, g.act({ counter: 7 }), opts)).ok).toBe(true); // other grant
  });

  it('racing distinct counters leave the stream at the maximum accepted and accepts a strictly increasing subset', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const accepted: number[] = [];
    const counters: CounterStore = {
      advance: async (k, c) => {
        const ok = await store.advance(k, c);
        if (ok) accepted.push(c);
        return ok;
      },
    };
    const order = Array.from({ length: 100 }, (_, i) => i + 1).sort(() => Math.random() - 0.5);
    await Promise.all(order.map((c) => guardPCActnReplay(store, f.act({ counter: c }), { aud: 'inst_A', now: NOW, counters, requireNonce: false })));
    for (let i = 1; i < accepted.length; i++) expect(accepted[i]!).toBeGreaterThan(accepted[i - 1]!);
  });

  it('store failure / timeout FAILS CLOSED (deny), never allow', async () => {
    const f = fixture();
    const boom: ReplayStore = { consumeOnce: () => Promise.reject(new Error('connection refused')) };
    const hang: ReplayStore = { consumeOnce: () => Promise.reject(new Error('timeout')) };
    for (const s of [boom, hang]) {
      expect(await guardPCActnReplay(s, f.act({ nonce: 'z' }), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'store_unavailable' });
    }
    const badCounters: CounterStore = { advance: () => Promise.reject(new Error('db down')) };
    expect(await guardPCActnReplay(new InMemoryReplayStore(), f.act({ nonce: 'z2' }), { aud: 'inst_A', now: NOW, counters: badCounters })).toMatchObject({
      ok: false,
      code: 'store_unavailable',
    });
    // a store that throws synchronously is also contained
    const sync: ReplayStore = {
      consumeOnce: () => {
        throw new Error('sync boom');
      },
    };
    expect(await guardPCActnReplay(sync, f.act({ nonce: 'z3' }), { aud: 'inst_A', now: NOW })).toMatchObject({ ok: false, code: 'store_unavailable' });
  });

  it('a full store rejects instead of evicting a live nonce; malformed horizon rejects', async () => {
    const store = new InMemoryReplayStore({ maxEntries: 2 });
    expect(await store.consumeOnce('a', NOW + 10, NOW)).toBe(true);
    expect(await store.consumeOnce('b', NOW + 10, NOW)).toBe(true);
    await expect(store.consumeOnce('c', NOW + 10, NOW)).rejects.toThrow(/full/);
    expect(await store.consumeOnce('a', NOW + 10, NOW)).toBe(false); // 'a' was NOT evicted
    // expired entries are reclaimed to make room
    expect(await store.consumeOnce('c', NOW + 30, NOW + 11)).toBe(true);
    await expect(store.consumeOnce('d', NOW - 1, NOW)).rejects.toThrow(RangeError);
    await expect(store.consumeOnce('', NOW + 1, NOW)).rejects.toThrow(RangeError);
  });

  it('malformed counters are refused, not stored', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const opts = { aud: 'inst_A', now: NOW, counters: store, requireNonce: false } as const;
    for (const bad of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1, Number.POSITIVE_INFINITY]) {
      const a = { ...f.act({ counter: 1 }), counter: bad } as PCActn;
      expect(await guardPCActnReplay(store, a, opts)).toMatchObject({ ok: false, code: 'malformed' });
    }
    expect((await guardPCActnReplay(store, f.act({ counter: Number.MAX_SAFE_INTEGER }), opts)).ok).toBe(true);
    expect((await guardPCActnReplay(store, f.act({ counter: 0 }), opts)).ok).toBe(false);
  });
});
