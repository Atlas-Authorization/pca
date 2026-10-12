/**
 * Mutation-kill tests for replay.ts. Boundary-exact: every comparison in the anti-replay guard is
 * exercised on both sides of its edge, and every store interaction is asserted by argument, so a
 * flipped operator, a dropped guard or a weakened bound changes an observable result.
 */
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS, type PCActn } from './pcactn';
import {
  guardPCActnReplay,
  InMemoryReplayStore,
  MAX_REPLAY_COMPONENT_LEN,
  REPLAY_MIN_RETENTION_MS,
  replayKey,
  type CounterStore,
  type ReplayStore,
} from './replay';
import { MAX_AUD_LEN, MAX_NONCE_LEN } from './wire';

const NOW = 1_800_000_000_000;
const AUD = 'rs.example';

const mk = (over: Record<string, unknown> = {}): PCActn =>
  ({
    aud: AUD,
    iat: NOW,
    exp: NOW + 60_000,
    counter: 7,
    nonce: 'n-1',
    grant_ref: 'grant-1',
    cap_chain: [{ holder: 'holder-A' }],
    ...over,
  }) as unknown as PCActn;

interface Call {
  key: string;
  retainUntil: number;
  now: number;
}
const recorder = (answer: (c: Call) => boolean | Error = () => true) => {
  const calls: Call[] = [];
  const store: ReplayStore = {
    consumeOnce: async (key, retainUntil, now) => {
      const c = { key, retainUntil, now };
      calls.push(c);
      const a = answer(c);
      if (a instanceof Error) throw a;
      return a;
    },
  };
  return { calls, store };
};
const g = (p: PCActn, store: ReplayStore, o: Partial<Parameters<typeof guardPCActnReplay>[2]> = {}) => guardPCActnReplay(store, p, { aud: AUD, now: NOW, ...o });
const codeOf = (v: { ok: boolean; code?: string }) => v.code;
const deny = (code: string, reason: string) => ({ ok: false, code, reason });

describe('replayKey: injective, length-prefixed, exact', () => {
  it('equals ns + ":" + b64u(sha256(len32be||bytes ...)) for the namespace and each part', () => {
    const parts = ['ns', 'é', 'b'];
    const buf: number[] = [];
    for (const s of parts) {
      const b = utf8(s);
      buf.push(0, 0, 0, b.length, ...b);
    }
    expect(replayKey('ns', 'é', 'b')).toBe(`ns:${b64u(sha256(new Uint8Array(buf)))}`);
  });

  it('boundaries between parts cannot be shifted', () => {
    expect(replayKey('n', 'ab', 'c')).not.toBe(replayKey('n', 'a', 'bc'));
    expect(replayKey('n', 'a', '')).not.toBe(replayKey('n', '', 'a'));
    expect(replayKey('n')).not.toBe(replayKey('n', ''));
  });

  it('the length prefix is the UTF-8 BYTE length (multi-byte characters)', () => {
    // 'é' is 2 bytes. If the prefix were the UTF-16 length these two would collide with the 1-char forms.
    expect(replayKey('n', 'é', 'x')).not.toBe(replayKey('n', 'e', 'x'));
    const bytes = utf8('éé');
    expect(bytes.length).toBe(4);
  });

  it('the retention floor is the longest lifetime plus skew in both directions', () => {
    expect(REPLAY_MIN_RETENTION_MS).toBe(PCACTN_MAX_LIFETIME_MS + 2 * PCACTN_MAX_SKEW_MS);
    expect(MAX_REPLAY_COMPONENT_LEN).toBe(512);
  });
});

describe('guardPCActnReplay: verifier configuration is validated', () => {
  it('a non-integer verifier clock is malformed', async () => {
    const { store, calls } = recorder();
    for (const now of [1.5, NaN, Infinity, 2 ** 53, '1' as never]) {
      expect(await g(mk(), store, { now })).toEqual(deny('malformed', 'verifier clock is not an integer epoch-ms'));
    }
    expect(calls).toHaveLength(0);
  });

  it('the verifier audience must be a non-empty string of at most MAX_AUD_LEN UTF-8 bytes', async () => {
    const { store } = recorder();
    for (const aud of ['', 5 as never, undefined as never, 'a'.repeat(MAX_AUD_LEN + 1), 'é'.repeat(MAX_AUD_LEN / 2 + 1)]) {
      expect(await g(mk({ aud }), store, { aud })).toEqual(deny('malformed', 'verifier audience is invalid'));
    }
    const ok = 'a'.repeat(MAX_AUD_LEN);
    expect((await g(mk({ aud: ok }), store, { aud: ok })).ok).toBe(true);
    const okMb = 'é'.repeat(MAX_AUD_LEN / 2);
    expect((await g(mk({ aud: okMb }), store, { aud: okMb })).ok).toBe(true);
  });

  it('non-objects are not a PCActn', async () => {
    const { store } = recorder();
    for (const p of [null, undefined, 0, 'x', false]) {
      expect(await g(p as never, store)).toEqual(deny('malformed', 'not a PCActn'));
    }
  });
});

describe('guardPCActnReplay: audience and validity window edges', () => {
  it('the audience is compared byte-exactly (case, prefix, type)', async () => {
    const { store, calls } = recorder();
    for (const aud of ['RS.example', 'rs.example ', 'rs.exampl', 5, undefined, null]) {
      expect(await g(mk({ aud }), store)).toEqual(deny('audience', 'the PCActn is for another audience'));
    }
    expect(calls).toHaveLength(0);
  });

  it('iat / exp must be non-negative safe integers with exp > iat (not -0, not floats, not strings)', async () => {
    const { store } = recorder();
    const bad = deny('malformed', 'iat / exp are not a valid bounded window');
    for (const o of [
      { iat: -1 },
      { iat: 1.5 },
      { iat: '1' },
      { iat: -0 },
      { exp: NOW },
      { exp: NOW - 1 },
      { exp: NOW + 0.5 },
      { exp: '9' },
      { exp: -0, iat: -1 },
      { exp: NaN },
      { exp: Infinity },
      { iat: 2 ** 53 },
    ]) {
      expect(await g(mk(o), store, { now: 0 })).toEqual(bad);
    }
  });

  it('lifetime: exactly PCACTN_MAX_LIFETIME_MS is accepted, one more ms is malformed', async () => {
    const { store } = recorder();
    expect((await g(mk({ exp: NOW + PCACTN_MAX_LIFETIME_MS }), store)).ok).toBe(true);
    expect(await g(mk({ exp: NOW + PCACTN_MAX_LIFETIME_MS + 1 }), store)).toEqual(deny('malformed', 'iat / exp are not a valid bounded window'));
    // minimal window exp = iat + 1
    expect((await g(mk({ iat: NOW, exp: NOW + 1 }), recorder().store)).ok).toBe(true);
  });

  it('iat in the future: allowed up to now + skew inclusive, refused one ms beyond (default skew)', async () => {
    const { store } = recorder();
    expect((await g(mk({ iat: NOW + PCACTN_MAX_SKEW_MS, exp: NOW + PCACTN_MAX_SKEW_MS + 1000 }), store)).ok).toBe(true);
    expect(await g(mk({ iat: NOW + PCACTN_MAX_SKEW_MS + 1, exp: NOW + PCACTN_MAX_SKEW_MS + 1000 }), store)).toEqual(
      deny('not_yet_valid', 'iat is in the future beyond the clock-skew allowance'),
    );
  });

  it('expiry: valid through exp inclusive, expired at exp + 1', async () => {
    const { store } = recorder();
    const p = mk({ iat: NOW - 1000, exp: NOW });
    expect((await g(p, store)).ok).toBe(true);
    expect(await g(mk({ iat: NOW - 1000, exp: NOW - 1 }), store)).toEqual(deny('expired', 'the PCActn has expired'));
  });

  it('clockSkewMs: honoured when smaller, capped at the ceiling, and invalid values fall back to the ceiling', async () => {
    const { store } = recorder();
    const future = (ms: number) => mk({ iat: NOW + ms, exp: NOW + ms + 1000 });
    // smaller skew: honoured exactly
    expect((await g(future(10), store, { clockSkewMs: 10 })).ok).toBe(true);
    expect(codeOf(await g(future(11), store, { clockSkewMs: 10 }))).toBe('not_yet_valid');
    // zero skew is a valid, strictest setting
    expect((await g(future(0), store, { clockSkewMs: 0 })).ok).toBe(true);
    expect(codeOf(await g(future(1), store, { clockSkewMs: 0 }))).toBe('not_yet_valid');
    // larger than the ceiling: capped
    expect((await g(future(PCACTN_MAX_SKEW_MS), store, { clockSkewMs: 10 * PCACTN_MAX_SKEW_MS })).ok).toBe(true);
    expect(codeOf(await g(future(PCACTN_MAX_SKEW_MS + 1), store, { clockSkewMs: 10 * PCACTN_MAX_SKEW_MS }))).toBe('not_yet_valid');
    // negative / NaN / non-number: ceiling (never negative skew, never a bypass)
    for (const s of [-5, NaN, Infinity, '5' as never]) {
      expect((await g(future(PCACTN_MAX_SKEW_MS), store, { clockSkewMs: s })).ok).toBe(true);
      expect(codeOf(await g(future(PCACTN_MAX_SKEW_MS + 1), store, { clockSkewMs: s }))).toBe('not_yet_valid');
    }
  });

  it('retention passed to the store is exp + the effective skew, with now as the clock', async () => {
    const r = recorder();
    await g(mk({ exp: NOW + 5000 }), r.store, { clockSkewMs: 123 });
    expect(r.calls).toEqual([{ key: replayKey('pca-nonce/v1', AUD, 'grant-1', 'holder-A', 'n-1'), retainUntil: NOW + 5000 + 123, now: NOW }]);
    const r2 = recorder();
    await g(mk({ exp: NOW + 5000 }), r2.store);
    expect(r2.calls[0]!.retainUntil).toBe(NOW + 5000 + PCACTN_MAX_SKEW_MS);
  });
});

describe('guardPCActnReplay: leaf holder / grant / counter / nonce shape', () => {
  it('a missing, empty or malformed chain is refused', async () => {
    const { store } = recorder();
    const bad = deny('malformed', 'no leaf holder / grant');
    for (const o of [
      { cap_chain: undefined },
      { cap_chain: [] },
      { cap_chain: 'x' },
      { cap_chain: [null] },
      { cap_chain: [{ holder: 5 }] },
      { cap_chain: [{}] },
      { grant_ref: undefined },
      { grant_ref: 5 },
    ]) {
      expect(await g(mk(o), store)).toEqual(bad);
    }
  });

  it('the LEAF (last hop) holder is the one used', async () => {
    const r = recorder();
    await g(mk({ cap_chain: [{ holder: 'first' }, { holder: 'leaf' }] }), r.store);
    expect(r.calls[0]!.key).toBe(replayKey('pca-nonce/v1', AUD, 'grant-1', 'leaf', 'n-1'));
  });

  it('grant_ref / holder: non-empty, no lone surrogate, at most 512 UTF-8 bytes', async () => {
    const { store } = recorder();
    const bad = deny('malformed', 'grant / holder is not a bounded string');
    const long = 'a'.repeat(MAX_REPLAY_COMPONENT_LEN + 1);
    const mb = 'é'.repeat(MAX_REPLAY_COMPONENT_LEN / 2 + 1);
    for (const v of ['', '\ud800', 'a\udc00b', long, mb]) {
      expect(await g(mk({ grant_ref: v }), store)).toEqual(bad);
      expect(await g(mk({ cap_chain: [{ holder: v }] }), store)).toEqual(bad);
    }
    const edge = 'a'.repeat(MAX_REPLAY_COMPONENT_LEN);
    expect((await g(mk({ grant_ref: edge, cap_chain: [{ holder: edge }] }), store)).ok).toBe(true);
    const edgeMb = 'é'.repeat(MAX_REPLAY_COMPONENT_LEN / 2);
    expect((await g(mk({ grant_ref: edgeMb }), store)).ok).toBe(true);
  });

  it('counter must be a non-negative safe integer (0 is fine; -0, floats, NaN, 2^53, strings are not)', async () => {
    const { store } = recorder();
    const bad = deny('malformed', 'counter is not a non-negative safe integer');
    for (const counter of [-1, -0, 1.5, NaN, Infinity, 2 ** 53, '1', null, undefined]) {
      expect(await g(mk({ counter }), store)).toEqual(bad);
    }
    for (const counter of [0, 1, Number.MAX_SAFE_INTEGER]) expect((await g(mk({ counter }), recorder().store)).ok).toBe(true);
  });

  it('nonce: non-empty well-formed string of at most 128 UTF-8 bytes', async () => {
    const { store, calls } = recorder();
    const bad = deny('malformed', 'nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes');
    for (const nonce of ['', 5, null, {}, '\ud800', 'x\udfff', 'n'.repeat(MAX_NONCE_LEN + 1), 'é'.repeat(MAX_NONCE_LEN / 2 + 1)]) {
      expect(await g(mk({ nonce }), store)).toEqual(bad);
    }
    expect(calls).toHaveLength(0);
    expect((await g(mk({ nonce: 'n'.repeat(MAX_NONCE_LEN) }), store)).ok).toBe(true);
    expect((await g(mk({ nonce: 'é'.repeat(MAX_NONCE_LEN / 2) }), store)).ok).toBe(true);
  });

  it('a missing nonce is refused by default and when requireNonce is true; counter-only mode needs requireNonce:false + counters', async () => {
    const r = recorder();
    const noNonce = mk({ nonce: undefined });
    expect(await g(noNonce, r.store)).toEqual(deny('malformed', 'a nonce is required'));
    expect(await g(noNonce, r.store, { requireNonce: true })).toEqual(deny('malformed', 'a nonce is required'));
    expect(r.calls).toHaveLength(0);
    // requireNonce:false without counters: nothing guards the action, but the guard does not invent a store call
    expect((await g(noNonce, r.store, { requireNonce: false })).ok).toBe(true);
    expect(r.calls).toHaveLength(0);
  });
});

describe('guardPCActnReplay: store interaction', () => {
  it('the nonce key binds audience, grant, leaf holder and nonce (each change is a different key)', async () => {
    const keys = new Set<string>();
    for (const o of [{}, { grant_ref: 'grant-2' }, { cap_chain: [{ holder: 'holder-B' }] }, { nonce: 'n-2' }]) {
      const r = recorder();
      await g(mk(o), r.store);
      keys.add(r.calls[0]!.key);
    }
    const r = recorder();
    await g(mk({ aud: 'other' }), r.store, { aud: 'other' });
    keys.add(r.calls[0]!.key);
    expect(keys.size).toBe(5);
  });

  it('a consumed nonce is a replay (code + reason) and the counter store is not touched', async () => {
    const r = recorder(() => false);
    let advanced = 0;
    const counters: CounterStore = { advance: async () => (advanced++, true) };
    expect(await g(mk(), r.store, { counters })).toEqual(deny('replay', 'nonce already consumed'));
    expect(advanced).toBe(0);
  });

  it('counters advance AFTER the nonce with the exact stream key and counter; a stale counter is a replay', async () => {
    const order: string[] = [];
    const store: ReplayStore = { consumeOnce: async () => (order.push('nonce'), true) };
    const seen: Array<[string, number]> = [];
    const counters: CounterStore = {
      advance: async (k, c) => {
        order.push('counter');
        seen.push([k, c]);
        return false;
      },
    };
    expect(await g(mk({ counter: 41 }), store, { counters })).toEqual(deny('replay', 'counter is not greater than the last accepted'));
    expect(order).toEqual(['nonce', 'counter']);
    expect(seen).toEqual([[replayKey('pca-counter/v1', AUD, 'grant-1', 'holder-A'), 41]]);
  });

  it('counter-only mode (requireNonce:false) accepts on a fresh counter and denies on a stale one', async () => {
    const mem = new InMemoryReplayStore();
    const p = mk({ nonce: undefined });
    expect((await g(p, mem, { requireNonce: false, counters: mem })).ok).toBe(true);
    expect(await g(p, mem, { requireNonce: false, counters: mem })).toEqual(deny('replay', 'counter is not greater than the last accepted'));
  });

  it('store failures fail closed with store_unavailable, carrying an Error message or a generic one', async () => {
    const e = recorder(() => new Error('db down'));
    expect(await g(mk(), e.store)).toEqual(deny('store_unavailable', 'replay store failed closed: db down'));
    const nonErr: ReplayStore = { consumeOnce: () => Promise.reject('boom') };
    expect(await g(mk(), nonErr)).toEqual(deny('store_unavailable', 'replay store failed closed: error'));
    const badCounters: CounterStore = { advance: () => Promise.reject(new Error('c down')) };
    expect(await g(mk(), recorder().store, { counters: badCounters })).toEqual(deny('store_unavailable', 'replay store failed closed: c down'));
    const throwsSync: ReplayStore = { consumeOnce: () => { throw new Error('sync'); } };
    expect(await g(mk(), throwsSync)).toEqual(deny('store_unavailable', 'replay store failed closed: sync'));
  });

  it('success returns exactly {ok:true}', async () => {
    expect(await g(mk(), recorder().store)).toEqual({ ok: true });
  });
});

describe('InMemoryReplayStore', () => {
  it('consumeOnce: first wins, second loses, until the retention instant (inclusive) has passed', async () => {
    const s = new InMemoryReplayStore();
    expect(await s.consumeOnce('k', 100, 10)).toBe(true);
    expect(await s.consumeOnce('k', 100, 10)).toBe(false);
    expect(await s.consumeOnce('k', 200, 100)).toBe(false); // now == until: still live
    expect(await s.consumeOnce('k', 300, 101)).toBe(true); // now > until: free again
    expect(await s.consumeOnce('k', 400, 150)).toBe(false); // and the new retention is in force
  });

  it('rejects (never resolves true) on an unusable key, clock or horizon', async () => {
    const s = new InMemoryReplayStore();
    for (const args of [
      ['', 10, 1],
      [5 as never, 10, 1],
      ['k', NaN, 1],
      ['k', Infinity, 1],
      ['k', 10, NaN],
      ['k', 10, Infinity],
      ['k', 9, 10],
    ] as Array<[string, number, number]>) {
      await expect(s.consumeOnce(...args)).rejects.toThrow(new RangeError('consumeOnce: invalid key or retention horizon'));
    }
    expect(s.size).toBe(0);
    // a horizon equal to now is allowed
    expect(await s.consumeOnce('k', 10, 10)).toBe(true);
  });

  it('is atomic under concurrency: N simultaneous consumers of one key yield exactly one winner', async () => {
    const s = new InMemoryReplayStore();
    const res = await Promise.all(Array.from({ length: 500 }, () => s.consumeOnce('same', 1000, 1)));
    expect(res.filter(Boolean)).toHaveLength(1);
  });

  it('capacity: refuses new keys when full of LIVE entries, frees expired ones, still answers false for a known key', async () => {
    const s = new InMemoryReplayStore({ maxEntries: 2 });
    expect(await s.consumeOnce('a', 100, 0)).toBe(true);
    expect(await s.consumeOnce('b', 50, 0)).toBe(true);
    await expect(s.consumeOnce('c', 100, 10)).rejects.toThrow('replay store full of live entries');
    expect(await s.consumeOnce('a', 100, 10)).toBe(false); // known key at capacity is a replay, not an error
    expect(s.size).toBe(2);
    expect(await s.consumeOnce('c', 100, 51)).toBe(true); // 'b' expired (50 < 51) and was pruned to make room
    expect(s.size).toBe(2);
    await expect(s.consumeOnce('d', 200, 60)).rejects.toThrow('replay store full of live entries');
  });

  it('default capacity is large (100000), not tiny', async () => {
    const s = new InMemoryReplayStore();
    for (let i = 0; i < 1000; i++) expect(await s.consumeOnce(`k${i}`, 10, 0)).toBe(true);
    expect(s.size).toBe(1000);
  });

  it('prune drops only entries whose retention is strictly in the past and reports how many', async () => {
    const s = new InMemoryReplayStore();
    await s.consumeOnce('old', 10, 0);
    await s.consumeOnce('edge', 20, 0);
    await s.consumeOnce('live', 30, 0);
    expect(s.prune(20)).toBe(1); // only 'old' (10 < 20); 'edge' (20 < 20 is false) stays
    expect(s.size).toBe(2);
    expect(await s.consumeOnce('edge', 99, 20)).toBe(false);
    expect(s.prune(1000)).toBe(2);
    expect(s.size).toBe(0);
  });

  it('advance: strictly increasing per stream; 0 is a valid first counter; a stale value never lowers the mark', async () => {
    const s = new InMemoryReplayStore();
    expect(await s.advance('x', 0)).toBe(true);
    expect(await s.advance('x', 0)).toBe(false);
    expect(await s.advance('x', 5)).toBe(true);
    expect(await s.advance('x', 5)).toBe(false);
    expect(await s.advance('x', 3)).toBe(false);
    expect(await s.advance('x', 4)).toBe(false); // would be true if the failed 3 had lowered the mark
    expect(await s.advance('x', 6)).toBe(true);
    expect(await s.advance('y', 1)).toBe(true); // independent stream
  });

  it('advance rejects an unusable stream or counter', async () => {
    const s = new InMemoryReplayStore();
    for (const [k, c] of [['', 1], [5 as never, 1], ['k', -1], ['k', 1.5], ['k', NaN], ['k', -0], ['k', 2 ** 53], ['k', '1' as never]] as Array<[string, number]>) {
      await expect(s.advance(k, c)).rejects.toThrow(new RangeError('advance: invalid stream or counter'));
    }
  });

  it('concurrent advance with the same counter: exactly one winner', async () => {
    const s = new InMemoryReplayStore();
    const res = await Promise.all(Array.from({ length: 300 }, () => s.advance('s', 10)));
    expect(res.filter(Boolean)).toHaveLength(1);
  });
});
