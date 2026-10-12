/**
 * Executable counterparts of the TLA+ results in formal/tla (ReplayContract / ApaContract) against the REAL
 * guardPCActnReplay + InMemoryReplayStore:
 *   - the retention horizon `exp + skew` is TIGHT: two verifier clocks that differ by exactly the skew bound cannot
 *     re-accept after the other prunes; one millisecond beyond the bound can (the documented environment assumption);
 *   - the nonce is consumed before the counter advances, so a counter-store failure after a nonce consume burns the
 *     nonce (fail closed: the retry is denied as a replay, never accepted twice);
 *   - a concurrent storm across several guard "servers" with random yielding admits exactly one.
 */
import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { PCACTN_MAX_SKEW_MS, buildPCActn } from './pcactn';
import { InMemoryReplayStore, guardPCActnReplay, type CounterStore } from './replay';

const NOW = 1_800_000_000_000;
const AUD = 'inst_T';

function fixture() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const plan = [{ id: 'n1', verb: 'read', resource: 'acct', reversibility_class: 'R0' }];
  return (o: { nonce: string; counter?: number; iat: number; exp: number }) =>
    buildPCActn({ aud: AUD, grant, chain: [grant], plan, nodeId: 'n1', counter: o.counter ?? 1, signerSecret: A.secretKey, iat: o.iat, exp: o.exp, nonce: o.nonce });
}

describe('retention horizon exp + skew is tight (TLA: ReplayContract / ApaContract)', () => {
  const EXP = NOW + 60_000;
  // Server A's clock reads `a`, server B's reads `b`; real time is irrelevant, only the two readings matter.
  async function replayAfterPrune(aClock: number, bClock: number) {
    const mk = fixture();
    const shared = new InMemoryReplayStore();
    const act = mk({ nonce: 'n', iat: NOW, exp: EXP });
    const first = await guardPCActnReplay(shared, act, { aud: AUD, now: NOW + 1000 });
    expect(first.ok).toBe(true);
    shared.prune(aClock); // the retention worker runs on server A and uses A's clock
    return guardPCActnReplay(shared, act, { aud: AUD, now: bClock }); // B, whose clock is behind, still sees the action as valid
  }

  it('A is ahead of B by exactly the skew bound: A prunes only at exp+skew+1, B has already seen it expire', async () => {
    // B reads EXP (last valid instant) when A reads EXP + skew: A.prune(EXP+skew) frees nothing (record retained until EXP+skew, `until < now` is strict)
    const r = await replayAfterPrune(EXP + PCACTN_MAX_SKEW_MS, EXP);
    expect(r).toMatchObject({ ok: false, code: 'replay' });
  });

  it('one ms beyond the skew bound the nonce CAN be re-accepted (the contract requires pairwise skew <= clockSkewMs)', async () => {
    const r = await replayAfterPrune(EXP + PCACTN_MAX_SKEW_MS + 1, EXP);
    expect(r.ok).toBe(true); // violation of the environment assumption, reproduced; mirrors formal/tla ReplayContract contract_bad_skew
  });
});

describe('nonce + counter are two store calls: partial failure is fail-closed (never accepted twice)', () => {
  it('counter store throws after the nonce was consumed: denied store_unavailable, retry denied as replay (availability cost, no double accept)', async () => {
    const mk = fixture();
    const store = new InMemoryReplayStore();
    let fail = true;
    const counters: CounterStore = { advance: async (k, c) => { if (fail) { fail = false; throw new Error('counter store down'); } return store.advance(k, c); } };
    const act = mk({ nonce: 'n1', counter: 1, iat: NOW, exp: NOW + 60_000 });
    expect(await guardPCActnReplay(store, act, { aud: AUD, now: NOW, counters })).toMatchObject({ ok: false, code: 'store_unavailable' });
    expect(await guardPCActnReplay(store, act, { aud: AUD, now: NOW, counters })).toMatchObject({ ok: false, code: 'replay' });
    // a fresh nonce for the same counter is accepted exactly once
    const again = mk({ nonce: 'n2', counter: 1, iat: NOW, exp: NOW + 60_000 });
    expect((await guardPCActnReplay(store, again, { aud: AUD, now: NOW, counters })).ok).toBe(true);
    expect((await guardPCActnReplay(store, mk({ nonce: 'n3', counter: 1, iat: NOW, exp: NOW + 60_000 }), { aud: AUD, now: NOW, counters })).ok).toBe(false);
  });
});

describe('a storm across several guard servers with a yielding store admits exactly one', () => {
  it('300 racing copies over 4 servers (random async yields inside the store)', async () => {
    const mk = fixture();
    const inner = new InMemoryReplayStore();
    const yielding = {
      consumeOnce: async (k: string, r: number, n: number) => { await new Promise((res) => setTimeout(res, Math.random() * 3)); return inner.consumeOnce(k, r, n); },
      advance: async (k: string, c: number) => { await new Promise((res) => setTimeout(res, Math.random() * 3)); return inner.advance(k, c); },
    };
    const act = mk({ nonce: 'storm', counter: 7, iat: NOW, exp: NOW + 60_000 });
    const res = await Promise.all(Array.from({ length: 300 }, () => guardPCActnReplay(yielding, act, { aud: AUD, now: NOW, counters: yielding })));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
  });
});
