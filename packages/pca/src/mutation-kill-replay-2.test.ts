/**
 * Second mutation-kill file for replay.ts, written after the guard was rewired onto the verified core: the facts the
 * glue hands the Dafny decision (iatOk) and the exact-bound malformed reasons.
 */
import { describe, expect, it } from 'vitest';
import { PCACTN_MAX_LIFETIME_MS } from './pcactn';
import { guardPCActnReplay, type ReplayStore } from './replay';
import type { PCActn } from './pcactn';

const AUD = 'rs.example';
const store = (): ReplayStore => ({ consumeOnce: async () => true });
const mk = (over: Record<string, unknown>): PCActn =>
  ({ aud: AUD, iat: 0, exp: 0, counter: 1, nonce: 'n', grant_ref: 'g', cap_chain: [{ holder: 'h' }], ...over }) as unknown as PCActn;
const g = (p: PCActn, now: number) => guardPCActnReplay(store(), p, { aud: AUD, now });

describe('replay guard: an invalid iat never reaches the decision as a valid one', () => {
  it('a negative iat is malformed even when exp-iat is a short window around now', async () => {
    const v = await g(mk({ iat: -5, exp: 10 }), 5);
    expect(v).toEqual({ ok: false, code: 'malformed', reason: 'iat / exp are not a valid bounded window' });
  });
  it('a fractional iat is malformed, not silently read as 0', async () => {
    const v = await g(mk({ iat: 1.5, exp: 10 }), 5);
    expect(v).toEqual({ ok: false, code: 'malformed', reason: 'iat / exp are not a valid bounded window' });
  });
  it('the same window with a valid iat is accepted', async () => {
    expect((await g(mk({ iat: 0, exp: 10 }), 5)).ok).toBe(true);
  });
});

describe('replay guard: the lifetime bound is inclusive', () => {
  it('a window of exactly PCACTN_MAX_LIFETIME_MS passes the window check (the next malformed reason is reported)', async () => {
    const v = await g(mk({ iat: 0, exp: PCACTN_MAX_LIFETIME_MS, cap_chain: [] }), 10);
    expect(v).toEqual({ ok: false, code: 'malformed', reason: 'no leaf holder / grant' });
  });
  it('one millisecond more is an invalid window', async () => {
    const v = await g(mk({ iat: 0, exp: PCACTN_MAX_LIFETIME_MS + 1, cap_chain: [] }), 10);
    expect(v).toEqual({ ok: false, code: 'malformed', reason: 'iat / exp are not a valid bounded window' });
  });
  it('a window of exactly PCACTN_MAX_LIFETIME_MS is accepted', async () => {
    expect((await g(mk({ iat: 0, exp: PCACTN_MAX_LIFETIME_MS }), 10)).ok).toBe(true);
  });
});
