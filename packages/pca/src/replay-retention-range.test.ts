import { describe, expect, it } from 'vitest';
import { InMemoryReplayStore, guardPCActnReplay, type ReplayStore } from './replay';

const MAXS = Number.MAX_SAFE_INTEGER;
const pa = (exp: number, extra: Record<string, unknown> = {}): never =>
  ({ ver: 2, grant_ref: 'g1', cap_chain: [{ holder: 'h1' }], aud: 'rs', iat: exp - 1000, exp, counter: 1, nonce: 'n1', ...extra }) as never;
const recording = () => {
  const calls: number[] = [];
  const store: ReplayStore = { async consumeOnce(_k, retain) { calls.push(retain); return true; } };
  return { store, calls };
};

describe('retention horizon exp + skew never leaves the safe-integer range', () => {
  it('exp within skew of 2^53: denied closed BEFORE any store call (a rounded horizon could free a live nonce)', async () => {
    for (const exp of [MAXS - 59_999, MAXS - 1, MAXS]) {
      const { store, calls } = recording();
      const v = await guardPCActnReplay(store, pa(exp), { aud: 'rs', now: exp - 500 });
      expect(v.ok, String(exp)).toBe(false);
      expect(v.ok === false && v.code).toBe('malformed');
      expect(calls).toEqual([]);
    }
  });
  it('a small configured skew keeps near-limit expiries usable; the horizon passed to the store is exact', async () => {
    const exp = MAXS - 100;
    const { store, calls } = recording();
    const v = await guardPCActnReplay(store, pa(exp), { aud: 'rs', now: exp - 500, clockSkewMs: 100 });
    expect(v.ok).toBe(true);
    expect(calls).toEqual([MAXS]);
  });
  it('safe-range behaviour is unchanged', async () => {
    const s = new InMemoryReplayStore();
    const exp = 1_800_000_000_000;
    expect((await guardPCActnReplay(s, pa(exp), { aud: 'rs', now: exp - 500 })).ok).toBe(true);
    const again = await guardPCActnReplay(s, pa(exp), { aud: 'rs', now: exp - 400 });
    expect(again.ok).toBe(false);
  });
});
