import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { InMemoryReplayStore, guardPCActnReplay, type CounterStore, type ReplayStore } from '../../pca/src/replay';
import { VerifiedReplayStoreModel } from '../src';
import { Rng } from './support/corpus';
import { guardPCActnReplay as guardPCActnReplayLegacy } from './support/legacy/replay';

const NOW = 1_700_000_000_000;
const base = (): any => ({
  ver: 2,
  grant_ref: 'g1',
  cap_chain: [{ holder: 'h1' }],
  aud: 'rs',
  iat: NOW - 1000,
  exp: NOW + 100_000,
  counter: 5,
  nonce: 'n-1',
});
const JUNK: unknown[] = [undefined, null, 0, -0, 1, -1, 1.5, NaN, Infinity, '', 'x', 'é', '\ud800', 'a'.repeat(600), [], {}, true, 2 ** 60];

function mutate(p: any, r: Rng): any {
  const x = structuredClone(p);
  for (let k = 0, n = r.next(3); k < n; k++) {
    switch (r.next(9)) {
      case 0:
        x[r.pick(['aud', 'iat', 'exp', 'counter', 'nonce', 'grant_ref'])] = r.pick(JUNK);
        break;
      case 1:
        x.cap_chain = r.pick([[], [{ holder: 5 }], [{ holder: '' }], [{ holder: 'a'.repeat(600) }], 'x', undefined, [{ holder: 'h\ud800' }]]);
        break;
      case 2:
        x.iat = NOW + r.pick([0, 59_999, 60_000, 60_001, 1_000_000]);
        x.exp = x.iat + r.pick([1, 3_600_000, 3_600_001]);
        break;
      case 3:
        x.exp = NOW + r.pick([-2, -1, 0, 1]);
        x.iat = x.exp - r.pick([1, 10, 3_600_000, 3_600_001]);
        break;
      case 4:
        delete x[r.pick(['nonce', 'aud', 'counter', 'grant_ref'])];
        break;
      case 5:
        x.nonce = r.pick(['', 'n'.repeat(128), 'n'.repeat(129), 'é'.repeat(65), 'ok']);
        break;
      default:
        break;
    }
  }
  return r.next(20) === 0 ? r.pick(JUNK) : x;
}

/** A store pair whose answers are scripted so both guards see identical store behaviour. */
function scripted(r: Rng) {
  const consume = r.pick([true, true, false, 'throw'] as const);
  const advance = r.pick([true, true, false, 'throw'] as const);
  const calls: string[] = [];
  const store: ReplayStore = {
    async consumeOnce(k, ret, now) {
      calls.push(`c:${k.slice(0, 12)}:${ret}:${now}`);
      if (consume === 'throw') throw new Error('boom');
      return consume;
    },
  };
  const counters: CounterStore = {
    async advance(k, c) {
      calls.push(`a:${k.slice(0, 14)}:${c}`);
      if (advance === 'throw') throw new Error('boom2');
      return advance;
    },
  };
  return { store, counters, calls };
}

describe('differential: guardPCActnReplay (TS) (production, verified core) vs legacy (frozen TS)', () => {
  it('agrees (verdict, code, reason, and the exact store calls) on 6000 random PCActns/options/store answers', async () => {
    let allowed = 0;
    let denied = 0;
    await fc.assert(
      fc.asyncProperty(fc.array(fc.nat(), { minLength: 6, maxLength: 24 }), async (pool) => {
        const r = new Rng(pool);
        const p = mutate(base(), r);
        const opts: any = { aud: r.pick(['rs', 'rs', 'other', '', 5]), now: r.pick([NOW, NOW, NOW + 200_000, NOW - 70_000, 1.5, NaN]) };
        if (r.bool()) opts.clockSkewMs = r.pick([0, 1000, 60_000, 90_000, -1, NaN, 5000]);
        if (r.bool()) opts.requireNonce = r.pick([true, false]);
        const s1 = scripted(new Rng(pool.slice(3)));
        const s2 = scripted(new Rng(pool.slice(3)));
        const useCounters = r.bool();
        const a = await guardPCActnReplayLegacy(s1.store, p, { ...opts, ...(useCounters ? { counters: s1.counters } : {}) });
        const b = await guardPCActnReplay(s2.store, p, { ...opts, ...(useCounters ? { counters: s2.counters } : {}) });
        expect(b).toEqual(a);
        expect(s2.calls).toEqual(s1.calls);
        if (a.ok) allowed++; else denied++;
      }),
      { numRuns: 6000 },
    );
    expect(allowed).toBeGreaterThan(50);
    expect(denied).toBeGreaterThan(1000);
  });

  it('InMemoryReplayStore agrees with the verified store model under random op sequences (monotone clock)', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(fc.nat(), { minLength: 20, maxLength: 120 }), fc.integer({ min: 1, max: 6 }), async (pool, cap) => {
        const real = new InMemoryReplayStore({ maxEntries: cap });
        const model = new VerifiedReplayStoreModel(cap);
        const r = new Rng(pool);
        let now = 1000;
        for (let i = 0; i < 60; i++) {
          now += r.next(40);
          const key = r.pick(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
          switch (r.next(4)) {
            case 0:
            case 1: {
              const retain = now + r.next(150) - (r.next(20) === 0 ? 200 : 0);
              let a: string;
              try {
                a = (await real.consumeOnce(key, retain, now)) ? 'accepted' : 'dup';
              } catch {
                a = 'rejected';
              }
              expect(model.consumeOnce(key, retain, now)).toBe(a);
              break;
            }
            case 2:
              real.prune(now);
              model.prune(now);
              expect(model.size).toBe(real.size);
              break;
            default: {
              const c = r.next(30);
              let a: string;
              try {
                a = (await real.advance('s' + key, c)) ? 'accepted' : 'dup';
              } catch {
                a = 'rejected';
              }
              expect(model.advance('s' + key, c)).toBe(a);
            }
          }
        }
      }),
      { numRuns: 400 },
    );
  });
});
