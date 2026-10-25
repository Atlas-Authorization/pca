/**
 * 0.4.2 mutation kills (Stryker run 39706550807): the validated-master-public-key memo. Validation costs a pairing; an unchanged key must
 * be validated once, not per call. The memo is a performance contract (its content is a pure function of the key), so it is pinned by
 * counting the pairings the validation spends.
 */
import { describe, expect, it, vi } from 'vitest';

const counter = vi.hoisted(() => ({ pairings: 0 }));
vi.mock('./bls', async (importOriginal) => {
  const real = await importOriginal<typeof import('./bls')>();
  return {
    ...real,
    pairing: (...a: Parameters<typeof real.pairing>) => {
      counter.pairings++;
      return real.pairing(...a);
    },
  };
});

import { encryptForPolicy, setup } from './abe';

describe('mpk validation memo', () => {
  it('the second use of an unchanged key (even as a fresh object) costs fewer pairings than the first', () => {
    encryptForPolicy(setup().mpk, { attr: 'a' }, 'x'); // warm the one-off generator pairing so only per-key validation is counted
    const { mpk } = setup();
    const p0 = counter.pairings;
    encryptForPolicy(mpk, { attr: 'a' }, 'x');
    const first = counter.pairings - p0;
    const p1 = counter.pairings;
    encryptForPolicy({ ...mpk }, { attr: 'a' }, 'x');
    const second = counter.pairings - p1;
    expect(first).toBeGreaterThan(0);
    expect(second).toBeLessThan(first);
  });
  it('a different key is validated afresh', () => {
    const a = setup().mpk;
    const b = setup().mpk;
    encryptForPolicy(a, { attr: 'a' }, 'x');
    const p = counter.pairings;
    encryptForPolicy(b, { attr: 'a' }, 'x');
    expect(counter.pairings - p).toBeGreaterThan(0);
  });
});
