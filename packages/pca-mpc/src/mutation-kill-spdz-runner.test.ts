/** Mutation-kill suite for spdz-runner.ts: RNG source, dealer options, open labels, result flags. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { composeClear } from './compose';
import { SecureFieldRng } from './csprng';
import { FieldRng } from './field';
import { makeNoDealerOffline } from './mascot';
import type { DecisionVector } from './party';
import { MacCheckAbort, SpdzEngine } from './spdz';
import { composeSecureMalicious } from './spdz-runner';

afterEach(() => vi.restoreAllMocks());

const V: DecisionVector[] = [
  { allow: 1, t: 2, rQuant: 3 },
  { allow: 1, t: 1, rQuant: 1 },
  { allow: 0, t: 3, rQuant: 2 },
];

describe('rng selection', () => {
  it('no seed draws from the secure RNG, never from the seeded FieldRng stream', () => {
    const secure = vi.spyOn(SecureFieldRng.prototype, 'next');
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4 });
    expect(secure).toHaveBeenCalled();
    expect(r.composed).toEqual(composeClear(V, 4));
  });
  it('a seed uses the deterministic stream and never the secure RNG', () => {
    const secure = vi.spyOn(SecureFieldRng.prototype, 'next');
    const base = vi.spyOn(FieldRng.prototype, 'next');
    composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 5n });
    // SecureFieldRng.next overrides FieldRng.next, so base calls here are the seeded ones.
    expect(base).toHaveBeenCalled();
    expect(secure).not.toHaveBeenCalled();
  });
  it('a seeded run is reproducible (same opens and result)', () => {
    const a = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 9n });
    const b = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 9n });
    expect(a).toEqual(b);
  });
});

describe('open labels and counts', () => {
  it('opens carry the documented labels in circuit order', () => {
    const labels: string[] = [];
    const orig = SpdzEngine.prototype.open;
    vi.spyOn(SpdzEngine.prototype, 'open').mockImplementation(function (this: SpdzEngine, x, label) {
      // sacrifice-verification openings run on their own engines; only the circuit engine's labels are pinned
      if (!(label ?? '').startsWith('sacrifice:')) labels.push(label ?? '');
      return orig.call(this, x, label);
    });
    const Q = 4;
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q, seed: 3n });
    const exp: string[] = [];
    for (let i = 1; i < 3; i++) exp.push(`and${i}:d`, `and${i}:e`);
    for (let k = 0; k < 3 + Q; k++) for (let i = 1; i < 3; i++) exp.push(`or${i}:d`, `or${i}:e`);
    exp.push('out:allow');
    for (let k = 0; k < 3; k++) exp.push(`out:t.ge${k + 1}`);
    for (let k = 0; k < Q; k++) exp.push(`out:r.ge${k + 1}`);
    expect(labels).toEqual(exp);
    expect(r.opens).toBe(exp.length);
    expect(r.multiplications).toBe(2 + (3 + Q) * 2);
  });
  it('a single party performs no multiplications and still composes', () => {
    const one: DecisionVector[] = [{ allow: 1, t: 2, rQuant: 3 }];
    const r = composeSecureMalicious(one, { insecureTrustedDealer: true, Q: 4, seed: 1n });
    expect(r.multiplications).toBe(0);
    expect(r.composed).toEqual(composeClear(one, 4));
    const zero: DecisionVector[] = [{ allow: 0, t: 1, rQuant: 0 }];
    expect(composeSecureMalicious(zero, { insecureTrustedDealer: true, Q: 4, seed: 1n }).composed).toEqual(composeClear(zero, 4));
  });
});

describe('dealer options', () => {
  it('partners:1 consumes exactly one sacrifice partner (a bad second-partner delta is ignored)', () => {
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n, dealer: { partners: 1, fault: { partnerCDelta: [undefined, 5n] } } });
    expect(r.composed).toEqual(composeClear(V, 4));
  });
  it('the default two partners catch a bad second-partner delta', () => {
    expect(() => composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n, dealer: { fault: { partnerCDelta: [undefined, 5n] } } })).toThrow(MacCheckAbort);
  });
  it('a lying dealer is caught with verification and passes silently without it', () => {
    const fault = { keepCDelta: 1n };
    expect(() => composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n, dealer: { fault } })).toThrow(MacCheckAbort);
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n, dealer: { verifyTriples: false, fault } });
    expect(r.triplesVerified).toBe(false);
  });
  it('verifyTriples:false without a fault uses plain authenticated triples and is correct', () => {
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n, dealer: { verifyTriples: false } });
    expect(r.composed).toEqual(composeClear(V, 4));
    expect(r.triplesVerified).toBe(false);
  });
  it('defaults report trusted-dealer with verified triples', () => {
    const r = composeSecureMalicious(V, { insecureTrustedDealer: true, Q: 4, seed: 2n });
    expect(r.offlineMode).toBe('trusted-dealer');
    expect(r.triplesVerified).toBe(true);
    expect(r.macChecked).toBe(true);
    expect(r.parties).toBe(3);
    expect(r.Q).toBe(4);
  });
});

describe('no-dealer offline', () => {
  it('reports no-dealer with certified triples and a correct result', () => {
    const two: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 2 },
      { allow: 1, t: 3, rQuant: 1 },
    ];
    const r = composeSecureMalicious(two, { Q: 4, seed: 1n, offline: makeNoDealerOffline(2, 70n), dealer: { verifyTriples: false } });
    expect(r.offlineMode).toBe('no-dealer');
    expect(r.triplesVerified).toBe(true);
    expect(r.composed).toEqual(composeClear(two, 4));
  }, 180_000);
  it('rejects an offline provider with a different party count', () => {
    expect(() => composeSecureMalicious(V, { Q: 4, offline: makeNoDealerOffline(2, 1n) })).toThrow(/party count/);
  }, 180_000);
});
