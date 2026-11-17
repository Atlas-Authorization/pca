import { describe, expect, it } from 'vitest';
import {
  admissionPolicy,
  DEFAULT_FATIGUE,
  doubleConfirmed,
  etaUnderLoad,
  noiseState,
  SlidingWindowCounter,
  type ConfirmationRecord,
  type NoiseState,
} from './index';

const EMPTY = { falseYes: 0, correctNo: 0, falseNo: 0, correctYes: 0 };

describe('etaUnderLoad argument checks', () => {
  it('rejects each bad argument on its own with the message', () => {
    const msg = 'etaUnderLoad: bad arguments';
    expect(() => etaUnderLoad(-0.1, 0.005, 1)).toThrow(msg);
    expect(() => etaUnderLoad(0.1, -0.005, 1)).toThrow(msg);
    expect(() => etaUnderLoad(0.1, 0.005, 1.5)).toThrow(msg);
    expect(() => etaUnderLoad(0.1, 0.005, -1)).toThrow(msg);
    expect(() => etaUnderLoad(Number.NaN, 0.005, 1)).toThrow(msg);
  });
  it('accepts zero for each argument', () => {
    expect(etaUnderLoad(0, 0, 0)).toBe(0);
    expect(etaUnderLoad(0.1, 0, 5)).toBe(0.1);
    expect(etaUnderLoad(0, 0.25, 4)).toBe(0.5);
    expect(etaUnderLoad(0.1, 0.01, 10)).toBeCloseTo(0.2, 12);
  });
});

describe('noiseState', () => {
  it('caps the false-no bound at one half', () => {
    const s = noiseState({ ...EMPTY, falseNo: 20 }, 0);
    expect(s.etaNegBar).toBe(0.5);
  });
  it('freezes strictly above etaStop, on the mean or the upper bound', () => {
    const mean = noiseState(EMPTY, 3);
    expect(noiseState(EMPTY, 3, { ...DEFAULT_FATIGUE, etaStop: mean.etaPos }).frozen).toBe(false);
    expect(noiseState(EMPTY, 3, { ...DEFAULT_FATIGUE, etaStop: mean.etaPos - 1e-9 }).frozen).toBe(true);
    const up = { ...DEFAULT_FATIGUE, freezeOn: 'upper' as const };
    expect(noiseState(EMPTY, 3, { ...up, etaStop: mean.etaPosBar }).frozen).toBe(false);
    expect(noiseState(EMPTY, 3, { ...up, etaStop: mean.etaPosBar - 1e-9 }).frozen).toBe(true);
  });
});

describe('admissionPolicy', () => {
  const st = (etaPosBar: number, etaNegBar: number): NoiseState => ({ etaPos: 0, etaPosBar, etaNegBar, frozen: false });
  it('rejects delta outside (0, 1) with the message', () => {
    for (const delta of [0, 1, -0.5, 2]) expect(() => admissionPolicy(st(0.1, 0.1), { ...DEFAULT_FATIGUE, delta })).toThrow('admissionPolicy: delta must be in (0, 1)');
    expect(admissionPolicy(st(0.1, 0.1), { ...DEFAULT_FATIGUE, delta: 0.5 }).tau).toBe(0.5);
  });
  it('clamps both learner noises just below one half', () => {
    const p = admissionPolicy(st(0.9, 0.8));
    expect(p.etaPos).toBe(0.5 - 1e-9);
    expect(p.etaNeg).toBe(0.5 - 1e-9);
    expect(p.falseAdmitBound).toBe((0.5 - 1e-9) ** 2);
  });
  it('requires double confirmation only when the noise bound is positive', () => {
    expect(admissionPolicy(st(0, 0))).toEqual({ tau: 1 - DEFAULT_FATIGUE.delta, etaPos: 0, etaNeg: 0, doubleConfirmIrreversible: false, falseAdmitBound: 0 });
    expect(admissionPolicy(st(0.1, 0.2))).toEqual({ tau: 1 - DEFAULT_FATIGUE.delta, etaPos: 0.1, etaNeg: 0.2, doubleConfirmIrreversible: true, falseAdmitBound: 0.1 * 0.1 });
  });
});

describe('SlidingWindowCounter', () => {
  it('rejects a window that is not a positive integer', () => {
    for (const w of [0, -1, 1.5, Number.NaN]) expect(() => new SlidingWindowCounter(w)).toThrow('SlidingWindowCounter: windowMs must be a positive integer');
    expect(new SlidingWindowCounter(1).windowMs).toBe(1);
  });
  it('drops an event exactly windowMs old, keeps a newer one', () => {
    const c = new SlidingWindowCounter(1000);
    expect(c.tryAdd(0, 5)).toBe(true);
    expect(c.count(999)).toBe(1);
    expect(c.count(1000)).toBe(0);
  });
  it('tryAdd prunes expired events before applying the cap', () => {
    const c = new SlidingWindowCounter(1000);
    expect(c.tryAdd(0, 1)).toBe(true);
    expect(c.tryAdd(500, 1)).toBe(false);
    expect(c.tryAdd(5000, 1)).toBe(true);
  });
  it('refuses time going backwards', () => {
    const c = new SlidingWindowCounter(1000);
    c.tryAdd(100, 5);
    expect(() => c.tryAdd(50, 5)).toThrow('SlidingWindowCounter: time went backwards');
    expect(c.tryAdd(100, 5)).toBe(true);
  });
});

describe('doubleConfirmed', () => {
  const r = (screen: number, tier: ConfirmationRecord['tier'] = 'typed'): ConfirmationRecord => ({ screen, tier });
  it('needs two strong confirmations at least two screens apart, in any input order', () => {
    expect(doubleConfirmed([r(0), r(2)])).toBe(true);
    expect(doubleConfirmed([r(0), r(1)])).toBe(false);
    expect(doubleConfirmed([r(9), r(6), r(3), r(0, 'device')])).toBe(true);
    expect(doubleConfirmed([r(5), r(0)])).toBe(true);
    expect(doubleConfirmed([r(0), r(3, 'device')])).toBe(true);
  });
  it('ignores tap and hold answers', () => {
    expect(doubleConfirmed([r(0), r(4, 'tap')])).toBe(false);
    expect(doubleConfirmed([r(0), r(4, 'hold')])).toBe(false);
    expect(doubleConfirmed([r(0, 'tap'), r(4, 'hold')])).toBe(false);
    expect(doubleConfirmed([])).toBe(false);
  });
});
