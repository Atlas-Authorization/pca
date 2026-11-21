/**
 * r13 mutation kills for ha.ts: the staleness boundary, quorum status boundaries, and the exact signer / failover order
 * (weight desc, then lastSeen desc, then id asc; a missing weight is 0).
 */
import { describe, expect, it } from 'vitest';
import { failoverPlan, liveGuardians, quorumStatus, selectSigners, validateGuardianSet, type GuardianHealth } from './ha';

const G = (id: string, lastSeen: number, weight?: number, healthy = true): GuardianHealth => ({ id, healthy, lastSeen, ...(weight !== undefined ? { weight } : {}) });
const NOW = 1_000_000;

describe('liveness and quorum', () => {
  it('a guardian seen exactly staleMs ago is live', () => {
    expect(liveGuardians({ guardians: [G('a', NOW - 30_000), G('b', NOW - 30_001)], quorum: 1 }, NOW).map((g) => g.id)).toEqual(['a']);
  });
  it('status boundaries', () => {
    const set = (n: number, quorum: number) => ({ guardians: Array.from({ length: 3 }, (_, i) => G(`g${i}`, NOW, undefined, i < n)), quorum });
    expect(quorumStatus(set(2, 2), NOW)).toEqual({ total: 3, live: 2, quorum: 2, available: true, degraded: false });
    expect(quorumStatus(set(1, 2), NOW)).toEqual({ total: 3, live: 1, quorum: 2, available: false, degraded: true });
    expect(quorumStatus(set(0, 2), NOW)).toEqual({ total: 3, live: 0, quorum: 2, available: false, degraded: false });
    expect(quorumStatus(set(0, 0), NOW)).toEqual({ total: 3, live: 0, quorum: 0, available: false, degraded: false });
  });
  it('selectSigners needs at least quorum live guardians', () => {
    expect(selectSigners({ guardians: [G('a', NOW), G('b', NOW)], quorum: 2 }, NOW)).toEqual(['a', 'b']);
    expect(selectSigners({ guardians: [G('a', NOW), G('b', NOW, undefined, false)], quorum: 2 }, NOW)).toEqual([]);
  });
  it('validateGuardianSet accepts quorum 1', () => {
    expect(validateGuardianSet({ guardians: [G('a', NOW)], quorum: 1 })).toBeNull();
    expect(validateGuardianSet({ guardians: [G('a', NOW)], quorum: 0 })).toBe('quorum must be an integer ≥ 1');
  });
});

describe('ordering', () => {
  // expected order: w3 (weight 3), w2 (weight 2), then weight-1 by lastSeen desc (s300, s200), then ids asc on ties, then unweighted
  const guardians = [G('z0', NOW - 10), G('s200', NOW - 200, 1), G('w2', NOW - 900, 2), G('tieB', NOW - 500, 1), G('s300', NOW - 100, 1), G('tieA', NOW - 500, 1), G('w3', NOW - 999, 3), G('y0', NOW - 10)];
  const expected = ['w3', 'w2', 's300', 's200', 'tieA', 'tieB', 'y0', 'z0'];
  it('failoverPlan orders by weight, recency, then id', () => {
    expect(failoverPlan({ guardians, quorum: 1 }, NOW)).toEqual({ primary: 'w3', standbys: expected.slice(1) });
    expect(failoverPlan({ guardians: [...guardians].reverse(), quorum: 1 }, NOW)).toEqual({ primary: 'w3', standbys: expected.slice(1) });
    expect(failoverPlan({ guardians: [], quorum: 1 }, NOW)).toEqual({ primary: null, standbys: [] });
  });
  it('selectSigners takes the first quorum in that order', () => {
    expect(selectSigners({ guardians, quorum: 8 }, NOW)).toEqual(expected);
    expect(selectSigners({ guardians: [...guardians].reverse(), quorum: 8 }, NOW)).toEqual(expected);
    expect(selectSigners({ guardians, quorum: 3 }, NOW)).toEqual(expected.slice(0, 3));
  });
});
