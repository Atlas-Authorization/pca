import { describe, expect, it } from 'vitest';
import {
  type GuardianSet,
  degradeMode,
  failoverPlan,
  liveGuardians,
  quorumStatus,
  selectSigners,
  validateGuardianSet,
} from './ha';

const set = (overrides: Partial<GuardianSet> = {}): GuardianSet => ({
  quorum: 2,
  guardians: [
    { id: 'g1', healthy: true, lastSeen: 1000, weight: 3 },
    { id: 'g2', healthy: true, lastSeen: 1000, weight: 2 },
    { id: 'g3', healthy: true, lastSeen: 1000, weight: 1 },
  ],
  ...overrides,
});

describe('quorum + liveness', () => {
  it('counts only healthy + fresh guardians as live', () => {
    const now = 100_000;
    const s = set({
      guardians: [
        { id: 'g1', healthy: true, lastSeen: now }, // fresh
        { id: 'g2', healthy: false, lastSeen: now }, // unhealthy
        { id: 'g3', healthy: true, lastSeen: now - 40_000 }, // stale (40s > 30s staleMs)
      ],
    });
    expect(liveGuardians(s, now).map((g) => g.id)).toEqual(['g1']);
    const st = quorumStatus(s, now);
    expect(st.live).toBe(1);
    expect(st.available).toBe(false);
    expect(st.degraded).toBe(true);
  });

  it('available when live ≥ quorum', () => {
    const st = quorumStatus(set(), 1000);
    expect(st.live).toBe(3);
    expect(st.available).toBe(true);
    expect(st.degraded).toBe(false);
  });
});

describe('degradeMode (never fails open)', () => {
  it('normal with quorum, read-only below quorum, halt when none', () => {
    expect(degradeMode(quorumStatus(set(), 1000))).toBe('normal');
    const below = quorumStatus(set({ guardians: [{ id: 'g1', healthy: true, lastSeen: 1000 }] }), 1000);
    expect(degradeMode(below)).toBe('read-only');
    const none = quorumStatus(set({ guardians: [{ id: 'g1', healthy: false, lastSeen: 1000 }] }), 1000);
    expect(degradeMode(none)).toBe('halt');
  });

  it('allowReadOnly:false forces halt below quorum', () => {
    const below = quorumStatus(set({ guardians: [{ id: 'g1', healthy: true, lastSeen: 1000 }] }), 1000);
    expect(degradeMode(below, { allowReadOnly: false })).toBe('halt');
  });
});

describe('signer selection + failover', () => {
  it('selects the quorum freshest/highest-weight signers, or none below quorum', () => {
    expect(selectSigners(set(), 1000)).toEqual(['g1', 'g2']); // top 2 by weight
    const below = set({ quorum: 2, guardians: [{ id: 'g1', healthy: true, lastSeen: 1000 }] });
    expect(selectSigners(below, 1000)).toEqual([]);
  });

  it('failoverPlan orders primary + standbys by preference', () => {
    const plan = failoverPlan(set(), 1000);
    expect(plan.primary).toBe('g1');
    expect(plan.standbys).toEqual(['g2', 'g3']);
    expect(failoverPlan(set({ guardians: [{ id: 'x', healthy: false, lastSeen: 0 }] }), 1000).primary).toBeNull();
  });
});

describe('validateGuardianSet', () => {
  it('accepts a well-formed set and rejects bad ones', () => {
    expect(validateGuardianSet(set())).toBeNull();
    expect(validateGuardianSet(set({ quorum: 0 }))).toMatch(/quorum/);
    expect(validateGuardianSet(set({ quorum: 9 }))).toMatch(/exceeds/);
    expect(validateGuardianSet(set({ guardians: [] }))).toMatch(/empty/);
    expect(
      validateGuardianSet(
        set({ guardians: [{ id: 'dup', healthy: true, lastSeen: 0 }, { id: 'dup', healthy: true, lastSeen: 0 }] }),
      ),
    ).toMatch(/duplicate/);
  });
});
