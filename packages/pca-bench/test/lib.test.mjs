import { describe, expect, it } from 'vitest';
import { gate, mannWhitneyGreaterP, mergeRuns, summarize } from '../lib.mjs';

const run = (rounds, over = {}) => ({
  schema: 'pca-bench-result/1',
  lang: 't',
  corpus: { digest: 'd' },
  runner: { os: 'linux', arch: 'x64', cpu: 'c' },
  scenarios: [{ id: 'verify.x', status: 'ok', rounds_ns: rounds, mean_ns: 1, p50_ns: 1, p95_ns: 1, p99_ns: 1, ops_per_sec: 1 }],
  ...over,
});

describe('mannWhitneyGreaterP', () => {
  it('is exact for fully separated samples (1 / C(10,5))', () => {
    expect(mannWhitneyGreaterP([6, 7, 8, 9, 10], [1, 2, 3, 4, 5])).toBeCloseTo(1 / 252, 10);
  });
  it('is 1 for the reverse and about one half for identical samples', () => {
    expect(mannWhitneyGreaterP([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])).toBe(1);
    expect(mannWhitneyGreaterP([1, 2, 3, 4, 5], [1, 2, 3, 4, 5])).toBeGreaterThan(0.5);
  });
  it('is deterministic', () => {
    const a = [3, 1, 4, 1, 5, 9, 2, 6];
    const b = [2, 7, 1, 8, 2, 8, 1, 8];
    expect(mannWhitneyGreaterP(a, b)).toBe(mannWhitneyGreaterP(a, b));
  });
});

describe('summarize', () => {
  it('computes percentiles and splits time-ordered rounds', () => {
    const s = summarize(Array.from({ length: 700 }, (_, i) => i + 1), 7);
    expect(s.p50_ns).toBe(350);
    expect(s.p99_ns).toBe(693);
    expect(s.rounds_ns).toHaveLength(7);
    expect(s.rounds_ns[0]).toBe(50.5);
  });
  it('rejects an empty sample', () => expect(() => summarize([])).toThrow());
});

describe('gate', () => {
  const base = run([100, 101, 99, 100, 102]);
  it('passes with a notice when there is no baseline', () => {
    const r = gate(null, run([500, 500, 500, 500, 500]));
    expect(r.verdict).toBe('pass');
    expect(r.notices[0]).toMatch(/no baseline yet/);
  });
  it('fails a clear, significant regression', () => {
    expect(gate(base, run([150, 151, 149, 150, 152])).verdict).toBe('fail');
  });
  it('passes ordinary noise around the baseline', () => {
    expect(gate(base, run([105, 98, 110, 97, 103])).verdict).toBe('pass');
  });
  it('never fails on one slow round among fast ones', () => {
    expect(gate(base, run([100, 101, 400, 99, 100])).verdict).toBe('pass');
  });
  it('does not judge a regression with too few rounds', () => {
    expect(gate(base, run([300, 300, 300])).verdict).toBe('pass');
  });
  it('skips the comparison on different hardware or a different corpus (notice, no failure)', () => {
    expect(gate(base, run([300, 300, 300, 300, 300], { runner: { os: 'linux', arch: 'x64', cpu: 'other' } })).verdict).toBe('pass');
    expect(gate(base, run([300, 300, 300, 300, 300], { corpus: { digest: 'e' } })).verdict).toBe('pass');
  });
  it('fails a scenario that used to run and now errors, or went missing', () => {
    const err = run([], {});
    err.scenarios[0] = { id: 'verify.x', status: 'error', note: 'boom' };
    expect(gate(base, err).verdict).toBe('fail');
    expect(gate(base, run([], { scenarios: [] })).verdict).toBe('fail');
  });
  it('fails a deny path that is slower than the allow path it pairs with, even with no baseline', () => {
    const c = run([], {});
    c.scenarios = [
      { id: 'verify.a', status: 'ok', rounds_ns: [100, 101, 99, 100, 102] },
      { id: 'deny.a', status: 'ok', pair: 'verify.a', rounds_ns: [200, 201, 199, 200, 202] },
    ];
    expect(gate(null, c).verdict).toBe('fail');
    c.scenarios[1].rounds_ns = [40, 41, 39, 40, 42];
    expect(gate(null, c).verdict).toBe('pass');
  });
});

describe('mergeRuns', () => {
  it('pools rounds of repeated runs', () => {
    const m = mergeRuns([run([1, 2, 3, 4, 5]), run([6, 7, 8, 9, 10])]);
    expect(m.scenarios[0].rounds_ns).toHaveLength(10);
    expect(m.repeats).toBe(2);
  });
});
