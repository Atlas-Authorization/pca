import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./deps', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./deps')>();
  return {
    ...actual,
    diffPolicies: vi.fn(actual.diffPolicies),
    diffGate: vi.fn(actual.diffGate),
    runPolicyTests: vi.fn(actual.runPolicyTests),
    coverage: vi.fn(actual.coverage),
    coverageGate: vi.fn(actual.coverageGate),
  };
});

import { coverage, coverageGate, diffGate, diffPolicies, runPolicyTests } from './deps';
import { coverageCommand, diffCommand, testCommand, toAnalyzerPolicy } from './authoring';

const P = { predicates: [{ verb: 'a.b', resource: '/x' }], caveats: [] };
const SHAPE = 'unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })';
const ACTION = { verb: 'a.b', resource: '/x' };
const TRAFFIC_MSG = 'traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document';

beforeEach(() => {
  vi.mocked(diffPolicies).mockClear();
  vi.mocked(diffGate).mockClear();
  vi.mocked(runPolicyTests).mockClear();
  vi.mocked(coverage).mockClear();
  vi.mocked(coverageGate).mockClear();
});

describe('toAnalyzerPolicy', () => {
  it('passes vetoes and tighten through only when they are arrays', () => {
    const plain = toAnalyzerPolicy(P);
    expect(plain).toStrictEqual({ ok: true, policy: { predicates: P.predicates, caveats: [] } });
    const vetoes = [{ id: 'v' }];
    const tighten = [{ id: 't' }];
    expect(toAnalyzerPolicy({ ...P, vetoes })).toStrictEqual({ ok: true, policy: { predicates: P.predicates, caveats: [], vetoes } });
    expect(toAnalyzerPolicy({ ...P, tighten })).toStrictEqual({ ok: true, policy: { predicates: P.predicates, caveats: [], tighten } });
    expect(toAnalyzerPolicy({ ...P, vetoes, tighten })).toStrictEqual({ ok: true, policy: { predicates: P.predicates, caveats: [], vetoes, tighten } });
    expect(toAnalyzerPolicy({ ...P, vetoes: 'x', tighten: {} })).toStrictEqual({ ok: true, policy: { predicates: P.predicates, caveats: [] } });
  });
  it('refuses an unusable document with the reason', () => {
    expect(toAnalyzerPolicy(5)).toEqual({ ok: false, reason: SHAPE });
  });
});

describe('diffCommand', () => {
  it('reports which side is unusable', () => {
    expect(diffCommand(5, P)).toEqual({ ok: false, exitCode: 2, lines: [`old policy: ${SHAPE}`] });
    expect(diffCommand(P, 5)).toEqual({ ok: false, exitCode: 2, lines: [`new policy: ${SHAPE}`] });
  });

  const fakeDiff = (over: object) => ({ equivalent: false, shifts: {}, widens: false, narrows: false, summary: [], ...over }) as never;

  it('passes only the exposure options that were given, to the analyzer', () => {
    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({}));
    diffCommand(P, P);
    expect(vi.mocked(diffPolicies).mock.calls[0]).toStrictEqual([{ predicates: P.predicates, caveats: [] }, { predicates: P.predicates, caveats: [] }, {}]);

    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({}));
    diffCommand(P, P, { verb: 'pay' });
    expect(vi.mocked(diffPolicies).mock.calls[1]![2]).toStrictEqual({ exposure: { verb: 'pay' } });

    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({}));
    diffCommand(P, P, { verb: 'pay', amountField: 'amt', integer: true, windowSecs: 0 });
    expect(vi.mocked(diffPolicies).mock.calls[2]![2]).toStrictEqual({ exposure: { verb: 'pay', amountField: 'amt', integer: true, windowSecs: 0 } });

    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({}));
    diffCommand(P, P, { verb: 'pay', integer: false, windowSecs: 60 });
    expect(vi.mocked(diffPolicies).mock.calls[3]![2]).toStrictEqual({ exposure: { verb: 'pay', windowSecs: 60 } });

    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({}));
    diffCommand(P, P, { amountField: 'amt', integer: true, windowSecs: 5 });
    expect(vi.mocked(diffPolicies).mock.calls[4]![2]).toStrictEqual({});
  });

  it('passes the widen and exposure allowance to the gate, naming only what was given', () => {
    const d = fakeDiff({});
    vi.mocked(diffPolicies).mockReturnValueOnce(d);
    diffCommand(P, P);
    expect(vi.mocked(diffGate).mock.calls[0]).toStrictEqual([d, { widen: false }]);
    vi.mocked(diffPolicies).mockReturnValueOnce(d);
    diffCommand(P, P, { allowWiden: true, maxExposureIncrease: 0 });
    expect(vi.mocked(diffGate).mock.calls[1]).toStrictEqual([d, { widen: true, maxExposureIncrease: 0 }]);
    vi.mocked(diffPolicies).mockReturnValueOnce(d);
    diffCommand(P, P, { allowWiden: false, maxExposureIncrease: 7 });
    expect(vi.mocked(diffGate).mock.calls[2]).toStrictEqual([d, { widen: false, maxExposureIncrease: 7 }]);
  });

  it('prints the equivalent line, the summary, or a fallback, then the verdict', () => {
    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({ equivalent: true, summary: ['ignored'] }));
    expect(diffCommand(P, P)).toEqual({ ok: true, exitCode: 0, lines: ['no change in what is admitted', 'PASS'] });
    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({ summary: ['deny->allow: 1+ action(s)', 'allow->deny: 2+ action(s)'] }));
    expect(diffCommand(P, P, { allowWiden: true })).toEqual({ ok: true, exitCode: 0, lines: ['deny->allow: 1+ action(s)', 'allow->deny: 2+ action(s)', 'PASS'] });
    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({ summary: [] }));
    expect(diffCommand(P, P, { allowWiden: true })).toEqual({ ok: true, exitCode: 0, lines: ['no witness found', 'PASS'] });
  });

  it('a failing gate lists each reason and ends FAIL with exit 1', () => {
    vi.mocked(diffPolicies).mockReturnValueOnce(fakeDiff({ summary: ['deny->allow: 1+ action(s)'] }));
    vi.mocked(diffGate).mockReturnValueOnce({ ok: false, reasons: ['widens authority: x', 'max exposure rises by 3'] });
    expect(diffCommand(P, P)).toEqual({ ok: false, exitCode: 1, lines: ['deny->allow: 1+ action(s)', 'FAIL: widens authority: x', 'FAIL: max exposure rises by 3', 'FAIL'] });
  });
});

describe('testCommand', () => {
  const DOC = { kind: 'pca-policy-tests', cases: [] };
  const run = (over: object) => ({ total: 0, passed: 0, failures: [], digestMatch: true, ok: true, ...over }) as never;

  it('reports an unusable policy and a document that is not a test document', () => {
    expect(testCommand(5, DOC)).toEqual({ ok: false, exitCode: 2, lines: [`policy: ${SHAPE}`] });
    const bad = { ok: false, exitCode: 2, lines: ['tests: not a pca-policy-tests document'] };
    expect(testCommand(P, null)).toEqual(bad);
    expect(testCommand(P, 5)).toEqual(bad);
    expect(testCommand(P, [])).toEqual(bad);
    expect(testCommand(P, { kind: 'other', cases: [] })).toEqual(bad);
    expect(testCommand(P, { kind: 'pca-policy-tests' })).toEqual(bad);
    expect(testCommand(P, { kind: 'pca-policy-tests', cases: 'x' })).toEqual(bad);
    vi.mocked(runPolicyTests).mockReturnValueOnce(run({}));
    expect(testCommand(P, DOC).exitCode).toBe(0);
  });

  it('passes requireDigest to the runner only when given', () => {
    for (const o of [undefined, { requireDigest: false }, { requireDigest: true }]) {
      vi.mocked(runPolicyTests).mockReturnValueOnce(run({}));
      testCommand(P, DOC, o);
    }
    const args = vi.mocked(runPolicyTests).mock.calls.map((c) => c[2]);
    expect(args).toStrictEqual([{}, { requireDigest: false }, { requireDigest: true }]);
    expect(vi.mocked(runPolicyTests).mock.calls[0]![1]).toBe(DOC);
  });

  it('prints one line per failure, with the expected clause when asserted', () => {
    vi.mocked(runPolicyTests).mockReturnValueOnce(
      run({
        total: 3,
        passed: 1,
        ok: false,
        failures: [
          { name: 'n1', expected: 'deny', expectedDecidedBy: 'permit[0]', got: 'allow', decidedBy: null },
          { name: 'n2', expected: 'allow', got: 'deny', decidedBy: 'veto-1' },
        ],
      }),
    );
    expect(testCommand(P, DOC)).toEqual({
      ok: false,
      exitCode: 1,
      lines: ['FAIL n1: expected deny by permit[0], got allow by no clause', 'FAIL n2: expected allow, got deny by veto-1', '1/3 examples FAIL'],
    });
  });

  it('a digest mismatch is a note, or a FAIL when the digest is required; a match prints nothing', () => {
    vi.mocked(runPolicyTests).mockReturnValueOnce(run({ total: 2, passed: 2, digestMatch: false }));
    expect(testCommand(P, DOC)).toEqual({
      ok: true,
      exitCode: 0,
      lines: ['note: the policy differs from the one the examples were confirmed against', '2/2 examples PASS'],
    });
    vi.mocked(runPolicyTests).mockReturnValueOnce(run({ total: 2, passed: 2, digestMatch: false, ok: false }));
    expect(testCommand(P, DOC, { requireDigest: true })).toEqual({
      ok: false,
      exitCode: 1,
      lines: ['FAIL: the policy differs from the one the examples were confirmed against', '2/2 examples FAIL'],
    });
    vi.mocked(runPolicyTests).mockReturnValueOnce(run({ total: 2, passed: 2, digestMatch: true }));
    expect(testCommand(P, DOC, { requireDigest: true }).lines).toEqual(['2/2 examples PASS']);
  });
});

describe('coverageCommand', () => {
  const report = (over: object = {}) =>
    ({
      score: { clauses: 0.5, boundaries: 0.25, mutation: 0.75 },
      mutants: { killed: 3, total: 6, equivalent: 1, survivors: [] },
      untested: [],
      unreachable: [],
      ...over,
    }) as never;

  it('refuses an unusable policy', () => {
    expect(coverageCommand(5, [ACTION])).toEqual({ ok: false, exitCode: 2, lines: [`policy: ${SHAPE}`] });
  });

  it('refuses traffic that is not a list of actions or a test document, without throwing', () => {
    const bad = { ok: false, exitCode: 2, lines: [TRAFFIC_MSG] };
    expect(coverageCommand(P, null)).toEqual(bad);
    expect(coverageCommand(P, undefined)).toEqual(bad);
    expect(coverageCommand(P, 5)).toEqual(bad);
    expect(coverageCommand(P, {})).toEqual(bad);
    expect(coverageCommand(P, { cases: 'x' })).toEqual(bad);
    expect(coverageCommand(P, { cases: [5] })).toEqual(bad);
    expect(coverageCommand(P, { cases: [null] })).toEqual(bad);
    expect(coverageCommand(P, { cases: [[]] })).toEqual(bad);
    expect(coverageCommand(P, [5])).toEqual(bad);
    expect(coverageCommand(P, [null])).toEqual(bad);
    expect(coverageCommand(P, [[]])).toEqual(bad);
    // one good action next to a bad one is still refused (every action must be valid)
    expect(coverageCommand(P, [ACTION, 5])).toEqual(bad);
    expect(coverageCommand(P, [ACTION, { verb: 1, resource: '/x' }])).toEqual(bad);
    expect(coverageCommand(P, [ACTION, { verb: 'a.b' }])).toEqual(bad);
    expect(coverageCommand(P, [ACTION, { verb: 'a.b', resource: 1 }])).toEqual(bad);
    expect(coverageCommand(P, [{ resource: '/x' }, ACTION])).toEqual(bad);
    expect(vi.mocked(coverage)).not.toHaveBeenCalled();
  });

  it('reads the traffic from an array or from the cases of a test document', () => {
    vi.mocked(coverage).mockReturnValueOnce(report());
    coverageCommand(P, [ACTION]);
    expect(vi.mocked(coverage).mock.calls[0]![1]).toEqual([ACTION]);
    vi.mocked(coverage).mockReturnValueOnce(report());
    coverageCommand(P, { cases: [{ name: 'c', action: ACTION, expect: 'allow' }] });
    expect(vi.mocked(coverage).mock.calls[1]![1]).toEqual([ACTION]);
    expect(vi.mocked(coverage).mock.calls[1]![0]).toStrictEqual({ predicates: P.predicates, caveats: [] });
  });

  it('prints the score line, untested clauses, surviving mutants, gate reasons and the verdict', () => {
    vi.mocked(coverage).mockReturnValueOnce(
      report({
        untested: ['permit[1]', 'permit[2]'],
        mutants: { killed: 3, total: 6, equivalent: 1, survivors: [{ description: 'lte 5 -> lte 6', killer: { verb: 'a.b' } }, { description: 'drop clause' }] },
      }),
    );
    vi.mocked(coverageGate).mockReturnValueOnce({ ok: false, reasons: ['r1', 'r2'] });
    expect(coverageCommand(P, [ACTION])).toEqual({
      ok: false,
      exitCode: 1,
      lines: [
        'clauses decisive 50%, boundaries covered 25%, mutants killed 75% (3/5)',
        'untested: permit[1]',
        'untested: permit[2]',
        'survives: lte 5 -> lte 6 (kill with {"verb":"a.b"})',
        'survives: drop clause',
        'FAIL: r1',
        'FAIL: r2',
        'FAIL',
      ],
    });
    vi.mocked(coverage).mockReturnValueOnce(report());
    vi.mocked(coverageGate).mockReturnValueOnce({ ok: true, reasons: [] });
    expect(coverageCommand(P, [ACTION])).toEqual({ ok: true, exitCode: 0, lines: ['clauses decisive 50%, boundaries covered 25%, mutants killed 75% (3/5)', 'PASS'] });
  });

  it('passes only the thresholds that were given to the gate', () => {
    const r = report();
    const opts: [object, object][] = [
      [{}, {}],
      [{ minClauses: 0, minBoundaries: 0, minMutation: 0, maxSurvivors: 0 }, { clauses: 0, boundaries: 0, mutation: 0, maxSurvivors: 0 }],
      [{ minClauses: 0.9 }, { clauses: 0.9 }],
      [{ minBoundaries: 0.8 }, { boundaries: 0.8 }],
      [{ minMutation: 0.7 }, { mutation: 0.7 }],
      [{ maxSurvivors: 2 }, { maxSurvivors: 2 }],
    ];
    opts.forEach(([given, passed], i) => {
      vi.mocked(coverage).mockReturnValueOnce(r);
      coverageCommand(P, [ACTION], given);
      expect(vi.mocked(coverageGate).mock.calls[i]).toStrictEqual([r, passed]);
    });
  });
});
