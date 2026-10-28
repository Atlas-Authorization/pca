import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateBoundaryTests } from '@atlasauth/pca-analyzer';
import { run } from './cli';
import { coverageCommand, diffCommand, lintPolicy, testCommand, toAnalyzerPolicy } from './index';

const refund = (max: number) => ({ verb: 'stripe.refund', resource: '/acct/*', where: [{ field: 'action.params.amount', op: 'lte' as const, value: max }] });
const policy = (max: number) => ({ predicates: [refund(max)], caveats: [] });

describe('diffCommand', () => {
  it('passes a narrowing and an identical policy, fails a widening with a witness line', () => {
    expect(diffCommand(policy(500), policy(100))).toMatchObject({ ok: true, exitCode: 0 });
    expect(diffCommand(policy(500), policy(500))).toEqual({ ok: true, exitCode: 0, lines: ['no change in what is admitted', 'PASS'] });
    const w = diffCommand(policy(500), policy(900));
    expect(w).toMatchObject({ ok: false, exitCode: 1 });
    expect(w.lines.some((l) => l.startsWith('deny->allow:'))).toBe(true);
    expect(w.lines.at(-1)).toBe('FAIL');
  });

  it('a reviewer can accept a widening, and the exposure gate still bites', () => {
    expect(diffCommand(policy(500), policy(900), { allowWiden: true })).toMatchObject({ ok: true });
    const e = diffCommand(policy(500), policy(900), { allowWiden: true, verb: 'stripe.refund', integer: true });
    expect(e).toMatchObject({ ok: false });
    expect(e.lines).toContain('FAIL: max exposure rises by 400');
    expect(diffCommand(policy(500), policy(900), { allowWiden: true, verb: 'stripe.refund', integer: true, maxExposureIncrease: 400 }).ok).toBe(true);
  });

  it('is exit 2 on an unusable file', () => {
    expect(diffCommand({}, policy(1))).toEqual({ ok: false, exitCode: 2, lines: [expect.stringMatching(/^old policy: unrecognized policy shape/)] });
  });

  it('reads vetoes and tighten rules from the document', () => {
    const withVeto = { ...policy(500), vetoes: [{ id: 'cap', kind: 'deny', when: { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gt', value: 100 }] } }] };
    expect(diffCommand(policy(500), withVeto).ok).toBe(true); // a veto narrows
    expect(diffCommand(withVeto, policy(500)).ok).toBe(false); // dropping it widens
    expect(toAnalyzerPolicy(withVeto)).toMatchObject({ ok: true, policy: { vetoes: [{ id: 'cap' }] } });
  });
});

describe('testCommand and coverageCommand', () => {
  const doc = generateBoundaryTests({ predicates: [refund(500)], caveats: [] });

  it('runs the examples and pins the digest', () => {
    expect(testCommand(policy(500), doc, { requireDigest: true })).toMatchObject({ ok: true, exitCode: 0 });
    const loose = testCommand(policy(501), doc);
    expect(loose.ok).toBe(false);
    expect(loose.lines[0]).toMatch(/^FAIL permit\[0\]: amount above 500: expected deny, got allow by permit\[0\]/);
    expect(testCommand(policy(500), { kind: 'x' })).toEqual({ ok: false, exitCode: 2, lines: ['tests: not a pca-policy-tests document'] });
  });

  it('coverage: the generated examples cover every threshold and kill the mutants', () => {
    const r = coverageCommand(policy(500), doc, { minClauses: 1, minBoundaries: 1, minMutation: 1, maxSurvivors: 0 });
    expect(r).toMatchObject({ ok: true, exitCode: 0 });
    expect(r.lines[0]).toMatch(/^clauses decisive 100%, boundaries covered 100%, mutants killed 100%/);
  });

  it('coverage: thin traffic fails the gate and says what to add', () => {
    const r = coverageCommand(policy(500), [{ verb: 'stripe.refund', resource: '/acct/1', params: { amount: 10 } }], { minMutation: 1, maxSurvivors: 0 });
    expect(r.ok).toBe(false);
    expect(r.lines.some((l) => l.startsWith('survives: '))).toBe(true);
    expect(r.lines.some((l) => l.includes('kill with'))).toBe(true);
    expect(coverageCommand(policy(500), 5)).toMatchObject({ exitCode: 2 });
  });
});

describe('rule schema-mismatch', () => {
  const schema = [{ verb: 'stripe.refund', params: { amount: { type: 'integer' as const, semantic: 'money.amount', max: 1000 } } }];
  it('is off without a schema, on with one', () => {
    const p = { predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amout', op: 'lte', value: 5 }] }], caveats: [{ type: 'expires', at: Date.now() + 1e7 }, { type: 'max_blast_radius', max: 0.1 }] };
    expect(lintPolicy(p).some((f) => f.rule === 'schema-mismatch')).toBe(false);
    const f = lintPolicy(p, { schema }).filter((x) => x.rule === 'schema-mismatch');
    expect(f.map((x) => [x.severity, x.message.split(':')[0]])).toEqual([['error', 'undeclared-param'], ['warn', 'unbounded-money']]);
  });
});

describe('CLI subcommands', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pca-policy-ci-auth-'));
  const file = (n: string, d: unknown) => {
    const p = join(dir, n);
    writeFileSync(p, JSON.stringify(d), 'utf8');
    return p;
  };
  const cap = (argv: string[]) => {
    const lines: string[] = [];
    return { code: run(argv, (s) => lines.push(s)), out: lines.join('\n') };
  };
  const a = file('a.json', policy(500));
  const b = file('b.json', policy(900));

  it('diff exits 1 on a widening, 0 with --allow-widen, 2 on bad usage', () => {
    expect(cap(['diff', a, b])).toMatchObject({ code: 1 });
    expect(cap(['diff', a, b, '--allow-widen']).code).toBe(0);
    expect(cap(['diff', a, b, '--allow-widen', '--verb', 'stripe.refund', '--integer', '--max-exposure-increase', '400']).code).toBe(0);
    expect(cap(['diff', a]).code).toBe(2);
    expect(cap(['diff', a, b, '--nope']).code).toBe(2);
    expect(cap(['diff', a, b, '--max-exposure-increase']).code).toBe(2);
    expect(cap(['diff', a, b, '--max-exposure-increase', 'lots']).code).toBe(2);
    expect(cap(['diff', a, join(dir, 'missing.json')]).code).toBe(2);
  });

  it('test and coverage run from files', () => {
    const tests = file('tests.json', generateBoundaryTests({ predicates: [refund(500)], caveats: [] }));
    expect(cap(['test', a, tests, '--require-digest']).code).toBe(0);
    expect(cap(['test', b, tests]).code).toBe(1);
    expect(cap(['coverage', a, tests, '--min-clauses', '1']).code).toBe(0);
  });

  it('--schema checks each linted policy against an action schema file', () => {
    const schema = file('schema.json', [{ verb: 'stripe.refund', params: { amount: { type: 'integer', max: 1000 } } }]);
    const bad = file('bad.json', { predicates: [{ verb: 'stripe.payout', where: [{ field: 'action.params.amount', op: 'lte', value: 5 }] }], caveats: [{ type: 'expires', at: Date.now() + 1e7 }, { type: 'max_blast_radius', max: 0.1 }] });
    const r = cap([bad, '--schema', schema]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/schema-mismatch.*undeclared-verb/);
    expect(cap([bad, '--schema', join(dir, 'nope.json')]).code).toBe(2);
  });
});
