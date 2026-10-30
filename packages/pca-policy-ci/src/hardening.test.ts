import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { run } from './cli';
import { lint, lintChain, lintPolicies, lintPolicy, summarize } from './index';

const dir = mkdtempSync(join(tmpdir(), 'pcaci-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const file = (name: string, body: unknown) => {
  const p = join(dir, name);
  writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body));
  return p;
};
const CLEAN = { predicates: [{ verb: 'read', resource: '/docs/*' }], caveats: [{ type: 'expires', at: 4_000_000_000_000 }, { type: 'rate', max: 5, per_secs: 60 }] };
const out = (argv: string[]) => {
  const lines: string[] = [];
  const code = run(argv, (s) => lines.push(s));
  return { code, text: lines.join('\n') };
};

describe('a gate that linted nothing does not pass', () => {
  it('an empty list is exit code 2 with a reason', () => {
    expect(summarize([])).toEqual({ results: [], counts: { error: 0, warn: 0, info: 0 }, maxSeverity: 'error', ok: false, exitCode: 2, reason: 'no policies were linted' });
    expect(lintPolicies([])).toMatchObject({ ok: false, exitCode: 2 });
    expect(summarize(null as never)).toMatchObject({ ok: false, exitCode: 2 });
  });
  it('one clean policy still passes', () => {
    const s = lintPolicies([{ policy: CLEAN }]);
    expect(s.ok).toBe(true);
    expect(s.exitCode).toBe(0);
    expect(s.reason).toBeUndefined();
  });
  it('the CLI with no files is a usage error', () => {
    expect(out([]).code).toBe(2);
  });
});

describe('an unknown threshold cannot pass everything', () => {
  it.each([['none'], ['ERROR'], [''], ['toString'], ['__proto__']])('maxSeverity %j is refused', (v) => {
    expect(() => summarize([{ label: 'x', findings: [{ rule: 'malformed-policy', severity: 'error', message: 'm' }] }], { maxSeverity: v as never })).toThrow('summarize: maxSeverity must be one of info, warn, error');
  });
  it('the three real thresholds', () => {
    const f = (severity: 'error' | 'warn' | 'info') => [{ label: 'x', findings: [{ rule: 'redundant-caveat' as const, severity, message: 'm' }] }];
    expect(summarize(f('warn')).ok).toBe(true);
    expect(summarize(f('warn'), { maxSeverity: 'warn' }).ok).toBe(false);
    expect(summarize(f('info'), { maxSeverity: 'info' }).exitCode).toBe(1);
    expect(summarize(f('error')).exitCode).toBe(1);
  });
});

describe('a finding with an unknown severity counts as an error', () => {
  it.each([['fatal'], [''], [undefined], ['toString']])('%j', (severity) => {
    const s = summarize([{ label: 'x', findings: [{ rule: 'redundant-caveat', severity: severity as never, message: 'm' }] }], { maxSeverity: 'error' });
    expect([s.ok, s.exitCode, s.counts]).toEqual([false, 1, { error: 1, warn: 0, info: 0 }]);
  });
});

describe('malformed input is an error finding, never a pass or a crash', () => {
  it.each([[null], [undefined], [5], ['x'], [{}], [{ predicates: 'x' }]])('%j', (input) => {
    const f = lint(input);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.severity).toBe('error');
    expect(f[0]?.rule).toBe('malformed-policy');
  });
  it('a chain with a non-policy hop, and an empty chain', () => {
    expect(lintChain([CLEAN, 5]).some((f) => f.rule === 'malformed-policy' && f.severity === 'error')).toBe(true);
    expect(lintChain([]).some((f) => f.severity === 'error')).toBe(true);
  });
  it('a rule that throws is an internal-error finding', () => {
    const poisoned = { predicates: [{ get verb(): string { throw new Error('boom'); } }], caveats: [] };
    const f = lintPolicy(poisoned);
    expect(f.length).toBeGreaterThan(0);
    expect(f.every((x) => x.severity === 'error')).toBe(true);
  });
  it('the CLI: unreadable, invalid JSON and directory inputs fail the gate', () => {
    expect(out([join(dir, 'missing.json')]).code).toBe(1);
    expect(out([file('bad.json', '{nope')]).code).toBe(1);
    expect(out([dir]).code).toBe(1);
    const mixed = out([file('ok.json', CLEAN), join(dir, 'missing2.json')]);
    expect(mixed.code).toBe(1);
    expect(mixed.text).toContain('cannot read file');
  });
});

describe('GitHub annotations cannot be forged through a file name', () => {
  it('commas, colons, percent signs and newlines in a name stay inside the property', () => {
    const p = file('a,title=forged::b%0A.json', { predicates: 'x' });
    const { text } = out([p, '--format', 'github']);
    const line = text.split('\n').find((l) => l.startsWith('::error'))!;
    const props = line.slice('::error '.length, line.indexOf('::', '::error '.length));
    expect(props.split(',')).toHaveLength(2); // file=... and title=...
    expect(props).toContain('file=');
    expect(props).toContain('%2Ctitle=forged'); // the comma is escaped, so it is part of the file value
    expect(line).not.toContain('\n');
  });
  it('a newline in a message cannot start a second command', () => {
    const { text } = out([file('multi.json', '{"predicates":"x\\n::error::injected"}'), '--format', 'github']);
    for (const l of text.split('\n')) if (l.startsWith('::')) expect(l.indexOf('\n')).toBe(-1);
    expect(text.split('\n').filter((l) => l.startsWith('::error')).length).toBeGreaterThan(0);
    expect(text.split('\n').some((l) => l === '::error::injected')).toBe(false);
  });
});
