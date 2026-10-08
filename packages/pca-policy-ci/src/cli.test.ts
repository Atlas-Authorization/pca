import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parseArgs, run } from './cli';

const dir = mkdtempSync(join(tmpdir(), 'pca-policy-ci-'));
const future = Date.now() + 3_600_000;

function policyFile(name: string, doc: unknown): string {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(doc), 'utf8');
  return p;
}

const cleanFile = policyFile('clean.json', {
  predicates: [{ verb: 'docs.read', resource: '/docs/*', where: [{ field: 'action.params.size', op: 'lte', value: 100 }] }],
  caveats: [{ type: 'expires', at: future }, { type: 'max_blast_radius', max: 0.1 }],
});
const failFile = policyFile('fail.json', { predicates: [{ verb: '*', resource: '*' }] });

afterAll(() => {
  // temp dir is left to the OS; nothing to clean deterministically
});

function capture(argv: string[]): { code: number; out: string } {
  const lines: string[] = [];
  const code = run(argv, (s) => lines.push(s));
  return { code, out: lines.join('\n') };
}

describe('CLI', () => {
  it('exits 0 on a clean policy', () => {
    const { code, out } = capture([cleanFile]);
    expect(code).toBe(0);
    expect(out).toMatch(/PASS/);
  });

  it('exits 1 on a failing (over-broad) policy', () => {
    const { code, out } = capture([failFile]);
    expect(code).toBe(1);
    expect(out).toMatch(/FAIL/);
    expect(out).toMatch(/over-broad-grant/);
  });

  it('emits GitHub-Actions annotations with --format github', () => {
    const { out } = capture([failFile, '--format', 'github']);
    expect(out).toMatch(/^::error file=.*over-broad-grant/m);
  });

  it('--max-severity warn fails a policy that only has warnings', () => {
    const warnOnly = policyFile('warn.json', {
      // dangerous verb but gated (info) + no expiry (warn): no hard errors.
      predicates: [{ verb: 'db.delete', resource: '/t/u', where: [{ field: 'action.params.n', op: 'lte', value: 1 }] }],
      caveats: [{ type: 'max_blast_radius', max: 0.1 }],
    });
    expect(capture([warnOnly]).code).toBe(0);
    expect(capture([warnOnly, '--max-severity', 'warn']).code).toBe(1);
  });

  it('errors (exit 2) on no files and on unknown options', () => {
    expect(capture([]).code).toBe(2);
    expect(capture([cleanFile, '--nope']).code).toBe(2);
  });

  it('parseArgs reads flags', () => {
    const p = parseArgs(['a.json', '--max-severity=warn', '--format=github', '-q']);
    expect('args' in p && p.args.maxSeverity).toBe('warn');
    expect('args' in p && p.args.format).toBe('github');
    expect('args' in p && p.args.quiet).toBe(true);
  });
});
