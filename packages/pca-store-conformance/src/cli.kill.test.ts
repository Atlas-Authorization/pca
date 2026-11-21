import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main, parseCli } from './cli';

const fx = (f: string): string => join(__dirname, '..', 'test', 'fixtures', f);

async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, (s) => out.push(s), (s) => err.push(s));
  return { code, out: out.join('\n'), err: err.join('\n') };
}
const logPath = (): string => join(mkdtempSync(join(tmpdir(), 'pcasc-cli-')), 'log');

describe('parseCli edge cases', () => {
  it('drops empty entries of --tests and names every unknown test', () => {
    expect(parseCli(['--tests', 'burst,,crash']).conf.tests).toEqual(['burst', 'crash']);
    expect(() => parseCli(['--tests', 'aa,bb'])).toThrow('--tests: unknown test(s) aa, bb');
    expect(() => parseCli(['--tests'])).toThrow('--tests: unknown test(s) (none given)');
  });
  it('--values accepts exactly 1 and refuses 0', () => {
    expect(parseCli(['--values', '1']).conf.values).toBe(1);
    expect(() => parseCli(['--values', '0'])).toThrow('--values needs a positive integer');
  });
});

describe('main: store profile teardown', () => {
  it('tears the adapter down after a passing run and after a failing run', async () => {
    const log = logPath();
    const ok = await run(['--adapter', fx('teardown-spy.mjs'), '--option', `log=${log}`, '--tests', 'burst', '--clients', '2', '--rounds', '1']);
    expect(ok.code).toBe(0);
    expect(readFileSync(log, 'utf8')).toBe('teardown\n');
    const log2 = logPath();
    const bad = await run(['--adapter', fx('teardown-spy.mjs'), '--option', `log=${log2}`, '--option', 'mode=open-fails', '--tests', 'burst']);
    expect(bad.code).toBe(2);
    expect(bad.err).toBe('conformance run failed: backend down');
    expect(readFileSync(log2, 'utf8')).toBe('teardown\n');
  });
});

describe('main: pca-state profile', () => {
  it('uses the documented defaults (10 rounds x 16 copies) when --rounds / --clients are left out', async () => {
    const r = await run(['--profile', 'pca-state', '--adapter', 'builtin:in-memory', '--tests', 'one-instance']);
    expect(r.code).toBe(0);
    expect(r.out.split('\n')[1]).toMatch(/^ {2}\[PASS\] one-instance +admitted per round \[1,1,1,1,1,1,1,1,1,1\]; state mode atomic-claim$/);
  });
  it('forwards --rounds', async () => {
    const r = await run(['--profile', 'pca-state', '--adapter', 'builtin:in-memory', '--tests', 'one-instance', '--rounds', '2', '--clients', '3']);
    expect(r.out.split('\n')[1]).toMatch(/admitted per round \[1,1\];/);
  });
  it('forwards --processes (and --clients as the copies per round) to the multi-process test, defaulting to 3 processes', async () => {
    // the compiled worker is not next to the sources, so no worker finishes: the run fails, but the note names what was configured
    const given = await run(['--profile', 'pca-state', '--adapter', 'builtin:durable-file', '--tests', 'processes', '--processes', '2', '--clients', '2', '--rounds', '1']);
    expect(given.code).toBe(1);
    expect(given.out).toContain('2 processes x 2 instances x 2 copies per round');
    const dflt = await run(['--profile', 'pca-state', '--adapter', 'builtin:durable-file', '--tests', 'processes', '--clients', '2', '--rounds', '1']);
    expect(dflt.out).toContain('3 processes x 2 instances x 2 copies per round');
  }, 60_000);
  it('exit 3 when the verdict is unresolved, and the adapter is torn down', async () => {
    const log = logPath();
    const r = await run(['--profile', 'pca-state', '--adapter', fx('pca-state-probe.mjs'), '--option', `log=${log}`, '--tests', 'claim-burst', '--clients', '2', '--rounds', '1', '--duration', '20']);
    expect(r.code).toBe(3);
    expect(r.out.split('\n')[0]).toMatch(/^pca-store-conformance \(pca-state\): fixture pca-state probe \[[a-z-]+\] -> UNRESOLVED$/);
    expect(readFileSync(log, 'utf8')).toBe('teardown\n');
  }, 60_000);
  it('exit 2 with the failure message when the run itself throws, and the adapter is still torn down', async () => {
    const log = logPath();
    const r = await run(['--profile', 'pca-state', '--adapter', fx('pca-state-probe.mjs'), '--option', `log=${log}`, '--option', 'mode=open-fails']);
    expect(r.code).toBe(2);
    expect(r.err).toBe('conformance run failed: state backend down');
    expect(r.out).toBe('');
    expect(readFileSync(log, 'utf8')).toBe('teardown\n');
  });
});
