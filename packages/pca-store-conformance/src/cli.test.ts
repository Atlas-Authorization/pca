import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { USAGE, main, parseCli } from './cli';

const fx = (f: string): string => join(__dirname, '..', 'test', 'fixtures', f);

async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, (s) => out.push(s), (s) => err.push(s));
  return { code, out: out.join('\n'), err: err.join('\n') };
}

describe('parseCli', () => {
  it('parses every flag', () => {
    const a = parseCli([
      '--adapter', 'x.mjs', '--option', 'dir=/a=b', '--option', 'k=', '--tests', 'burst,crash', '--clients', '3', '--duration', '50',
      '--rounds', '2', '--revisit-keys', '9', '--processes', '4', '--kill-every', '0', '--budget', '77', '--values', '3', '--seed', '42', '--json',
    ]);
    expect(a).toEqual({
      adapter: 'x.mjs',
      options: { dir: '/a=b', k: '' },
      json: true,
      help: false,
      conf: { tests: ['burst', 'crash'], clients: 3, durationMs: 50, rounds: 2, revisitKeys: 9, budget: 77, values: 3, seed: 42 },
      processes: 4,
      killEveryMs: 0,
    });
    expect(parseCli([])).toEqual({ options: {}, json: false, help: false, conf: {} });
    expect(parseCli(['-h']).help).toBe(true);
    expect(parseCli(['--help']).help).toBe(true);
  });
  it('refuses bad input', () => {
    expect(() => parseCli(['--option', 'novalue'])).toThrow('--option needs k=v');
    expect(() => parseCli(['--option', '=v'])).toThrow('--option needs k=v');
    expect(() => parseCli(['--option'])).toThrow('--option needs k=v');
    expect(() => parseCli(['--tests', 'burst,nope'])).toThrow('--tests: unknown test(s) nope');
    expect(() => parseCli(['--tests', ''])).toThrow('--tests: unknown test(s) (none given)');
    expect(() => parseCli(['--clients', '-1'])).toThrow('--clients needs a non-negative number');
    expect(() => parseCli(['--clients', 'x'])).toThrow('--clients needs a non-negative number');
    expect(() => parseCli(['--budget', 'Infinity'])).toThrow('--budget needs a non-negative number');
    expect(() => parseCli(['--duration'])).toThrow('--duration needs a non-negative number');
    expect(parseCli(['--rounds', '0']).conf.rounds).toBe(0);
    expect(() => parseCli(['--values', '0'])).toThrow('--values needs a positive integer');
    expect(() => parseCli(['--values', '2.5'])).toThrow('--values needs a positive integer');
    expect(() => parseCli(['--seed', '1.5'])).toThrow('--seed needs a non-negative integer');
    expect(() => parseCli(['--seed', '-1'])).toThrow('--seed needs a non-negative number');
    expect(() => parseCli(['--wat'])).toThrow('unknown argument --wat');
  });
});

describe('main', () => {
  it('help, usage errors and adapter errors exit 0 / 2', async () => {
    expect(await run(['--help'])).toEqual({ code: 0, out: USAGE, err: '' });
    const noAdapter = await run([]);
    expect(noAdapter.code).toBe(2);
    expect(noAdapter.err).toBe(`--adapter is required\n\n${USAGE}`);
    const bad = await run(['--nope']);
    expect(bad.code).toBe(2);
    expect(bad.err).toBe(`unknown argument --nope\n\n${USAGE}`);
    const load = await run(['--adapter', fx('not-an-adapter.mjs')]);
    expect(load.code).toBe(2);
    expect(load.err).toMatch(/^cannot load adapter: .*does not export a store adapter/);
    const failing = await run(['--adapter', fx('failing-open.mjs')]);
    expect(failing.code).toBe(2);
    expect(failing.err).toBe('conformance run failed: connection refused');
  });
  it('exit 0 and a text report for a conforming store', async () => {
    const r = await run(['--adapter', fx('default-object.mjs'), '--tests', 'burst,retention', '--clients', '4', '--rounds', '3', '--revisit-keys', '10']);
    expect(r.code).toBe(0);
    expect(r.out.split('\n')[0]).toBe('pca-store-conformance: fixture default object -> PASS');
    expect(r.out).toContain('[PASS] burst/consumeOnce');
    expect(r.out).toContain('[PASS] retention/advance');
  });
  it('exit 1 with counterexamples for a bad store; JSON on request', async () => {
    // Seeded and with a small value range: with the default random seed and 20 values, 6 clients x 4 rounds draw no
    // accepted duplicate about a third of the time (the non-strict counter is then indistinguishable from a good one),
    // which made this test flaky in CI. Seed + 3 values makes an accepted equal value certain and the run reproducible.
    const r = await run(['--adapter', 'builtin:bad-non-strict-counter', '--tests', 'burst', '--clients', '6', '--rounds', '4', '--values', '3', '--seed', '7', '--json']);
    expect(r.code).toBe(1);
    const j = JSON.parse(r.out);
    expect(j.status).toBe('fail');
    expect(j.tests[0].violations[0].counterexample.length).toBe(2);
  });
  it('exit 3 when nothing definite was observed', async () => {
    const r = await run(['--adapter', fx('always-error.mjs'), '--tests', 'burst', '--clients', '2', '--rounds', '1']);
    expect(r.code).toBe(3);
    expect(r.out).toContain('-> UNRESOLVED');
  });
  it('passes the module, options, processes and kill period to the crash test, and tears the adapter down', async () => {
    const r = await run(['--adapter', fx('factory.mjs'), '--option', 'label=Z', '--tests', 'crash', '--processes', '1', '--kill-every', '0', '--duration', '30']);
    // the crash test is reached (not skipped): its children run dist/worker.js when built, else record nothing
    expect(r.out).toMatch(/^pca-store-conformance: fixture factory Z -> /);
    expect(r.out).not.toContain('[SKIP]');
    expect(r.out).toContain('crash/advance');
  }, 60_000);
});

describe('--profile pca-state', () => {
  it('parses the profile and validates --tests against it', () => {
    expect(parseCli(['--profile', 'pca-state', '--tests', 'one-instance,instances'])).toEqual({
      options: {}, json: false, help: false, conf: {}, profile: 'pca-state', pcaStateTests: ['one-instance', 'instances'],
    });
    expect(() => parseCli(['--profile', 'pca-state', '--tests', 'burst'])).toThrow('--tests: unknown test(s) burst');
    expect(() => parseCli(['--tests', 'one-instance'])).toThrow('--tests: unknown test(s) one-instance');
    expect(() => parseCli(['--profile', 'other'])).toThrow('--profile: unknown profile other (known: pca-state)');
  });

  it('exit 0 for the good in-memory reference, exit 1 for a bad one, exit 2 for an unknown adapter', async () => {
    const good = await run(['--profile', 'pca-state', '--adapter', 'builtin:in-memory', '--tests', 'one-instance,retry-after-timeout', '--rounds', '3', '--clients', '5']);
    expect(good.code).toBe(0);
    expect(good.out.split('\n')).toEqual([
      'pca-store-conformance (pca-state): in-memory atomic (atomicMemoryPcaStore) [atomic-claim] -> PASS',
      expect.stringMatching(/^ {2}\[PASS\] one-instance +admitted per round \[1,1,1\]; state mode atomic-claim$/),
      expect.stringMatching(/^ {2}\[PASS\] retry-after-timeout /),
    ]);
    const bad = await run(['--profile', 'pca-state', '--adapter', 'builtin:bad-read-then-write-claim', '--tests', 'one-instance', '--rounds', '2', '--clients', '4', '--json']);
    expect(bad.code).toBe(1);
    expect(JSON.parse(bad.out).tests[0]).toMatchObject({ test: 'one-instance', status: 'fail', admitted: [4, 4] });
    const unknown = await run(['--profile', 'pca-state', '--adapter', 'builtin:nope']);
    expect(unknown.code).toBe(2);
    expect(unknown.err).toMatch(/^cannot load adapter: unknown built-in pca-state adapter 'nope'/);
  }, 60_000);
});
