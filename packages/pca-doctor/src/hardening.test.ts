import { describe, expect, it } from 'vitest';
import { main, parseDoctorArgs } from './cli';
import { configFromEnv, configProblems, formatResults, mergeConfig, runDoctor, verdictOf } from './doctor';
import { scrubDeep, scrubText } from './scrub';
import type { CheckResult } from './types';

const r = (status: CheckResult['status'], id = 'x'): CheckResult => ({ id, status, detail: 'd' });
const deps = { fetch: async () => { throw new Error('ECONNREFUSED https://user:hunter2@dep.example/?token=abcdef123456'); }, now: () => 1_760_000_000_000 };

describe('a doctor that checked nothing does not report a healthy deployment', () => {
  it('no results, or only skips, is a fail', () => {
    expect(verdictOf([])).toBe('fail');
    expect(verdictOf([], true)).toBe('fail');
    expect(verdictOf([r('skip'), r('skip')])).toBe('fail');
  });
  it('a real result restores the usual verdicts', () => {
    expect(verdictOf([r('pass'), r('skip')])).toBe('pass');
    expect(verdictOf([r('warn'), r('skip')])).toBe('warn');
    expect(verdictOf([r('warn')], true)).toBe('fail');
    expect(verdictOf([r('pass'), r('fail')])).toBe('fail');
  });
  it('the text output says so', () => {
    expect(formatResults([], undefined)).toContain('nothing checked');
    expect(formatResults([r('skip')], undefined)).toContain('nothing about this deployment was verified');
    expect(formatResults([r('pass')], undefined)).not.toContain('nothing checked');
  });
  it('the CLI exits 1 when every group is skipped', async () => {
    const out: string[] = [];
    const code = await main(['--skip', 'clock,store,proxy,suites,caveats'], {}, (s) => out.push(s), () => undefined);
    expect(code).toBe(1);
    expect(out.join('\n')).toMatch(/FAIL/);
  });
  it('running no groups at all fails', async () => {
    expect(verdictOf(await runDoctor({}, []))).toBe('fail');
  });
});

describe('a check that throws is a failed check', () => {
  it('the run completes, the group is reported as failed and the others still run', async () => {
    const res = await runDoctor({ verifier: { allowedSuites: 5 as never, pqPins: 7 as never } }, ['suites', 'clock']);
    expect(res.map((x) => x.id)).toEqual(expect.arrayContaining(['clock']));
    expect(verdictOf(res)).toBe('fail');
  });
  it('a thrown message is scrubbed and the id names the group', async () => {
    const res = await runDoctor({ url: 'https://dep.example' }, ['clock'], { ...deps, fetch: (() => { throw new Error('boom https://u:hunter2@h/?password=sekret123'); }) as never });
    const dump = JSON.stringify(res);
    expect(dump).not.toMatch(/hunter2|sekret123/);
    expect(res.length).toBeGreaterThan(0);
  });
});

describe('no credential in anything the doctor prints', () => {
  it('a URL with userinfo and a failing fetch', async () => {
    const res = await runDoctor({ url: 'https://admin:hunter2@dep.example/?token=abcdef123456', clock: { referenceUrl: 'local' } }, ['clock'], deps);
    expect(JSON.stringify(res)).not.toMatch(/hunter2|abcdef123456/);
    expect(formatResults(res, 'https://admin:hunter2@dep.example')).toBeTruthy();
  });
  it('a store adapter option that holds a password', async () => {
    const res = await runDoctor({ store: { adapter: './does-not-exist.mjs', options: { url: 'postgres://app:hunter2@db/pca', password: 'sekret987' } } }, ['store']);
    expect(JSON.stringify(res)).not.toMatch(/hunter2|sekret987/);
    expect(res[0]?.status).toBe('fail');
  });
  it('configuration errors never echo the value', () => {
    expect(() => configFromEnv({ PCA_PQ_PINS: '{"issuer":"super-secret-pin"' })).toThrow('PCA_PQ_PINS is not valid JSON');
    try {
      configFromEnv({ PCA_PQ_PINS: '{"issuer":"super-secret-pin"' });
    } catch (e) {
      expect((e as Error).message).not.toContain('super-secret-pin');
    }
  });
  it('scrubText and scrubDeep', () => {
    expect(scrubText('connect postgres://app:hunter2@db:5432/x')).toBe('connect postgres://[redacted]@db:5432/x');
    expect(scrubText('Authorization: Bearer abc.def.ghi')).toBe('Authorization: [redacted]');
    expect(scrubText('PCA_ALLOWED_SUITES=ed25519,ml-dsa-65')).toBe('PCA_ALLOWED_SUITES=ed25519,ml-dsa-65');
    expect(scrubDeep({ a: { b: ['password=x1y2z3', 5, null] } })).toEqual({ a: { b: ['password=[redacted]', 5, null] } });
  });
});

describe('configuration is validated before anything runs', () => {
  it.each([
    [{ clock: { maxSkewMs: Number.NaN } }, 'clock.maxSkewMs must be a positive number'],
    [{ clock: { maxSkewMs: -1 } }, 'clock.maxSkewMs must be a positive number'],
    [{ clock: { timeoutMs: 0 } }, 'clock.timeoutMs must be a positive number'],
    [{ clock: { warnFraction: 2 } }, 'clock.warnFraction must be a number in (0, 1]'],
    [{ store: { concurrency: 1.5 } }, 'store.concurrency must be a positive integer'],
    [{ store: { rounds: 0 } }, 'store.rounds must be a positive integer'],
    [{ proxy: { trustedProxyCount: -1 } }, 'proxy.trustedProxyCount must be a non-negative integer'],
    [{ proxy: { hops: Number.NaN } }, 'proxy.hops must be a non-negative integer'],
    [{ url: 'not a url' }, 'url is not a valid URL'],
    [{ url: 'ftp://x/' }, 'url must be an http(s) URL'],
  ])('%j', async (cfg, why) => {
    expect(configProblems(cfg as never)).toEqual([why]);
    const res = await runDoctor(cfg as never);
    expect(res).toEqual([{ id: 'config', status: 'fail', detail: `invalid configuration: ${why}`, remediation: 'Correct the setting; no check was run.' }]);
  });
  it('a valid configuration has no problems', () => {
    expect(configProblems({ url: 'https://a.example', clock: { maxSkewMs: 1000, warnFraction: 1 }, store: { concurrency: 4, rounds: 2 }, proxy: { trustedProxyCount: 0, hops: 1 } })).toEqual([]);
  });
  it('environment values that are not numbers or headers are errors, not NaN', () => {
    expect(() => configFromEnv({ TRUSTED_PROXY_COUNT: 'many' })).toThrow('TRUSTED_PROXY_COUNT must be a non-negative integer');
    expect(() => configFromEnv({ PCA_TRUSTED_PROXY_HOPS: '-2' })).toThrow('PCA_TRUSTED_PROXY_HOPS must be a non-negative integer');
    expect(() => configFromEnv({ TRUSTED_PROXY_HEADER: 'x-evil' })).toThrow('TRUSTED_PROXY_HEADER must be one of x-forwarded-for, forwarded, x-real-ip');
    expect(configFromEnv({ TRUSTED_PROXY_HEADER: 'X-Real-IP' }).proxy?.header).toBe('x-real-ip');
    expect(() => configFromEnv({ PCA_PQ_PINS: '[]' })).toThrow('PCA_PQ_PINS must be a JSON object');
    expect(() => configFromEnv({ PCA_PQ_PINS: '{"a":5}' })).toThrow('PCA_PQ_PINS must be a JSON object');
  });
  it('a bad --proxy-header is a usage error', () => {
    expect(() => parseDoctorArgs(['--proxy-header', 'x-evil'])).toThrow('--proxy-header must be x-forwarded-for, forwarded or x-real-ip');
  });
  it('config keys that would reach the prototype are refused', () => {
    expect(() => mergeConfig(JSON.parse('{"__proto__":{"url":"https://evil"}}'))).toThrow('config key "__proto__" is not allowed');
    expect(({} as { url?: string }).url).toBeUndefined();
  });
  it('the CLI reports a bad environment as a usage error with exit code 2 and no secret', async () => {
    const err: string[] = [];
    const code = await main([], { PCA_PQ_PINS: '{"k":"super-secret-pin"' }, () => undefined, (s) => err.push(s));
    expect(code).toBe(2);
    expect(err.join('')).not.toContain('super-secret-pin');
  });
});
