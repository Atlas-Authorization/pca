import { describe, expect, it } from 'vitest';
import { checkEnforcement, checkRootCaveats, compareVersion, loadPca, type LoadedPca } from './caveats';
import { checkClock, readDate, type FetchLike } from './clock';
import { main, parseDoctorArgs } from './cli';
import { configFromEnv, formatResults, mergeConfig, runDoctor, verdictOf } from './doctor';
import { checkProxyConfig, checkProxyProbe, forgedHeaders, testNetIp } from './proxy';
import { checkStore } from './store';
import { checkAllowedSuites, checkPqBinding } from './suites';
import type { CheckResult } from './types';

/** A fake fetch: per-URL Date header (as an offset from `now`) and a RateLimit-Remaining sequence. */
function fakeFetch(opts: { date?: Record<string, number | null>; remaining?: (headers: Record<string, string>) => number | null; fail?: boolean; now: () => number }): FetchLike {
  return async (url, init) => {
    if (opts.fail) throw new Error('ECONNREFUSED');
    const host = new URL(url).origin;
    const off = opts.date?.[host];
    const h = new Map<string, string>();
    if (off !== undefined && off !== null) h.set('date', new Date(opts.now() + off).toUTCString());
    const rem = opts.remaining?.(init?.headers ?? {});
    if (rem !== undefined && rem !== null) h.set('ratelimit-remaining', String(rem));
    return { status: 200, headers: { get: (n: string) => h.get(n.toLowerCase()) ?? null }, arrayBuffer: async () => new ArrayBuffer(0) };
  };
}

const T = 1_760_000_000_000; // a whole second
const now = (): number => T;

describe('clock', () => {
  it('readDate: offset from the Date header with +-0.5 s plus half the round trip', async () => {
    const r = await readDate('https://a.example', fakeFetch({ date: { 'https://a.example': 5000 }, now }), now, 1000);
    expect(r).toEqual({ offsetMs: 5500, uncertaintyMs: 500 });
    expect(await readDate('https://a.example', fakeFetch({ now }), now, 1000)).toEqual({ error: 'no Date header' });
    expect(await readDate('https://a.example', fakeFetch({ fail: true, now }), now, 1000)).toEqual({ error: 'request failed: ECONNREFUSED' });
  });
  const run = (depOff: number, refOff: number | null = 0, extra = {}) =>
    checkClock({ url: 'https://dep.example', clock: { referenceUrl: 'https://ref.example', ...extra } }, { fetch: fakeFetch({ date: { 'https://dep.example': depOff, 'https://ref.example': refOff }, now }), now });
  it('pass / warn / fail against the reference, using the uncertainty', async () => {
    expect((await run(2000)).status).toBe('pass');
    expect((await run(20_000)).status).toBe('warn'); // above 15 s (25% of 60 s)
    expect((await run(59_500)).status).toBe('warn'); // could be beyond 60 s
    expect((await run(90_000)).status).toBe('fail');
    expect((await run(-90_000)).status).toBe('fail');
    expect((await run(90_000, 85_000)).status).toBe('pass'); // relative to the reference, not to this machine
    expect((await run(5000, 0, { maxSkewMs: 2000 })).status).toBe('fail');
    const r = await run(90_000);
    expect(r.remediation).toMatch(/NTP/);
    expect(r.observed).toMatchObject({ skewMs: 90_000, uncertaintyMs: 1000, maxSkewMs: 60_000, warnAtMs: 15_000, reference: 'https://ref.example' });
  });
  it('skips without a URL, warns when the deployment has no Date, falls back to the local clock', async () => {
    expect((await checkClock({}, { fetch: fakeFetch({ now }) })).status).toBe('skip');
    const noDate = await checkClock({ url: 'https://dep.example' }, { fetch: fakeFetch({ now }), now });
    expect(noDate).toMatchObject({ status: 'warn', detail: expect.stringMatching(/no Date header/) });
    const fallback = await run(1000, null);
    expect(fallback.status).toBe('pass');
    expect(fallback.detail).toMatch(/compared with this machine's clock instead/);
    const local = await checkClock({ url: 'https://dep.example', clock: { referenceUrl: 'local' } }, { fetch: fakeFetch({ date: { 'https://dep.example': 0 }, now }), now });
    expect(local.detail).toMatch(/relative to this machine's clock \(/);
  });
});

describe('proxy', () => {
  it('config: range, x-real-ip, and comparison with the stated hop count', () => {
    expect(checkProxyConfig({}).status).toBe('skip');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: -1 } }).status).toBe('fail');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 17 } }).status).toBe('fail');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 1.5 } }).status).toBe('fail');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 0, header: 'x-real-ip' } }).status).toBe('fail');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 0 } }).status).toBe('pass');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 1 } }).status).toBe('warn');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 2, hops: 1 } }).status).toBe('fail');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 0, hops: 1 } }).status).toBe('warn');
    expect(checkProxyConfig({ proxy: { trustedProxyCount: 1, hops: 1 } }).status).toBe('pass');
  });
  it('forged headers are documentation addresses, 17 hops long', () => {
    expect(testNetIp(() => 0)).toBe('198.51.100.1');
    expect(testNetIp(() => 0.99)).toBe('203.0.113.252');
    const h = forgedHeaders(() => 0.3);
    expect(h['x-forwarded-for']!.split(', ')).toHaveLength(17);
    expect(h.forwarded!.startsWith('for=198.51.100.')).toBe(true);
    expect(h['x-real-ip']).toMatch(/^198\.51\.100\.\d+$/);
  });
  const bucketed = (trustForged: boolean) => {
    let plain = 60;
    let forged = 60;
    return (headers: Record<string, string>) => (trustForged && headers['x-forwarded-for'] ? --forged : --plain);
  };
  it('probe: fail when a forged header picks a fresh bucket, pass when it is ignored', async () => {
    const cfg = { url: 'https://dep.example' };
    expect((await checkProxyProbe(cfg, { fetch: fakeFetch({ remaining: bucketed(true), now }) })).status).toBe('fail');
    const ok = await checkProxyProbe(cfg, { fetch: fakeFetch({ remaining: bucketed(false), now }) });
    expect(ok.status).toBe('pass');
    expect(ok.observed).toEqual({ url: 'https://dep.example/v1/pca/suites', remaining: [59, 58, 57, 56] });
  });
  it('probe: skip / warn when it cannot conclude', async () => {
    expect((await checkProxyProbe({}, { fetch: fakeFetch({ now }) })).status).toBe('skip');
    expect((await checkProxyProbe({ url: 'https://d.example', proxy: { probe: false } }, { fetch: fakeFetch({ now }) })).status).toBe('skip');
    expect((await checkProxyProbe({ url: 'https://d.example' }, { fetch: fakeFetch({ now }) })).detail).toMatch(/not observable remotely/);
    expect((await checkProxyProbe({ url: 'https://d.example' }, { fetch: fakeFetch({ remaining: () => 30, now }) })).status).toBe('warn');
    expect((await checkProxyProbe({ url: 'https://d.example' }, { fetch: fakeFetch({ fail: true, now }) })).status).toBe('warn');
  });
});

describe('suites', () => {
  it('allowedSuites: unset warns, empty / unknown fail, known pass', () => {
    expect(checkAllowedSuites({}).status).toBe('skip');
    expect(checkAllowedSuites({ verifier: {} }).status).toBe('warn');
    expect(checkAllowedSuites({ verifier: { allowedSuites: [] } }).status).toBe('fail');
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['ed25519', 'rsa'] } })).toMatchObject({ status: 'fail', detail: expect.stringContaining('rsa') });
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['toString'] } }).status).toBe('fail');
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'] } }).status).toBe('pass');
  });
  it('PQ binding: allowUnboundPq fails, malformed pins fail, PQ without pins or trustedRoot warns', () => {
    const id = 'A'.repeat(43);
    expect(checkPqBinding({ verifier: { allowUnboundPq: true } }).status).toBe('fail');
    expect(checkPqBinding({ verifier: { pqPins: { short: 'x' } } }).status).toBe('fail');
    expect(checkPqBinding({ verifier: { pqPins: { [id]: 'not b64u!' } } }).status).toBe('fail');
    expect(checkPqBinding({ verifier: { allowedSuites: ['ed25519'] } }).status).toBe('pass');
    expect(checkPqBinding({ verifier: { allowedSuites: ['ml-dsa-65'] } }).status).toBe('warn');
    expect(checkPqBinding({ verifier: {} }).status).toBe('warn'); // unset = every suite, PQ included
    expect(checkPqBinding({ verifier: { allowedSuites: ['ml-dsa-65'], trustedRoot: true } }).status).toBe('pass');
    expect(checkPqBinding({ verifier: { allowedSuites: ['ml-dsa-65'], pqPins: { [id]: 'AbC_-1' } } }).status).toBe('pass');
  });
});

describe('root caveats', () => {
  it('compareVersion', () => {
    expect(compareVersion('0.4.1', '0.4.1')).toBe(0);
    expect(compareVersion('0.4.0', '0.4.1')).toBe(-1);
    expect(compareVersion('0.10.0', '0.4.1')).toBe(1);
    expect(compareVersion('1.0.0-rc.1', '0.4.1')).toBe(1);
    expect(compareVersion('garbage', '0.4.1')).toBe(-1);
  });
  it('the installed library (>= 0.4.1) enforces root caveats', () => {
    const r = checkRootCaveats({});
    expect(r.status).toBe('pass');
    expect(r.observed).toMatchObject({ over: { allowed: false }, under: { allowed: true }, unknown: { allowed: false } });
  });
  it('an old version fails without probing; a library that ignores root caveats fails the probe', () => {
    const real = loadPca();
    const old: LoadedPca = { ...real, version: '0.4.0' };
    expect(checkRootCaveats({}, { loadPca: () => old })).toMatchObject({ status: 'fail', detail: expect.stringMatching(/NOT enforced before 0.4.1/) });
    const ignoring: LoadedPca = { ...real, module: { ...real.module, decide: () => ({ releaseGuardianShare: true, reasons: [] }) } };
    expect(checkRootCaveats({}, { loadPca: () => ignoring }).status).toBe('fail');
    const denyAll: LoadedPca = { ...real, module: { ...real.module, decide: () => ({ releaseGuardianShare: false, reasons: ['x'] }) } };
    expect(checkRootCaveats({}, { loadPca: () => denyAll }).status).toBe('warn');
    const broken: LoadedPca = { ...real, module: {} };
    expect(checkRootCaveats({}, { loadPca: () => broken }).status).toBe('fail');
    expect(checkRootCaveats({ verifier: { pcaDir: '/nonexistent' } }).status).toBe('fail');
  });
  it('enforcement: insecureAllowUnenforced fails, a require list dropping defaults warns', () => {
    expect(checkEnforcement({}).status).toBe('skip');
    expect(checkEnforcement({ verifier: { insecureAllowUnenforced: true } }).status).toBe('fail');
    expect(checkEnforcement({ verifier: { require: ['counter'] } }).status).toBe('warn');
    expect(checkEnforcement({ verifier: {} }).status).toBe('pass');
  });
});

describe('store', () => {
  it('skips without an adapter; good references pass; bad ones fail with a counterexample', async () => {
    expect((await checkStore({})).map((r) => r.status)).toEqual(['skip', 'skip']);
    const good = await checkStore({ store: { adapter: 'builtin:durable-file', concurrency: 6, rounds: 3 } });
    expect(good.map((r) => r.status)).toEqual(['pass', 'pass']);
    const rtw = await checkStore({ store: { adapter: 'builtin:bad-read-then-write', concurrency: 8, rounds: 4 } });
    expect(rtw[0]).toMatchObject({ status: 'fail', detail: expect.stringMatching(/NOT linearizable[\s\S]*First violating key/) });
    expect(rtw[1]!.status).toBe('warn'); // declared non-durable
    const vol = await checkStore({ store: { adapter: 'builtin:bad-volatile', concurrency: 4, rounds: 2 } });
    expect(vol.map((r) => r.status)).toEqual(['pass', 'fail']);
    expect((await checkStore({ store: { adapter: 'builtin:nope' } }))[0]!.status).toBe('fail');
  }, 60_000);
});

describe('doctor runner and CLI', () => {
  const res = (status: CheckResult['status']): CheckResult => ({ id: 'x', status, detail: 'd', ...(status === 'fail' ? { remediation: 'r' } : {}) });
  it('verdict and format', () => {
    expect(verdictOf([res('pass'), res('skip')])).toBe('pass');
    expect(verdictOf([res('warn')])).toBe('warn');
    expect(verdictOf([res('warn')], true)).toBe('fail');
    expect(verdictOf([res('fail'), res('pass')])).toBe('fail');
    const text = formatResults([res('pass'), res('fail')], 'https://d.example');
    expect(text.split('\n')).toEqual([
      'pca-doctor: https://d.example',
      '  PASS  x                    d',
      '  FAIL  x                    d',
      '                             fix: r',
      'Summary: 1 pass, 0 warn, 1 fail, 0 skip -> FAIL',
    ]);
  });
  it('config from env, merged under flags', () => {
    const e = configFromEnv({ PCA_DOCTOR_URL: 'https://e', TRUSTED_PROXY_COUNT: '1', PCA_TRUSTED_PROXY_HOPS: '1', PCA_ALLOWED_SUITES: 'ed25519, ml-dsa-65', PCA_ALLOW_UNBOUND_PQ: 'true', PCA_PQ_PINS: '{"a":"b"}' });
    expect(e).toEqual({ url: 'https://e', proxy: { trustedProxyCount: 1, hops: 1 }, verifier: { allowedSuites: ['ed25519', 'ml-dsa-65'], pqPins: { a: 'b' }, allowUnboundPq: true } });
    expect(mergeConfig(e, { url: 'https://f', proxy: { trustedProxyCount: 2 } })).toMatchObject({ url: 'https://f', proxy: { trustedProxyCount: 2, hops: 1 } });
  });
  it('runDoctor runs only the requested groups', async () => {
    const r = await runDoctor({ verifier: { allowedSuites: ['ed25519'] } }, ['suites']);
    expect(r.map((x) => [x.id, x.status])).toEqual([
      ['suites.allowed', 'pass'],
      ['suites.pq-binding', 'pass'],
    ]);
  });
  it('parses flags; exit codes', async () => {
    const a = parseDoctorArgs(['--url', 'https://d', '--store', 's.mjs', '--store-option', 'k=v', '--trusted-proxy-count', '1', '--proxy-hops', '1', '--skip', 'clock,store', '--strict', '--json', '--no-probe']);
    expect(a.flags).toEqual({ url: 'https://d', store: { adapter: 's.mjs', options: { k: 'v' } }, proxy: { trustedProxyCount: 1, hops: 1, probe: false } });
    expect(a.only).toEqual(['proxy', 'suites', 'caveats']);
    expect(() => parseDoctorArgs(['--only', 'nope'])).toThrow(/unknown check group/);
    expect(() => parseDoctorArgs(['--max-skew-ms', 'x'])).toThrow(/needs a number/);
    const out: string[] = [];
    expect(await main(['--only', 'suites'], { PCA_ALLOWED_SUITES: 'ed25519' }, (s) => out.push(s), () => undefined)).toBe(0);
    expect(await main(['--only', 'suites'], { PCA_ALLOWED_SUITES: 'rsa' }, (s) => out.push(s), () => undefined)).toBe(1);
    expect(await main(['--only', 'suites', '--strict'], { PCA_ALLOW_UNBOUND_PQ: 'false' }, () => undefined, () => undefined)).toBe(1); // unset suites warns
    expect(await main(['--only', 'suites'], { PCA_ALLOW_UNBOUND_PQ: 'false' }, () => undefined, () => undefined)).toBe(0);
    expect(await main(['--bogus'], {}, () => undefined, () => undefined)).toBe(2);
    expect(await main(['--only', 'suites', '--json'], { PCA_ALLOWED_SUITES: 'ed25519' }, (s) => out.push(s), () => undefined)).toBe(0);
    expect(JSON.parse(out[out.length - 1]!)).toMatchObject({ verdict: 'pass', target: null });
  });
});
