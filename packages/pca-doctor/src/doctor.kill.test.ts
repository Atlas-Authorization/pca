import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FetchLike } from './clock';
import { configFromEnv, configProblems, formatResults, loadConfigFile, mergeConfig, runDoctor } from './doctor';
import type { CheckResult, DoctorConfig } from './types';

const T = 1_760_000_000_000;
const GUARD_FIX = 'Fix the configuration or the dependency named above and run the doctor again.';

/** Defines `key` on `base` so that reads after the first `free` ones throw `thrown`. */
function armed<B extends object>(base: B, key: string, value: unknown, free: number, thrown: unknown): B {
  let n = 0;
  Object.defineProperty(base, key, {
    enumerable: true,
    get() {
      if (n++ >= free) throw thrown;
      return value;
    },
  });
  return base;
}
const guardFail = (id: string, msg: string): CheckResult => ({ id, status: 'fail', detail: `${id} could not run: ${msg}`, remediation: GUARD_FIX });
const never = (): FetchLike => async () => {
  throw new Error('no network in this test');
};

describe('configProblems', () => {
  it('tolerates a missing configuration object', () => {
    expect(configProblems(undefined as never)).toEqual([]);
  });

  it('accepts warnFraction in (0, 1] only, and only as a number', () => {
    const msg = 'clock.warnFraction must be a number in (0, 1]';
    for (const wf of ['0.5', 0, -1, 5, 1.0001, Number.NaN]) expect(configProblems({ clock: { warnFraction: wf as never } })).toEqual([msg]);
    for (const wf of [1, 0.0001, 0.25]) expect(configProblems({ clock: { warnFraction: wf } })).toEqual([]);
  });

  it('accepts http and https URLs only', () => {
    expect(configProblems({ url: 'http://dep.example' })).toEqual([]);
    expect(configProblems({ url: 'https://dep.example' })).toEqual([]);
    expect(configProblems({ url: 'ftp://dep.example' })).toEqual(['url must be an http(s) URL']);
    expect(configProblems({ url: 'not a url' })).toEqual(['url is not a valid URL']);
  });
});

describe('a group that throws is reported under its own id', () => {
  it('clock', async () => {
    const cfg = armed({} as DoctorConfig, 'url', 'https://dep.example', 2, new Error('url read'));
    expect(await runDoctor(cfg, ['clock'], { fetch: never() })).toStrictEqual([guardFail('clock', 'url read')]);
  });

  it('store', async () => {
    const cfg = armed({} as DoctorConfig, 'store', {}, 2, new Error('store read'));
    expect(await runDoctor(cfg, ['store'])).toStrictEqual([guardFail('store', 'store read')]);
  });

  it('proxy.config and proxy.probe', async () => {
    const cfg = armed(armed({} as DoctorConfig, 'proxy', {}, 2, new Error('proxy read')), 'url', 'https://dep.example', 2, new Error('url read'));
    expect(await runDoctor(cfg, ['proxy'], { fetch: never() })).toStrictEqual([guardFail('proxy.config', 'proxy read'), guardFail('proxy.probe', 'url read')]);
  });

  it('suites.allowed and suites.pq, with a non-Error throw', async () => {
    const cfg = armed({} as DoctorConfig, 'verifier', {}, 0, 'plain text');
    expect(await runDoctor(cfg, ['suites'])).toStrictEqual([guardFail('suites.allowed', 'plain text'), guardFail('suites.pq', 'plain text')]);
  });

  it('caveats.root and caveats.enforcement, with the message scrubbed', async () => {
    const cfg = armed({} as DoctorConfig, 'verifier', {}, 0, new Error('password=hunter2'));
    expect(await runDoctor(cfg, ['caveats'])).toStrictEqual([guardFail('caveats.root', 'password=[redacted]'), guardFail('caveats.enforcement', 'password=[redacted]')]);
  });
});

describe('runDoctor runs exactly the requested groups with its dependencies', () => {
  it('clock only: no other group appears', async () => {
    const r = await runDoctor({}, ['clock']);
    expect(r).toEqual([{ id: 'clock', status: 'skip', detail: 'no deployment URL given (--url)' }]);
  });

  it('clock uses the injected fetch and clock', async () => {
    const seen: string[] = [];
    const fetch: FetchLike = async (url) => {
      seen.push(url);
      return { status: 200, headers: { get: (n: string) => (n === 'date' ? new Date(T + 3000).toUTCString() : null) }, arrayBuffer: async () => new ArrayBuffer(0) };
    };
    const r = await runDoctor({ url: 'https://dep.example', clock: { referenceUrl: 'local' } }, ['clock'], { fetch, now: () => T });
    expect(seen).toEqual(['https://dep.example']);
    expect(r).toHaveLength(1);
    expect(r[0]).toMatchObject({ id: 'clock', status: 'pass' });
    expect(r[0]!.detail.startsWith("deployment clock +3.5 s relative to this machine's clock (")).toBe(true);
  });

  it('store only: both store results', async () => {
    expect((await runDoctor({}, ['store'])).map((x) => [x.id, x.status])).toEqual([
      ['store.atomicity', 'skip'],
      ['store.durability', 'skip'],
    ]);
  });

  it('proxy only: config and probe, the probe through the injected fetch', async () => {
    let calls = 0;
    const fetch: FetchLike = async () => {
      calls++;
      return { status: 200, headers: { get: (n: string) => (n === 'ratelimit-remaining' ? String(10 - calls) : null) }, arrayBuffer: async () => new ArrayBuffer(0) };
    };
    const r = await runDoctor({ url: 'https://dep.example', proxy: { trustedProxyCount: 1, hops: 1 } }, ['proxy'], { fetch });
    expect(calls).toBe(4);
    expect(r.map((x) => [x.id, x.status])).toEqual([
      ['proxy.config', 'pass'],
      ['proxy.probe', 'pass'],
    ]);
  });

  it('suites only: no clock, store, proxy or caveat results', async () => {
    const r = await runDoctor({ verifier: { allowedSuites: ['ed25519'] } }, ['suites']);
    expect(r.map((x) => x.id)).toEqual(['suites.allowed', 'suites.pq-binding']);
  });

  it('caveats only: the loader is injected and receives the configured directory', async () => {
    let dir: string | undefined;
    const r = await runDoctor({ verifier: { pcaDir: '/app' } }, ['caveats'], {
      loadPca: (d) => {
        dir = d;
        return { module: {}, version: '0.4.0', path: '/p' };
      },
    });
    expect(dir).toBe('/app');
    expect(r.map((x) => [x.id, x.status])).toEqual([
      ['caveats.root', 'fail'],
      ['verifier.enforcement', 'pass'],
    ]);
    expect(r[0]!.detail).toBe('@atlasauth/pca 0.4.0 at /p: root caveats outside the envelope are NOT enforced before 0.4.1 (legacy behaviour)');
  });

  it('with no groups it returns nothing', async () => {
    expect(await runDoctor({ url: 'https://dep.example' }, [])).toEqual([]);
  });
});

describe('formatResults', () => {
  const r = (status: CheckResult['status']): CheckResult => ({ id: 'x', status, detail: 'd' });

  it('titles with the target only when there is one, counts every status, and defaults to non-strict', () => {
    expect(formatResults([r('warn'), r('skip'), r('pass')], undefined)).toBe(
      ['pca-doctor', '  WARN  x                    d', '  SKIP  x                    d', '  PASS  x                    d', 'Summary: 1 pass, 1 warn, 0 fail, 1 skip -> WARN'].join('\n'),
    );
    expect(formatResults([r('warn')], 'https://t', true).split('\n')).toEqual(['pca-doctor: https://t', '  WARN  x                    d', 'Summary: 0 pass, 1 warn, 0 fail, 0 skip -> FAIL']);
  });
});

describe('configFromEnv', () => {
  it('an empty environment gives an empty configuration', () => {
    expect(configFromEnv({})).toStrictEqual({});
  });

  it('maps each variable to its section', () => {
    expect(configFromEnv({ PCA_DOCTOR_URL: 'https://e', PCA_DOCTOR_REFERENCE_URL: 'local', PCA_DOCTOR_STORE: './s.mjs' })).toStrictEqual({
      url: 'https://e',
      clock: { referenceUrl: 'local' },
      store: { adapter: './s.mjs' },
    });
  });

  it('proxy settings: numbers, header (case-insensitive) and hops', () => {
    expect(configFromEnv({ TRUSTED_PROXY_COUNT: '0', TRUSTED_PROXY_HEADER: 'X-Real-IP', PCA_TRUSTED_PROXY_HOPS: '2' })).toStrictEqual({
      proxy: { trustedProxyCount: 0, header: 'x-real-ip', hops: 2 },
    });
    expect(configFromEnv({ TRUSTED_PROXY_COUNT: '' })).toStrictEqual({ proxy: { trustedProxyCount: undefined } });
    expect(configFromEnv({ PCA_TRUSTED_PROXY_HOPS: '' })).toStrictEqual({ proxy: { hops: undefined } });
    expect(() => configFromEnv({ TRUSTED_PROXY_HEADER: 'x-bogus' })).toThrow('TRUSTED_PROXY_HEADER must be one of x-forwarded-for, forwarded, x-real-ip');
    for (const bad of ['-1', '1.5', 'abc', '-0']) expect(() => configFromEnv({ TRUSTED_PROXY_COUNT: bad })).toThrow('TRUSTED_PROXY_COUNT must be a non-negative integer');
    expect(() => configFromEnv({ PCA_TRUSTED_PROXY_HOPS: '-1' })).toThrow('PCA_TRUSTED_PROXY_HOPS must be a non-negative integer');
  });

  it('allowed suites are trimmed and empty entries dropped', () => {
    expect(configFromEnv({ PCA_ALLOWED_SUITES: ' a , ,b,,' })).toStrictEqual({ verifier: { allowedSuites: ['a', 'b'] } });
    expect(configFromEnv({ PCA_ALLOWED_SUITES: '' })).toStrictEqual({ verifier: { allowedSuites: [] } });
  });

  it('pins must be a JSON object of strings', () => {
    const msg = 'PCA_PQ_PINS must be a JSON object of issuer -> public key strings';
    expect(() => configFromEnv({ PCA_PQ_PINS: '{not json' })).toThrow('PCA_PQ_PINS is not valid JSON');
    for (const bad of ['null', '"str"', '7', '[]', '["a"]', '{"a":"b","c":1}']) expect(() => configFromEnv({ PCA_PQ_PINS: bad })).toThrow(msg);
    expect(configFromEnv({ PCA_PQ_PINS: '{"a":"b","c":"d"}' })).toStrictEqual({ verifier: { pqPins: { a: 'b', c: 'd' } } });
  });

  it('allowUnboundPq reads the whole value as a boolean word', () => {
    for (const t of ['1', 'true', 'TRUE', 'yes', 'On']) expect(configFromEnv({ PCA_ALLOW_UNBOUND_PQ: t })).toStrictEqual({ verifier: { allowUnboundPq: true } });
    for (const f of ['0', 'false', 'no', 'xyes', 'yesx', 'on1', '']) expect(configFromEnv({ PCA_ALLOW_UNBOUND_PQ: f })).toStrictEqual({ verifier: { allowUnboundPq: false } });
  });
});

describe('mergeConfig', () => {
  it('merges sections per field, later wins, and skips undefined values', () => {
    expect(mergeConfig({ url: 'a', proxy: { hops: 1, trustedProxyCount: 1 } }, { url: undefined, proxy: { hops: 2 } }, {})).toStrictEqual({ url: 'a', proxy: { hops: 2, trustedProxyCount: 1 } });
    expect(mergeConfig({ url: 'a' }, { url: 'b' })).toStrictEqual({ url: 'b' });
  });

  it('refuses prototype-polluting keys', () => {
    for (const k of ['constructor', 'prototype']) expect(() => mergeConfig({ [k]: {} } as never)).toThrow(`config key "${k}" is not allowed`);
    expect(() => mergeConfig(JSON.parse('{"__proto__": {"x": 1}}'))).toThrow('config key "__proto__" is not allowed');
  });
});

describe('loadConfigFile', () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it('parses a .json file', async () => {
    dir = mkdtempSync(join(tmpdir(), 'pca-doctor-cfg-'));
    const f = join(dir, 'c.json');
    writeFileSync(f, JSON.stringify({ url: 'https://j.example', proxy: { hops: 3 } }));
    expect(await loadConfigFile(f)).toEqual({ url: 'https://j.example', proxy: { hops: 3 } });
  });

  it('imports any other file as a module and takes its default export', async () => {
    dir = mkdtempSync(join(tmpdir(), 'pca-doctor-cfg-'));
    const f = join(dir, 'c.mjs');
    writeFileSync(f, "export default { url: 'https://m.example' };\n");
    expect(await loadConfigFile(f)).toEqual({ url: 'https://m.example' });
  });
});
