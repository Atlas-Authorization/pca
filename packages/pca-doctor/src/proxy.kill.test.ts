import { describe, expect, it } from 'vitest';
import type { FetchLike } from './clock';
import { PROXY_REMEDIATION, checkProxyConfig, checkProxyProbe, forgedHeaders, testNetIp } from './proxy';

describe('checkProxyConfig', () => {
  const cfg = (p: NonNullable<Parameters<typeof checkProxyConfig>[0]['proxy']>) => checkProxyConfig({ proxy: p });

  it('skips with an exact message when the count is not given', () => {
    expect(checkProxyConfig({})).toStrictEqual({ id: 'proxy.config', status: 'skip', detail: 'TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)' });
  });

  it('rejects counts outside the integer range 0..16 (16 is allowed)', () => {
    for (const n of [-1, 1.5, 17, Number.NaN, -0]) {
      expect(cfg({ trustedProxyCount: n })).toStrictEqual({ id: 'proxy.config', status: 'fail', detail: `TRUSTED_PROXY_COUNT=${String(n)} is not an integer in 0..16`, remediation: PROXY_REMEDIATION });
    }
    expect(cfg({ trustedProxyCount: 16, hops: 16 }).status).toBe('pass');
  });

  it('x-real-ip needs at least one trusted proxy', () => {
    expect(cfg({ trustedProxyCount: 0, header: 'x-real-ip' })).toStrictEqual({
      id: 'proxy.config',
      status: 'fail',
      detail: 'TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)',
      remediation: PROXY_REMEDIATION,
    });
    expect(cfg({ trustedProxyCount: 1, header: 'x-real-ip' }).status).toBe('warn');
    expect(cfg({ trustedProxyCount: 0, header: 'forwarded' }).status).toBe('pass');
  });

  it('without a stated hop count: pass for 0 (no remediation), warn for more', () => {
    expect(cfg({ trustedProxyCount: 0 })).toStrictEqual({
      id: 'proxy.config',
      status: 'pass',
      detail: 'TRUSTED_PROXY_COUNT=0 (x-forwarded-for); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared',
    });
    expect(cfg({ trustedProxyCount: 2, header: 'forwarded' })).toStrictEqual({
      id: 'proxy.config',
      status: 'warn',
      detail: 'TRUSTED_PROXY_COUNT=2 (forwarded); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared',
      remediation: PROXY_REMEDIATION,
    });
  });

  it('compares the count with the stated hops', () => {
    expect(cfg({ trustedProxyCount: 3, hops: 1 })).toStrictEqual({
      id: 'proxy.config',
      status: 'fail',
      detail: 'TRUSTED_PROXY_COUNT=3 is larger than the 1 proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra x-forwarded-for entries',
      remediation: PROXY_REMEDIATION,
    });
    expect(cfg({ trustedProxyCount: 1, hops: 2, header: 'forwarded' })).toStrictEqual({
      id: 'proxy.config',
      status: 'warn',
      detail: "TRUSTED_PROXY_COUNT=1 is smaller than the 2 proxies in front of the API: clients are keyed by a proxy's address and share its bucket",
      remediation: PROXY_REMEDIATION,
    });
    expect(cfg({ trustedProxyCount: 2, hops: 2, header: 'forwarded' })).toStrictEqual({
      id: 'proxy.config',
      status: 'pass',
      detail: 'TRUSTED_PROXY_COUNT=2 (forwarded) matches the stated 2 appending proxies',
    });
  });
});

describe('forged header generation', () => {
  it('picks the TEST-NET range by the 0.5 threshold and a host octet in 1..254', () => {
    expect(testNetIp(() => 0.5)).toBe('203.0.113.128');
    expect(testNetIp(() => 0.49)).toBe('198.51.100.125');
    expect(testNetIp(() => 0)).toBe('198.51.100.1');
    expect(testNetIp(() => 0.999)).toBe('203.0.113.254');
  });

  it('builds 17 entries joined by comma and space for each header', () => {
    const h = forgedHeaders(() => 0);
    const ip = '198.51.100.1';
    expect(h).toStrictEqual({
      'x-forwarded-for': Array(17).fill(ip).join(', '),
      forwarded: Array(17).fill(`for=${ip}`).join(', '),
      'x-real-ip': ip,
    });
  });
});

describe('checkProxyProbe', () => {
  const rand = () => 0;
  /** Replies with the given RateLimit-Remaining values in order (undefined = no header); records requests. */
  const replying = (values: (number | undefined)[], seen: { url: string; headers: Record<string, string> | undefined }[] = []): FetchLike => {
    let i = 0;
    return async (url, init) => {
      seen.push({ url, headers: init?.headers });
      const v = values[i++];
      return { status: 200, headers: { get: (n: string) => (n === 'ratelimit-remaining' && v !== undefined ? String(v) : null) }, arrayBuffer: async () => new ArrayBuffer(0) };
    };
  };
  const probe = (values: (number | undefined)[], cfg = {}) => checkProxyProbe({ url: 'https://dep.example', ...cfg }, { fetch: replying(values), rand });
  const url = 'https://dep.example/v1/pca/suites';

  it('skips without a URL and when disabled, with exact messages; an unset probe flag still probes', async () => {
    expect(await checkProxyProbe({}, { fetch: replying([]) })).toStrictEqual({ id: 'proxy.probe', status: 'skip', detail: 'no deployment URL given (--url)' });
    expect(await probe([], { proxy: { probe: false } })).toStrictEqual({ id: 'proxy.probe', status: 'skip', detail: 'disabled (--no-probe)' });
    expect((await probe([9, 8, 7, 6], { proxy: { probe: true } })).status).toBe('pass');
    expect((await probe([9, 8, 7, 6], { proxy: {} })).status).toBe('pass');
  });

  it('sends two plain requests, one with forged headers, then a plain one, to the probe path', async () => {
    const seen: { url: string; headers: Record<string, string> | undefined }[] = [];
    await checkProxyProbe({ url: 'https://dep.example', proxy: { probePath: '/p' } }, { fetch: replying([9, 8, 7, 6], seen), rand });
    expect(seen.map((s) => s.url)).toEqual(Array(4).fill('https://dep.example/p'));
    expect(seen.map((s) => s.headers)).toEqual([{}, {}, forgedHeaders(rand), {}]);
  });

  it('a failing request is a warn with the exact message and remediation', async () => {
    const r = await checkProxyProbe({ url: 'https://dep.example' }, { fetch: async () => { throw new Error('ECONNREFUSED'); }, rand });
    expect(r).toStrictEqual({
      id: 'proxy.probe',
      status: 'warn',
      detail: `probe request to ${url} failed: ECONNREFUSED`,
      remediation: 'Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.',
    });
  });

  it('skips when any response lacks a usable RateLimit-Remaining header', async () => {
    for (const seqs of [[9, undefined, 7, 6], [undefined, undefined, undefined, undefined], [9, 8, 7, undefined]]) {
      const r = await probe(seqs);
      expect(r).toStrictEqual({
        id: 'proxy.probe',
        status: 'skip',
        detail: `not observable remotely: ${url} does not return a RateLimit-Remaining header on every response`,
        observed: { url, remaining: seqs },
      });
    }
  });

  it('is inconclusive unless both plain steps drain strictly', async () => {
    for (const v of [[5, 5, 4, 3], [5, 4, 3, 4], [5, 6, 3, 2], [5, 4, 3, 5], [5, 5, 3, 3], [4, 5, 3, 2]]) {
      const [a, b, f, c] = v as [number, number, number, number];
      expect(await probe(v)).toStrictEqual({
        id: 'proxy.probe',
        status: 'warn',
        detail: `inconclusive: the plain requests' bucket did not drain monotonically (${a}, ${b}, then ${c}): a window rollover, a shared bucket or concurrent traffic. Re-run.`,
        observed: { url, remaining: [a, b, f, c] },
      });
    }
  });

  it('fails when the forged request lands in a fresher bucket, passes when it is equal or lower', async () => {
    expect(await probe([9, 8, 9, 7])).toStrictEqual({
      id: 'proxy.probe',
      status: 'fail',
      detail: "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining 9, while the plain requests' bucket was at 8): the deployment trusts client-written forwarding entries",
      remediation: PROXY_REMEDIATION,
      observed: { url, remaining: [9, 8, 9, 7] },
    });
    expect(await probe([9, 8, 8, 7])).toStrictEqual({
      id: 'proxy.probe',
      status: 'pass',
      detail: 'forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining 9, 8, forged 8, 7). A count that is too LOW is not observable from one client.',
      observed: { url, remaining: [9, 8, 8, 7] },
    });
  });
});
