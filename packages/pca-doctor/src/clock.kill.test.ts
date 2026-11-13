import { describe, expect, it } from 'vitest';
import { CLOCK_REMEDIATION, checkClock, DEFAULT_REFERENCE_URL, readDate, type FetchLike } from './clock';

const T = 1_760_000_000_000; // a whole second

interface Seen {
  url: string;
  init?: Parameters<FetchLike>[1];
}

/** Date header = fixed `date` value per origin (undefined = none); records every call. */
function fetcher(dates: Record<string, string | undefined>, seen: Seen[] = []): FetchLike {
  return async (url, init) => {
    seen.push({ url, init });
    const d = dates[new URL(url).origin];
    return { status: 200, headers: { get: (n: string) => (n === 'date' ? d ?? null : null) }, arrayBuffer: async () => new ArrayBuffer(0) };
  };
}
const utc = (ms: number): string => new Date(ms).toUTCString();
/** A clock that returns the given readings in order. */
const seq = (...v: number[]): (() => number) => {
  let i = 0;
  return () => v[Math.min(i++, v.length - 1)]!;
};

describe('readDate', () => {
  it('sends a HEAD with manual redirects and an abort signal', async () => {
    const seen: Seen[] = [];
    await readDate('https://a.example', fetcher({ 'https://a.example': utc(T) }, seen), () => T, 1000);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.init?.method).toBe('HEAD');
    expect(seen[0]!.init?.redirect).toBe('manual');
    expect(seen[0]!.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it('computes the offset from the midpoint of the round trip and the uncertainty from half of it', async () => {
    const r = await readDate('https://a.example', fetcher({ 'https://a.example': utc(T + 5000) }), seq(T, T + 400), 1000);
    expect(r).toEqual({ offsetMs: 5300, uncertaintyMs: 700 });
  });

  it('distinguishes a missing Date header from an unparseable one', async () => {
    expect(await readDate('https://a.example', fetcher({}), () => T, 1000)).toEqual({ error: 'no Date header' });
    expect(await readDate('https://a.example', fetcher({ 'https://a.example': 'garbage' }), () => T, 1000)).toEqual({ error: "unparseable Date header 'garbage'" });
  });
});

describe('checkClock', () => {
  const s = (v: number): string => `${v >= 0 ? '+' : '-'}${(Math.abs(v) / 1000).toFixed(1)} s`;

  it('skips with an exact message when no URL is given', async () => {
    expect(await checkClock({}, { fetch: fetcher({}) })).toStrictEqual({ id: 'clock', status: 'skip', detail: 'no deployment URL given (--url)' });
  });

  it('warns with the exact message and remediation when the deployment has no usable Date', async () => {
    const r = await checkClock({ url: 'https://dep.example' }, { fetch: fetcher({}), now: () => T });
    expect(r).toStrictEqual({
      id: 'clock',
      status: 'warn',
      detail: "cannot observe the deployment's clock at https://dep.example: no Date header",
      remediation: `Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. ${CLOCK_REMEDIATION}`,
    });
  });

  it('uses the default reference URL when none is configured, and reports a negative skew', async () => {
    const seen: Seen[] = [];
    const r = await checkClock({ url: 'https://dep.example' }, { fetch: fetcher({ 'https://dep.example': utc(T - 2000), [new URL(DEFAULT_REFERENCE_URL).origin]: utc(T) }, seen), now: () => T });
    expect(seen.map((x) => x.url)).toEqual(['https://dep.example', DEFAULT_REFERENCE_URL]);
    expect(r.status).toBe('pass');
    expect(r.detail).toBe(
      `deployment clock ${s(-2000)} relative to ${DEFAULT_REFERENCE_URL} (+-1.0 s: Date has 1 s resolution, plus round trips); fail beyond 60 s, warn above 15 s. The Date header is written by whatever answers the request (a CDN or proxy may set it).`,
    );
    expect(r.detail.startsWith('deployment clock -2.0 s')).toBe(true);
  });

  it("'local' reads only the deployment and compares with this machine's clock", async () => {
    const seen: Seen[] = [];
    const r = await checkClock({ url: 'https://dep.example', clock: { referenceUrl: 'local' } }, { fetch: fetcher({ 'https://dep.example': utc(T + 3000) }, seen), now: () => T });
    expect(seen).toHaveLength(1);
    expect(r).toStrictEqual({
      id: 'clock',
      status: 'pass',
      detail:
        "deployment clock +3.5 s relative to this machine's clock (+-0.5 s: Date has 1 s resolution, plus round trips); fail beyond 60 s, warn above 15 s. The Date header is written by whatever answers the request (a CDN or proxy may set it).",
      observed: { skewMs: 3500, uncertaintyMs: 500, maxSkewMs: 60_000, warnAtMs: 15_000, reference: "this machine's clock" },
    });
  });

  it('falls back to the local clock when the reference is unusable, naming why', async () => {
    const r = await checkClock({ url: 'https://dep.example', clock: { referenceUrl: 'https://ref.example' } }, { fetch: fetcher({ 'https://dep.example': utc(T) }), now: () => T });
    expect(r.detail).toContain("relative to this machine's clock (reference https://ref.example unusable: no Date header; compared with this machine's clock instead) (+-0.5 s");
  });

  it('uses the reference reading, its uncertainty, and reports thresholds in seconds', async () => {
    const r = await checkClock(
      { url: 'https://dep.example', clock: { referenceUrl: 'https://ref.example', maxSkewMs: 30_000, warnFraction: 0.5 } },
      { fetch: fetcher({ 'https://dep.example': utc(T + 20_000), 'https://ref.example': utc(T + 10_000) }), now: () => T },
    );
    expect(r.status).toBe('pass');
    expect(r.detail).toBe(
      'deployment clock +10.0 s relative to https://ref.example (+-1.0 s: Date has 1 s resolution, plus round trips); fail beyond 30 s, warn above 15 s. The Date header is written by whatever answers the request (a CDN or proxy may set it).',
    );
    expect(r.observed).toEqual({ skewMs: 10_000, uncertaintyMs: 1000, maxSkewMs: 30_000, warnAtMs: 15_000, reference: 'https://ref.example' });
  });

  describe('threshold boundaries (local reference: skew = offset + 500, uncertainty = 500)', () => {
    const run = (offset: number, clock: { maxSkewMs: number; warnFraction?: number }) =>
      checkClock({ url: 'https://dep.example', clock: { referenceUrl: 'local', ...clock } }, { fetch: fetcher({ 'https://dep.example': utc(T + offset) }), now: () => T });

    it('fails only when the lower end of the interval is strictly beyond the limit', async () => {
      expect((await run(10_000, { maxSkewMs: 10_000 })).status).toBe('warn'); // lower == max
      const f = await run(11_000, { maxSkewMs: 10_000 });
      expect(f.status).toBe('fail');
      expect(f.remediation).toBe(CLOCK_REMEDIATION);
      expect((await run(-12_000, { maxSkewMs: 10_000 })).status).toBe('fail');
    });

    it('warns when the skew is strictly above the warning level', async () => {
      expect((await run(10_000, { maxSkewMs: 42_000 })).status).toBe('pass'); // skew 10.5 s == warnAt
      expect((await run(11_000, { maxSkewMs: 42_000 })).status).toBe('warn');
    });

    it('warns when the upper end of the interval is strictly beyond the limit', async () => {
      expect((await run(10_000, { maxSkewMs: 11_000, warnFraction: 1 })).status).toBe('pass'); // upper == max
      expect((await run(10_000, { maxSkewMs: 10_500, warnFraction: 1 })).status).toBe('warn'); // skew == warnAt, upper > max
    });

    it('omits the remediation on pass only', async () => {
      expect('remediation' in (await run(0, { maxSkewMs: 60_000 }))).toBe(false);
      expect((await run(15_000, { maxSkewMs: 60_000 })).remediation).toBe(CLOCK_REMEDIATION);
    });
  });
});
