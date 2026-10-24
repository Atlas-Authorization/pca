/**
 * Clock skew of the deployment against a reference, from HTTP `Date` headers. `Date` has one-second resolution and is
 * truncated, so each reading carries +-0.5 s plus half the round trip; the verdict uses that uncertainty: FAIL only when
 * the skew is beyond the limit even at the favourable end of the interval, WARN when it is above the warning fraction or
 * could be beyond the limit.
 */
import { PCACTN_MAX_SKEW_MS } from '@atlasauth/pca';
import type { CheckResult, DoctorConfig } from './types';

export type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal; redirect?: 'manual' }) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  arrayBuffer(): Promise<ArrayBuffer>;
}>;

export const DEFAULT_REFERENCE_URL = 'https://www.google.com/generate_204';

export interface DateReading {
  /** Remote clock minus local clock (ms). */
  offsetMs: number;
  uncertaintyMs: number;
}

/** One reading of a server's clock relative to `now()` from its Date header. */
export async function readDate(url: string, fetchImpl: FetchLike, now: () => number, timeoutMs: number): Promise<DateReading | { error: string }> {
  const t0 = now();
  let res;
  try {
    res = await fetchImpl(url, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    return { error: `request failed: ${(e as Error).message}` };
  }
  const t1 = now();
  const date = res.headers.get('date');
  const d = date === null ? NaN : Date.parse(date);
  if (!Number.isFinite(d)) return { error: date === null ? 'no Date header' : `unparseable Date header '${date}'` };
  return { offsetMs: d + 500 - (t0 + t1) / 2, uncertaintyMs: 500 + (t1 - t0) / 2 };
}

const s = (ms: number): string => `${ms >= 0 ? '+' : '-'}${(Math.abs(ms) / 1000).toFixed(1)} s`;

export const CLOCK_REMEDIATION =
  'Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions.';

export async function checkClock(cfg: DoctorConfig, deps: { fetch: FetchLike; now?: () => number }): Promise<CheckResult> {
  const now = deps.now ?? Date.now;
  if (!cfg.url) return { id: 'clock', status: 'skip', detail: 'no deployment URL given (--url)' };
  const max = cfg.clock?.maxSkewMs ?? PCACTN_MAX_SKEW_MS;
  const warnAt = max * (cfg.clock?.warnFraction ?? 0.25);
  const timeout = cfg.clock?.timeoutMs ?? 10_000;
  const dep = await readDate(cfg.url, deps.fetch, now, timeout);
  if ('error' in dep) {
    return {
      id: 'clock',
      status: 'warn',
      detail: `cannot observe the deployment's clock at ${cfg.url}: ${dep.error}`,
      remediation: `Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. ${CLOCK_REMEDIATION}`,
    };
  }
  const refUrl = cfg.clock?.referenceUrl ?? DEFAULT_REFERENCE_URL;
  let ref: DateReading = { offsetMs: 0, uncertaintyMs: 0 };
  let refName = "this machine's clock";
  let refNote = '';
  if (refUrl !== 'local') {
    const r = await readDate(refUrl, deps.fetch, now, timeout);
    if ('error' in r) refNote = ` (reference ${refUrl} unusable: ${r.error}; compared with this machine's clock instead)`;
    else {
      ref = r;
      refName = refUrl;
    }
  }
  const skew = dep.offsetMs - ref.offsetMs;
  const unc = dep.uncertaintyMs + ref.uncertaintyMs;
  const lower = Math.abs(skew) - unc;
  const upper = Math.abs(skew) + unc;
  const status = lower > max ? 'fail' : Math.abs(skew) > warnAt || upper > max ? 'warn' : 'pass';
  const detail =
    `deployment clock ${s(skew)} relative to ${refName}${refNote} (+-${(unc / 1000).toFixed(1)} s: Date has 1 s resolution, plus round trips); ` +
    `fail beyond ${max / 1000} s, warn above ${warnAt / 1000} s. The Date header is written by whatever answers the request (a CDN or proxy may set it).`;
  return {
    id: 'clock',
    status,
    detail,
    ...(status === 'pass' ? {} : { remediation: CLOCK_REMEDIATION }),
    observed: { skewMs: skew, uncertaintyMs: unc, maxSkewMs: max, warnAtMs: warnAt, reference: refName },
  };
}
