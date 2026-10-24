/**
 * TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER sanity. Two parts:
 *  - config: the stated values against the stated number of appending proxies (`hops`);
 *  - live probe: forged forwarding headers sent to a public rate-limited path, watching `RateLimit-Remaining`. If a forged
 *    request lands in a FRESH bucket while plain requests keep draining one bucket, the deployment derives the client
 *    address from client-written entries (count too large, or a proxy that passes the header through untouched).
 * What cannot be observed from one vantage point: a count that is too LOW (every client merged into the proxy's bucket
 * looks the same as one client), the socket-address fallback, and anything the deployment does not reflect in headers.
 */
import type { FetchLike } from './clock';
import type { CheckResult, DoctorConfig } from './types';

export const PROXY_REMEDIATION =
  'Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy\'s bucket.';

export function checkProxyConfig(cfg: DoctorConfig): CheckResult {
  const p = cfg.proxy;
  const n = p?.trustedProxyCount;
  if (n === undefined) return { id: 'proxy.config', status: 'skip', detail: 'TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)' };
  const header = p?.header ?? 'x-forwarded-for';
  const fail = (detail: string): CheckResult => ({ id: 'proxy.config', status: 'fail', detail, remediation: PROXY_REMEDIATION });
  if (!Number.isInteger(n) || n < 0 || n > 16) return fail(`TRUSTED_PROXY_COUNT=${String(n)} is not an integer in 0..16`);
  if (header === 'x-real-ip' && n === 0) return fail('TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)');
  if (p?.hops === undefined) {
    return {
      id: 'proxy.config',
      status: n === 0 ? 'pass' : 'warn',
      detail: `TRUSTED_PROXY_COUNT=${n} (${header}); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared`,
      ...(n === 0 ? {} : { remediation: PROXY_REMEDIATION }),
    };
  }
  if (n > p.hops) return fail(`TRUSTED_PROXY_COUNT=${n} is larger than the ${p.hops} proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra ${header} entries`);
  if (n < p.hops) {
    return { id: 'proxy.config', status: 'warn', detail: `TRUSTED_PROXY_COUNT=${n} is smaller than the ${p.hops} proxies in front of the API: clients are keyed by a proxy's address and share its bucket`, remediation: PROXY_REMEDIATION };
  }
  return { id: 'proxy.config', status: 'pass', detail: `TRUSTED_PROXY_COUNT=${n} (${header}) matches the stated ${p.hops} appending proxies` };
}

/** A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client. */
export function testNetIp(rand: () => number = Math.random): string {
  return `${rand() < 0.5 ? '198.51.100' : '203.0.113'}.${1 + Math.floor(rand() * 254)}`;
}

/** Forged values for all three headers at once (the server trusts at most one of them). */
export function forgedHeaders(rand: () => number = Math.random): Record<string, string> {
  const chain = Array.from({ length: 17 }, () => testNetIp(rand));
  return { 'x-forwarded-for': chain.join(', '), forwarded: chain.map((ip) => `for=${ip}`).join(', '), 'x-real-ip': testNetIp(rand) };
}

async function remaining(fetchImpl: FetchLike, url: string, headers: Record<string, string>, timeoutMs: number): Promise<number | undefined> {
  const r = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  await r.arrayBuffer().catch(() => undefined);
  const v = r.headers.get('ratelimit-remaining');
  const n = v === null ? NaN : Number(v);
  return Number.isFinite(n) ? n : undefined;
}

export async function checkProxyProbe(cfg: DoctorConfig, deps: { fetch: FetchLike; rand?: () => number }): Promise<CheckResult> {
  const id = 'proxy.probe';
  if (!cfg.url) return { id, status: 'skip', detail: 'no deployment URL given (--url)' };
  if (cfg.proxy?.probe === false) return { id, status: 'skip', detail: 'disabled (--no-probe)' };
  const url = new URL(cfg.proxy?.probePath ?? '/v1/pca/suites', cfg.url).href;
  const t = cfg.clock?.timeoutMs ?? 10_000;
  let seq: (number | undefined)[];
  try {
    const a = await remaining(deps.fetch, url, {}, t);
    const b = await remaining(deps.fetch, url, {}, t);
    const f = await remaining(deps.fetch, url, forgedHeaders(deps.rand), t);
    const c = await remaining(deps.fetch, url, {}, t);
    seq = [a, b, f, c];
  } catch (e) {
    return { id, status: 'warn', detail: `probe request to ${url} failed: ${(e as Error).message}`, remediation: 'Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.' };
  }
  const observed = { url, remaining: seq };
  if (seq.some((x) => x === undefined)) {
    return { id, status: 'skip', detail: `not observable remotely: ${url} does not return a RateLimit-Remaining header on every response`, observed };
  }
  const [a, b, f, c] = seq as [number, number, number, number];
  if (!(b < a && c < b)) {
    return { id, status: 'warn', detail: `inconclusive: the plain requests' bucket did not drain monotonically (${a}, ${b}, then ${c}): a window rollover, a shared bucket or concurrent traffic. Re-run.`, observed };
  }
  if (f > b) {
    return {
      id,
      status: 'fail',
      detail: `a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining ${f}, while the plain requests' bucket was at ${b}): the deployment trusts client-written forwarding entries`,
      remediation: PROXY_REMEDIATION,
      observed,
    };
  }
  return { id, status: 'pass', detail: `forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining ${a}, ${b}, forged ${f}, ${c}). A count that is too LOW is not observable from one client.`, observed };
}
