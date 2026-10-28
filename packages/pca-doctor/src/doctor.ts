/** Run every check, merge configuration (file < env < flags), and format the results. */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkEnforcement, checkRootCaveats, type LoadedPca } from './caveats';
import { checkClock, type FetchLike } from './clock';
import { checkProxyConfig, checkProxyProbe } from './proxy';
import { checkStore } from './store';
import { checkAllowedSuites, checkPqBinding } from './suites';
import { scrubDeep, scrubText } from './scrub';
import type { CheckResult, DoctorConfig, ProxyHeader } from './types';

export const CHECK_GROUPS = ['clock', 'store', 'proxy', 'suites', 'caveats'] as const;
export type CheckGroup = (typeof CHECK_GROUPS)[number];

export interface DoctorDeps {
  fetch?: FetchLike;
  now?: () => number;
  loadPca?: (dir?: string) => LoadedPca;
}

/** One check group that throws is a failed check, not a crashed run and not a skipped one. */
async function guarded(id: string, run: () => CheckResult | CheckResult[] | Promise<CheckResult | CheckResult[]>): Promise<CheckResult[]> {
  try {
    const r = await run();
    return Array.isArray(r) ? r : [r];
  } catch (e) {
    return [{ id, status: 'fail', detail: `${id} could not run: ${scrubText(e instanceof Error ? e.message : String(e))}`, remediation: 'Fix the configuration or the dependency named above and run the doctor again.' }];
  }
}

/** Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors. */
export function configProblems(cfg: DoctorConfig): string[] {
  const out: string[] = [];
  const pos = (name: string, v: unknown, int = false): void => {
    if (v === undefined) return;
    if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0 || (int && !Number.isInteger(v))) out.push(`${name} must be a positive ${int ? 'integer' : 'number'}`);
  };
  const nonneg = (name: string, v: unknown): void => {
    if (v === undefined) return;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) out.push(`${name} must be a non-negative integer`);
  };
  pos('clock.maxSkewMs', cfg?.clock?.maxSkewMs);
  pos('clock.timeoutMs', cfg?.clock?.timeoutMs);
  const wf = cfg?.clock?.warnFraction;
  if (wf !== undefined && !(typeof wf === 'number' && wf > 0 && wf <= 1)) out.push('clock.warnFraction must be a number in (0, 1]');
  pos('store.concurrency', cfg?.store?.concurrency, true);
  pos('store.rounds', cfg?.store?.rounds, true);
  nonneg('proxy.trustedProxyCount', cfg?.proxy?.trustedProxyCount);
  nonneg('proxy.hops', cfg?.proxy?.hops);
  if (cfg?.url !== undefined) {
    try {
      const u = new URL(cfg.url);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') out.push('url must be an http(s) URL');
    } catch {
      out.push('url is not a valid URL');
    }
  }
  return out;
}

export async function runDoctor(cfg: DoctorConfig, only: readonly CheckGroup[] = CHECK_GROUPS, deps: DoctorDeps = {}): Promise<CheckResult[]> {
  const problems = configProblems(cfg);
  if (problems.length > 0) {
    return problems.map((p) => ({ id: 'config', status: 'fail' as const, detail: scrubText(`invalid configuration: ${p}`), remediation: 'Correct the setting; no check was run.' }));
  }
  const fetchImpl = deps.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const out: CheckResult[] = [];
  if (only.includes('clock')) out.push(...(await guarded('clock', () => checkClock(cfg, { fetch: fetchImpl, now: deps.now }))));
  if (only.includes('store')) out.push(...(await guarded('store', () => checkStore(cfg))));
  if (only.includes('proxy')) {
    out.push(...(await guarded('proxy.config', () => checkProxyConfig(cfg))));
    out.push(...(await guarded('proxy.probe', () => checkProxyProbe(cfg, { fetch: fetchImpl }))));
  }
  if (only.includes('suites')) {
    out.push(...(await guarded('suites.allowed', () => checkAllowedSuites(cfg))));
    out.push(...(await guarded('suites.pq', () => checkPqBinding(cfg))));
  }
  if (only.includes('caveats')) {
    out.push(...(await guarded('caveats.root', () => checkRootCaveats(cfg, { loadPca: deps.loadPca }))));
    out.push(...(await guarded('caveats.enforcement', () => checkEnforcement(cfg))));
  }
  // Nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message.
  return out.map((r) => scrubDeep(r));
}

export type Verdict = 'pass' | 'warn' | 'fail';

/**
 * fail if any check failed; warn if any warned (fail under --strict); else pass. A run in which nothing was checked
 * (no results, or every result skipped) is a fail: a doctor that looked at nothing must not report a healthy deployment.
 */
export function verdictOf(results: readonly CheckResult[], strict = false): Verdict {
  if (!results.some((r) => r.status !== 'skip')) return 'fail';
  if (results.some((r) => r.status === 'fail')) return 'fail';
  if (results.some((r) => r.status === 'warn')) return strict ? 'fail' : 'warn';
  return 'pass';
}

export function formatResults(results: readonly CheckResult[], target: string | undefined, strict = false): string {
  const lines = [`pca-doctor${target ? `: ${target}` : ''}`];
  for (const r of results) {
    lines.push(`  ${r.status.toUpperCase().padEnd(4)}  ${r.id.padEnd(20)} ${r.detail}`);
    if (r.remediation) lines.push(`  ${''.padEnd(4)}  ${''.padEnd(20)} fix: ${r.remediation}`);
  }
  const n = (s: CheckResult['status']): number => results.filter((r) => r.status === s).length;
  if (!results.some((r) => r.status !== 'skip')) lines.push('  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified');
  lines.push(`Summary: ${n('pass')} pass, ${n('warn')} warn, ${n('fail')} fail, ${n('skip')} skip -> ${verdictOf(results, strict).toUpperCase()}`);
  return lines.join('\n');
}

const bool = (v: string | undefined): boolean | undefined => (v === undefined ? undefined : /^(1|true|yes|on)$/i.test(v));
const int = (name: string, v: string | undefined): number | undefined => {
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer`);
  return n;
};
const PROXY_HEADERS: readonly string[] = ['x-forwarded-for', 'forwarded', 'x-real-ip'];

/** The deployment's own environment variable names (as the API and the guides use them). */
export function configFromEnv(env: Record<string, string | undefined>): DoctorConfig {
  const c: DoctorConfig = {};
  if (env.PCA_DOCTOR_URL) c.url = env.PCA_DOCTOR_URL;
  if (env.PCA_DOCTOR_REFERENCE_URL) c.clock = { referenceUrl: env.PCA_DOCTOR_REFERENCE_URL };
  if (env.PCA_DOCTOR_STORE) c.store = { adapter: env.PCA_DOCTOR_STORE };
  const proxy: NonNullable<DoctorConfig['proxy']> = {};
  if (env.TRUSTED_PROXY_COUNT !== undefined) proxy.trustedProxyCount = int('TRUSTED_PROXY_COUNT', env.TRUSTED_PROXY_COUNT);
  if (env.TRUSTED_PROXY_HEADER) {
    const h = env.TRUSTED_PROXY_HEADER.toLowerCase();
    if (!PROXY_HEADERS.includes(h)) throw new Error(`TRUSTED_PROXY_HEADER must be one of ${PROXY_HEADERS.join(', ')}`);
    proxy.header = h as ProxyHeader;
  }
  if (env.PCA_TRUSTED_PROXY_HOPS !== undefined) proxy.hops = int('PCA_TRUSTED_PROXY_HOPS', env.PCA_TRUSTED_PROXY_HOPS);
  if (Object.keys(proxy).length) c.proxy = proxy;
  const v: NonNullable<DoctorConfig['verifier']> = {};
  if (env.PCA_ALLOWED_SUITES !== undefined) v.allowedSuites = env.PCA_ALLOWED_SUITES.split(',').map((s) => s.trim()).filter(Boolean);
  if (env.PCA_PQ_PINS) {
    let pins: unknown;
    try {
      pins = JSON.parse(env.PCA_PQ_PINS);
    } catch {
      throw new Error('PCA_PQ_PINS is not valid JSON'); // never echo the value
    }
    if (pins === null || typeof pins !== 'object' || Array.isArray(pins) || !Object.values(pins).every((x) => typeof x === 'string')) {
      throw new Error('PCA_PQ_PINS must be a JSON object of issuer -> public key strings');
    }
    v.pqPins = pins as Record<string, string>;
  }
  if (env.PCA_ALLOW_UNBOUND_PQ !== undefined) v.allowUnboundPq = bool(env.PCA_ALLOW_UNBOUND_PQ);
  if (Object.keys(v).length) c.verifier = v;
  return c;
}

/** Two-level merge: later sources win per field inside each section. */
export function mergeConfig(...cs: DoctorConfig[]): DoctorConfig {
  const out: Record<string, unknown> = {};
  for (const c of cs) {
    for (const [k, val] of Object.entries(c)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') throw new Error(`config key "${k}" is not allowed`);
      if (val === undefined) continue;
      out[k] = val && typeof val === 'object' && !Array.isArray(val) ? { ...((out[k] as object) ?? {}), ...val } : val;
    }
  }
  return out as DoctorConfig;
}

/** A JSON file, or a JS module whose default export is the config object. */
export async function loadConfigFile(path: string): Promise<DoctorConfig> {
  if (path.endsWith('.json')) return JSON.parse(readFileSync(path, 'utf8')) as DoctorConfig;
  const m = (await import(pathToFileURL(resolve(path)).href)) as { default?: DoctorConfig };
  return (m.default ?? m) as DoctorConfig;
}
