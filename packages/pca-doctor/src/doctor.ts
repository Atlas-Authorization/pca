/** Run every check, merge configuration (file < env < flags), and format the results. */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkEnforcement, checkRootCaveats, type LoadedPca } from './caveats';
import { checkClock, type FetchLike } from './clock';
import { checkProxyConfig, checkProxyProbe } from './proxy';
import { checkStore } from './store';
import { checkAllowedSuites, checkPqBinding } from './suites';
import type { CheckResult, DoctorConfig, ProxyHeader } from './types';

export const CHECK_GROUPS = ['clock', 'store', 'proxy', 'suites', 'caveats'] as const;
export type CheckGroup = (typeof CHECK_GROUPS)[number];

export interface DoctorDeps {
  fetch?: FetchLike;
  now?: () => number;
  loadPca?: (dir?: string) => LoadedPca;
}

export async function runDoctor(cfg: DoctorConfig, only: readonly CheckGroup[] = CHECK_GROUPS, deps: DoctorDeps = {}): Promise<CheckResult[]> {
  const fetchImpl = deps.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const out: CheckResult[] = [];
  if (only.includes('clock')) out.push(await checkClock(cfg, { fetch: fetchImpl, now: deps.now }));
  if (only.includes('store')) out.push(...(await checkStore(cfg)));
  if (only.includes('proxy')) out.push(checkProxyConfig(cfg), await checkProxyProbe(cfg, { fetch: fetchImpl }));
  if (only.includes('suites')) out.push(checkAllowedSuites(cfg), checkPqBinding(cfg));
  if (only.includes('caveats')) out.push(checkRootCaveats(cfg, { loadPca: deps.loadPca }), checkEnforcement(cfg));
  return out;
}

export type Verdict = 'pass' | 'warn' | 'fail';

/** fail if any check failed; warn if any warned (fail under --strict); else pass. */
export function verdictOf(results: readonly CheckResult[], strict = false): Verdict {
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
  lines.push(`Summary: ${n('pass')} pass, ${n('warn')} warn, ${n('fail')} fail, ${n('skip')} skip -> ${verdictOf(results, strict).toUpperCase()}`);
  return lines.join('\n');
}

const bool = (v: string | undefined): boolean | undefined => (v === undefined ? undefined : /^(1|true|yes|on)$/i.test(v));
const int = (v: string | undefined): number | undefined => (v === undefined || v === '' ? undefined : Number(v));

/** The deployment's own environment variable names (as the API and the guides use them). */
export function configFromEnv(env: Record<string, string | undefined>): DoctorConfig {
  const c: DoctorConfig = {};
  if (env.PCA_DOCTOR_URL) c.url = env.PCA_DOCTOR_URL;
  if (env.PCA_DOCTOR_REFERENCE_URL) c.clock = { referenceUrl: env.PCA_DOCTOR_REFERENCE_URL };
  if (env.PCA_DOCTOR_STORE) c.store = { adapter: env.PCA_DOCTOR_STORE };
  const proxy: NonNullable<DoctorConfig['proxy']> = {};
  if (env.TRUSTED_PROXY_COUNT !== undefined) proxy.trustedProxyCount = int(env.TRUSTED_PROXY_COUNT);
  if (env.TRUSTED_PROXY_HEADER) proxy.header = env.TRUSTED_PROXY_HEADER as ProxyHeader;
  if (env.PCA_TRUSTED_PROXY_HOPS !== undefined) proxy.hops = int(env.PCA_TRUSTED_PROXY_HOPS);
  if (Object.keys(proxy).length) c.proxy = proxy;
  const v: NonNullable<DoctorConfig['verifier']> = {};
  if (env.PCA_ALLOWED_SUITES !== undefined) v.allowedSuites = env.PCA_ALLOWED_SUITES.split(',').map((s) => s.trim()).filter(Boolean);
  if (env.PCA_PQ_PINS) v.pqPins = JSON.parse(env.PCA_PQ_PINS) as Record<string, string>;
  if (env.PCA_ALLOW_UNBOUND_PQ !== undefined) v.allowUnboundPq = bool(env.PCA_ALLOW_UNBOUND_PQ);
  if (Object.keys(v).length) c.verifier = v;
  return c;
}

/** Two-level merge: later sources win per field inside each section. */
export function mergeConfig(...cs: DoctorConfig[]): DoctorConfig {
  const out: Record<string, unknown> = {};
  for (const c of cs) {
    for (const [k, val] of Object.entries(c)) {
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
