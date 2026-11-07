/**
 * Root-caveat enforcement (0.4.1 security fix). There is NO switch that turns it off in 0.4.1: decide() / verifyPCActn /
 * requirePCA always evaluate the caveats on the root grant. What can leave a deployment without it is an OLDER library
 * (< 0.4.1, where root caveats outside the envelope were signed but ignored) or a verifier that skips enforcement. So:
 *  - the installed @atlasauth/pca version (the deployment's own, via verifier.pcaDir) must be >= 0.4.1;
 *  - a functional probe through THAT library: a root max_spend of 100 must deny 150 and allow 50, and an unknown root
 *    caveat type must deny (fail closed);
 *  - requirePCA must not run with insecureAllowUnenforced, and a custom `require` list should keep the defaults.
 */
import { existsSync } from 'node:fs';
import { dirname, join, resolve as resolvePath } from 'node:path';
import type { CheckResult, DoctorConfig } from './types';

/** The parts of @atlasauth/pca the probe uses (typed loosely: any version may be loaded). */
export type PcaLike = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export interface LoadedPca {
  module: PcaLike;
  version: string;
  path: string;
}

/** Load @atlasauth/pca as resolved from `dir` (the deployed application), or the doctor's own copy. */
export function loadPca(dir?: string): LoadedPca {
  // With `paths`, require.resolve falls back to the GLOBAL folders (NODE_PATH, which pnpm's bin shims set to the store's
  // hoisted node_modules, and ~/.node_modules) when nothing under `dir` has the package, and would silently probe some
  // other copy (e.g. the doctor's own) instead of the application's. So `dir` must itself install it: the nearest
  // ancestor holding node_modules/@atlasauth/pca is the resolution base, and none is an error.
  let base: string | undefined;
  if (dir) {
    for (let d = resolvePath(dir); ; d = dirname(d)) {
      if (existsSync(join(d, 'node_modules', '@atlasauth', 'pca', 'package.json'))) { base = d; break; }
      if (dirname(d) === d) break;
    }
    if (base === undefined) throw new Error(`@atlasauth/pca is not installed in ${dir} or any parent node_modules`);
  }
  const opts = base ? { paths: [base] } : undefined;
  const pkgPath = require.resolve('@atlasauth/pca/package.json', opts);
  const main = require.resolve('@atlasauth/pca', opts);
  return { module: require(main) as PcaLike, version: String((require(pkgPath) as { version?: unknown }).version), path: dirname(pkgPath) };
}

/** -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1. */
export function compareVersion(a: string, b: string): number {
  const pa = a.split(/[.+-]/).slice(0, 3).map(Number);
  const pb = b.split(/[.+-]/).slice(0, 3).map(Number);
  for (let i = 0; i < 3; i++) {
    const x = Number.isFinite(pa[i]) ? pa[i]! : -1;
    const y = Number.isFinite(pb[i]) ? pb[i]! : -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export const ROOT_CAVEAT_MIN_VERSION = '0.4.1';
export const CAVEAT_REMEDIATION =
  'Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.';

/** Decide a payment of `amount` USD under a root grant carrying `rootCaveat`; returns the decision. */
export function probeDecision(m: PcaLike, rootCaveat: Record<string, unknown>, amount: number, now = Date.now()): { allowed: boolean; reasons: string[] } {
  const principal = m.generateKeyPair();
  const pPub = m.encodeKey(principal.publicKey);
  const { grant: g0 } = m.mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'pca-doctor root caveat probe',
    envelope: { predicates: [{ verb: 'pay', resource: 'invoice:*' }], caveats: [{ type: 'expires', at: now + 3_600_000 }], agent_binding: {}, risk_policy: m.DEFAULT_RISK_POLICY },
  });
  const grant = m.mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: pPub, caveats: [...g0.caveats, rootCaveat] });
  const agent = m.generateKeyPair();
  const task = m.delegate(grant, m.encodeKey(agent.publicKey), [], principal.secretKey);
  const d = m.decide({
    grant,
    chain: [grant, task],
    action: { action: { verb: 'pay', resource: 'invoice:42', params: { amount, currency: 'usd' }, reversibility_class: 'reversible' } },
    risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 },
    budget: { B: 1e9, tau: now, asOf: now },
    now,
  });
  return { allowed: d.releaseGuardianShare === true, reasons: Array.isArray(d.reasons) ? d.reasons.map(String) : [] };
}

export function checkRootCaveats(cfg: DoctorConfig, deps: { loadPca?: (dir?: string) => LoadedPca } = {}): CheckResult {
  const id = 'caveats.root';
  let pca: LoadedPca;
  try {
    pca = (deps.loadPca ?? loadPca)(cfg.verifier?.pcaDir);
  } catch (e) {
    return { id, status: 'fail', detail: `cannot load @atlasauth/pca${cfg.verifier?.pcaDir ? ` from ${cfg.verifier.pcaDir}` : ''}: ${(e as Error).message}`, remediation: CAVEAT_REMEDIATION };
  }
  const where = `@atlasauth/pca ${pca.version} at ${pca.path}`;
  if (compareVersion(pca.version, ROOT_CAVEAT_MIN_VERSION) < 0) {
    return { id, status: 'fail', detail: `${where}: root caveats outside the envelope are NOT enforced before ${ROOT_CAVEAT_MIN_VERSION} (legacy behaviour)`, remediation: CAVEAT_REMEDIATION };
  }
  let over: ReturnType<typeof probeDecision>, under: ReturnType<typeof probeDecision>, unknown: ReturnType<typeof probeDecision>;
  try {
    over = probeDecision(pca.module, { type: 'max_spend', usd: 100 }, 150);
    under = probeDecision(pca.module, { type: 'max_spend', usd: 100 }, 50);
    unknown = probeDecision(pca.module, { type: 'pca-doctor-unknown-caveat' }, 50);
  } catch (e) {
    return { id, status: 'fail', detail: `${where}: the enforcement probe could not run: ${(e as Error).message}`, remediation: CAVEAT_REMEDIATION };
  }
  const observed = { version: pca.version, over, under, unknown };
  if (over.allowed || unknown.allowed) {
    return {
      id,
      status: 'fail',
      detail: `${where}: a root caveat was NOT enforced (${over.allowed ? 'max_spend 100 allowed a 150 payment' : 'an unknown root caveat type was allowed'})`,
      remediation: CAVEAT_REMEDIATION,
      observed,
    };
  }
  if (!under.allowed) {
    return { id, status: 'warn', detail: `${where}: inconclusive: the control payment within the root max_spend was denied too (${under.reasons.join('; ')})`, observed };
  }
  return { id, status: 'pass', detail: `${where}: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)`, observed };
}

export const DEFAULT_REQUIRED = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];

export function checkEnforcement(cfg: DoctorConfig): CheckResult {
  const id = 'verifier.enforcement';
  const v = cfg.verifier;
  if (!v) return { id, status: 'skip', detail: 'no verifier configuration given (config verifier.*)' };
  if (v.insecureAllowUnenforced === true) {
    return { id, status: 'fail', detail: 'requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny', remediation: 'Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).' };
  }
  if (v.require !== undefined) {
    const missing = DEFAULT_REQUIRED.filter((c) => !v.require!.includes(c));
    if (missing.length > 0) {
      return { id, status: 'warn', detail: `the require list drops default check(s): ${missing.join(', ')}`, remediation: `Keep every default required check (${DEFAULT_REQUIRED.join(', ')}) and add to it.` };
    }
  }
  return { id, status: 'pass', detail: v.require ? `require = ${v.require.join(', ')}` : 'default required checks; insecureAllowUnenforced off' };
}
