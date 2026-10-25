/**
 * Which OPT-IN verified-core paths are switched on (`PCA_VERIFIED_CORE`).
 *
 * Every decision listed under "proved code by default" in docs/pca/security/verified-core.md always runs the Dafny-proved code
 * (no switch, no fallback). The modules here are proved too, but their compiled code is much slower than the hand-written
 * TypeScript on realistic inputs (numbers in that doc and in packages/pca/bench/results/verified-core.json), so the hand-written
 * code stays the default and the proved code is opt-in:
 *
 *   PCA_VERIFIED_CORE=1 | all | true      every opt-in module below
 *   PCA_VERIFIED_CORE=wire,regex,...      the named ones (comma-separated; unknown names are ignored)
 *   unset, empty, 0, false, none          none (default)
 *
 * The variable is read once, on first use. In an environment without `process.env` (a browser bundle) nothing is opted in.
 */
export const VERIFIED_CORE_OPT_IN_MODULES = ['wire', 'regex', 'policyvm', 'merkle-strict', 'noncestore'] as const;
export type VerifiedCoreOptInModule = (typeof VERIFIED_CORE_OPT_IN_MODULES)[number];

let active: ReadonlySet<VerifiedCoreOptInModule> | undefined;

/** Parse a `PCA_VERIFIED_CORE` value. Exported for tests. */
export function parseVerifiedCoreMode(raw: unknown): ReadonlySet<VerifiedCoreOptInModule> {
  if (typeof raw !== 'string') return new Set();
  const v = raw.trim().toLowerCase();
  if (v === '1' || v === 'all' || v === 'true') return new Set(VERIFIED_CORE_OPT_IN_MODULES);
  const out = new Set<VerifiedCoreOptInModule>();
  for (const part of v.split(',')) {
    const p = part.trim();
    if ((VERIFIED_CORE_OPT_IN_MODULES as readonly string[]).includes(p)) out.add(p as VerifiedCoreOptInModule);
  }
  return out;
}

function readEnv(): unknown {
  try {
    // no `process` / `env` (a browser bundle) throws a TypeError here, which the catch turns into "not set"
    return (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env.PCA_VERIFIED_CORE;
  } catch {
    return undefined;
  }
}

/** Is the proved path of `m` switched on? */
export function verifiedCoreOptIn(m: VerifiedCoreOptInModule): boolean {
  if (active === undefined) active = parseVerifiedCoreMode(readEnv());
  return active.has(m);
}

/**
 * TEST HOOK (not exported from the package index): force the opt-in set (a `PCA_VERIFIED_CORE`-style string), or pass
 * `undefined` to re-read the environment on next use.
 */
export function __setVerifiedCoreModeForTests(raw: string | undefined): void {
  active = raw === undefined ? undefined : parseVerifiedCoreMode(raw);
}
