// Shared TypeScript REFERENCE adapter (the oracle every other verifier is judged against).
// Used by the generator (expected verdicts) and by the all-languages runner (ref-driver.ts).
import { safeParse } from '../../../tools/pca-diff-fuzz/gen/safejson';
import type * as PcaT from '../../pca/src/index';
// Reference = TypeScript SOURCE. Other agents edit packages/pca/src concurrently; if the source tree is momentarily
// unloadable (half-written import) fall back to the built dist (same wire logic) and say so. PCA_REF=dist forces dist.
function loadRef(): typeof PcaT {
  const want = process.env.PCA_REF;
  if (want !== 'dist') { try { return require('../../pca/src/index'); } catch (e) { if (want === 'src') throw e; console.error('[ref] source tree not loadable, using packages/pca/dist:', (e as Error).message.split('\n')[0]); } }
  return require('../../pca/dist/index.js');
}
export const pca = loadRef();
export type PCActn = PcaT.PCActn; type Capability = PcaT.Capability;


// ---------------------------------------------------------------- reference oracle (mirrors tools/pca-diff-fuzz/gen/oracle.ts)
const CK = [['version', 'version'], ['audience', 'audience'], ['validity', 'validity'], ['chain', 'cap_chain'], ['grant_ref_bound', 'grant_ref_bound'], ['plan_inclusion', 'plan_inclusion'], ['leaf_signature', 'leaf_signature'], ['counter', 'counter']] as const;
export async function refVerify(rawStr: string, grantStr: string, now: number, aud: string): Promise<Record<string, unknown>> {
  try {
    let p: PCActn | undefined;
    try { p = pca.decodePCActn(rawStr); } catch { /* wire failure */ }
    if (p === undefined) return { allow: false, checks: { wire: false } };
    const g = await pca.verifyPCActnCore(p, { grant: safeParse(grantStr) as Capability, nowEpoch: now, audience: aud });
    return { allow: g.allow, checks: g.checks.wire === 'fail' ? { wire: false } : Object.fromEntries([['wire', true], ...CK.map(([k, t]) => [k, g.checks[t] === 'pass'])]) };
  } catch (e) { return { error: 'exception:' + (e as Error).message.slice(0, 60) }; }
}
export function refCanon(rawStr: string): Record<string, unknown> {
  try { const v = pca.strictParse(rawStr); return { canon: pca.canonicalizeStrict(v), hash: pca.hashCanonical(v) }; }
  catch { return { error: 'parse' }; }
}

