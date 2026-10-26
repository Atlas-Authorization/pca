// Shared TypeScript REFERENCE adapter (the oracle every other verifier is judged against).
// Used by the generator (expected verdicts) and by the all-languages runner (ref-driver.ts).
import { safeParse } from '../../../tools/pca-diff-fuzz/gen/safejson';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type * as PcaT from '../../pca/src/index';

const nodeRequire = createRequire(__filename);
// Reference = TypeScript SOURCE. Other agents edit packages/pca/src concurrently; if the source tree is momentarily
// unloadable (half-written import) fall back to the built dist (same wire logic) and say so. PCA_REF=dist forces dist.
function loadRef(): typeof PcaT {
  const want = process.env.PCA_REF;
  if (want !== 'dist') { try { return nodeRequire('../../pca/src/index'); } catch (e) { if (want === 'src') throw e; console.error('[ref] source tree not loadable, using packages/pca/dist:', (e as Error).message.split('\n')[0]); } }
  return nodeRequire('../../pca/dist/index.js');
}
export const pca = loadRef();
export type PCActn = PcaT.PCActn; type Capability = PcaT.Capability;


// ---------------------------------------------------------------- reference oracle (mirrors tools/pca-diff-fuzz/gen/oracle.ts)
const CK = [['version', 'version'], ['audience', 'audience'], ['validity', 'validity'], ['chain', 'cap_chain'], ['grant_ref_bound', 'grant_ref_bound'], ['plan_inclusion', 'plan_inclusion'], ['leaf_signature', 'leaf_signature'], ['counter_format', 'counter_format']] as const;
export async function refVerify(rawStr: string, grantStr: string, now: number, aud: string, allowedSuites?: string[], intentPolicy?: PcaT.IntentPolicy, intentPolicyJson?: string, intentV2?: unknown): Promise<Record<string, unknown>> {
  // `intent_policy_json` is the policy as raw JSON text (lexical forms such as 950000.0 / 1e6 survive transport); it wins.
  if (intentPolicyJson !== undefined) intentPolicy = JSON.parse(intentPolicyJson) as PcaT.IntentPolicy;
  try {
    let p: PCActn | undefined;
    try { p = pca.decodePCActn(rawStr); } catch { /* wire failure */ }
    if (p === undefined) return { allow: false, checks: { wire: false } };
    const g = await pca.verifyPCActnCore(p, { grant: safeParse(grantStr) as Capability, nowEpoch: now, audience: aud, ...(allowedSuites !== undefined ? { allowedSuites: allowedSuites as never } : {}), ...(intentPolicy !== undefined ? { intent: intentPolicy } : {}), ...(intentV2 !== undefined ? { intentV2: intentV2 as never } : {}) });
    // Intent Layer M2: `intent` is reported only when evaluated (the PCActn carries `intent` or the policy is active).
    const intent = g.checks.intent !== undefined ? [['intent', g.checks.intent === 'pass']] : [];
    // `unsupported_suite`: the reference itself refused with that reason (a suite no verifier implements, e.g. an
    // unregistered alg in the Intent v2 context); the gate's suite judge reads it (drivers tag theirs the same way).
    const uns = typeof g.reason === 'string' && g.reason.includes('unsupported_suite') ? { unsupported_suite: g.reason } : {};
    return { allow: g.allow, checks: g.checks.wire === 'fail' ? { wire: false } : Object.fromEntries([['wire', true], ...CK.map(([k, t]) => [k, g.checks[t] === 'pass']), ...intent]), ...uns };
  } catch (e) { return { error: 'exception:' + (e as Error).message.slice(0, 60) }; }
}
/** Standalone chain API (R4-01): `raw` is JSON text `{ chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites? }`. */
export function refChain(rawStr: string): Record<string, unknown> {
  try {
    const o = safeParse(rawStr) as { chain: unknown; expected_root_issuer?: string; pq_pins?: Record<string, string>; trusted_root?: Capability; allowed_suites?: string[] };
    const r = pca.verifyChain(o.chain as never, o.expected_root_issuer, {
      ...(o.pq_pins !== undefined ? { pqPins: o.pq_pins } : {}),
      ...(o.trusted_root !== undefined ? { trustedRoot: o.trusted_root } : {}),
      ...(o.allowed_suites !== undefined ? { allowedSuites: o.allowed_suites as never } : {}),
    });
    return { allow: r.ok, checks: { chain: r.ok } };
  } catch (e) { return { error: 'exception:' + (e as Error).message.slice(0, 60) }; }
}
// Layered conformance (packages/pca/conformance/LAYERS.md): the policy and stateful layers, evaluated by the same shared
// modules the generators and the TS conformance test use.
const scriptUrl = (f: string) => pathToFileURL(join(__dirname, '../../pca/scripts', f)).href;
/** Policy layer (kind `policy`): raw = JSON text `{ grant, chain, context }`. `allow` / `failed` are the caveat projection
 *  (what the native drivers answer); `decision` is the whole policy decision (no native driver answers it yet). */
export async function refPolicy(rawStr: string): Promise<Record<string, unknown>> {
  try {
    const m = await import(scriptUrl('policy-decision.mjs'));
    const r = m.evaluatePolicyVector(pca, safeParse(rawStr));
    return { allow: r.caveats.allow, failed: r.caveats.failed, decision: r.decision };
  } catch (e) { return { error: 'exception:' + (e as Error).message.slice(0, 60) }; }
}
/** Stateful layer (kind `stateful`): raw = JSON text of one sequence; one `{ allow, failed }` (or null) per step. */
export async function refStateful(rawStr: string): Promise<Record<string, unknown>> {
  try {
    const m = await import(scriptUrl('stateful-sequence.mjs'));
    return { steps: await m.runSequence(pca, safeParse(rawStr)) };
  } catch (e) { return { error: 'exception:' + (e as Error).message.slice(0, 60) }; }
}
export function refCanon(rawStr: string): Record<string, unknown> {
  try { const v = pca.strictParse(rawStr); return { canon: pca.canonicalizeStrict(v), hash: pca.hashCanonical(v) }; }
  catch { return { error: 'parse' }; }
}

