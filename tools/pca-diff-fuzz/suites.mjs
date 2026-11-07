// Suite capability for the cross-language gate (packages/pca/conformance/README.md "Suite capability",
// packages/pca/conformance/SUITES.md).
//
// Every verifier declares the signature suites it implements (driver protocol: input {id, kind:"suites"} -> output
// {id, suites:[...]}). A vector that carries a registered suite outside a language's declaration is NOT compared with the
// reference for that language; instead the language must refuse it: allow == false AND either its verdict carries the
// reason `unsupported_suite` (drivers tag it as the `unsupported_suite` output field) or, when the reference itself
// rejects the vector at the wire stage, the same terminal {wire:false} (more generally: the reference rejects it at a
// pre-intent PCActn check for its own reason and the language rejects at that same check). A language that refuses with `unsupported_suite`
// a vector whose suites it all declares is a finding too (a capability it claims but does not deliver).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..');

/** The suite registry, read from the TS reference (`export type SigAlg = ...` in packages/pca/src/pq.ts) so it cannot drift. */
export const REGISTERED_SUITES = (() => {
  const src = readFileSync(join(ROOT, 'packages/pca/src/pq.ts'), 'utf8');
  const m = /export type SigAlg =([^;]*);/.exec(src);
  const names = m ? [...m[1].matchAll(/'([a-z0-9-]+)'/g)].map((x) => x[1]) : [];
  if (names.length < 3 || !names.includes('ed25519')) throw new Error('suites.mjs: could not read SigAlg from packages/pca/src/pq.ts');
  return Object.freeze(names);
})();
const REGISTERED = new Set(REGISTERED_SUITES);

/** What a driver that does not answer kind "suites" is assumed to implement (the pre-manifest cross-impl set). */
export const LEGACY_SUITES = Object.freeze(['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']);

/** The protocol line that asks a driver for its manifest. */
export const SUITES_QUERY = { id: '__suites__', kind: 'suites', raw: '', grant: '', now: 0, aud: '' };

/** The manifest from a driver's answer to SUITES_QUERY, or null when the driver did not answer it. */
export function manifestOf(row) {
  return row && Array.isArray(row.suites) && row.suites.every((s) => typeof s === 'string') ? row.suites : null;
}

/**
 * The registered suites a vector carries: every string `alg` member anywhere in the parsed artifact (PCActn leaf,
 * capability hops, threshold shares, Intent v2 artifacts, a chain-pin input) that names a registered suite. A vector
 * whose text does not parse carries none (every verifier refuses it at the wire stage anyway). `context` (optional) is
 * the verifier state sent beside the artifact (the Intent v2 `intent_v2` object: a session root, sequencer keys, a
 * receipt); the suites its keys name are carried too.
 */
export function suitesOf(raw, context) {
  let v;
  try { v = JSON.parse(raw); } catch { return []; }
  if (context !== undefined) v = [v, context];
  const found = new Set();
  const walk = (x, depth) => {
    if (depth > 64 || x === null || typeof x !== 'object') return;
    if (Array.isArray(x)) { for (const y of x) walk(y, depth + 1); return; }
    for (const [k, y] of Object.entries(x)) {
      if (k === 'alg' && typeof y === 'string' && REGISTERED.has(y)) found.add(y);
      else walk(y, depth + 1);
    }
  };
  walk(v, 0);
  return [...found];
}

const onlyWireFalse = (r) => r && r.allow === false && r.checks && Object.keys(r.checks).length === 1 && r.checks.wire === false;

// The PCActn checks that run before any Intent v2 stage, in pipeline order (scripts/pca-conformance-all.mjs CHECK_ORDER).
const PRE_INTENT_ORDER = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
/** The first failed pre-intent check of a raw verdict, or null when every pre-intent check it reports passed. */
const firstPreIntentFail = (r) => (r && r.checks ? PRE_INTENT_ORDER.find((k) => k in r.checks && r.checks[k] === false) ?? null : null);
/**
 * The reference refused the vector at a pre-intent check for a reason of its own (not unsupported_suite) and the
 * language refused at that SAME check. This generalises the terminal-wire allowance: a fuzzed variant of a vector whose
 * suite sits in the Intent v2 context (e.g. a session root signed with fn-dsa-512) whose chain or plan proof the mutation
 * broke is refused by every verifier at that check, before the suite is ever dispatched, so no `unsupported_suite` tag
 * can appear - the refusal is the right one. A failure at an Intent v2 check (outside this order) is NOT excused.
 */
const sameEarlyRefusal = (ref, res) => {
  if (!ref || !res || ref.allow !== false || res.allow !== false) return false;
  if (typeof ref.unsupported_suite === 'string') return false;
  const a = firstPreIntentFail(ref);
  return a !== null && a === firstPreIntentFail(res);
};

/**
 * Judge one language's raw result for one vector under its declared suites.
 *   { gated: false }                          the vector stays inside the declaration: compare with the reference as usual
 *                                             (`ok` false when the language nevertheless refused with unsupported_suite);
 *   { gated: true, ok, missing }              the vector needs `missing` (outside the declaration): `ok` iff the language
 *                                             refused as the rule requires. Never compared with the reference.
 * `ref` is the reference's raw result for the same vector (the terminal-wire allowance, and its own `unsupported_suite`
 * tag); `context` is the
 * vector's verifier state (`intent_v2`), scanned for suites like the artifact.
 */
export function judgeSuite(declared, raw, res, ref, context) {
  const missing = suitesOf(raw, context).filter((s) => !declared.has(s));
  const flagged = typeof res?.unsupported_suite === 'string' && res.unsupported_suite.includes('unsupported_suite');
  // a refusal tagged unsupported_suite inside the declaration is a finding unless the reference refused the same way
  // (the vector names a suite no verifier implements, e.g. an unregistered alg in the Intent v2 context)
  const refFlagged = typeof ref?.unsupported_suite === 'string' && ref.unsupported_suite.includes('unsupported_suite');
  if (!missing.length) return { gated: false, ok: !flagged || (refFlagged && res?.allow === false), missing, flagged };
  if (!res || res.error !== undefined || res.marker) return { gated: true, ok: false, missing, flagged };
  const ok = res.allow === false && (flagged || (onlyWireFalse(ref) && onlyWireFalse(res)) || sameEarlyRefusal(ref, res));
  return { gated: true, ok, missing, flagged };
}
