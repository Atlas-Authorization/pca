// Writes conformance/core-profile.json: the PCA Core conformance profile, i.e. the subset of conformance/vectors.json a
// Core-only implementation (Ed25519, no extensions) must pass. The subset is SELECTED BY RULE from the existing corpus
// (no vector is added or changed); see docs/pca/core.md "Core conformance profile". Deterministic and idempotent:
//
//     node packages/pca/scripts/gen-core-profile.mjs           # write
//     node packages/pca/scripts/gen-core-profile.mjs --check   # exit 1 if the committed file is stale
//
// src/core-conformance.test.ts runs exactly this subset against the TypeScript reference through `@atlasauth/pca/core`.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, CORE_PATH } from './conformance-io.mjs';

export const PROFILE_PATH = join(confDir, 'core-profile.json');

/** Top-level PCActn members that belong to an extension (suites, threshold, intent layers, ZK, bonds). */
export const EXT_TOP = ['alg', 'pq_pk', 'pq_sig', 'threshold', 'intent', 'intent_session', 'zk_compliance', 'bond_ref'];
/** Capability-hop members that belong to the post-quantum suite extension. */
export const EXT_HOP = ['alg', 'pq_pk', 'pq_sig', 'holder_pq'];
/** The only verifier inputs a Core vector may use. */
export const CORE_CONTEXT = ['now', 'aud'];
/** Caveat types a Core verifier evaluates (anything else is unknown and therefore unsatisfied). */
export const CORE_CAVEATS = ['expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc', 'max_spend'];

const own = (o, k) => o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);
const hopHasExt = (h) => EXT_HOP.some((k) => own(h, k));
const chainHasExt = (c) => Array.isArray(c) && c.some(hopHasExt);

/** The parsed PCActn of a vector, or undefined when its raw text is not even JSON (a pure wire refusal). */
function pcactnOf(v) {
  if (v.pcactn !== undefined) return v.pcactn;
  try {
    return JSON.parse(v.pcactn_json);
  } catch {
    return undefined;
  }
}

/** Why a PCActn vector is NOT in the Core profile, or null when it is. */
export function pcactnExclusion(v, checkOrder) {
  if (v.requires !== undefined) return `requires ${v.requires}`;
  if (v.requires_suite !== undefined) return 'requires_suite';
  const extraCtx = Object.keys(v.context ?? {}).filter((k) => !CORE_CONTEXT.includes(k));
  if (extraCtx.length) return `context ${extraCtx.join(',')}`;
  const extraChecks = Object.keys(v.expect?.checks ?? {}).filter((k) => !checkOrder.includes(k));
  if (extraChecks.length) return `checks ${extraChecks.join(',')}`;
  if (hopHasExt(v.grant)) return 'grant uses a PQ suite';
  const p = pcactnOf(v);
  if (p !== null && typeof p === 'object' && !Array.isArray(p)) {
    const top = EXT_TOP.filter((k) => own(p, k));
    if (top.length) return `member ${top.join(',')}`;
    if (chainHasExt(p.cap_chain)) return 'hop uses a PQ suite';
  }
  return null;
}

const caveatTypes = (c) => [...(c.grant?.caveats ?? []), ...(c.chain ?? []).flatMap((h) => h?.caveats ?? [])].map((x) => x?.type);

export function selectCoreProfile(file) {
  const order = file.check_order;
  const P = file.primitives;
  const vectors = file.vectors.filter((v) => pcactnExclusion(v, order) === null).map((v) => v.name);
  // caveat_eval: entries without an `envelope` caveat (the envelope is the Policy-and-risk extension). Unknown types
  // (e.g. `note`) stay: a Core evaluator must refuse them.
  const caveat_eval = P.caveat_eval.filter((c) => !caveatTypes(c).includes('envelope')).map((c) => c.name);
  const malformed = P.malformed.filter((m) => m.api === 'chain' || m.api === 'pcactn_json').map((m) => m.name);
  const depth = P.depth.filter((d) => d.api !== 'threshold_share').map((d) => d.name);
  return {
    profile: 'pca-core/1',
    source: 'vectors.json',
    check_order: order,
    rules: {
      vectors: `no "requires" / "requires_suite"; context only {${CORE_CONTEXT.join(', ')}}; expected checks only check_order; no top-level ${EXT_TOP.join(' / ')} and no hop or grant ${EXT_HOP.join(' / ')}`,
      primitives: 'canonical, json_parse, b64u, merkle, params_digest_empty, pca_header: all; caveat_eval: entries without an envelope caveat; malformed and depth: the chain / pcactn_json / json_parse entries',
      core_caveats: CORE_CAVEATS,
    },
    counts: {
      vectors: vectors.length,
      canonical: P.canonical.length,
      json_parse: P.json_parse.length,
      b64u: P.b64u.length,
      merkle: P.merkle.length,
      pca_header: P.pca_header.length,
      caveat_eval: caveat_eval.length,
      malformed: malformed.length,
      depth: depth.length,
    },
    vectors,
    primitives: { caveat_eval, malformed, depth },
  };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const file = JSON.parse(readFileSync(CORE_PATH, 'utf8'));
  const text = JSON.stringify(selectCoreProfile(file), null, 1) + '\n';
  if (process.argv.includes('--check')) {
    let cur = '';
    try {
      cur = readFileSync(PROFILE_PATH, 'utf8');
    } catch {}
    if (cur !== text) {
      console.error('core-profile.json is stale: run node packages/pca/scripts/gen-core-profile.mjs');
      process.exit(1);
    }
    console.log('core-profile.json is current');
  } else {
    writeFileSync(PROFILE_PATH, text);
    const p = JSON.parse(text);
    console.log(`core profile: ${JSON.stringify(p.counts)}`);
  }
}
