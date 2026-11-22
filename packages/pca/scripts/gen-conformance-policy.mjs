// Policy layer vectors (conformance/LAYERS.md): conformance/policy-vectors.json, section `policy_decision`.
//
// Each vector is a grant, its delegation chain and a context (the `primitives.caveat_eval` input shape) with two expected
// results computed by the TypeScript reference (scripts/policy-decision.mjs):
//   expect.decision  { allow, reasons: [code...], failed: { envelope, root, delegated } }   the whole policy decision
//   expect.caveats   { allow, failed }                                                     the caveat projection
// No reason text. Families:
//   pd-<placement>-<type>-<case>  every caveat type (max_spend, expires, not_before, rate, max_blast_radius,
//                                 reversibility_max, delegation_depth, budget_alloc, predicates, tool_schema, unknown types)
//                                 at every placement: root-only (no hop), root (with a hop), delegated (appended by a hop),
//                                 envelope (inside the envelope), satisfied / unsatisfied / missing context
//   pd-both-*, pd-dup-*, pd-conflict-*, pd-env-*, pd-pred-*, pd-chain-*   combinations: narrowing, widening attempts,
//                                 duplicates, conflicting caveats, missing or malformed policy, envelope predicates
//   pd-rnd-NNNN                   a seeded random batch (SEED below) over the same catalogue
// Deterministic: fixed key seeds, Ed25519 signatures, a seeded PRNG, no clock.
//
//     node packages/pca/scripts/gen-conformance-policy.mjs [--check]                  (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-policy.mjs   (reads ../src)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, serializeCorpus } from './conformance-io.mjs';
import { evaluatePolicyVector } from './policy-decision.mjs';

const pca = process.env.PCA_SRC ? await import('../src/index.ts') : await import('../dist/index.js');
const OUT = join(confDir, 'policy-vectors.json');
const SEED = 20261025;
const RANDOM_N = 240;
const NOW = 1_800_000_000_000;

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent'), sub2 = mk('policy/subagent-2');

const STAR = [{ verb: '*', resource: '*' }];
const envelope = (predicates = STAR, caveats = []) => ({
  type: 'envelope', goal_commit: pca.b64u(new Uint8Array(32)), predicates, caveats, agent_binding: {}, risk_policy: pca.DEFAULT_RISK_POLICY,
});
const ACTION = { verb: 'pay', resource: 'invoice:42', params: { amount: 10 } };
const TOOL = pca.agentNative.toolSchemaCaveat('pay', { props: { amount: { type: 'number', min: 0, max: 500 }, memo: { type: 'string', maxLength: 16 } }, required: ['amount'] });

/**
 * Build one vector. spec: { env: envelope caveat | null (no envelope), root: [caveat], hops: [[caveat]...] (one array per
 * delegation hop), emptyChain?: true, ctx: extra context members, action: action overrides }.
 */
function build(spec) {
  const rootCaveats = [...(spec.env === null ? [] : [spec.env ?? envelope()]), ...(spec.root ?? [])];
  const grant = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: rootCaveats });
  const chain = [grant];
  const holders = [[sub.pub, agent.sk], [sub2.pub, sub.sk]];
  (spec.hops ?? []).forEach((cs, i) => chain.push(pca.delegate(chain[i], holders[i][0], cs, holders[i][1])));
  const action = { ...ACTION, ...(spec.action ?? {}) };
  const finalChain = spec.emptyChain ? [] : chain;
  const context = { now: NOW, delegation_depth: Math.max(0, finalChain.length - 1), ...(spec.ctx ?? {}), action };
  const v = { grant, chain: finalChain, context };
  const vc = pca.verifyChain(chain, principal.pub);
  if (vc.ok !== true) throw new Error(`fixture chain does not verify: ${vc.reason} ${JSON.stringify(spec).slice(0, 200)}`);
  return v;
}

/** Caveat types used anywhere in the vector (envelope members included), plus `envelope_predicates` when they narrow. */
function features(v) {
  const types = new Set();
  const add = (c) => { if (c && typeof c === 'object' && !Array.isArray(c)) types.add(typeof c.type === 'string' ? c.type : '<untyped>'); else types.add('<non-object>'); };
  const all = [...(v.grant.caveats ?? []), ...(v.chain.length ? v.chain[v.chain.length - 1].caveats.slice(v.grant.caveats.length) : [])];
  for (const c of all) {
    add(c);
    if (c?.type === 'envelope') {
      for (const x of c.caveats ?? []) add(x);
      if (JSON.stringify(c.predicates) !== JSON.stringify(STAR)) types.add('envelope_predicates');
    }
  }
  return [...types].sort();
}

function chainOk(spec) {
  try { build(spec); return true; } catch (e) { if (/fixture chain does not verify/.test(e.message)) return false; throw e; }
}

const vectors = [];
const names = new Set();
function pd(name, description, spec, intended) {
  if (names.has(name)) throw new Error(`duplicate vector name ${name}`);
  names.add(name);
  const v = build(spec);
  const expect = evaluatePolicyVector(pca, v);
  if (intended) {
    if (intended.allow !== undefined && expect.decision.allow !== intended.allow) throw new Error(`${name}: reference decision allow=${expect.decision.allow} ${JSON.stringify(expect.decision.reasons)} != intended ${intended.allow}`);
    if (intended.reasons && JSON.stringify(expect.decision.reasons) !== JSON.stringify(intended.reasons)) throw new Error(`${name}: reference reasons ${JSON.stringify(expect.decision.reasons)} != intended ${JSON.stringify(intended.reasons)}`);
    if (intended.caveats !== undefined && expect.caveats.allow !== intended.caveats) throw new Error(`${name}: reference caveat projection allow=${expect.caveats.allow} != intended ${intended.caveats}`);
  }
  vectors.push({ name, description, layer: 'policy', features: features(v), ...v, expect });
}

// ------------------------------------------------------------------ the per-type matrix
const amt = (amount) => ({ action: { params: { amount } } });
/** type -> [case, caveat, context/action spec, satisfied?] (satisfied: true / false / null = whatever the reference says) */
const CATALOGUE = {
  max_spend: [
    ['within', { type: 'max_spend', usd: 100 }, amt(100), true],
    ['exceeded', { type: 'max_spend', usd: 100 }, amt(101), false],
    ['no-amount', { type: 'max_spend', usd: 100 }, { action: { params: {} } }, false],
    ['currency-eur', { type: 'max_spend', usd: 100 }, { action: { params: { amount: 5, currency: 'eur' } } }, false],
  ],
  expires: [
    ['future', { type: 'expires', at: NOW + 1 }, {}, true],
    ['now', { type: 'expires', at: NOW }, {}, false],
    ['at-missing', { type: 'expires' }, {}, false],
  ],
  not_before: [
    ['now', { type: 'not_before', at: NOW }, {}, true],
    ['future', { type: 'not_before', at: NOW + 1 }, {}, false],
  ],
  rate: [
    ['under', { type: 'rate', max: 2, per_secs: 60 }, { ctx: { recent_action_times: [NOW - 1000, NOW - 60_000] } }, true],
    ['at-limit', { type: 'rate', max: 2, per_secs: 60 }, { ctx: { recent_action_times: [NOW - 1000, NOW - 2000] } }, false],
    ['history-missing', { type: 'rate', max: 2, per_secs: 60 }, {}, false],
  ],
  max_blast_radius: [
    ['equal', { type: 'max_blast_radius', max: 0.5 }, { ctx: { blast_radius: 0.5 } }, true],
    ['above', { type: 'max_blast_radius', max: 0.5 }, { ctx: { blast_radius: 0.6 } }, false],
    ['radius-missing', { type: 'max_blast_radius', max: 0.5 }, {}, false],
  ],
  reversibility_max: [
    ['reversible', { type: 'reversibility_max', class: 'rate_limited' }, { ctx: { reversibility_class: 'reversible' } }, true],
    ['irreversible', { type: 'reversibility_max', class: 'rate_limited' }, { ctx: { reversibility_class: 'irreversible' } }, false],
    ['class-missing', { type: 'reversibility_max', class: 'rate_limited' }, {}, false],
    ['class-unknown', { type: 'reversibility_max', class: 'rate_limited' }, { ctx: { reversibility_class: 'sometimes' } }, false],
  ],
  delegation_depth: [
    ['max-2', { type: 'delegation_depth', max: 2 }, {}, true],
    ['max-0', { type: 'delegation_depth', max: 0 }, {}, null],
    ['max-missing', { type: 'delegation_depth' }, {}, false],
  ],
  budget_alloc: [
    ['limit', { type: 'budget_alloc', limit: 10 }, {}, null],
    // a malformed budget_alloc (negative / missing limit) fails the chain check (capability layer), not policy
    ['limit-zero', { type: 'budget_alloc', limit: 0 }, {}, null],
  ],
  predicates: [
    ['match', { type: 'predicates', allow: [{ verb: 'pay', resource: 'invoice:*' }] }, {}, true],
    ['no-match', { type: 'predicates', allow: [{ verb: 'refund', resource: 'invoice:*' }] }, {}, false],
    ['allow-malformed', { type: 'predicates', allow: 'pay' }, {}, false],
  ],
  tool_schema: [
    ['conforming', TOOL, { action: { params: { amount: 10, memo: 'ok' } } }, true],
    ['out-of-range', TOOL, amt(600), false],
    ['extra-arg', TOOL, { action: { params: { amount: 10, to: 'x' } } }, false],
    ['other-tool', TOOL, { action: { verb: 'refund' } }, false],
  ],
  unknown: [
    ['note', { type: 'note', text: 'n' }, {}, false],
    ['case-variant', { type: 'Max_Spend', usd: 100 }, {}, false],
    ['vendor-extension', { type: 'x-acme-quota', calls: 5 }, {}, false],
    // an untyped or non-string-typed caveat is a malformed capability (capability layer), not a policy input
  ],
};
const PLACEMENTS = {
  'root-only': (c) => ({ root: [c] }),
  root: (c) => ({ root: [c], hops: [[]] }),
  delegated: (c) => ({ hops: [[c]] }),
  envelope: (c) => ({ env: envelope(STAR, [c]) }),
};
const CODE = { 'root-only': 'root_caveats_unsatisfied', root: 'root_caveats_unsatisfied', delegated: 'delegated_caveats_unsatisfied', envelope: 'envelope_caveats_unsatisfied' };
for (const [type, cases] of Object.entries(CATALOGUE)) {
  for (const [cname, cav, extra, sat] of cases) {
    for (const [pl, place] of Object.entries(PLACEMENTS)) {
      const spec = { ...place(cav), ...extra };
      // the envelope's own caveats are not part of the caveat projection (policy_caveats skips the envelope)
      const intended = sat === null ? undefined : { allow: sat, reasons: sat ? [] : [CODE[pl]], ...(pl === 'envelope' ? { caveats: true } : { caveats: sat }) };
      pd(`pd-${pl}-${type}-${cname}`, `${type} (${cname}) ${pl === 'envelope' ? 'inside the envelope' : pl === 'delegated' ? 'appended by a delegation hop' : pl === 'root' ? 'on the root grant, one delegation hop' : 'on the root grant, no delegation hop'}.`, spec, intended);
    }
  }
}

// ------------------------------------------------------------------ combinations
const MS = (usd) => ({ type: 'max_spend', usd });
pd('pd-both-narrowing-within', 'Root max_spend 100, hop narrows to 20, the action spends 20: allowed.', { root: [MS(100)], hops: [[MS(20)]], ...amt(20) }, { allow: true });
pd('pd-both-narrowing-hop-denies', 'Root max_spend 100, hop narrows to 20, the action spends 50: the delegated caveat denies.', { root: [MS(100)], hops: [[MS(20)]], ...amt(50) }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-both-narrowing-both-deny', 'Root max_spend 100, hop 20, the action spends 150: both groups deny.', { root: [MS(100)], hops: [[MS(20)]], ...amt(150) }, { allow: false, reasons: ['root_caveats_unsatisfied', 'delegated_caveats_unsatisfied'] });
pd('pd-both-widening-attempt', 'Root max_spend 20, hop "widens" to 100, the action spends 50: the root caveat still denies (attenuation only).', { root: [MS(20)], hops: [[MS(100)]], ...amt(50) }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-both-envelope-root-hop', 'max_spend 100 in the envelope, 50 on the root, 20 on the hop, the action spends 60: the root (outside the envelope) and the hop deny, the envelope passes.', { env: envelope(STAR, [MS(100)]), root: [MS(50)], hops: [[MS(20)]], ...amt(60) }, { allow: false, reasons: ['root_caveats_unsatisfied', 'delegated_caveats_unsatisfied'] });
pd('pd-both-all-three-deny', 'Envelope 10, root 10, hop 10, the action spends 11: all three groups deny, in order.', { env: envelope(STAR, [MS(10)]), root: [MS(10)], hops: [[MS(10)]], ...amt(11) }, { allow: false, reasons: ['envelope_caveats_unsatisfied', 'root_caveats_unsatisfied', 'delegated_caveats_unsatisfied'] });
pd('pd-both-two-hops', 'Two delegation hops each append a caveat: both are evaluated (depth 2).', { root: [{ type: 'delegation_depth', max: 2 }], hops: [[MS(50)], [{ type: 'expires', at: NOW + 1 }]], ...amt(40) }, { allow: true });
pd('pd-both-two-hops-depth', 'Two hops under a root delegation_depth max 1: the root caveat denies.', { root: [{ type: 'delegation_depth', max: 1 }], hops: [[], []] }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-both-two-hops-second-denies', 'Two hops; the second hop\'s max_spend 5 denies a spend of 10.', { hops: [[MS(50)], [MS(5)]], ...amt(10) }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-dup-root-same', 'The same max_spend twice on the root, satisfied: allowed.', { root: [MS(100), MS(100)], ...amt(100) }, { allow: true });
pd('pd-dup-root-both-fail', 'The same max_spend twice on the root, exceeded: both listed.', { root: [MS(100), MS(100)], ...amt(101) }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-dup-root-and-hop', 'An identical caveat on the root and the hop, exceeded: both groups deny.', { root: [MS(100)], hops: [[MS(100)]], ...amt(101) }, { allow: false, reasons: ['root_caveats_unsatisfied', 'delegated_caveats_unsatisfied'] });
pd('pd-dup-hop-different', 'One hop appends max_spend 100 and max_spend 20: the tighter one denies a spend of 50.', { hops: [[MS(100), MS(20)]], ...amt(50) }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-conflict-window', 'Root expires at now+10, hop not_before now+20: no instant satisfies both; at now the hop denies.', { root: [{ type: 'expires', at: NOW + 10 }], hops: [[{ type: 'not_before', at: NOW + 20 }]] }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-conflict-window-later', 'The same conflicting window evaluated at now+20: the root expiry denies.', { root: [{ type: 'expires', at: NOW + 10 }], hops: [[{ type: 'not_before', at: NOW + 20 }]], ctx: { now: NOW + 20 } }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-conflict-reversibility', 'Root reversibility_max irreversible, hop reversibility_max reversible, class rate_limited: the hop denies.', { root: [{ type: 'reversibility_max', class: 'irreversible' }], hops: [[{ type: 'reversibility_max', class: 'reversible' }]], ctx: { reversibility_class: 'rate_limited' } }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-env-missing', 'No envelope caveat at all (missing policy), every other caveat satisfied: denied.', { env: null, root: [MS(100)], ...amt(10) }, { allow: false, reasons: ['envelope_missing'], caveats: true });
pd('pd-env-missing-no-caveats', 'No caveats at all: denied (missing policy); the caveat projection is empty and allows.', { env: null }, { allow: false, reasons: ['envelope_missing'], caveats: true });
pd('pd-env-malformed-risk-policy', 'An envelope without a valid risk_policy is not a valid envelope: denied.', { env: { ...envelope(), risk_policy: {} } }, { allow: false, reasons: ['envelope_missing'] });
pd('pd-env-malformed-predicates', 'An envelope whose predicates is not an array is not a valid envelope: denied.', { env: { ...envelope(), predicates: { verb: '*' } } }, { allow: false, reasons: ['envelope_missing'] });
pd('pd-env-second-envelope', 'A second envelope caveat on the root is an unknown caveat (root group).', { root: [envelope()] }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-env-second-envelope-hop', 'A delegation hop appends an envelope caveat: unsatisfied (delegated group).', { hops: [[envelope()]] }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-pred-exact', 'Envelope predicate pay on invoice:42: allowed.', { env: envelope([{ verb: 'pay', resource: 'invoice:42' }]) }, { allow: true });
pd('pd-pred-prefix', 'Envelope predicate pay on invoice:*: allowed.', { env: envelope([{ verb: 'pay', resource: 'invoice:*' }]) }, { allow: true });
pd('pd-pred-verb-list', 'Envelope predicate verb [read, pay]: allowed.', { env: envelope([{ verb: ['read', 'pay'], resource: '*' }]) }, { allow: true });
pd('pd-pred-verb-mismatch', 'Envelope predicate refund only: denied by the predicates.', { env: envelope([{ verb: 'refund', resource: '*' }]) }, { allow: false, reasons: ['predicates_unsatisfied'] });
pd('pd-pred-resource-mismatch', 'Envelope predicate pay on order:*: denied by the predicates.', { env: envelope([{ verb: 'pay', resource: 'order:*' }]) }, { allow: false, reasons: ['predicates_unsatisfied'] });
pd('pd-pred-empty', 'An envelope with no predicates grants nothing: denied.', { env: envelope([]) }, { allow: false, reasons: ['predicates_unsatisfied'] });
pd('pd-pred-where-lt', 'Envelope predicate with where amount < 500, the action spends 10: allowed.', { env: envelope([{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lt', value: 500 }] }]) }, { allow: true });
pd('pd-pred-where-lt-denies', 'Envelope predicate with where amount < 500, the action spends 500: denied.', { env: envelope([{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lt', value: 500 }] }]), ...amt(500) }, { allow: false, reasons: ['predicates_unsatisfied'] });
pd('pd-pred-where-missing-field', 'Envelope predicate with where on a param the action lacks: denied (fail closed).', { env: envelope([{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lt', value: 500 }] }]), action: { params: {} } }, { allow: false, reasons: ['predicates_unsatisfied'] });
pd('pd-pred-and-caveat-deny', 'Predicates refuse and a root caveat is unsatisfied: both reasons, predicates first.', { env: envelope([{ verb: 'refund', resource: '*' }]), root: [MS(1)], ...amt(5) }, { allow: false, reasons: ['predicates_unsatisfied', 'root_caveats_unsatisfied'] });
pd('pd-pred-delegated-narrows', 'Envelope allows everything, the hop narrows to read: the delegated predicates caveat denies pay.', { hops: [[{ type: 'predicates', allow: [{ verb: 'read', resource: '*' }] }]] }, { allow: false, reasons: ['delegated_caveats_unsatisfied'] });
pd('pd-chain-empty', 'An empty delegation chain: chain_malformed (the root caveats are still evaluated).', { root: [MS(100)], emptyChain: true, ...amt(10) }, { allow: false, reasons: ['chain_malformed'] });
pd('pd-chain-empty-root-denies', 'An empty delegation chain and an exceeded root caveat.', { root: [MS(100)], emptyChain: true, ...amt(101) }, { allow: false, reasons: ['chain_malformed', 'root_caveats_unsatisfied'] });
pd('pd-ctx-all-missing', 'Every context-dependent caveat with no context member: each is unsatisfied (fail closed).', { root: [{ type: 'rate', max: 1, per_secs: 1 }, { type: 'max_blast_radius', max: 1 }, { type: 'reversibility_max', class: 'irreversible' }], action: { params: {} } }, { allow: false, reasons: ['root_caveats_unsatisfied'] });
pd('pd-ctx-all-present', 'The same caveats with every context member present: allowed.', { root: [{ type: 'rate', max: 1, per_secs: 1 }, { type: 'max_blast_radius', max: 1 }, { type: 'reversibility_max', class: 'irreversible' }], ctx: { recent_action_times: [], blast_radius: 0, reversibility_class: 'irreversible' } }, { allow: true });

// ------------------------------------------------------------------ seeded random batch
function mulberry32(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const rnd = mulberry32(SEED);
const int = (n) => Math.floor(rnd() * n);
const pick = (a) => a[int(a.length)];
const POOL = Object.values(CATALOGUE).flatMap((cs) => cs.map(([, c]) => c));
const PREDS = [STAR, STAR, STAR, [{ verb: 'pay', resource: 'invoice:*' }], [{ verb: 'refund', resource: '*' }], [{ verb: 'pay', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }]];
const AMOUNTS = [0, 10, 20, 100, 101, 600, 0.5];
for (let i = 0; i < RANDOM_N; i++) {
  const cavs = (n) => Array.from({ length: n }, () => pick(POOL));
  const envKind = rnd();
  const env = envKind < 0.05 ? null : envelope(pick(PREDS), cavs(int(2)));
  const nh = int(3);
  const ctx = {};
  if (rnd() < 0.6) ctx.recent_action_times = Array.from({ length: int(3) }, () => NOW - int(90) * 1000);
  if (rnd() < 0.6) ctx.blast_radius = pick([0, 0.25, 0.5, 0.75, 1]);
  if (rnd() < 0.6) ctx.reversibility_class = pick(['reversible', 'rate_limited', 'irreversible', 'costly']);
  const params = rnd() < 0.85 ? { amount: pick(AMOUNTS) } : {};
  const action = { verb: rnd() < 0.85 ? 'pay' : 'refund', params };
  let spec;
  // re-draw the caveats until the chain is a valid capability chain (e.g. budget_alloc may only narrow along it): an
  // invalid chain is the capability layer's business
  do spec = { env, root: cavs(int(3)), hops: Array.from({ length: nh }, () => cavs(int(3))), ctx, action };
  while (!chainOk(spec));
  const n = String(i).padStart(4, '0');
  pd(`pd-rnd-${n}`, `Seeded random policy (seed ${SEED}, #${i}).`, spec, undefined);
}

// ------------------------------------------------------------------ write / check
const tally = (f) => vectors.reduce((m, v) => { const k = f(v); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const file = {
  format: 1,
  layer: 'policy',
  description: 'Policy-layer decision vectors (conformance/LAYERS.md). Generated by packages/pca/scripts/gen-conformance-policy.mjs from the TypeScript reference; do not edit.',
  seed: SEED,
  reason_codes: (await import('./policy-decision.mjs')).REASON_CODES,
  counts: { policy_decision: vectors.length, allow: vectors.filter((v) => v.expect.decision.allow).length, deny: vectors.filter((v) => !v.expect.decision.allow).length, by_family: tally((v) => v.name.replace(/^pd-([a-z]+(?:-only)?)-.*$/, '$1')) },
  policy_decision: vectors,
};
const text = serializeCorpus(file);
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error(`policy-vectors.json differs from a fresh regeneration (${vectors.length} vectors): re-run gen-conformance-policy.mjs and commit`); process.exit(1); }
  console.log(`policy-vectors.json up to date (${vectors.length} vectors)`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${vectors.length} policy_decision vectors (${file.counts.allow} allow / ${file.counts.deny} deny) ${JSON.stringify(file.counts.by_family)}`);
}
