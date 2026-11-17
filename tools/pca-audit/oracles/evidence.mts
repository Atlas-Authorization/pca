// Oracle: @atlasauth/pca-evidence (dispute evidence bundle): shape validation, normal form, commitments-only form, digest,
// reference + anchor leaf, grant cap reader, trust-input validators. Deterministic (no clocks, no randomness).
// PORTING (fn(args) -> native entry point, comparison rule; all by JSON value, a throw requires the native to refuse):
//   bundleShapeError(b)                 EvidenceBundle.bundleShapeError(b): exact string or null
//   normalizeBundle(b)                  EvidenceBundle.normalizeBundle(b): JSON equality (or must throw)
//   buildEvidenceBundle(parts)          EvidenceBundle.buildEvidenceBundle(parts): JSON equality (or must throw)
//   commitmentForm(b)                   EvidenceBundle.commitmentForm(b)
//   evidenceDigest(b)                   EvidenceBundle.evidenceDigest(b): exact string
//   evidenceRef(b)                      EvidenceScitt.evidenceRef(b)
//   evidenceAnchorCommit(d)             EvidenceScitt.evidenceAnchorCommit(d); anchorCommit(kind, d) EvidenceVerify.anchorCommit
//   capOf(grant, acc, verb)             EvidenceVerify.capOf: number or null
//   principalsTrustError(p) / accTrustError(a)   EvidenceVerify.*: exact string or null (an absent argument is "undefined": the oracle
//                                       records it as the no-argument case "absent", which the native maps to null)
//   consts                              EVIDENCE_DOMAIN, EVIDENCE_REPORT_DOMAIN, EVIDENCE_CONTENT_TYPE
// Not ported: verifyEvidenceBundle (needs core intent-v2 verifier, wallet and WebAuthn verifiers), CLI. evidenceSignedStatement: evidence-java-extra.mts.
import * as Ev from '@atlasauth/pca-evidence';
import { Oracle, refWrite, reparse, getAt, setAt, paths, DEL } from './lib.mjs';

const E: any = (Ev as any).default ?? Ev;
const o = new Oracle('evidence', 'tools/pca-audit/oracles/evidence.mts', 'TS-reference oracle for the dispute evidence bundle.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const h = (c: string) => Buffer.alloc(32, c.charCodeAt(0)).toString('base64url');
const sig = (c: string) => Buffer.alloc(64, c.charCodeAt(0)).toString('base64url');

const grant = (id: string, seq: number, extra: any[] = []) => ({
  v: 2, id, issuer: h('p'), caveats: [{ type: 'intent_session', session: 's1', seq, root: h('r') }, ...extra], sig: sig('g'),
});
const envCaveat = (preds: any[]) => ({
  type: 'envelope', goal_commit: h('g'), predicates: preds, caveats: [], agent_binding: {},
  risk_policy: { weights: { alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1 }, theta1: 0.3, theta2: 0.7, kappa: 1, lambda: 1, rho: 1, bMax: 10 },
});
const pcactn = (iat: number, counter: number, c: string) => ({ v: 2, iat, counter, action: { verb: 'air.book', resource: 'r' + c, params_digest: h(c) }, cap_chain: [], sig: sig(c) });
const full = (): any => ({
  v: 1, kind: 'pca-intent-evidence',
  subject: { pcactn_digest: h('a'), aud: 'shop', session: 's1' },
  statement: { commit: h('c'), opening: { v: 1, kind: 'pca-intent-statement', principal: h('p'), text: 'buy' } },
  session_root: { v: 1, kind: 'pca-intent-session', session: 's1', intent_ref: h('c'), expires_at: 1_800_000_000, principals: [{ key: h('p') }] },
  schema: { doc: { kind: 'pca-action-schema', sig: { kid: 'k' }, verbs: {} }, anchor: { log: 'l', index: 1, head: h('x') } },
  root_grant: grant('g0', 0),
  maps: [{ seq: 2, commit: h('m'), map: { v: 1 }, disclosed: ['b', 'a'] }, { seq: 1, commit: h('n') }, { seq: 1, commit: h('l') }],
  answers: [
    { question_id: 'q2', observed_at: 5, sig: 'zz', y: 1 }, { question_id: 'q1', observed_at: 5, sig: 'bb', y: 0 },
    { question_id: 'q1', observed_at: 5, sig: 'aa', y: 1 }, { question_id: 'q0', observed_at: 1, sig: 'cc', y: 1 },
  ],
  canary_labels: [{ question_id: 'q2', label: 1 }, { question_id: 'q1', label: 0 }, { question_id: 'q1', label: 1 }],
  canaries: { asked: 2, false_yes: 0, false_no: 1 },
  deltas: [grant('d2', 2), grant('d1', 1), { ...grant('dx', 1), id: 'dw' }, { v: 2, id: 'noseq', issuer: h('p'), caveats: [], sig: sig('g') }],
  pcactns: [pcactn(10, 2, 'b'), pcactn(9, 1, 'c'), pcactn(10, 1, 'd'), pcactn(10, 1, 'e')],
  verdicts: [{ pcactn_digest: h('b'), allow: true }, { pcactn_digest: h('b'), allow: false, reasons: ['r'] }, { pcactn_digest: h('a'), allow: true }],
  accumulator: { holder: 'sequenced', events: [{ acc: 'spend', post: 5, pcactn_digest: h('b') }, { acc: 'spend', post: 3, pcactn_digest: h('a'), delta: 1, status: 'committed' }], receipts: [{ k: 'z' }, { k: 'a' }], sequencer_keys: [] },
  facts: [{ f: 2 }, { f: 1 }], classifier: [{ c: 'b' }, { c: 'a' }], offer_sets: [{ o: 2 }, { o: 1 }], labels: [{ l: 'y' }, { l: 'x' }],
  effects: [
    { pcactn_digest: h('b'), params: { total: 5 }, charged: { amount: 5, ref: 'action.params.total' } },
    { pcactn_digest: h('a'), params: { total: 3, z: [1, 2.5] }, frame_violations: [] },
    { pcactn_digest: h('a'), frame_violations: ['v'] },
  ],
  settlements: [{ s: 2 }, { s: 1 }],
  revocation_epochs: [{ epoch: { epoch: 2, issued_at: 20 }, revoked: [] }, { epoch: { epoch: 1, issued_at: 20 }, revoked: ['x'] }, { epoch: { epoch: 5, issued_at: 10 }, revoked: [] }],
  anchors: [{ kind: 'map', digest: h('m'), index: 3, proof: { index: 3 }, signed_tree_head: { size: 4 } }, { kind: 'evidence', digest: h('z'), index: 1, proof: {}, signed_tree_head: {} }, { kind: 'evidence', digest: h('y'), index: 1, proof: {}, signed_tree_head: {} }],
});
const small = (): any => {
  const b = full();
  b.maps = [b.maps[1]]; b.answers = [b.answers[0]]; b.canary_labels = [b.canary_labels[0]]; b.deltas = [b.deltas[0]]; b.pcactns = [b.pcactns[0]];
  b.verdicts = [b.verdicts[0]]; b.accumulator = { holder: 'site_local', events: [b.accumulator.events[0]] }; delete b.facts; delete b.classifier; delete b.offer_sets; delete b.labels; delete b.settlements;
  b.effects = [b.effects[0]]; b.revocation_epochs = [b.revocation_epochs[0]]; b.anchors = [b.anchors[0]];
  return b;
};
const run = (fn: string, name: string, args: any[]) => o.run(fn, nm(name), (E as any)[fn], args);

const shuffle = (b: any, mode: number) => {
  const c = reparse(b);
  for (const k of ['maps', 'answers', 'canary_labels', 'deltas', 'pcactns', 'verdicts', 'effects', 'revocation_epochs', 'anchors', 'facts', 'classifier', 'offer_sets', 'labels', 'settlements']) {
    if (!Array.isArray(c[k])) continue;
    if (mode === 1) c[k].reverse();
    if (mode === 2) c[k].push(c[k].shift());
  }
  if (mode === 1) c.accumulator.receipts?.reverse();
  return c;
};

for (const [label, base] of [['full', full()], ['small', small()]] as const) {
  for (const mode of [0, 1, 2]) {
    const b = shuffle(base, mode);
    for (const fn of ['bundleShapeError', 'normalizeBundle', 'commitmentForm', 'evidenceDigest', 'evidenceRef']) await run(fn, `${label}/m${mode}`, [b]);
    const { v, kind, ...parts } = b;
    await run('buildEvidenceBundle', `${label}/m${mode}`, [parts]);
  }
}
// digest invariants: dropping openings and anchors must not move the digest
{
  const b = full();
  const a = reparse(b);
  delete a.statement.opening; a.maps = a.maps.map((m: any) => ({ seq: m.seq, commit: m.commit, ...(m.disclosed ? { disclosed: m.disclosed } : {}) }));
  a.effects = a.effects.map(({ params, ...k }: any) => k); a.anchors = [];
  await run('evidenceDigest', 'stripped', [a]);
}

// ---- shape: sampled structural edits of the small bundle ------------------------------------------------------------------
{
  const seedB = small();
  const ps = paths(seedB, 5);
  const stride = Math.max(1, Math.ceil(ps.length / 170));
  const HOST = [null, 0, -0, 1.5, '', 'x', [], {}, true, 2 ** 53, -1];
  for (const [i, p] of ps.entries()) {
    if (i % stride !== 0) continue;
    const at = '/' + p.join('/');
    const old = getAt(seedB, p);
    if (p.length) await run('bundleShapeError', `del ${at}`, [setAt(seedB, p, () => DEL)]);
    for (const [j, hv] of HOST.entries()) await run('bundleShapeError', `${at}=h${j}`, [setAt(seedB, p, () => hv)]);
    if (old !== null && typeof old === 'object' && !Array.isArray(old)) await run('bundleShapeError', `${at}+unknown`, [setAt(seedB, p, () => ({ zz: 1, ...old }))]);
  }
  for (const k of Object.keys(seedB)) {
    await run('bundleShapeError', `top-del ${k}`, [setAt(seedB, [k], () => DEL)]);
    await run('bundleShapeError', `top-null ${k}`, [setAt(seedB, [k], () => null)]);
    await run('bundleShapeError', `top-unknown`, [{ ...seedB, '5': 1, zz: 2 }]);
  }
  for (const x of [null, 5, 'x', [], {}, true]) await run('bundleShapeError', `nonobj/${JSON.stringify(x)}`, [x]);
  // unknown-member order: integer-like keys come first in JS
  await run('bundleShapeError', 'keyorder', [{ ...seedB, b: 1, '7': 1, a: 2, '3': 3 }]);
  await run('bundleShapeError', 'keyorder-sub', [{ ...seedB, subject: { ...seedB.subject, zz: 1, '10': 1, '2': 2 } }]);
  // normalize / digest over structural edits that keep the shape valid or not
  for (const [i, p] of ps.entries()) {
    if (i % (stride * 2) !== 0 || !p.length) continue;
    const at = '/' + p.join('/');
    await run('evidenceDigest', `del ${at}`, [setAt(seedB, p, () => DEL)]);
    await run('normalizeBundle', `null ${at}`, [setAt(seedB, p, () => null)]);
  }
  for (const [name, mut] of [['dup-seq', (b: any) => b.maps.push({ seq: 1, commit: h('n') })], ['neg-epoch', (b: any) => b.revocation_epochs.push({ epoch: { epoch: -1, issued_at: 10 }, revoked: [] })],
    ['empty-lists', (b: any) => { b.maps = []; b.answers = []; b.deltas = []; b.pcactns = []; }], ['receipts-null', (b: any) => { b.accumulator.receipts = null; }],
    ['receipts-list', (b: any) => { b.accumulator.receipts = [{ b: 1 }, { a: 1 }]; }], ['extra-key-build', (b: any) => { b.v = 2; }]] as const) {
    const b = full(); mut(b);
    await run('normalizeBundle', name, [b]); await run('evidenceDigest', name, [b]);
    const { v, kind, ...parts } = b; await run('buildEvidenceBundle', name, [name === 'extra-key-build' ? { ...parts, v: 2 } : parts]);
  }
  for (const [i, p] of ps.entries()) {
    if (i % (stride * 3) !== 0 || p.length < 1 || p[0] === 'v' || p[0] === 'kind') continue;
    const { v, kind, ...parts } = setAt(seedB, p, () => 'x');
    await run('buildEvidenceBundle', `str ${'/' + p.join('/')}`, [parts]);
  }
}

// ---- anchors / refs ------------------------------------------------------------------------------------------------------------
for (const d of [h('a'), '', 'x', 'é', '\ud800', h('z')]) { await run('evidenceAnchorCommit', `d/${d.length}`, [d]); }
for (const kind of ['evidence', 'schema', 'statement', 'map', 'observation', '', 'weird']) await run('anchorCommit', kind, [kind, h('a')]);

// ---- capOf ------------------------------------------------------------------------------------------------------------------------
const lte = (path: string, v: number, op = 'lte') => ({ field: path, op, value: v });
const P = 'env.acc.trip.post';
const grants: any[] = [
  grant('a', 0, [envCaveat([{ verb: 'air.book', where: [lte(P, 40000)] }])]),
  grant('b', 1, [envCaveat([{ verb: 'air.book', where: [lte(P, 80000), lte(P, 50000)] }])]),
  grant('c', 1, [envCaveat([{ verb: ['air.book', 'x'], where: [lte(P, 10, 'lt')] }, { verb: 'hotel.book', where: [lte(P, 7)] }])]),
  grant('d', 1, [envCaveat([{ verb: '*', where: [{ all_of: [lte(P, 9), lte(P, 3)] }] }])]),
  grant('e', 1, [envCaveat([{ verb: 'air.book', where: [lte(P, 5)] }, { verb: 'air.book' }])]),
  grant('f', 1, [envCaveat([{ verb: 'air.book', where: [lte(P, 5)] }, { verb: 'air.book', where: [lte(P, 8)] }])]),
  grant('g', 1, [envCaveat([{ verb: 'air.book', where: [{ field: P, op: 'lte', value: 5, ref: 'x' }, { field: P, op: 'lte', value: '5' }, { any_of: [lte(P, 1)] }, lte('other', 1)] }])]),
  grant('h', 1, [envCaveat([{ verb: 'air.book', where: [lte(P, -0)] }, { verb: 'air.book', where: [lte(P, 1.5, 'lt')] }])]),
  grant('i', 1, []),
  grant('j', 1, [{ type: 'envelope', goal_commit: 1 }]),
  grant('k', 1, [envCaveat([{ verb: 'air.book', where: 'abc' }])]),
  grant('l', 1, [envCaveat([{ verb: 'air.book', where: [{ all_of: 'abc' }, { all_of: [lte(P, 4)] }] }])]),
  null, 5, {}, { caveats: 'x' },
];
for (const [i, g] of grants.entries()) for (const [acc, verb] of [['trip', 'air.book'], ['trip', 'hotel.book'], ['other', 'air.book'], ['trip', 'zzz'], ['trip', '*']]) await run('capOf', `g${i}/${acc}/${verb}`, [g, acc, verb]);

// ---- trust validators ----------------------------------------------------------------------------------------------------------------
const K = h('k');
const principals: any[] = [undefined, null, [], [{ key: K }], [{ key: K, pq_pk: 'AAAA' }], [{ key: K, pq_pk: '!!' }], [{ key: K }, { key: 'x' }], [{ key: K, zz: 1 }], [{ key: K, '5': 1, a: 2 }], [5], [null], [[]], 'x', 5, {}, [{ pq_pk: 'AAAA' }], [{ key: h('k') + 'A' }], [{ key: K.slice(0, 40) }], [{ key: K, pq_pk: '' }], [{ key: K, pq_pk: null }]];
for (const [i, p] of principals.entries()) await run('principalsTrustError', `p${i}`, p === undefined ? [] : [p]);
const accs: any[] = [undefined, null, {}, { max_receipt_age_s: 0 }, { max_keyset_age_s: 5, max_receipt_age_s: 7 }, { max_receipt_age_s: -1 }, { max_receipt_age_s: 1.5 }, { max_receipt_age_s: -0 }, { max_receipt_age_s: 2 ** 53 }, { max_receipt_age_s: 2 ** 53 - 1 }, { max_receipt_age_s: '5' }, { max_receipt_age_s: null }, { zz: 1 }, { '3': 1, max_receipt_age_s: 1 }, [], 'x', 5, true, { max_keyset_age_s: 1e21 }];
for (const [i, a] of accs.entries()) await run('accTrustError', `a${i}`, a === undefined ? [] : [a]);

o.add('consts', 'all', [], { EVIDENCE_DOMAIN: E.EVIDENCE_DOMAIN, EVIDENCE_REPORT_DOMAIN: E.EVIDENCE_REPORT_DOMAIN, EVIDENCE_CONTENT_TYPE: E.EVIDENCE_CONTENT_TYPE });
refWrite(o, 'evidence');
