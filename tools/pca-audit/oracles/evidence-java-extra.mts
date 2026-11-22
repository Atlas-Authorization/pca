// Oracle (Java lane, extra): @atlasauth/pca-evidence evidenceSignedStatement (the COSE signed statement over the bundle reference).
// Ed25519 only, so the signature is deterministic and the statement bytes are compared exactly.
// PORTING: evidenceSignedStatement(bundle, spec) -> EvidenceScitt.evidenceSignedStatement(bundle, opts), spec = {alg: "EdDSA", seed (b64u),
//   issuer, subject?}; the native signs with the Ed25519 key of that seed. Returns bytes ({"$bytes": b64url}); a reference throw requires a native throw.
import { createHash } from 'node:crypto';
import { createPrivateKey } from 'node:crypto';
import * as Ev from '@atlasauth/pca-evidence';
import { Oracle, refWrite, seed } from './lib.mjs';

const E: any = (Ev as any).default ?? Ev;
const o = new Oracle('evidence-java-extra', 'tools/pca-audit/oracles/evidence-java-extra.mts', 'TS-reference oracle for the evidence signed statement (Java lane).');
const h = (c: string) => Buffer.alloc(32, c.charCodeAt(0)).toString('base64url');
const sig = (c: string) => Buffer.alloc(64, c.charCodeAt(0)).toString('base64url');
const nm = (s: string) => `${s}#${n++}`;

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
const edSpec = (label: string, extra: any = {}) => ({ alg: 'EdDSA', seed: Buffer.from(seed(label)).toString('base64url'), issuer: 'https://issuer.example', ...extra });
const toKey = (s: any) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s.seed, 'base64url')]), format: 'der', type: 'pkcs8' });
const impl = (b: any, spec: any) => E.evidenceSignedStatement(b, { alg: spec.alg, key: toKey(spec), issuer: spec.issuer, ...(spec.subject !== undefined ? { subject: spec.subject } : {}) });
const add = (name: string, b: any, spec: any) => o.run('evidenceSignedStatement', name, impl, [b, spec]);
void createHash;
for (const [label, b] of [['full', full()], ['small', small()]] as const) {
  await add(`${label}/default-subject`, b, edSpec('evidence/issuer'));
  await add(`${label}/explicit-subject`, b, edSpec('evidence/issuer-2', { subject: 'dispute:42' }));
  await add(`${label}/empty-subject`, b, edSpec('evidence/issuer-3', { subject: '' }));
  await add(`${label}/other-issuer`, b, edSpec('evidence/issuer', { issuer: 'é-iss' }));
}
// hostile bundles: shape errors must throw
for (const [i, bad] of [null, 5, 'x', [], {}, { v: 1 }, { ...small(), kind: 'other' }, { ...small(), subject: null }].entries()) await add(`bad${i}`, bad, edSpec('evidence/issuer'));
refWrite(o, 'evidence-java-extra');
