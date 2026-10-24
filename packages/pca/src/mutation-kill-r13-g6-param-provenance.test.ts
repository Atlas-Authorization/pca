/**
 * r13 mutation kills for param-provenance.ts (rule 17): exact policy / prov-wire refusals, parseLabelRef, and the exact
 * deny reason of every decideParamProvenance step (input shape, committed labels, label-receipt resolution, value digest,
 * flows, the critical cap, tainted modes, env nesting, the fail-closed catch).
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { labelsRef, signLabels, type PcaLabels } from './label-receipts';
import {
  decideParamProvenance,
  isProvPath,
  parseLabelRef,
  validateProvWire,
  validateProvenancePolicy,
  type ProvenanceInput,
  type ProvenancePolicy,
} from './param-provenance';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g6-prov/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const D = (l: string) => b64u(seed(l));
const SITE = key('site');
const OTHER = key('other');
const SESSION = D('session');
const AUD = 'skyair.example';
const OFFER = 'action.params.offer_id';
const PAY = 'action.params.pay';

const POLICY: ProvenancePolicy = {
  params: { [OFFER]: 'material', [PAY]: 'critical' },
  registry: { 'reg:fp': 'first_party', 'reg:tr': 'trusted', 'reg:tool': 'tool' },
  label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'g1', pk: OTHER.pk }],
};
const PARAMS = { offer_id: 'OF-1', pay: 'pm_1', note: 'hi' };
const run = (over: Partial<ProvenanceInput> = {}, policy: Partial<ProvenancePolicy> = {}) =>
  decideParamProvenance({
    aud: AUD, session: SESSION, action: { params: PARAMS }, prov: { [OFFER]: ['reg:tr'], [PAY]: ['reg:tr'] }, policy: { ...POLICY, ...policy }, ...over,
  });
const reason = (d: { reason?: string }) => d.reason;

const receipt = (site: string, sk: Uint8Array, kid: string, fields: PcaLabels['fields'], session = SESSION) =>
  signLabels({ site, session, response_digest: D('resp'), fields, issued_at: 1_800_000_000_000, kid }, sk);
const R = receipt(AUD, SITE.sk, 'k1', { f: { class: 'public', value_digest: hashCanonical('OF-1') } });
const refTo = (r: PcaLabels, field = 'f') => `pca-labels:${labelsRef(r)}#${field}`;
const withReceipt = (r: PcaLabels, field = 'f', extra: Partial<ProvenanceInput> = {}, policy: Partial<ProvenancePolicy> = {}) =>
  run({ prov: { [OFFER]: [refTo(r, field)], [PAY]: ['reg:tr'] }, committed_labels: [labelsRef(r)], labels: [r], ...extra }, policy);

describe('validateProvenancePolicy: exact refusals', () => {
  it('a non-object policy or a missing / non-object params map', () => {
    const m = 'provenance policy needs a params map';
    expect(validateProvenancePolicy(null as never)).toBe(m);
    expect(validateProvenancePolicy({} as never)).toBe(m);
    expect(validateProvenancePolicy({ params: [] } as never)).toBe(m);
  });
  it('an unknown member is named under policy.', () => {
    expect(validateProvenancePolicy({ params: {}, extra: 1 } as never)).toBe("unknown member 'policy.extra'");
  });
  it('params: a non-path key and a free sensitivity', () => {
    expect(validateProvenancePolicy({ params: { foo: 'material' } } as never)).toBe("policy param 'foo' is not an action.params path");
    expect(validateProvenancePolicy({ params: { 'action.params.x': 'free' } } as never)).toBe(
      "policy param 'action.params.x': sensitivity must be material or critical",
    );
    expect(validateProvenancePolicy({ params: { 'action.params.x': 'material', 'action.params.y': 'critical' } })).toBeNull();
  });
  it('registry must be an object; label_keys a list of well-formed keys', () => {
    expect(validateProvenancePolicy({ params: {}, registry: [] as never })).toBe('registry must be an object');
    expect(validateProvenancePolicy({ params: {}, label_keys: {} as never })).toBe('label_keys must be a list');
    expect(validateProvenancePolicy({ params: {}, label_keys: [{}] as never })).toBe(
      'every label key needs site, kid, a 32-byte pk and an optional string pq_pk',
    );
  });
  it('critical_tainted accepts question / question_typed / deny, never allow', () => {
    for (const v of ['question', 'question_typed', 'deny'] as const) expect(validateProvenancePolicy({ params: {}, critical_tainted: v })).toBeNull();
    expect(validateProvenancePolicy({ params: {}, critical_tainted: 'allow' as never })).toBe('critical_tainted must be question | question_typed | deny');
  });
  it('well-formed flows are accepted', () => {
    expect(validateProvenancePolicy({ params: {}, flows: { 'pii.*': [AUD] } })).toBeNull();
  });
});

describe('validateProvWire / isProvPath / parseLabelRef', () => {
  it('prov must be an object of at most 32 paths', () => {
    expect(validateProvWire([])).toBe("'prov' must be an object");
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, ['r']]));
    expect(validateProvWire(many(32))).toBeNull();
    expect(validateProvWire(many(33))).toBe("'prov' holds more than 32 paths");
  });
  it('1..8 non-empty refs per path', () => {
    expect(validateProvWire({ 'action.params.a': Array(8).fill('r') })).toBeNull();
    expect(validateProvWire({ 'action.params.a': Array(9).fill('r') })).toBe("'prov.action.params.a' must hold 1..8 refs");
    expect(validateProvWire({ 'action.params.a': [''] })).toBe("'prov.action.params.a' refs must be non-empty strings (<= 256 bytes)");
  });
  it('a prototype name after action.params. is not a prov path', () => {
    expect(isProvPath('action.params.ok')).toBe(true);
    for (const n of ['__proto__', 'constructor', 'prototype']) expect(isProvPath(`action.params.${n}`)).toBe(false);
    expect(validateProvWire({ 'action.params.constructor': ['r'] })).toBe(
      "'prov' key 'action.params.constructor' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)",
    );
  });
  it('parseLabelRef needs the # separator', () => {
    expect(parseLabelRef(`pca-labels:${D('r')}x`)).toBeNull();
    expect(parseLabelRef(`pca-labels:${D('r')}#f`)).toStrictEqual({ receipt: D('r'), field: 'f' });
  });
});

describe('decideParamProvenance: input-shape refusals', () => {
  it('a non-object input, a misconfigured policy', () => {
    expect(decideParamProvenance(null as never)).toMatchObject({ outcome: 'deny', reason: 'provenance: input must be an object' });
    expect(reason(run({ policy: {} as never }))).toBe('provenance: policy misconfigured (fail closed): provenance policy needs a params map');
  });
  it('absent prov / action.params / labels default to empty', () => {
    const d = decideParamProvenance({ aud: AUD, session: SESSION, action: {}, policy: POLICY });
    expect(d.outcome).toBe('pass');
    expect({ ...d.labels }).toStrictEqual({});
    expect(run({ prov: undefined }).outcome).toBe('question'); // both carried params undeclared -> agent
  });
  it('committed labels: a list of at most 16 distinct digests', () => {
    const m = 'provenance: committed labels must be a list of at most 16 digests';
    expect(reason(run({ committed_labels: 'x' }))).toBe(m);
    expect(reason(run({ committed_labels: Array.from({ length: 17 }, (_, i) => D(`c${i}`)) }))).toBe(m);
    expect(run({ committed_labels: Array.from({ length: 16 }, (_, i) => D(`c${i}`)) }).outcome).toBe('pass');
    const d = 'provenance: committed labels must be distinct canonical 32-byte digests';
    expect(reason(run({ committed_labels: ['x'] }))).toBe(d);
    expect(reason(run({ committed_labels: [D('a'), D('a')] }))).toBe(d);
  });
  it('action, action.params and labels of the wrong type', () => {
    expect(reason(run({ action: null as never }))).toBe('provenance: action must be an object');
    expect(reason(run({ action: { params: [] as never } }))).toBe('provenance: action.params must be an object');
    expect(reason(run({ labels: {} as never }))).toBe('provenance: labels must be an array');
  });
  it('the first (bytewise) undeclared-carried prov path is named', () => {
    const d = run({ action: { params: {} }, prov: { 'action.params.zz': ['r'], 'action.params.aa': ['r'] } });
    expect(reason(d)).toBe("provenance: prov names 'action.params.aa', a parameter the action does not carry");
  });
  it('prov paths sharing a name prefix (a / ab) do not overlap', () => {
    const d = run({ action: { params: { a: 1, ab: 2 } }, prov: { 'action.params.a': ['reg:tr'], 'action.params.ab': ['reg:tr'] } }, { params: {} });
    expect(d.outcome).toBe('pass');
    expect({ ...d.labels }).toStrictEqual({ 'action.params.a': 'trusted', 'action.params.ab': 'trusted' });
  });
  it('a throwing input member fails closed with its message', () => {
    const input = { aud: AUD, session: SESSION, action: {}, get policy(): ProvenancePolicy { throw new Error('boom'); } };
    expect(decideParamProvenance(input as never)).toMatchObject({ outcome: 'deny', reason: 'provenance: evaluation error (fail closed): boom' });
  });
});

describe('decideParamProvenance: label receipts', () => {
  it('a matching receipt from this audience is first_party (with its class)', () => {
    const d = withReceipt(R);
    expect(d.outcome).toBe('pass');
    expect(d.labels[OFFER]).toBe('first_party');
    expect({ ...d.classes }).toStrictEqual({ [OFFER]: ['public'] });
  });
  it('another site is tool; a mismatching value digest is agent', () => {
    const o = receipt('gov.example', OTHER.sk, 'g1', { f: { class: 'public', value_digest: hashCanonical('OF-1') } });
    expect(withReceipt(o).labels[OFFER]).toBe('tool');
    const bad = receipt(AUD, SITE.sk, 'k1', { f: { class: 'public', value_digest: hashCanonical('other') } });
    expect(withReceipt(bad).labels[OFFER]).toBe('agent');
  });
  it('a value that cannot be canonically hashed never matches', () => {
    const d = withReceipt(R, 'f', { action: { params: { ...PARAMS, offer_id: Number.NaN } } });
    expect(d.labels[OFFER]).toBe('agent');
  });
  it('classes are sorted and de-duplicated', () => {
    const z = receipt(AUD, SITE.sk, 'k1', { f: { class: 'zeta', value_digest: hashCanonical('OF-1') } });
    const a = receipt(AUD, SITE.sk, 'k1', { f: { class: 'alpha', value_digest: hashCanonical('OF-1') } });
    const d = run({ prov: { [OFFER]: [refTo(z), refTo(a), refTo(z)], [PAY]: ['reg:tr'] }, committed_labels: [labelsRef(z), labelsRef(a)], labels: [z, a] });
    expect(d.classes[OFFER]).toStrictEqual(['alpha', 'zeta']);
  });
  it('each resolution step has its own reason', () => {
    const p = `'${OFFER}'`;
    expect(reason(run({ prov: { [OFFER]: ['pca-labels:bad'], [PAY]: ['reg:tr'] } }))).toBe(`provenance: malformed label ref on ${p}`);
    expect(reason(withReceipt(R, 'f', { committed_labels: [] }))).toBe(`provenance: label ref on ${p} names a receipt the PCActn does not commit`);
    expect(reason(withReceipt(R, 'f', { labels: [] }))).toBe(`provenance: label receipt for ${p} was not supplied`);
    expect(reason(withReceipt(R, 'f', {}, { label_keys: [] }))).toBe(`provenance: label receipt for ${p}: no pinned label key for site '${AUD}' kid 'k1'`);
    const { label_keys: _k, ...noKeys } = POLICY;
    expect(reason(withReceipt(R, 'f', { policy: noKeys }))).toBe(`provenance: label receipt for ${p}: no pinned label key for site '${AUD}' kid 'k1'`);
    const other = receipt(AUD, SITE.sk, 'k1', { f: { class: 'public', value_digest: hashCanonical('OF-1') } }, D('other-session'));
    expect(reason(withReceipt(other))).toBe(`provenance: label receipt for ${p} is bound to another session`);
    expect(reason(withReceipt(R, 'g'))).toBe(`provenance: label receipt for ${p} has no field 'g'`);
  });
  it('a supplied receipt that is not wire-valid is never resolved (not supplied)', () => {
    const bad = { ...R, extra: 1 } as unknown as PcaLabels;
    const d = run({ prov: { [OFFER]: [refTo(bad)], [PAY]: ['reg:tr'] }, committed_labels: [labelsRef(bad)], labels: [bad] });
    expect(reason(d)).toBe(`provenance: label receipt for '${OFFER}' was not supplied`);
  });
  it('a non-public class from another site needs a flow rule to this audience', () => {
    const o = receipt('gov.example', OTHER.sk, 'g1', { f: { class: 'pii.contact', value_digest: hashCanonical('OF-1') } });
    expect(reason(withReceipt(o))).toBe(`provenance: flow: class 'pii.contact' from 'gov.example' may not reach '${AUD}' (parameter '${OFFER}')`);
    expect(withReceipt(o, 'f', {}, { flows: { 'pii.*': [AUD] } }).outcome).toBe('question'); // allowed; a tool-labelled material value
  });
});

describe('decideParamProvenance: sensitivity rules', () => {
  it('an undeclared policy param the action does not carry gets no label', () => {
    const d = run({}, { params: { ...POLICY.params, 'action.params.missing': 'critical' } });
    expect(Object.keys(d.labels).sort()).toStrictEqual([OFFER, PAY]);
  });
  it('critical_max caps only CRITICAL parameters, with the exact reason', () => {
    expect(run({ prov: { [OFFER]: ['reg:fp'], [PAY]: ['reg:tr'] } }, { critical_max: 'trusted' }).outcome).toBe('pass');
    expect(reason(run({ prov: { [OFFER]: ['reg:tr'], [PAY]: ['reg:fp'] } }, { critical_max: 'trusted' }))).toBe(
      `provenance: critical parameter '${PAY}' has provenance 'first_party', above the policy maximum 'trusted'`,
    );
  });
  it('critical_tainted deny, and the question reason', () => {
    const t = { prov: { [OFFER]: ['reg:tr'], [PAY]: ['reg:tool'] } };
    expect(reason(run(t, { critical_tainted: 'deny' }))).toBe(`provenance: tainted critical parameter '${PAY}' (provenance 'tool') is denied by policy`);
    expect(run(t)).toMatchObject({ outcome: 'question', friction: 'typed', reason: 'provenance: a tainted value needs the principal (lazy question)' });
  });
  it('nested policy params that overlap deny when nesting env.prov', () => {
    const d = run({ action: { params: { a: { b: 1 } } }, prov: {} }, { params: { 'action.params.a': 'material', 'action.params.a.b': 'material' } });
    expect(reason(d)).toBe("provenance: provenance paths overlap at 'action.params.a.b'");
  });
});
