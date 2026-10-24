/**
 * 0.4.2 r13 mutation kills (g5): intent-env.ts (the W-B composition, rules 16-18). Exact results of
 * intentProvenanceActive / intentWBActive / intentWBContextError, and full decideIntentWB flows: world facts (pass,
 * single-source, fail), the offer set, provenance (pass, question, deny, label receipts committed and supplied),
 * classes (pass, fail), absent policies, and the fail-closed catch (Error and non-Error).
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { decideIntentWB, intentProvenanceActive, intentWBActive, intentWBContextError, type IntentWBInput } from './intent-env';
import { factRef, signFact, type WorldPolicy } from './oracle-facts';
import { offerSetRef, signOfferSet, type OfferPolicy } from './offer-set';
import { decideParamProvenance, type ProvenancePolicy } from './param-provenance';
import { labelsRef, signLabels } from './label-receipts';
import { classifierContentDigest, classifierVerdictRef, signClassifierVerdict, type ClassifierPolicy } from './intent-classifier';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g5-env/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const O1 = key('o1');
const O2 = key('o2');
const SITE = key('site');
const JUDGE = key('judge');
const NOW = 1_800_000_000_000;
const SESSION = b64u(seed('session'));
const AUD = 'skyair.example';
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', passport: 'X1', text: 'hello' } };

const fare = (o: { sk: Uint8Array }, kid: string, value: number) => signFact({ name: 'fare', subject: 'OF-2', value, t_obs: NOW - 1_000, oracle: kid }, o.sk);
const world = (min = 1): WorldPolicy => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: [{ kid: 'o1', pk: O1.pk }, { kid: 'o2', pk: O2.pk }], freshness_ms: 60_000, min_oracles: min, max_faulty: 0 });
const base = (over: Partial<IntentWBInput> = {}): IntentWBInput => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, intent_session: {}, ...over });

const PROV_POLICY: ProvenancePolicy = { params: { 'action.params.offer_id': 'material' }, registry: { 'skyair:offers': 'first_party' }, label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }] };
const passport = signLabels({ site: AUD, session: SESSION, response_digest: b64u(seed('resp')), fields: { 'travellers[0].passport': { class: 'pii.identity', value_digest: hashCanonical('X1') } }, issued_at: NOW - 5_000, kid: 'k1' }, SITE.sk);
const PASS_POLICY: ProvenancePolicy = { ...PROV_POLICY, params: { 'action.params.passport': 'critical' } };
const passportRef = `pca-labels:${labelsRef(passport)}#travellers[0].passport`;

const verdict = (label = 'neutral') => signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest('hello'), label, measurement: 'm' }, JUDGE.sk);
const CLS: ClassifierPolicy = { id: 'tone', param: 'action.params.text', labels: ['neutral', 'hostile'], keys: [JUDGE.pk], k: 1 };

describe('intentProvenanceActive', () => {
  it('prov present, non-empty labels array, or a plain-object policy', () => {
    expect(intentProvenanceActive(null as never)).toBe(false);
    expect(intentProvenanceActive({})).toBe(false);
    expect(intentProvenanceActive({ prov: null })).toBe(true);
    expect(intentProvenanceActive({ labels: ['x'] })).toBe(true);
    expect(intentProvenanceActive({ labels: [] })).toBe(false);
    expect(intentProvenanceActive({ labels: { length: 1 } })).toBe(false);
    expect(intentProvenanceActive({ policy: {} })).toBe(true);
    expect(intentProvenanceActive({ policy: null })).toBe(false);
    expect(intentProvenanceActive({ policy: [] })).toBe(false);
    expect(intentProvenanceActive({ policy: 'x' })).toBe(false);
  });
});

describe('intentWBActive', () => {
  const none = { facts: false, provenance: false, classes: false };
  it('each member and policy activates exactly its check', () => {
    expect(intentWBActive({})).toEqual(none);
    expect(intentWBActive({ intent_session: { facts: [SESSION] } })).toEqual({ ...none, facts: true });
    expect(intentWBActive({ intent_session: { offer_set: SESSION } })).toEqual({ ...none, facts: true });
    expect(intentWBActive({ intent_session: {}, policy: { world: { worlds: [world()] } } })).toEqual({ ...none, facts: true });
    expect(intentWBActive({ intent_session: { labels: ['x'] } })).toEqual({ ...none, provenance: true });
    expect(intentWBActive({ intent_session: { prov: {} } })).toEqual({ ...none, provenance: true });
    expect(intentWBActive({ intent_session: {}, policy: { provenance: {} } })).toEqual({ ...none, provenance: true });
    expect(intentWBActive({ intent_session: { classes: [SESSION] } })).toEqual({ ...none, classes: true });
    expect(intentWBActive({ intent_session: {}, policy: { classifiers: [CLS] } })).toEqual({ ...none, classes: true });
    expect(intentWBActive({ intent_session: { '': [1] }, policy: { '': {} } })).toEqual(none);
  });
});

describe('intentWBContextError: exact reasons', () => {
  const e = (over: Record<string, unknown>) => intentWBContextError({ intent_session: {}, ...over } as never);
  it('well-formed contexts', () => {
    expect(e({})).toBeNull();
    expect(e({ artifacts: {}, policy: {} })).toBeNull();
    expect(e({ artifacts: { facts: [], labels: [], verdicts: [], offer_set: {} } })).toBeNull();
    expect(e({ policy: { world: {}, provenance: {}, classifiers: [] } })).toBeNull();
  });
  it('input, intent_session', () => {
    expect(intentWBContextError(null as never)).toBe('input must be an object');
    expect(intentWBContextError({ intent_session: null } as never)).toBe('intent_session must be an object');
    expect(intentWBContextError({ intent_session: [] } as never)).toBe('intent_session must be an object');
  });
  it('artifacts', () => {
    expect(e({ artifacts: null })).toBe('artifacts must be an object');
    expect(e({ artifacts: [] })).toBe('artifacts must be an object');
    expect(e({ artifacts: { x: 1 } })).toBe("unknown member 'artifacts.x'");
    for (const k of ['facts', 'labels', 'verdicts']) {
      expect(e({ artifacts: { [k]: 'x' } })).toBe(`artifacts.${k} must be an array`);
      expect(e({ artifacts: { [k]: null } })).toBe(`artifacts.${k} must be an array`);
      expect(e({ artifacts: { [k]: [] } })).toBeNull();
    }
    expect(e({ artifacts: { offer_set: [] } })).toBe('artifacts.offer_set must be an object');
    expect(e({ artifacts: { offer_set: null } })).toBe('artifacts.offer_set must be an object');
  });
  it('policy', () => {
    expect(e({ policy: null })).toBe('policy must be an object');
    expect(e({ policy: [] })).toBe('policy must be an object');
    expect(e({ policy: { x: 1 } })).toBe("unknown member 'policy.x'");
    for (const k of ['world', 'provenance']) {
      expect(e({ policy: { [k]: [] } })).toBe(`policy.${k} must be an object`);
      expect(e({ policy: { [k]: null } })).toBe(`policy.${k} must be an object`);
      expect(e({ policy: { [k]: {} } })).toBeNull();
    }
    expect(e({ policy: { classifiers: {} } })).toBe('policy.classifiers must be an array');
    expect(e({ policy: { classifiers: null } })).toBe('policy.classifiers must be an array');
  });
});

describe('decideIntentWB: composition', () => {
  it('nothing active admits with no checks (absent artifacts and policy)', () => {
    expect(decideIntentWB(base())).toEqual({ outcome: 'admit', checks: {}, env: {} });
  });
  it('a malformed context fails facts', () => {
    expect(decideIntentWB(base({ policy: null as never }))).toEqual({ outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: 'facts: the W-B context is malformed: policy must be an object' });
  });
  it('world: pass (single source and quorum), fail', () => {
    const f1 = fare(O1, 'o1', 100);
    const f2 = fare(O2, 'o2', 90);
    expect(decideIntentWB(base({ intent_session: { facts: [factRef(f1)] }, artifacts: { facts: [f1] }, policy: { world: { worlds: [world()] } } }))).toEqual({
      outcome: 'admit', checks: { facts: 'pass' }, env: { world: { fare: 100 } }, single_source: ['fare'],
    });
    expect(decideIntentWB(base({ intent_session: { facts: [factRef(f1), factRef(f2)] }, artifacts: { facts: [f1, f2] }, policy: { world: { worlds: [world(2)] } } }))).toEqual({
      outcome: 'admit', checks: { facts: 'pass' }, env: { world: { fare: 90 } },
    });
    expect(decideIntentWB(base({ intent_session: { facts: [factRef(f1)] }, policy: { world: { worlds: [world()] } } }))).toEqual({
      outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: 'facts: a committed fact was not supplied (or is malformed)',
    });
    // committed facts with no world policy: the fact names an undeclared world
    expect(decideIntentWB(base({ intent_session: { facts: [factRef(f1)] }, artifacts: { facts: [f1] } }))).toEqual({
      outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: "facts: fact for undeclared world 'fare'",
    });
    // a world policy with nothing committed is active and fails for want of facts
    expect(decideIntentWB(base({ policy: { world: { worlds: [world()] } } }))).toEqual({
      outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: "facts: world 'fare' has 0 fresh fact(s), needs 1",
    });
  });
  it('world: the offer set is passed through and committed', () => {
    const offers: OfferPolicy = { name: 'excess', site_keys: [{ kid: 'k1', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: {}, offer: {} } };
    const os = signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: {}, rank: 'price_asc', complete: true, offers: [{ offer_id: 'OF-1', price: 5 }, { offer_id: 'OF-2', price: 9 }], issued_at: NOW - 1, kid: 'k1' }, SITE.sk);
    expect(decideIntentWB(base({ intent_session: { offer_set: offerSetRef(os) }, artifacts: { offer_set: os }, policy: { world: { offers } } }))).toEqual({
      outcome: 'admit', checks: { facts: 'pass' }, env: { world: { excess: 4 } },
    });
    expect(decideIntentWB(base({ intent_session: { offer_set: offerSetRef(os) }, policy: { world: { offers } } }))).toMatchObject({
      outcome: 'deny', reason: 'facts: offers: the committed offer set was not supplied',
    });
    expect(decideIntentWB(base({ artifacts: { offer_set: os }, policy: { world: { offers } } }))).toMatchObject({
      outcome: 'deny', reason: 'facts: offers: the PCActn commits no offer set but the policy requires one',
    });
  });
  it('provenance: pass, question, deny; absent policy is {params: {}}', () => {
    const prov = { 'action.params.offer_id': ['skyair:offers'] };
    const direct = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov, policy: PROV_POLICY });
    expect(direct.outcome).toBe('pass');
    expect(decideIntentWB(base({ intent_session: { prov }, policy: { provenance: PROV_POLICY } }))).toEqual({ outcome: 'admit', checks: { provenance: 'pass' }, env: { prov: direct.env } });
    // prov present without a policy: params {} (everything passes)
    const noPol = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov, policy: { params: {} } });
    expect(decideIntentWB(base({ intent_session: { prov } }))).toEqual({ outcome: 'admit', checks: { provenance: 'pass' }, env: { prov: noPol.env } });
    // an unknown ref on a material parameter: question (tap)
    const q = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov: { 'action.params.offer_id': ['unknown'] }, policy: PROV_POLICY });
    expect(q.outcome).toBe('question');
    expect(decideIntentWB(base({ intent_session: { prov: { 'action.params.offer_id': ['unknown'] } }, policy: { provenance: PROV_POLICY } }))).toEqual({
      outcome: 'question', checks: { provenance: 'question' }, env: { prov: q.env }, reason: q.reason, friction: q.friction,
    });
    const dpol = { ...PROV_POLICY, material_tainted: 'deny' } as ProvenancePolicy;
    const d = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov: { 'action.params.offer_id': ['unknown'] }, policy: dpol });
    expect(d.outcome).toBe('deny');
    expect(decideIntentWB(base({ intent_session: { prov: { 'action.params.offer_id': ['unknown'] } }, policy: { provenance: dpol } }))).toEqual({
      outcome: 'deny', checks: { provenance: 'fail' }, env: {}, reason: d.reason,
    });
    // committed labels are passed through (a malformed value is refused by rule 17)
    expect(decideIntentWB(base({ intent_session: { prov, labels: 'x' }, policy: { provenance: PROV_POLICY } }))).toMatchObject({
      outcome: 'deny', checks: { provenance: 'fail' }, reason: 'provenance: committed labels must be a list of at most 16 digests',
    });
  });
  it('provenance: a committed label receipt supplied in the artifacts vouches for the parameter', () => {
    const prov = { 'action.params.passport': [passportRef] };
    const direct = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov, committed_labels: [labelsRef(passport)], labels: [passport], policy: PASS_POLICY });
    expect(direct.outcome).toBe('pass');
    expect(decideIntentWB(base({ intent_session: { prov, labels: [labelsRef(passport)] }, artifacts: { labels: [passport] }, policy: { provenance: PASS_POLICY } }))).toEqual({
      outcome: 'admit', checks: { provenance: 'pass' }, env: { prov: direct.env },
    });
    expect(decideIntentWB(base({ intent_session: { prov, labels: [labelsRef(passport)] }, policy: { provenance: PASS_POLICY } }))).toEqual({
      outcome: 'deny', checks: { provenance: 'fail' }, env: {}, reason: "provenance: label receipt for 'action.params.passport' was not supplied",
    });
  });
  it('classes: pass, fail; committed classes without a classifier policy', () => {
    const v = verdict();
    expect(decideIntentWB(base({ intent_session: { classes: [classifierVerdictRef(v)] }, artifacts: { verdicts: [v] }, policy: { classifiers: [CLS] } }))).toEqual({
      outcome: 'admit', checks: { classes: 'pass' }, env: { class: { tone: 'neutral' } },
    });
    expect(decideIntentWB(base({ intent_session: { classes: [classifierVerdictRef(v)] }, policy: { classifiers: [CLS] } }))).toEqual({
      outcome: 'deny', checks: { classes: 'fail' }, env: {}, reason: 'classes: a committed verdict was not supplied (or is malformed)',
    });
    expect(decideIntentWB(base({ policy: { classifiers: [CLS] } }))).toEqual({
      outcome: 'deny', checks: { classes: 'fail' }, env: {}, reason: "classes: classifier 'tone': no label reaches the quorum 1",
    });
    expect(decideIntentWB(base({ intent_session: { classes: [classifierVerdictRef(v)] }, artifacts: { verdicts: [v] } }))).toEqual({
      outcome: 'deny', checks: { classes: 'fail' }, env: {}, reason: "classes: verdict for undeclared classifier 'tone'",
    });
  });
  it('all three pass together, in order', () => {
    const f1 = fare(O1, 'o1', 100);
    const v = verdict('hostile');
    const prov = { 'action.params.offer_id': ['skyair:offers'] };
    const direct = decideParamProvenance({ aud: AUD, session: SESSION, action: ACTION, prov, policy: PROV_POLICY });
    expect(decideIntentWB(base({
      intent_session: { facts: [factRef(f1)], prov, classes: [classifierVerdictRef(v)] },
      artifacts: { facts: [f1], verdicts: [v] },
      policy: { world: { worlds: [world()] }, provenance: PROV_POLICY, classifiers: [CLS] },
    }))).toEqual({ outcome: 'admit', checks: { facts: 'pass', provenance: 'pass', classes: 'pass' }, env: { world: { fare: 100 }, prov: direct.env, class: { tone: 'hostile' } }, single_source: ['fare'] });
  });
  it('fail closed on an internal throw (Error message, else unknown)', () => {
    const f1 = fare(O1, 'o1', 100);
    const mk = (thrown: unknown) => {
      const i = base({ intent_session: { facts: [factRef(f1)] }, artifacts: { facts: [f1] }, policy: { world: { worlds: [world()] } } }) as unknown as Record<string, unknown>;
      Object.defineProperty(i, 'aud', { enumerable: true, get: () => { throw thrown; } });
      return i as unknown as IntentWBInput;
    };
    expect(decideIntentWB(mk(new Error('boom')))).toEqual({ outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: 'facts: evaluation error (fail closed): boom' });
    expect(decideIntentWB(mk('raw'))).toEqual({ outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: 'facts: evaluation error (fail closed): unknown' });
  });
});
