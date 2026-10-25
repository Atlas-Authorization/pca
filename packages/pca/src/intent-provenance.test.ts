import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { evaluatePredicates } from './predicates';
import { TAINT_LEVELS, labelRank, type TaintLabel, type TaintLevel } from './taint';
import { decideParamProvenance, parseLabelRef, type ProvenanceInput, type ProvenancePolicy } from './param-provenance';
import { decideReadPurpose, flowAllowed, flowRuleFor, labelsRef, signLabels, verifyLabels, type PcaLabels } from './label-receipts';
import {
  classifierContentDigest,
  classifierVerdictRef,
  decideClassifierDimensions,
  signClassifierVerdict,
  type ClassifierInput,
  type ClassifierPolicy,
} from './intent-classifier';
import { decideIntentWB } from './intent-env';
import * as cl from './intent-classifier';

// Intent Layer v2 milestones V7 (per-parameter provenance), V14 (label receipts, flows, read purpose) and
// V8 (classifier verdicts): rules 17 and 18, T26 (the agent can only raise a label), T27 (declared flows).

const seed = (l: string) => sha256(utf8(`atlas-pca-test/intent-prov/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const SITE = key('site');
const OTHER_SITE = key('other-site');
const ROGUE = key('rogue');
const SESSION = b64u(seed('session'));
const AUD = 'skyair.example';

const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm_ana_visa', add_ons: 'tripshield', passport: 'X1234567', note: 'hi' };
const POLICY: ProvenancePolicy = {
  params: { 'action.params.offer_id': 'material', 'action.params.add_ons': 'material', 'action.params.payment_ref': 'critical', 'action.params.passport': 'critical' },
  registry: { 'skyair:offer_set:1': 'first_party', 'wallet:profile:ana': 'trusted', 'web:skyair.example/results#ad-3': 'web', 'tool:fx': 'tool' },
  label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'g1', pk: OTHER_SITE.pk }],
};
const prov = (over: Record<string, string[]> = {}) => ({
  'action.params.offer_id': ['skyair:offer_set:1'],
  'action.params.payment_ref': ['wallet:profile:ana'],
  'action.params.add_ons': ['wallet:profile:ana'],
  'action.params.passport': ['wallet:profile:ana'],
  ...over,
});
const run = (over: Partial<ProvenanceInput> = {}, policy: Partial<ProvenancePolicy> = {}) =>
  decideParamProvenance({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov: prov(), policy: { ...POLICY, ...policy }, ...over });

const receipt = (site: string, sk: Uint8Array, kid: string, fields: PcaLabels['fields'], session = SESSION) =>
  signLabels({ site, session, response_digest: b64u(seed('resp')), fields, issued_at: 1_800_000_000_000, kid }, sk);

describe('rule 17: per-parameter provenance', () => {
  it('classifies every declared ref through the server registry and joins per parameter', () => {
    const r = run();
    expect(r.outcome).toBe('pass');
    expect(r.labels).toEqual({ 'action.params.add_ons': 'trusted', 'action.params.offer_id': 'first_party', 'action.params.passport': 'trusted', 'action.params.payment_ref': 'trusted' });
  });

  it('env.prov nests by path so grant predicates read env.prov.action.params.<p>', () => {
    const r = run();
    const ctx = { action: { verb: 'air.book', resource: 'r' }, env: { prov: r.env } };
    const pred = (vals: string[]) => [{ verb: 'air.book', where: [{ field: 'env.prov.action.params.offer_id', op: 'in' as const, value: vals }] }];
    expect(evaluatePredicates(pred(['trusted', 'first_party']), ctx).allowed).toBe(true);
    expect(evaluatePredicates(pred(['trusted']), ctx).allowed).toBe(false);
  });

  it('an undeclared material or critical parameter is agent; an unknown ref is agent', () => {
    const { 'action.params.payment_ref': _drop, ...rest } = prov();
    const r = run({ prov: { ...rest, 'action.params.offer_id': ['made-up-ref'] } });
    expect(r.labels['action.params.payment_ref']).toBe('agent');
    expect(r.labels['action.params.offer_id']).toBe('agent');
    expect(r.outcome).toBe('question');
    expect(r.friction).toBe('typed'); // a tainted critical value is a typed-tier question by default
  });

  it('a tainted material value is a tap-tier question by default and follows material_tainted', () => {
    const p = prov({ 'action.params.add_ons': ['web:skyair.example/results#ad-3'] });
    expect(run({ prov: p })).toMatchObject({ outcome: 'question', friction: 'tap' });
    expect(run({ prov: p }, { material_tainted: 'question_typed' })).toMatchObject({ outcome: 'question', friction: 'typed' });
    expect(run({ prov: p }, { material_tainted: 'deny' }).outcome).toBe('deny');
    expect(run({ prov: p }, { material_tainted: 'allow' }).outcome).toBe('pass');
  });

  it('critical_max is a hard deny for a more tainted critical value', () => {
    const p = prov({ 'action.params.payment_ref': ['tool:fx'] });
    expect(run({ prov: p }, { critical_max: 'first_party' }).outcome).toBe('deny');
    expect(run({ prov: p }, { critical_max: 'tool' }).outcome).toBe('question');
  });

  it('wire: prov paths must be carried by the action, must not overlap, and are bounded', () => {
    expect(run({ prov: prov({ 'action.params.missing': ['x'] }) }).outcome).toBe('deny');
    expect(run({ prov: { 'action.params.offer_id': [] } }).outcome).toBe('deny');
    expect(run({ prov: { 'action.params.offer_id': Array(9).fill('x') } }).outcome).toBe('deny');
    expect(run({ prov: { 'env.world.x': ['x'] } }).outcome).toBe('deny');
    expect(run({ prov: { 'action.params.__proto__': ['x'] } }).outcome).toBe('deny');
    const nested = decideParamProvenance({ aud: AUD, session: SESSION, action: { params: { a: { b: 1 } } }, prov: { 'action.params.a.b': ['x'] }, policy: { params: {} } });
    expect(nested.outcome).toBe('deny'); // only action.params.<name>
    expect(run({ prov: prov({ 'action.params.add-ons': ['x'] }) }).outcome).toBe('deny');
    const objectParam = decideParamProvenance({ aud: AUD, session: SESSION, action: { params: { a: { b: 1 } } }, prov: { 'action.params.a': ['x'] }, policy: { params: {} } });
    expect(objectParam).toMatchObject({ outcome: 'pass', labels: { 'action.params.a': 'agent' } });
  });

  it('policy sanity fails closed', () => {
    expect(run({}, { critical_max: 'nope' as TaintLevel }).outcome).toBe('deny');
    expect(run({}, { registry: { x: 'super-trusted' as TaintLevel } }).outcome).toBe('deny');
  });

  it('T26 / taint rule: adding refs to a parameter never lowers its label (the agent can only raise it)', () => {
    const refs = ['skyair:offer_set:1', 'wallet:profile:ana', 'web:skyair.example/results#ad-3', 'tool:fx', 'unknown', 'agent:me'];
    fc.assert(
      fc.property(fc.array(fc.constantFrom(...refs), { minLength: 1, maxLength: 4 }), fc.array(fc.constantFrom(...refs), { minLength: 1, maxLength: 4 }), (a, b) => {
        const la = run({ prov: prov({ 'action.params.offer_id': a }) }).labels['action.params.offer_id']!;
        const lab = run({ prov: prov({ 'action.params.offer_id': [...a, ...b].slice(0, 8) }) }).labels['action.params.offer_id']!;
        return labelRank({ kind: lab } as TaintLabel) >= labelRank({ kind: la } as TaintLabel);
      }),
    );
  });

  it('T26: no declared ref can yield a label below what the registry vouches for (unknown refs are agent)', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 40 }), (ref) => {
        fc.pre(!Object.prototype.hasOwnProperty.call(POLICY.registry, ref) && !ref.startsWith('pca-labels:'));
        return run({ prov: prov({ 'action.params.offer_id': [ref] }) }).labels['action.params.offer_id'] === 'agent';
      }),
    );
  });
});

describe('rule 17 / V14: label receipt refs and flow rules', () => {
  const passport = receipt(AUD, SITE.sk, 'k1', { 'travellers[0].passport': { class: 'pii.identity', value_digest: hashCanonical('X1234567') } });
  const ref = (r: PcaLabels, field: string) => `pca-labels:${labelsRef(r)}#${field}`;

  it('a committed, pinned, session-bound receipt whose value digest matches makes the value first_party at its own site', () => {
    const r = run({ prov: prov({ 'action.params.passport': [ref(passport, 'travellers[0].passport')] }), committed_labels: [labelsRef(passport)], labels: [passport] });
    expect(r.outcome).toBe('pass');
    expect(r.labels['action.params.passport']).toBe('first_party');
    expect(r.classes).toEqual({ 'action.params.passport': ['pii.identity'] });
  });

  it('a mismatching value is agent (the receipt does not vouch for it) but the class still restricts the flow', () => {
    const r = decideParamProvenance({
      aud: AUD,
      session: SESSION,
      action: { params: { ...PARAMS, passport: 'OTHER' } },
      prov: prov({ 'action.params.passport': [ref(passport, 'travellers[0].passport')] }),
      committed_labels: [labelsRef(passport)],
      labels: [passport],
      policy: POLICY,
    });
    expect(r.labels['action.params.passport']).toBe('agent');
    expect(r.classes['action.params.passport']).toEqual(['pii.identity']);
  });

  it('refuses an uncommitted, unsupplied, unpinned, foreign-session receipt or an unknown field', () => {
    const p = prov({ 'action.params.passport': [ref(passport, 'travellers[0].passport')] });
    expect(run({ prov: p, committed_labels: [], labels: [passport] }).outcome).toBe('deny');
    expect(run({ prov: p, committed_labels: [labelsRef(passport)], labels: [] }).outcome).toBe('deny');
    const forged = receipt(AUD, ROGUE.sk, 'k1', passport.fields);
    expect(run({ prov: prov({ 'action.params.passport': [ref(forged, 'travellers[0].passport')] }), committed_labels: [labelsRef(forged)], labels: [forged] }).outcome).toBe('deny');
    const foreign = receipt(AUD, SITE.sk, 'k1', passport.fields, b64u(seed('other')));
    expect(run({ prov: prov({ 'action.params.passport': [ref(foreign, 'travellers[0].passport')] }), committed_labels: [labelsRef(foreign)], labels: [foreign] }).outcome).toBe('deny');
    expect(run({ prov: prov({ 'action.params.passport': [ref(passport, 'nope')] }), committed_labels: [labelsRef(passport)], labels: [passport] }).outcome).toBe('deny');
    expect(run({ prov: prov({ 'action.params.passport': ['pca-labels:short#x'] }) }).outcome).toBe('deny');
  });

  it('T27 (declared flows): a pii value labelled elsewhere may reach this site only when a flow rule lists it', () => {
    const gov = receipt('gov.example', OTHER_SITE.sk, 'g1', { passport: { class: 'pii.identity', value_digest: hashCanonical('X1234567') } });
    const input = { prov: prov({ 'action.params.passport': [ref(gov, 'passport')] }), committed_labels: [labelsRef(gov)], labels: [gov] };
    expect(run(input).outcome).toBe('deny');
    expect(run(input, { flows: { 'pii.*': [AUD] } })).toMatchObject({ outcome: 'question', labels: { 'action.params.passport': 'tool' } });
    expect(run(input, { flows: { 'pii.*': [AUD], 'pii.identity': ['elsewhere'] } }).outcome).toBe('deny'); // most specific rule wins
  });

  it('flow rule specificity and defaults', () => {
    const rules = { '*': ['a'], 'pii.*': ['b'], 'pii.contact': ['c'], 'pii.contact.*': ['d'] };
    expect(flowRuleFor(rules, 'pii.contact')).toBe('pii.contact');
    expect(flowRuleFor(rules, 'pii.contact.email')).toBe('pii.contact.*');
    expect(flowRuleFor(rules, 'pii.identity')).toBe('pii.*');
    expect(flowRuleFor(rules, 'piix')).toBe('*');
    expect(flowRuleFor({}, 'pii')).toBeUndefined();
    expect(flowAllowed({}, 'pii.identity', 'x.example', 'x.example')).toBe(true); // back to its origin
    expect(flowAllowed({}, 'public', 'x.example', 'y.example')).toBe(true);
    expect(flowAllowed({}, 'pii.identity', 'x.example', 'y.example')).toBe(false);
  });

  it('receipt signatures verify only under the key pinned for (site, kid)', () => {
    expect(verifyLabels(passport, [{ site: AUD, kid: 'k1', pk: SITE.pk }])).toBeNull();
    expect(verifyLabels(passport, [{ site: AUD, kid: 'k1', pk: ROGUE.pk }])).toMatch(/signature/);
    expect(verifyLabels(passport, [{ site: 'other', kid: 'k1', pk: SITE.pk }])).toMatch(/no pinned/);
    expect(verifyLabels({ ...passport, extra: 1 }, [{ site: AUD, kid: 'k1', pk: SITE.pk }])).toMatch(/unknown member/);
  });

  it('parseLabelRef', () => {
    const d = labelsRef(passport);
    expect(parseLabelRef(`pca-labels:${d}#a.b`)).toEqual({ receipt: d, field: 'a.b' });
    expect(parseLabelRef(`pca-labels:${d}#`)).toBeNull();
    expect(parseLabelRef(`pca-labels:${d}`)).toBeNull();
    expect(parseLabelRef('x')).toBeNull();
  });
});

describe('V14: read-side purpose limitation', () => {
  const fields = [
    { path: 'passengers[].name', class: 'pii.identity' },
    { path: 'passengers[].email', class: 'pii.contact', optional: true },
    { path: 'loyalty', class: 'internal', optional: true },
    { path: 'fares', class: 'public' },
  ];
  const coverage = { booking: ['pii.identity', 'itinerary'], support: ['pii.*', 'internal'], comparison: [] };

  it('covered classes pass, optional uncovered fields are minimised, required uncovered ones need the principal', () => {
    expect(decideReadPurpose(fields, 'booking', coverage)).toEqual({ outcome: 'allow', minimise: ['loyalty', 'passengers[].email'], uncovered: [] });
    expect(decideReadPurpose(fields, 'support', coverage)).toEqual({ outcome: 'allow', minimise: [], uncovered: [] });
    expect(decideReadPurpose(fields, 'comparison', coverage)).toEqual({ outcome: 'question', minimise: ['loyalty', 'passengers[].email'], uncovered: ['passengers[].name'] });
    expect(decideReadPurpose(fields, 'comparison', coverage, 'deny').outcome).toBe('deny');
    expect(decideReadPurpose(fields, 'unknown', coverage).outcome).toBe('question');
  });

  it('monotone: widening a purpose coverage never adds uncovered fields', () => {
    const classes = ['pii.identity', 'pii.contact', 'internal', 'public', 'itinerary'];
    fc.assert(
      fc.property(fc.subarray(classes), fc.subarray(classes), fc.array(fc.record({ path: fc.string(), class: fc.constantFrom(...classes), optional: fc.boolean() })), (a, b, fs) => {
        const narrow = decideReadPurpose(fs, 'p', { p: a });
        const wide = decideReadPurpose(fs, 'p', { p: [...a, ...b] });
        return wide.uncovered.every((x) => narrow.uncovered.includes(x)) && wide.uncovered.length <= narrow.uncovered.length;
      }),
    );
  });
});

describe('rule 18: classifier verdicts', () => {
  const J = [key('judge-1'), key('judge-2'), key('judge-3')];
  const MESSAGE = 'We are sorry for the delay.';
  const CLS: ClassifierPolicy = { id: 'tone', param: 'action.params.body', labels: ['neutral', 'apologetic', 'hostile', 'other'], keys: J.map((j) => j.pk), k: 2, measurements: ['m-tone-1'] };
  const verdict = (j: { sk: Uint8Array }, label: string, over: { session?: string; content?: unknown; measurement?: string; classifier?: string } = {}) =>
    signClassifierVerdict({ classifier: over.classifier ?? 'tone', session: over.session ?? SESSION, content_digest: classifierContentDigest(over.content ?? MESSAGE), label, measurement: over.measurement ?? 'm-tone-1' }, j.sk);
  const run18 = (verdicts: ReturnType<typeof verdict>[], over: Partial<ClassifierInput> = {}) =>
    decideClassifierDimensions({ session: SESSION, action: { params: { body: MESSAGE } }, committed: verdicts.map(classifierVerdictRef), verdicts, policy: { classifiers: [CLS] }, ...over });

  it('k-of-n distinct allowlisted judges fix env.class.<id>', () => {
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'apologetic'), verdict(J[2]!, 'neutral')])).toMatchObject({ ok: true, classes: { tone: 'apologetic' } });
  });

  it('no quorum, ambiguity, an off-list judge, another session, other content, an unknown label, an unpinned measurement and a double vote all fail', () => {
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'neutral')]).ok).toBe(false);
    const amb = { ...CLS, k: 1 };
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'neutral')], { policy: { classifiers: [amb] } }).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(ROGUE, 'apologetic')]).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'apologetic', { session: b64u(seed('x')) })]).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'apologetic', { content: 'other text' })]).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'sarcastic')]).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'apologetic', { measurement: 'm-evil' })]).ok).toBe(false);
    expect(run18([verdict(J[0]!, 'apologetic'), verdict(J[0]!, 'neutral'), verdict(J[1]!, 'apologetic')]).ok).toBe(false); // one judge, two votes
  });

  it('only committed verdicts count; a committed verdict must be supplied', () => {
    const vs = [verdict(J[0]!, 'apologetic'), verdict(J[1]!, 'apologetic')];
    expect(run18(vs, { committed: [classifierVerdictRef(vs[0]!)] }).ok).toBe(false); // one vote < k
    expect(run18(vs, { verdicts: [vs[0]!] }).ok).toBe(false);
  });

  it('a tampered label breaks the signature', () => {
    const v = verdict(J[0]!, 'apologetic');
    const t = { ...v, label: 'neutral' };
    const w = verdict(J[1]!, 'neutral');
    expect(run18([t, w], {}).ok).toBe(false);
  });
});

describe('W-B composition (decideIntentWB)', () => {
  it('reports nothing and admits when no member is present and no policy is active (back-compat)', () => {
    expect(decideIntentWB({ now: 0, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: {} }, intent_session: {}, policy: {} })).toEqual({ outcome: 'admit', checks: {}, env: {} });
  });

  it('runs provenance and surfaces a question with its friction', () => {
    const r = decideIntentWB({
      now: 0,
      aud: AUD,
      session: SESSION,
      action: { verb: 'air.book', resource: 'r', params: PARAMS },
      intent_session: { prov: prov({ 'action.params.add_ons': ['web:skyair.example/results#ad-3'] }) },
      policy: { provenance: POLICY },
    });
    expect(r).toMatchObject({ outcome: 'question', checks: { provenance: 'question' }, friction: 'tap' });
    expect((r.env.prov as Record<string, Record<string, Record<string, string>>>).action!.params!.add_ons).toBe('web');
  });

  it('a failing classifier check denies after a passing provenance check', () => {
    const r = decideIntentWB({
      now: 0,
      aud: AUD,
      session: SESSION,
      action: { verb: 'v', resource: 'r', params: PARAMS },
      intent_session: { prov: prov(), classes: [] },
      policy: { provenance: POLICY, classifiers: [{ id: 'tone', param: 'action.params.note', labels: ['a'], keys: [SITE.pk], k: 1 }] },
    });
    expect(r).toMatchObject({ outcome: 'deny', checks: { provenance: 'pass', classes: 'fail' } });
  });

  it('every taint level appears in some outcome (lattice sanity)', () => {
    expect([...TAINT_LEVELS].sort()).toEqual(['agent', 'first_party', 'tool', 'trusted', 'web']);
  });
});

describe('prototype-named keys, non-integer clocks, strict activity typing', () => {
  const J = [key('pj-1'), key('pj-2')];
  const MSG = 'hello';
  const LABELS = ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty'];
  const v = (j: { sk: Uint8Array }, label: string) =>
    signClassifierVerdict({ classifier: 'constructor', session: SESSION, content_digest: classifierContentDigest(MSG), label, measurement: 'm' }, j.sk);

  it('a classifier id and labels named like Object.prototype members reach quorum like any other, repeatably', () => {
    for (let round = 0; round < 2; round++) {
      for (const label of LABELS) {
        const vs = [v(J[0]!, label), v(J[1]!, label)];
        const r = decideClassifierDimensions({ session: SESSION, action: { params: { body: MSG } }, committed: vs.map(classifierVerdictRef), verdicts: vs, policy: { classifiers: [{ id: 'constructor', param: 'action.params.body', labels: LABELS, keys: J.map((j) => j.pk), k: 2 }] } });
        expect(r.ok).toBe(true);
        expect(r.ok && r.classes.constructor).toBe(label);
        expect(r.ok && Object.keys(r.classes)).toEqual(['constructor']);
      }
    }
    expect(({} as Record<string, unknown>).constructor).toBe(Object); // the global prototype was not touched
  });

  it('a flow rule or label field is looked up as an own member only', () => {
    expect(flowRuleFor({}, 'constructor')).toBeUndefined();
    expect(flowAllowed({}, 'constructor', 'a.example', 'b.example')).toBe(false);
    expect(flowAllowed({ constructor: ['b.example'] }, 'constructor', 'a.example', 'b.example')).toBe(true);
  });

  it('a non-integer now makes every fact and offer set stale (never coerced)', async () => {
    const { decideIntentWorld, signFact, factRef } = await import('./oracle-facts');
    const O = key('o-clock');
    const NOW = 1_800_000_000_000;
    const f = signFact({ name: 'fare', subject: 'OF-1', value: 5, t_obs: NOW, oracle: 'o1' }, O.sk);
    const base = { aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: { offer_id: 'OF-1' } }, committed: { facts: [factRef(f)] }, facts: [f], policy: { worlds: [{ name: 'fare', subject_path: 'action.params.offer_id', oracles: [{ kid: 'o1', pk: O.pk }], freshness_ms: 60_000, min_oracles: 1, max_faulty: 0 }] } };
    expect(decideIntentWorld({ ...base, now: NOW }).ok).toBe(true);
    for (const now of [String(NOW), NOW + 0.5, null, NaN, Infinity]) expect(decideIntentWorld({ ...base, now: now as unknown as number }).ok).toBe(false);
  });

  it('activity: only real arrays / strings / plain objects make a check active', async () => {
    const { intentWBActive } = await import('./intent-env');
    const none = { facts: false, provenance: false, classes: false };
    expect(intentWBActive({ intent_session: { facts: { length: 1 }, labels: { length: 1 }, classes: { length: 1 }, offer_set: { length: 43 } }, policy: {} })).toEqual(none);
    expect(intentWBActive({ intent_session: {}, policy: { world: { worlds: { length: 2 } as never }, classifiers: { length: 1 } as never, provenance: [] as never } })).toEqual(none);
    expect(intentWBActive({ intent_session: { facts: [SESSION], prov: null, classes: [SESSION] }, policy: {} })).toEqual({ facts: true, provenance: true, classes: true });
  });
});

describe('absent vs null and suite capability (README "strict values, absent vs null, suite capability")', () => {
  const NOW = 1_800_000_000_000;
  it('rule 16: an absent optional member is empty, a present null is malformed', async () => {
    const { decideIntentWorld } = await import('./oracle-facts');
    const base = { now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: { a: 2, b: 1 } } };
    const rel = { relational: [{ name: 'd', fn: 'sub' as const, a: 'action.params.a', b: 'action.params.b' }] };
    expect(decideIntentWorld({ ...base, policy: rel })).toMatchObject({ ok: true, world: { d: 1 } });
    expect(decideIntentWorld({ ...base, committed: {}, policy: {} })).toMatchObject({ ok: true });
    for (const bad of [{ policy: null }, { committed: null }, { committed: { facts: null } }, { committed: { offer_set: null } }, { facts: null }, { facts: 'x' }, { offer_set: null }, { policy: { worlds: null } }, { policy: { relational: null } }, { policy: { offers: null } }, { policy: { skew_ms: null } }]) {
      expect(decideIntentWorld({ ...base, ...(bad as object) } as never).ok).toBe(false);
    }
    expect(decideIntentWorld({ ...base, action: { verb: 'v', resource: 'r', params: null } as never, policy: rel }).ok).toBe(false);
  });

  it('rule 17: null prov / committed_labels / labels / params / policy members deny', () => {
    for (const k of ['prov', 'committed_labels', 'labels']) expect(run({ [k]: null } as never).outcome).toBe('deny');
    expect(run({ action: { params: null } } as never).outcome).toBe('deny');
    for (const k of ['registry', 'label_keys', 'critical_max', 'material_tainted', 'critical_tainted', 'flows']) expect(run({}, { [k]: null } as never).outcome).toBe('deny');
    expect(decideParamProvenance({ aud: AUD, session: SESSION, action: { params: PARAMS }, policy: null as never }).outcome).toBe('deny');
  });

  it('rule 18: null committed / verdicts / measurements / pq_keys fail; absent measurements is no pin', () => {
    const J = [key('nv-1'), key('nv-2')];
    const v = (j: { sk: Uint8Array }) => signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest('m'), label: 'a', measurement: 'x' }, j.sk);
    const vs = [v(J[0]!), v(J[1]!)];
    const pol = (over: object) => ({ classifiers: [{ id: 'tone', param: 'action.params.body', labels: ['a'], keys: J.map((j) => j.pk), k: 2, ...over }] });
    const base = { session: SESSION, action: { params: { body: 'm' } }, committed: vs.map(classifierVerdictRef), verdicts: vs };
    expect(decideClassifierDimensions({ ...base, policy: pol({}) }).ok).toBe(true);
    for (const over of [{ measurements: null }, { pq_keys: null }]) expect(decideClassifierDimensions({ ...base, policy: pol(over) as never }).ok).toBe(false);
    for (const k of ['committed', 'verdicts']) expect(decideClassifierDimensions({ ...base, [k]: null, policy: pol({}) }).ok).toBe(false);
  });

  it('an alg this verifier does not implement fails with unsupported_suite; a non-string alg is malformed', async () => {
    const { decideIntentWorld, signFact, factRef } = await import('./oracle-facts');
    const O = key('o-suite');
    const f = { ...signFact({ name: 'fare', subject: 'OF-1', value: 5, t_obs: NOW, oracle: 'o1' }, O.sk), alg: 'no-such-suite' };
    const pol = { worlds: [{ name: 'fare', subject_path: 'action.params.offer_id', oracles: [{ kid: 'o1', pk: O.pk }], freshness_ms: 60_000, min_oracles: 1, max_faulty: 0 }] };
    const r = decideIntentWorld({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: { offer_id: 'OF-1' } }, committed: { facts: [factRef(f)] }, facts: [f], policy: pol });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/unsupported_suite/);
    const g = { ...f, alg: 7 as unknown as string };
    const r2 = decideIntentWorld({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: { offer_id: 'OF-1' } }, committed: { facts: [factRef(g)] }, facts: [g], policy: pol });
    expect(r2.ok).toBe(false);
    expect(!r2.ok && r2.reason).not.toMatch(/unsupported_suite/);
    const forged = { ...verdictLike(), alg: 'no-such-suite' };
    expect(verifyLabels(forged, [{ site: AUD, kid: 'k1', pk: SITE.pk }])).toMatch(/unsupported_suite/);
  });
});

function verdictLike(): PcaLabels {
  return signLabels({ site: AUD, session: SESSION, response_digest: b64u(seed('r')), fields: { a: { class: 'public', value_digest: hashCanonical('x') } }, issued_at: 1, kid: 'k1' }, SITE.sk);
}

describe('V14 read purpose: canonical (UTF-8 byte) ordering and strict input', () => {
  it('sorts paths in UTF-8 byte order, not UTF-16 order (U+FFFD before U+1F600)', () => {
    const paths = ['\u{1F600}', '�', 'zé', 'a'];
    const r = decideReadPurpose(paths.map((path) => ({ path, class: 'secret' })), 'p', { p: [] });
    expect(r.uncovered).toEqual(['a', 'zé', '�', '\u{1F600}']);
    expect([...paths].sort()).not.toEqual(r.uncovered); // the default sort would differ
  });
  it('malformed input (null members) is deny with empty lists', () => {
    expect(decideReadPurpose(null as never, 'p', {})).toEqual({ outcome: 'deny', minimise: [], uncovered: [] });
    expect(decideReadPurpose([{ path: 'x', class: 'c', optional: null as never }], 'p', {})).toEqual({ outcome: 'deny', minimise: [], uncovered: [] });
  });
});

describe('verifier entry points never throw (fail closed on any input)', () => {
  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic.self = cyclic;
  const odd: unknown[] = [null, undefined, 42, 'x', true, [], cyclic, { intent_session: cyclic, policy: cyclic, artifacts: cyclic, action: cyclic, committed: cyclic, facts: cyclic }];
  it('decide* / verify* / *Active return fail-closed values for null, primitives, arrays and cyclic input', async () => {
    const env = await import('./intent-env');
    const world = await import('./oracle-facts');
    const offers = await import('./offer-set');
    const layers = await import('./intent-layers');
    for (const x of odd) {
      const a = x as never;
      expect(() => env.decideIntentWB(a)).not.toThrow();
      expect(env.decideIntentWB(a)).toMatchObject({ outcome: 'deny', checks: { facts: 'fail' } });
      expect(typeof env.intentWBContextError(a)).toBe('string');
      expect(() => env.intentWBActive(a)).not.toThrow();
      expect(() => env.intentProvenanceActive(a)).not.toThrow();
      expect(world.decideIntentWorld(a).ok).toBe(false);
      expect(() => world.intentWorldActive(a)).not.toThrow();
      expect(offers.decideOfferSet(a).ok).toBe(false);
      expect(decideParamProvenance(a).outcome).toBe('deny');
      expect(decideClassifierDimensions(a).ok).toBe(false);
      expect(() => (cl as typeof import('./intent-classifier')).classifierCheckActive(a)).not.toThrow();
      expect(typeof verifyLabels(a, a)).toBe('string');
      expect(() => flowAllowed(a, a, a, a)).not.toThrow();
      expect(() => flowRuleFor(a, a)).not.toThrow();
      expect(parseLabelRef(a)).toBeNull();
      expect(decideReadPurpose(a, a, a, a)).toEqual({ outcome: 'deny', minimise: [], uncovered: [] });
      expect(() => layers.decideLayerCeilings(a, a)).not.toThrow();
      expect(() => layers.decideLayers(a, a)).not.toThrow();
      expect(() => (cl as typeof import('./intent-classifier')).verifyClassifierAttestation(a, undefined)).not.toThrow();
    }
    expect(env.decideIntentWB(null as never).reason).toBe('facts: the W-B context is malformed: input must be an object');
    expect(world.ratioPpm(1.5, 2)).toBeNull();
  });

  it('huge inputs are refused by their bounds, not by an exception', async () => {
    const world = await import('./oracle-facts');
    const big = Array.from({ length: 100_000 }, (_, i) => `d${i}`);
    expect(world.decideIntentWorld({ now: 1, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r' }, committed: { facts: big }, policy: {} }).ok).toBe(false);
    expect(decideClassifierDimensions({ session: SESSION, action: { params: {} }, committed: big, policy: { classifiers: [] } }).ok).toBe(false);
    expect(decideParamProvenance({ aud: AUD, session: SESSION, action: { params: {} }, committed_labels: big, policy: { params: {} } }).outcome).toBe('deny');
  });
});
