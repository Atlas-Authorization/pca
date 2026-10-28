import { describe, expect, it } from 'vitest';
import { MAX_OBLIGATIONS, collectObligations, mergeObligations, obligationError, obligationOutcome, obligationsError, pepObligationGate } from './obligations';
import { classVerdictsError, decideClasses, MAX_POLICY_CLASSES, POLICY_CLASSES } from './policy-classes';
import { bindContext, decideWithMissing, supplierOf, supplierTableError } from './missing-context';
import { createLink, instantiateTemplate, slotsDigest, resolveLink, signTemplate, templateDigest, verifyLinkedPolicy } from './policy-link';
import { templateRefError } from './envelope-rules';
import { b64u } from './hash';
import { publicKeyOf } from './keys';

describe('obligation parameter limits are exact', () => {
  it.each([
    ['log sink 128', { kind: 'log', params: { sink: 'a'.repeat(128) } }, null],
    ['log sink 129', { kind: 'log', params: { sink: 'a'.repeat(129) } }, 'log.sink must be a non-empty string of at most 128 characters'],
    ['log sink empty', { kind: 'log', params: { sink: '' } }, 'log.sink must be a non-empty string of at most 128 characters'],
    ['log sink number', { kind: 'log', params: { sink: 5 } }, 'log.sink must be a non-empty string of at most 128 characters'],
    ['notify to 256', { kind: 'notify', params: { to: 'a'.repeat(256) } }, null],
    ['notify to 257', { kind: 'notify', params: { to: 'a'.repeat(257) } }, 'notify.to is required (a non-empty string of at most 256 characters)'],
    ['watermark id 128', { kind: 'watermark', params: { id: 'a'.repeat(128) } }, null],
    ['watermark id 129', { kind: 'watermark', params: { id: 'a'.repeat(129) } }, 'watermark.id is required (a non-empty string of at most 128 characters)'],
    ['redact 32 fields', { kind: 'redact', params: { fields: Array.from({ length: 32 }, (_, i) => `f${i}`) } }, null],
    ['redact 33 fields', { kind: 'redact', params: { fields: Array.from({ length: 33 }, (_, i) => `f${i}`) } }, 'redact.fields must be 1..32 dotted field paths'],
    ['redact depth 8', { kind: 'redact', params: { fields: ['a.b.c.d.e.f.g.h'] } }, null],
    ['redact depth 9', { kind: 'redact', params: { fields: ['a.b.c.d.e.f.g.h.i'] } }, 'redact.fields must be 1..32 dotted field paths'],
    ['redact segment 64', { kind: 'redact', params: { fields: ['a'.repeat(64)] } }, null],
    ['redact segment 65', { kind: 'redact', params: { fields: ['a'.repeat(65)] } }, 'redact.fields must be 1..32 dotted field paths'],
    ['redact digit start', { kind: 'redact', params: { fields: ['1a'] } }, 'redact.fields must be 1..32 dotted field paths'],
    ['redact underscore start', { kind: 'redact', params: { fields: ['_a'] } }, null],
    ['redact fields not array', { kind: 'redact', params: { fields: 'a' } }, 'redact.fields must be 1..32 dotted field paths'],
    ['redact duplicate', { kind: 'redact', params: { fields: ['a', 'a'] } }, 'redact.fields has a duplicate'],
    ['due 0', { kind: 'log', due: 0 }, null],
    ['due max safe', { kind: 'log', due: Number.MAX_SAFE_INTEGER }, null],
    ['due above safe', { kind: 'log', due: Number.MAX_SAFE_INTEGER + 1 }, 'due must be a non-negative safe integer'],
    ['due -0', { kind: 'log', due: -0 }, null],
    ['due string', { kind: 'log', due: '1' }, 'due must be a non-negative safe integer'],
    ['params array', { kind: 'log', params: [] }, 'params must be an object'],
    ['params null', { kind: 'log', params: null }, 'params must be an object'],
    ['unknown member', { kind: 'log', x: 1 }, "unknown member 'x'"],
    ['kind not string', { kind: 5 }, "unknown obligation kind '5'"],
    ['array not object', [], 'an obligation must be an object'],
  ])('%s', (_n, o, want) => expect(obligationError(o)).toBe(want));
  it('list limits and duplicate positions', () => {
    expect(obligationsError(Array.from({ length: MAX_OBLIGATIONS }, (_, i) => ({ kind: 'log', params: { sink: `s${i}` } })))).toBeNull();
    expect(obligationsError(Array.from({ length: MAX_OBLIGATIONS + 1 }, (_, i) => ({ kind: 'log', params: { sink: `s${i}` } })))).toBe('more than 16 obligations');
    expect(obligationsError([{ kind: 'log' }, { kind: 'log', params: {} }])).toBe('obligations[1] duplicates an earlier obligation');
    expect(obligationsError([{ kind: 'log' }, { kind: 'shred' }])).toBe("obligations[1]: unknown obligation kind 'shred'");
    expect(obligationsError('x')).toBe('obligations must be an array');
    expect(obligationsError(null)).toBe('obligations must be an array');
  });
  it('merge and collect exact refusals', () => {
    expect(mergeObligations([{ kind: 'shred' }])).toEqual({ ok: false, reason: "obligations[0]: unknown obligation kind 'shred'" });
    const nine = Array.from({ length: 9 }, (_, i) => ({ kind: 'log', params: { sink: `a${i}` } }));
    const nine2 = Array.from({ length: 9 }, (_, i) => ({ kind: 'log', params: { sink: `b${i}` } }));
    expect(mergeObligations(nine, nine2)).toEqual({ ok: false, reason: 'more than 16 obligations after merging' });
    expect(collectObligations([{ id: 'a', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [{ kind: 'log' }], extra: 1 }], {})).toEqual({ ok: false, reason: 'obligation rule 0 is malformed' });
    expect(collectObligations([{ id: '', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [{ kind: 'log' }] }], {})).toEqual({ ok: false, reason: 'obligation rule 0 is malformed' });
    expect(collectObligations([{ id: 'a', when: 5, obligations: [{ kind: 'log' }] }], {})).toEqual({ ok: false, reason: 'obligation rule 0 is malformed' });
    expect(collectObligations([{ id: 'a', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [] }], {})).toEqual({ ok: false, reason: "obligation rule 'a': obligations must not be empty" });
    expect(collectObligations([{ id: 'a', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [{ kind: 'shred' }] }], {})).toEqual({ ok: false, reason: "obligation rule 'a': obligations[0]: unknown obligation kind 'shred'" });
    expect(collectObligations(undefined, {})).toEqual({ ok: true, obligations: [] });
    const rules = [{ id: 'a', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [{ kind: 'log' }] }, { id: 'b', when: { field: 'env.x', op: 'eq', value: 1 }, obligations: [{ kind: 'log' }] }];
    expect(collectObligations(rules, { env: { x: 1 } })).toEqual({ ok: true, obligations: [{ kind: 'log' }] });
  });
  it('gate and outcome boundary cases', () => {
    expect(pepObligationGate('deny', true, [{ kind: 'log' }], ['log'])).toEqual({ decision: 'deny', perform: [], unsupported: [] });
    expect(pepObligationGate('escalate', false, [{ kind: 'log' }], ['log'])).toEqual({ decision: 'escalate', perform: [], unsupported: [] });
    expect(pepObligationGate('allow', false, [{ kind: 'log' }], null)).toMatchObject({ decision: 'deny', reason: 'the supported obligation kinds are malformed' });
    expect(pepObligationGate('allow', false, [{ kind: 'log' }, { kind: 'log', params: { sink: 'a' } }], ['log'])).toMatchObject({ decision: 'allow' });
    expect(pepObligationGate('allow', false, [{ kind: 'log' }], ['notify', 'log']).perform).toEqual([{ kind: 'log' }]);
    expect(obligationOutcome([{ kind: 'log', due: 5 }], [0, 0], 5)).toEqual({ outcome: 'ok', overdue: [] });
    expect(obligationOutcome([{ kind: 'log', due: 5 }], [0.5], 5)).toEqual({ outcome: 'escalate', overdue: [0], status: 'obligation_unmet' });
    expect(obligationOutcome([{ kind: 'log', due: 5 }], [], -1)).toEqual({ outcome: 'escalate', overdue: [0], status: 'obligation_unmet' });
    expect(obligationOutcome([{ kind: 'shred' }], [], 5)).toEqual({ outcome: 'escalate', overdue: [0], status: 'obligation_unmet' });
    expect(obligationOutcome('x', [], 5)).toEqual({ outcome: 'escalate', overdue: [], status: 'obligation_unmet' });
  });
});

describe('policy classes', () => {
  const c = (cls: string, decision = 'allow', over: Record<string, unknown> = {}) => ({ class: cls, revision: 1, digest: 'd', decision, ...over });
  it('limits', () => {
    expect(MAX_POLICY_CLASSES).toBe(5);
    expect(POLICY_CLASSES).toEqual(['constitution', 'regulatory', 'org', 'blueprint', 'user']);
    expect(classVerdictsError(POLICY_CLASSES.map((x) => c(x)))).toBeNull();
    expect(classVerdictsError([c('org', 'allow', { revision: 0 })])).toBeNull();
    expect(classVerdictsError([c('org', 'allow', { revision: 2 ** 53 })])).toBe('policy_classes[0].revision must be a non-negative safe integer');
    expect(classVerdictsError([c('org', 'allow', { digest: 'a'.repeat(128) })])).toBeNull();
    expect(classVerdictsError([c('org', 'allow', { digest: 'a'.repeat(129) })])).toBe('policy_classes[0].digest invalid');
    expect(classVerdictsError([1])).toBe('policy_classes[0] must be an object');
    expect(classVerdictsError([c('org', 'allow', { x: 1 })])).toBe("policy_classes[0] has unknown member 'x'");
    expect(classVerdictsError([c('org'), c('org')])).toBe("policy class 'org' appears twice");
    expect(classVerdictsError([c('org', 'maybe')])).toBe('policy_classes[0].decision must be allow, escalate or deny');
    expect(classVerdictsError([...POLICY_CLASSES.map((x) => c(x)), c('org')])).toBe('more than 5 policy classes');
  });
  it('decide is deterministic and names who said no', () => {
    const r = decideClasses([c('user', 'deny'), c('constitution', 'escalate'), c('org', 'deny')]);
    expect(r.decision).toBe('deny');
    expect(r.denied_by).toEqual(['org', 'user']);
    expect(r.escalated_by).toEqual(['constitution']);
    expect(r.classes.map((x) => x.class)).toEqual(['constitution', 'org', 'user']);
    expect(r.reason).toBeUndefined();
    expect(decideClasses([c('org')]).decision).toBe('allow');
  });
});

describe('missing context', () => {
  const eq = (field: string, value: unknown) => ({ field, op: 'eq', value });
  const bound = { action: { verb: 'v', resource: 'r', params: { a: 1 } }, subject: { id: 'u' }, env: { t: 1 } };
  it('supplier lookup and table validation', () => {
    expect(supplierOf('env.x', {})).toBe('principal');
    expect(supplierOf('env', { env: 'rs_observation' })).toBe('rs_observation');
    expect(supplierOf('env.x.y', { env: 'rs_observation', 'env.x': 'discharge_issuer' })).toBe('discharge_issuer');
    expect(supplierOf('envx', { env: 'rs_observation' })).toBe('principal');
    expect(supplierTableError({})).toBeNull();
    expect(supplierTableError(null)).toBe('the supplier table must be an object');
    expect(supplierTableError([])).toBe('the supplier table must be an object');
    expect(supplierTableError({ 'action.params': 'principal' })).toBeNull();
    expect(supplierTableError({ 'action.verb': 'principal' })).toBe("bad supplier path 'action.verb'");
    expect(supplierTableError({ 'env.__proto__': 'principal' })).toBe("bad supplier path 'env.__proto__'");
    expect(supplierTableError({ 'env.a': 5 })).toBe("bad supplier for 'env.a'");
  });
  it('bind never writes into prototypes and never takes verb or resource', () => {
    const r = bindContext(bound as never, JSON.parse('{"env":{"__proto__":{"polluted":true},"ok":1}}'), {});
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(r.context.env).toEqual({ t: 1, ok: 1 });
    expect(r.conflicts).toEqual([]);
    expect(bindContext(bound as never, { action: { verb: 'x' } } as never).context.action.verb).toBe('v');
    expect(bindContext(bound as never, { env: { t: 1 } }).conflicts).toEqual([]);
    expect(bindContext(bound as never, { env: { t: 2 } }).conflicts).toEqual(['env.t']);
    expect(bindContext(bound as never, { env: { t: null } } as never).conflicts).toEqual(['env.t']);
  });
  it('typed decisions: exact result objects', () => {
    expect(decideWithMissing({ where: [eq('env.t', 1)], bound: bound as never })).toEqual({ decision: 'allow', missing: [] });
    expect(decideWithMissing({ where: undefined, bound: bound as never })).toEqual({ decision: 'deny', reason: 'condition_false', missing: [] });
    expect(decideWithMissing({ where: [eq('env.u', 1)], bound: bound as never, suppliers: { env: 'rs_observation' } })).toEqual({ decision: 'escalate', reason: 'escalate: missing_context rs_observation:env.u', missing: [{ path: 'env.u', supplier: 'rs_observation' }] });
    expect(decideWithMissing({ where: [{ all_of: [] }], bound: bound as never })).toEqual({ decision: 'deny', reason: 'ill_typed_context', missing: [] });
    expect(decideWithMissing({ where: [eq('env.u', 1), { field: 'env.t', op: 'lt', value: 'x' }], bound: bound as never })).toEqual({ decision: 'deny', reason: 'ill_typed_context', missing: [] });
    expect(decideWithMissing({ where: [eq('env.u', 1)], bound: bound as never, suppliers: 5 as never })).toEqual({ decision: 'deny', reason: 'bad supplier table: the supplier table must be an object', missing: [] });
    expect(decideWithMissing({ where: [eq('env.u', 1)], bound: null as never })).toEqual({ decision: 'deny', reason: 'bad_context', missing: [] });
  });
});

describe('bound parameter objects (bind_params_digest)', () => {
  const SK = new Uint8Array(32).fill(7);
  const pub = b64u(publicKeyOf(SK));
  const def = { v: 1 as const, kind: 'pca-policy-template' as const, id: 't', version: '1', slots: { n: { type: 'integer' as const, min: 1, max: 9 } }, body: { predicates: [{ verb: 'x', where: [{ field: 'action.params.n', op: 'lte', value: { $slot: 'n' } }] }] } };
  const digest = templateDigest(def as never);
  const reg = (params?: Record<string, Record<string, unknown>>) => ({ templates: { [digest]: signTemplate(def as never, SK, pub) }, trusted: [pub], ...(params ? { params } : {}) });
  it('createLink binds, resolves and verifies', () => {
    const ref = createLink(def as never, { n: 5 }, { bindParams: true });
    expect(ref).toEqual({ template_id: 't', version_digest: digest, bind_params_digest: slotsDigest({ n: 5 }) });
    expect(templateRefError(ref)).toBeNull();
    const r = resolveLink(ref, reg({ [slotsDigest({ n: 5 })]: { n: 5 } }));
    expect(r.ok && r.policy.predicates[0]?.where?.[0]).toEqual({ field: 'action.params.n', op: 'lte', value: 5 });
    const inst = instantiateTemplate(def as never, { n: 5 });
    expect(inst.ok).toBe(true);
    if (inst.ok) expect(verifyLinkedPolicy({ template_ref: ref, predicates: inst.policy.predicates, caveats: [] }, reg({ [slotsDigest({ n: 5 })]: { n: 5 } }))).toEqual({ ok: true, template: digest });
    expect(verifyLinkedPolicy({ template_ref: ref, predicates: inst.ok ? inst.policy.predicates : [], caveats: [] }, reg())).toEqual({ ok: false, reason: 'parameter object is not available' });
    expect(createLink(def as never, { n: 5 })).toEqual({ template_id: 't', version_digest: digest, slots: { n: 5 } });
  });
  it('a parameter object reached through the prototype is not available', () => {
    const ref = { template_id: 't', version_digest: digest, bind_params_digest: 'constructor' };
    expect(resolveLink(ref, reg({}))).toEqual({ ok: false, reason: 'parameter object is not available' });
    expect(resolveLink(ref, reg({ constructor: [] as never }))).toEqual({ ok: false, reason: 'parameter object is not available' });
  });
  it('template_ref shape: exact messages', () => {
    const base = { template_id: 't', version_digest: 'd' };
    expect(templateRefError({ ...base, slots: {}, bind_params_digest: 'x' })).toBe('template_ref has both slots and bind_params_digest');
    expect(templateRefError({ ...base, bind_params_digest: 'a'.repeat(128) })).toBeNull();
    expect(templateRefError({ ...base, bind_params_digest: 'a'.repeat(129) })).toBe('template_ref.bind_params_digest invalid');
    expect(templateRefError(base)).toBe('template_ref.slots must be an object');
    expect(templateRefError({ ...base, slots: {}, other: 1 })).toBe("template_ref has unknown member 'other'");
  });
});
