import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair, encodeKey } from './keys';
import { decideTighten, decideUnits, decisionOf, isModelDerivedPath, meet, meetAll, modelPathsRead, pepDecision, signalCeiling, tighten } from './decision';
import { MAX_TIGHTEN_RULES, tightenListError, unitTagsError } from './envelope-rules';
import { ESCALATION_MAX_LIFETIME_MS, buildEscalationRequest, escalationAnswerShapeError, signEscalationAnswer, verifyEscalationAnswer, type EscalationAnswerBody } from './escalation';

// Exact-outcome kill tests (Stryker): every branch of decision.ts, envelope-rules.ts and escalation.ts asserts the exact value.

describe('decision.ts: lattice', () => {
  it('meet picks the lower, returns deny for any unknown operand (either side)', () => {
    expect(meet('allow', 'escalate')).toBe('escalate');
    expect(meet('escalate', 'allow')).toBe('escalate');
    expect(meet('allow', 'allow')).toBe('allow');
    expect(meet('deny', 'deny')).toBe('deny');
    expect(meet('bogus' as never, 'allow')).toBe('deny');
    expect(meet('allow', 'bogus' as never)).toBe('deny');
    expect(meet(undefined as never, undefined as never)).toBe('deny');
  });
  it('meetAll is allow for [] and the minimum otherwise', () => {
    expect(meetAll([])).toBe('allow');
    expect(meetAll(['allow', 'escalate', 'allow'])).toBe('escalate');
    expect(meetAll(['escalate', 'deny'])).toBe('deny');
  });
  it('signalCeiling maps exactly ok/escalate/deny and everything else to deny', () => {
    expect([signalCeiling('ok'), signalCeiling('escalate'), signalCeiling('deny'), signalCeiling('allow'), signalCeiling(undefined), signalCeiling(1)]).toEqual(['allow', 'escalate', 'deny', 'deny', 'deny', 'deny']);
  });
  it('tighten / pepDecision exact table', () => {
    expect(tighten('allow', 'ok')).toBe('allow');
    expect(tighten('allow', 'escalate')).toBe('escalate');
    expect(tighten('escalate', 'ok')).toBe('escalate');
    expect(tighten('deny', 'ok')).toBe('deny');
    expect(pepDecision('escalate', true)).toBe('allow');
    expect(pepDecision('escalate', false)).toBe('escalate');
    expect(pepDecision('deny', true)).toBe('deny');
    expect(pepDecision('allow', false)).toBe('allow');
    expect(pepDecision('escalate', 1 as never)).toBe('escalate');
  });
});

describe('decision.ts: decisionOf', () => {
  const v = (checks: Record<string, string>, reasons: string[], allow = false) => decisionOf({ allow, checks, reasons });
  it('every branch', () => {
    expect(v({}, [], true)).toBe('allow');
    expect(v({ a: 'pass' }, [])).toBe('deny');
    expect(v({ a: 'not-enforced' }, ['a: intent_required: x'])).toBe('deny');
    expect(v({ a: 'fail' }, ['a: intent_required: x'])).toBe('escalate');
    expect(v({ a: 'fail' }, ['a: escalate: x'])).toBe('escalate');
    expect(v({ a: 'fail' }, ['a: x'])).toBe('deny');
    expect(v({ a: 'fail' }, [])).toBe('deny');
    expect(v({ a: 'fail' }, ['b: intent_required: x'])).toBe('deny');
    expect(v({ a: 'fail' }, ['a: intent_required: x', 'a: other'])).toBe('deny');
    expect(v({ a: 'fail', b: 'fail' }, ['a: escalate: 1', 'b: intent_required: 2'])).toBe('escalate');
    expect(v({ a: 'fail', b: 'fail' }, ['a: escalate: 1'])).toBe('deny');
    expect(v({ a: 'fail' }, ['a:intent_required: x'])).toBe('deny'); // the separator is ": "
    expect(v({ a: 'fail' }, [5 as never])).toBe('deny');
    expect(decisionOf(null as never)).toBe('deny');
  });
});

describe('decision.ts: model paths', () => {
  it('isModelDerivedPath exact', () => {
    expect(isModelDerivedPath('env.class.a')).toBe(true);
    expect(isModelDerivedPath('env.prov.a')).toBe(true);
    expect(isModelDerivedPath('env.judge')).toBe(true);
    expect(isModelDerivedPath('env.acc.a')).toBe(false);
    expect(isModelDerivedPath('env')).toBe(false);
    expect(isModelDerivedPath('action.class.a')).toBe(false);
    expect(isModelDerivedPath('env.world')).toBe(false);
    expect(isModelDerivedPath('env.world', ['x'])).toBe(true);
    expect(isModelDerivedPath('env.world.x', ['x'])).toBe(true);
    expect(isModelDerivedPath('env.world.y', ['x'])).toBe(false);
    expect(isModelDerivedPath('env.world.y')).toBe(false);
    expect(isModelDerivedPath(5)).toBe(false);
  });
  it('modelPathsRead walks field, ref, collection, not, all_of, any_of; sorts; dedupes; ignores malformed', () => {
    const where = [
      { field: 'env.prov.b', op: 'eq', value: 1 },
      { all_of: [{ field: 'action.params.a', op: 'eq', ref: 'env.class.z' }] },
      { any_of: [{ not: { field: 'x', op: 'member_of', value: 1, collection: 'env.judge.k' } }] },
      { field: 'env.prov.b', op: 'eq', value: 2 },
    ];
    expect(modelPathsRead([[{ verb: '*', where }], 'junk', [null, { verb: '*' }, { verb: '*', where: 'x' }]])).toEqual(['env.class.z', 'env.judge.k', 'env.prov.b']);
    expect(modelPathsRead([[{ verb: '*', where: [{ field: 'env.world.w', op: 'eq', value: 1 }] }]], ['w'])).toEqual(['env.world.w']);
    expect(modelPathsRead(['x'] as never)).toEqual([]);
    // depth cap: a path nested deeper than 64 levels is not seen
    let deep: object = { field: 'env.class.deep', op: 'eq', value: 1 };
    for (let i = 0; i < 70; i++) deep = { not: deep };
    expect(modelPathsRead([[{ verb: '*', where: [deep] }]])).toEqual([]);
    let ok: object = { field: 'env.class.deep', op: 'eq', value: 1 };
    for (let i = 0; i < 60; i++) ok = { not: ok };
    expect(modelPathsRead([[{ verb: '*', where: [ok] }]])).toEqual(['env.class.deep']);
  });
});

describe('envelope-rules.ts: exact messages', () => {
  const rule = (o: object = {}) => ({ id: 'r1', when: { field: 'a', op: 'eq', value: 1 }, signal: 'escalate', ...o });
  it('tightenListError', () => {
    expect(tightenListError(undefined)).toBeNull();
    expect(tightenListError([])).toBeNull();
    expect(tightenListError([rule()])).toBeNull();
    expect(tightenListError([rule({ reason: 'x'.repeat(256) })])).toBeNull();
    expect(tightenListError(null)).toBe('tighten must be an array');
    expect(tightenListError({})).toBe('tighten must be an array');
    expect(tightenListError(Array.from({ length: MAX_TIGHTEN_RULES }, (_, i) => rule({ id: `r${i}` })))).toBeNull();
    expect(tightenListError(Array.from({ length: MAX_TIGHTEN_RULES + 1 }, (_, i) => rule({ id: `r${i}` })))).toBe('tighten has more than 64 rules');
    expect(tightenListError([1])).toBe('tighten[0] must be an object');
    expect(tightenListError([[]])).toBe('tighten[0] must be an object');
    expect(tightenListError([rule({ x: 1 })])).toBe("unknown member 'tighten[0].x'");
    expect(tightenListError([{ id: 'a', when: {} }])).toBe("missing member 'tighten[0].signal'");
    expect(tightenListError([rule({ id: 'A' })])).toBe('tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$');
    expect(tightenListError([rule({ id: 5 })])).toBe('tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$');
    expect(tightenListError([rule(), rule()])).toBe("tighten[1].id 'r1' is a duplicate");
    expect(tightenListError([rule({ when: [] })])).toBe('tighten[0].when must be a condition object');
    expect(tightenListError([rule({ signal: 'ok' })])).toBe("tighten[0].signal must be 'escalate' or 'deny'");
    expect(tightenListError([rule({ reason: 'x'.repeat(257) })])).toBe('tighten[0].reason must be a string of at most 256 characters');
    expect(tightenListError([rule({ reason: 5 })])).toBe('tighten[0].reason must be a string of at most 256 characters');
  });
  const A = 'action.params.amount';
  it('unitTagsError', () => {
    const m = { kind: 'money', currency: 'USD', exponent: 2 };
    expect(unitTagsError({ [A]: m })).toBeNull();
    expect(unitTagsError({ [A]: { kind: 'k' } })).toBeNull();
    expect(unitTagsError({ [A]: { kind: 'k', exponent: 0 } })).toBeNull();
    expect(unitTagsError({ [A]: { kind: 'k', exponent: 18 } })).toBeNull();
    expect(unitTagsError([])).toBe('units must be an object');
    expect(unitTagsError(null)).toBe('units must be an object');
    expect(unitTagsError(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`action.params.p${i}`, { kind: 'k' }])))).toBe('units has more than 64 entries');
    expect(unitTagsError({ amount: m })).toBe("units key 'amount' must be an action.params.<name> path");
    expect(unitTagsError({ [A]: 5 })).toBe(`units['${A}'] must be an object`);
    expect(unitTagsError({ [A]: { ...m, z: 1 } })).toBe(`unknown member 'units['${A}'].z'`);
    expect(unitTagsError({ [A]: { currency: 'USD' } })).toBe(`missing member 'units['${A}'].kind'`);
    expect(unitTagsError({ [A]: { kind: '' } })).toBe(`units['${A}'].kind must be a string of 1..64 characters`);
    expect(unitTagsError({ [A]: { kind: 'k'.repeat(65) } })).toBe(`units['${A}'].kind must be a string of 1..64 characters`);
    expect(unitTagsError({ [A]: { kind: 'k'.repeat(64) } })).toBeNull();
    expect(unitTagsError({ [A]: { kind: 'k', currency: '' } })).toBe(`units['${A}'].currency must be a string of 1..16 characters`);
    expect(unitTagsError({ [A]: { kind: 'k', currency: 'x'.repeat(17) } })).toBe(`units['${A}'].currency must be a string of 1..16 characters`);
    expect(unitTagsError({ [A]: { kind: 'k', currency: 'x'.repeat(16) } })).toBeNull();
    for (const e of [-1, 19, 1.5, '2', -0]) expect(unitTagsError({ [A]: { kind: 'k', exponent: e } })).toBe(`units['${A}'].exponent must be an integer in [0, 18]`);
  });
});

describe('decision.ts: decideTighten exact outcomes and reasons', () => {
  const W = (f: string) => [[{ verb: '*', where: [{ field: f, op: 'eq', value: 1 }] }]];
  const ctx = { action: { verb: 'v', resource: 'r', params: { amount: 80 } }, env: { class: { tone: 'hostile' } } };
  const big = { field: 'action.params.amount', op: 'gt', value: 50 };
  it('typing refusals', () => {
    expect(decideTighten({ polarity: 'strict' })).toEqual({ outcome: 'deny', legacy: false, offending: [], reason: "model_polarity must be 'legacy' when present" });
    expect(decideTighten({ tighten: {} })).toEqual({ outcome: 'deny', legacy: false, offending: [], reason: 'malformed tighten list: tighten must be an array' });
    expect(decideTighten({ predicates: W('env.class.a') })).toEqual({
      outcome: 'deny', legacy: false, offending: ['env.class.a'],
      reason: "a grant's where reads model-derived path(s) env.class.a: a model may only tighten (move them into tighten[]) (rule 21)",
    });
    expect(decideTighten({ predicates: W('env.class.a'), polarity: 'legacy' })).toEqual({ outcome: 'ok', legacy: true, offending: ['env.class.a'] });
    expect(decideTighten({ predicates: W('env.acc.a'), polarity: 'legacy' })).toEqual({ outcome: 'ok', legacy: false, offending: [] });
    expect(decideTighten({ predicates: W('env.world.w'), single_source: ['w', 5 as never] })).toMatchObject({ outcome: 'deny', offending: ['env.world.w'] });
    expect(decideTighten({})).toEqual({ outcome: 'ok', legacy: false, offending: [] });
  });
  it('rules: reasons, meet, order independence, unknown', () => {
    const r = (id: string, when: object, signal: 'escalate' | 'deny', reason?: string) => ({ id, when, signal, ...(reason ? { reason } : {}) });
    expect(decideTighten({ tighten: [r('a', big, 'escalate')], context: ctx })).toEqual({ outcome: 'escalate', legacy: false, offending: [], reason: "escalate: asked by tighten rule 'a'" });
    expect(decideTighten({ tighten: [r('a', big, 'escalate', 'why')], context: ctx }).reason).toBe("escalate: asked by tighten rule 'a' (why)");
    expect(decideTighten({ tighten: [r('a', big, 'deny')], context: ctx }).reason).toBe("denied by tighten rule 'a'");
    expect(decideTighten({ tighten: [r('a', { ...big, value: 99 }, 'deny')], context: ctx })).toEqual({ outcome: 'ok', legacy: false, offending: [] });
    expect(decideTighten({ tighten: [r('a', { field: 'env.class.none', op: 'eq', value: 1 }, 'deny')], context: ctx })).toEqual({
      outcome: 'escalate', legacy: false, offending: [], reason: "escalate: rule 'a' could not be decided (a value it reads is missing or ill-typed)",
    });
    const esc = r('e', big, 'escalate');
    const den = r('d', { field: 'env.class.tone', op: 'eq', value: 'hostile' }, 'deny');
    expect(decideTighten({ tighten: [esc, den], context: ctx }).outcome).toBe('deny');
    expect(decideTighten({ tighten: [den, esc], context: ctx })).toMatchObject({ outcome: 'deny', reason: "denied by tighten rule 'd'" });
    expect(decideTighten({ tighten: [esc, esc2()], context: ctx }).reason).toBe("escalate: asked by tighten rule 'e'"); // equal rank does not overwrite
    function esc2() { return r('f', big, 'escalate'); }
    expect(decideTighten({ tighten: [r('a', big, 'deny')], context: 'junk' as never }).outcome).toBe('escalate'); // no context: values missing -> unknown
  });
});

describe('decision.ts: decideUnits exact reasons', () => {
  const A = 'action.params.amount';
  const M = { kind: 'money', currency: 'USD', exponent: 2 };
  const base = { schema_units: { m: M, e: { kind: 'money', currency: 'EUR', exponent: 2 } }, verb_params: { [A]: { type: 'integer', unit: 'm' }, 'action.params.note': { type: 'string' } }, verb: 'refund' };
  const run = (o: object) => decideUnits({ ...base, ...o } as never);
  it('success and each refusal', () => {
    expect(run({ units: { [A]: M } })).toEqual({ ok: true });
    expect(run({ units: {} })).toEqual({ ok: true });
    expect(run({ units: { [A]: { ...M, currency: 'EUR' } } })).toEqual({ ok: false, reason: `'${A}' is declared as money/USD/e2 by the action schema but the policy term is tagged money/EUR/e2 (unit confusion)` });
    expect(run({ units: { [A]: { kind: 'money', currency: 'USD' } } })).toEqual({ ok: false, reason: `'${A}' is declared as money/USD/e2 by the action schema but the policy term is tagged money/USD (unit confusion)` });
    expect(run({ units: { 'action.params.note': { kind: 'x' } } })).toEqual({ ok: false, reason: "'action.params.note' is declared as no unit by the action schema but the policy term is tagged x (unit confusion)" });
    expect(run({ units: { 'action.params.other': { kind: 'x' } } })).toEqual({ ok: true });
    expect(run({ units: [] })).toEqual({ ok: false, reason: 'units must be an object' });
    expect(run({ units: {}, verb: '' })).toEqual({ ok: false, reason: 'the verb is missing' });
    expect(run({ units: {}, verb: 5 })).toEqual({ ok: false, reason: 'the verb is missing' });
    expect(run({ units: {}, schema_units: [] })).toEqual({ ok: false, reason: 'the schema units table must be an object' });
    expect(run({ units: {}, schema_units: undefined })).toEqual({ ok: true });
    expect(run({ units: {}, verb_params: undefined })).toEqual({ ok: false, reason: "the schema does not declare verb 'refund'" });
    expect(run({ units: { [A]: M }, schema_units: { m: 5 } })).toMatchObject({ ok: false });
    expect(run({ units: { [A]: M }, verb_params: { [A]: { unit: 'nope' } } })).toMatchObject({ ok: false });
    expect(run({ units: { [A]: M }, verb_params: { [A]: { unit: 'constructor' } } })).toMatchObject({ ok: false }); // own properties only
  });
  const P = (verb: unknown, field: string) => [[{ verb, where: [{ field, op: 'lte', value: 1 }] }]];
  it('untagged terms: scope, nesting, non-param paths, arrays', () => {
    const untagged = { ok: false, reason: `a policy term reads '${A}' (money/USD/e2) without a unit tag` };
    expect(run({ units: {}, predicates: P('refund', A) })).toEqual(untagged);
    expect(run({ units: {}, predicates: P('*', A) })).toEqual(untagged);
    expect(run({ units: {}, predicates: P(['x', 'refund'], A) })).toEqual(untagged);
    expect(run({ units: {}, predicates: P('other', A) })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: P(['x'], A) })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: P(5, A) })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: P('refund', 'action.params.note') })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: P('refund', 'env.acc.x') })).toEqual({ ok: true });
    expect(run({ units: { [A]: M }, predicates: P('refund', A) })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: ['junk', [null, { verb: 'refund' }, { verb: 'refund', where: 'x' }]] })).toEqual({ ok: true });
    expect(run({ units: {}, predicates: [[{ verb: 'refund', where: [{ not: { any_of: [{ field: 'a', op: 'eq', ref: A }] } }] }]] })).toEqual(untagged);
  });
});

const NOW = 1_800_000_000_000;
const k = generateKeyPair();
const pub = encodeKey(k.publicKey);
const dg = (c: string) => b64u(new Uint8Array(32).fill(c.charCodeAt(0)));
const body = (o: Partial<EscalationAnswerBody> = {}): EscalationAnswerBody => ({
  v: 1, kind: 'pca-escalation-answer', principal: pub, policy_digest: dg('a'), action_digest: dg('b'), history_head: dg('c'), decision: 'allow', iat: NOW, expires_at: NOW + 1000, nonce: b64u(new Uint8Array(16).fill(7)), ...o,
});
const bind = { policy_digest: dg('a'), action_digest: dg('b'), history_head: dg('c') };

describe('escalation.ts: exact outcomes', () => {
  const sign = (o: Partial<EscalationAnswerBody> = {}) => signEscalationAnswer(body(o), k.secretKey);
  it('window boundaries are inclusive; one tick outside refuses', () => {
    const a = sign();
    expect(verifyEscalationAnswer(a, [pub], bind, NOW)).toEqual({ ok: true, principal: pub, decision: 'allow' });
    expect(verifyEscalationAnswer(a, [pub], bind, NOW + 1000)).toMatchObject({ ok: true });
    expect(verifyEscalationAnswer(a, [pub], bind, NOW + 1001)).toEqual({ ok: false, reason: 'the answer has expired' });
    expect(verifyEscalationAnswer(a, [pub], bind, NOW - 1)).toEqual({ ok: false, reason: 'the answer is from the future' });
  });
  it('each refusal reason', () => {
    const a = sign();
    expect(verifyEscalationAnswer(a, [pub], bind, 1.5)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    expect(verifyEscalationAnswer({ ...a, v: 2 }, [pub], bind, NOW)).toMatchObject({ ok: false, reason: 'malformed escalation answer: not a pca-escalation-answer v1' });
    expect(verifyEscalationAnswer(a, [], bind, NOW)).toEqual({ ok: false, reason: 'no principal is pinned for escalation answers' });
    expect(verifyEscalationAnswer(a, 'x' as never, bind, NOW)).toEqual({ ok: false, reason: 'no principal is pinned for escalation answers' });
    expect(verifyEscalationAnswer(a, [encodeKey(generateKeyPair().publicKey)], bind, NOW)).toEqual({ ok: false, reason: 'the answering principal is not pinned by this verifier' });
    expect(verifyEscalationAnswer(a, [{ pk: pub }], bind, NOW)).toMatchObject({ ok: true });
    expect(verifyEscalationAnswer({ ...a, decision: 'deny' }, [pub], bind, NOW)).toEqual({ ok: false, reason: 'escalation answer signature invalid' });
    expect(verifyEscalationAnswer(a, [pub], { ...bind, policy_digest: dg('z') }, NOW)).toEqual({ ok: false, reason: 'the answer is bound to another policy' });
    expect(verifyEscalationAnswer(a, [pub], { ...bind, action_digest: dg('z') }, NOW)).toEqual({ ok: false, reason: 'the answer is bound to another action' });
    expect(verifyEscalationAnswer(a, [pub], { ...bind, history_head: dg('z') }, NOW)).toEqual({ ok: false, reason: 'the answer is bound to another state of the history' });
    expect(verifyEscalationAnswer(sign({ decision: 'deny' }), [pub], bind, NOW)).toEqual({ ok: true, principal: pub, decision: 'deny' });
  });
  it('shape errors are exact', () => {
    const a = sign();
    const e = (o: object) => escalationAnswerShapeError({ ...a, ...o });
    expect(escalationAnswerShapeError(a)).toBeNull();
    expect(escalationAnswerShapeError(5)).toBe('not an object');
    expect(e({ extra: 1 })).toBe("unknown member 'answer.extra'");
    expect(e({ kind: 'x' })).toBe('not a pca-escalation-answer v1');
    expect(e({ principal: 'short' })).toBe('principal must be canonical base64url (32 bytes)');
    expect(e({ policy_digest: 'x' })).toBe('policy_digest must be canonical base64url (32 bytes)');
    expect(e({ action_digest: 'x' })).toBe('action_digest must be canonical base64url (32 bytes)');
    expect(e({ history_head: 'x' })).toBe('history_head must be canonical base64url (32 bytes)');
    expect(e({ decision: 'maybe' })).toBe("decision must be 'allow' or 'deny'");
    expect(e({ iat: -1 })).toBe('iat and expires_at must be non-negative safe integers');
    expect(e({ expires_at: 1.5 })).toBe('iat and expires_at must be non-negative safe integers');
    expect(e({ expires_at: NOW })).toBe('expires_at must be greater than iat');
    expect(e({ expires_at: NOW + ESCALATION_MAX_LIFETIME_MS + 1 })).toBe(`an answer lives at most ${ESCALATION_MAX_LIFETIME_MS} ms`);
    expect(e({ expires_at: NOW + ESCALATION_MAX_LIFETIME_MS })).toBeNull();
    expect(e({ nonce: b64u(new Uint8Array(15)) })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(e({ nonce: 5 })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(e({ sig: 5 })).toBe('sig must be a string');
    expect(() => signEscalationAnswer(body({ decision: 'maybe' as never }), k.secretKey)).toThrow("signEscalationAnswer: decision must be 'allow' or 'deny'");
  });
  it('buildEscalationRequest: fields, ttl default and override, reason caps', () => {
    const pcactn = { action: { verb: 'v', resource: 'r' } } as never;
    const grant = { id: 'g' } as never;
    const reasons = Array.from({ length: 20 }, (_, i) => `r${i}${'x'.repeat(600)}`);
    const r = buildEscalationRequest({ aud: 'a', grant, pcactn, lastCounter: 3, reasons, now: NOW });
    expect(r).toMatchObject({ v: 1, kind: 'pca-escalation-request', aud: 'a', verb: 'v', resource: 'r', expires_at: NOW + 3_600_000 });
    expect(r.reasons).toHaveLength(16);
    expect(r.reasons[0]).toHaveLength(512);
    expect(buildEscalationRequest({ aud: undefined, grant, pcactn, lastCounter: undefined, reasons: [], now: NOW, ttlMs: 5 })).toMatchObject({ aud: '', expires_at: NOW + 5, reasons: [] });
    expect(buildEscalationRequest({ aud: 'a', grant, pcactn, lastCounter: 3, reasons: [], now: NOW }).history_head).not.toBe(buildEscalationRequest({ aud: 'a', grant, pcactn, lastCounter: undefined, reasons: [], now: NOW }).history_head);
  });
});
