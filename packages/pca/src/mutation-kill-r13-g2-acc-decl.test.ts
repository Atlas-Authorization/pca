/**
 * r13 mutation kills for intent-acc.ts (group g2): accumulator / monitor declarations, selection, values, pre-states and
 * the combine / receipt arithmetic. Until now these were reached only through verifyPCActnCore's happy and specific deny
 * paths, so every other branch (and every error text) was NoCoverage. Each case pins the exact outcome.
 */
import { describe, expect, it } from 'vitest';
import {
  ACC_ID_RE,
  accSelects as accSelects_,
  accValueOf as accValueOf_,
  accumulatorDeclError as accumulatorDeclError_,
  combineAcc as combineAcc_,
  distinctKey as distinctKey_,
  monitorDeclError as monitorDeclError_,
  monitorInitialState as monitorInitialState_,
  monitorStates as monitorStates_,
  preStateError as preStateError_,
  preValue as preValue_,
  receiptArithmeticOk as receiptArithmeticOk_,
  sortedDistinct as sortedDistinct_,
  type AccumulatorDecl,
} from './intent-acc';
import { b64u, sha256, utf8 } from './hash';

// ---- exact outcomes: every call of the module under test is settled, so a thrown error is an outcome compared with
// toEqual (an assertion), never an uncaught error. A throw comes back as { ok: false, error: { name, message } }.
type Settled = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const failed = (e: unknown): Settled => ({ ok: false, error: { name: e instanceof Error ? e.name : typeof e, message: e instanceof Error ? e.message : String(e) } });
const settle = (f: () => unknown): Settled => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return failed(e);
  }
};
const sv = <F extends (...a: never[]) => unknown>(f: F): F =>
  ((...a: Parameters<F>) => {
    const r = settle(() => f(...a));
    return r.ok ? r.value : r;
  }) as unknown as F;
const thrown = (message: string, name = 'Error') => ({ ok: false, error: { name, message } });
const accSelects = sv(accSelects_);
const accValueOf = sv(accValueOf_);
const accumulatorDeclError = sv(accumulatorDeclError_);
const combineAcc = sv(combineAcc_);
const distinctKey = sv(distinctKey_);
const monitorDeclError = sv(monitorDeclError_);
const monitorInitialState = sv(monitorInitialState_);
const monitorStates = sv(monitorStates_);
const preStateError = sv(preStateError_);
const preValue = sv(preValue_);
const receiptArithmeticOk = sv(receiptArithmeticOk_);
const sortedDistinct = sv(sortedDistinct_);

const R32 = b64u(sha256(utf8('r13-g2/root')));
const AT = "accumulator 'a1'";
const B = (): Record<string, unknown> => ({ id: 'a1', agg: 'sum', val: 'action.params.total', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } });
const with_ = (o: Record<string, unknown>) => ({ ...B(), ...o });
const err = (o: Record<string, unknown>) => accumulatorDeclError(with_(o));
const SEQ = { kind: 'sequenced', uri: 'https://seq.example', root: R32 };

describe('accumulatorDeclError', () => {
  it('accepts well-formed declarations of every kind', () => {
    expect(accumulatorDeclError(B())).toBeNull();
    expect(accumulatorDeclError(Object.assign(Object.create(null), B()))).toBeNull();
    expect(err({ unit: 'usd_cents', domain_max: 0, cap: 0 })).toBeNull();
    expect(err({ unit: 'a'.repeat(64) })).toBeNull();
    expect(err({ unit: 'spend.usd_cents' })).toBeNull();
    expect(err({ id: 'A'.repeat(64) })).toBeNull();
    expect(err({ agg: 'count', val: undefined })).toBeNull();
    expect(err({ agg: 'max' })).toBeNull();
    expect(err({ agg: 'distinct' })).toBeNull();
    expect(err({ agg: 'sum', val: undefined, sel: { accumulates_into: 'spend.usd_cents' } })).toBeNull();
    expect(err({ sel: { verbs: Array.from({ length: 64 }, (_, i) => `v${i}`) } })).toBeNull();
    expect(err({ sel: { verbs: ['pay'], accumulates_into: 'spend' } })).toBeNull();
    expect(err({ win: { kind: 'sliding', ms: 1 } })).toBeNull();
    expect(err({ win: { ms: 5, kind: 'sliding' } })).toBeNull();
    expect(err({ win: { kind: 'period', ms: 10, t0: 0 } })).toBeNull();
    expect(err({ win: { t0: 3, ms: 10, kind: 'period' } })).toBeNull();
    expect(err({ key: 'action.params.payee' })).toBeNull();
    expect(err({ holder: SEQ })).toBeNull();
    expect(err({ holder: { ...SEQ, root_alg: 'ml-dsa-65', root_pq_pk: R32, keys_uri: 'https://seq.example/keys' } })).toBeNull();
    for (const event of ['intent_required', 'question', 'clarification']) expect(err({ agg: 'count', val: undefined, sel: { event }, holder: { kind: 'wallet' } })).toBeNull();
    // the wallet branch skips the action-only val rules
    expect(err({ agg: 'max', val: undefined, sel: { event: 'question' }, holder: { kind: 'wallet' } })).toBeNull();
    expect(err({ agg: 'count', sel: { event: 'question' }, holder: { kind: 'wallet' } })).toBeNull();
  });
  it('refuses a non-object', () => {
    for (const x of [null, undefined, [], 'acc', 7, Object.create({ id: 'a1' })]) expect(accumulatorDeclError(x)).toBe('accumulator must be an object');
  });
  it('refuses unknown members and bad ids', () => {
    expect(err({ extra: 1 })).toBe("accumulator: unknown member 'extra'");
    const idMsg = 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
    for (const id of [123, ['a1'], '', 'a-b', 'A'.repeat(65), 'constructor', 'prototype', '__proto__', undefined]) expect(err({ id })).toBe(idMsg);
    expect(ACC_ID_RE.test('a_1')).toBe(true);
  });
  it('refuses agg / val / unit errors with the exact text', () => {
    expect(err({ agg: 'avg' })).toBe(`${AT}: unknown agg`);
    expect(err({ agg: undefined })).toBe(`${AT}: unknown agg`);
    for (const val of [['action.params.total'], 'params.total', 'xaction.params.total', 'action.params.', 'action.params.a-b', 5]) expect(err({ val })).toBe(`${AT}: val must be action.params.<name>`);
    for (const unit of [['usd'], 'USD', 'a'.repeat(65), '', 'a..b', 5]) expect(err({ unit })).toBe(`${AT}: unit must be a unit id`);
  });
  it('refuses selector errors with the exact text', () => {
    for (const sel of [null, [], 'pay']) expect(err({ sel })).toBe(`${AT}: sel must be an object`);
    expect(err({ sel: { verbs: ['pay'], x: 1 } })).toBe(`${AT}: sel has unknown member 'x'`);
    const verbsMsg = `${AT}: sel.verbs must be 1..64 verb names`;
    for (const verbs of ['pay', [], Array.from({ length: 65 }, (_, i) => `v${i}`), [''], [1], ['pay', ''], ['pay', 3], [['pay']], { 0: 'pay', length: 1 }]) expect(err({ sel: { verbs } })).toBe(verbsMsg);
    for (const accumulates_into of [['spend'], 'Spend', '', 7]) expect(err({ sel: { accumulates_into } })).toBe(`${AT}: sel.accumulates_into must be a unit id`);
    for (const event of ['other', '', 3]) expect(err({ sel: { event } })).toBe(`${AT}: unknown sel.event`);
    const kindMsg = `${AT}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind`;
    expect(err({ sel: {} })).toBe(kindMsg);
    expect(err({ sel: { verbs: ['pay'], event: 'question' } })).toBe(kindMsg);
    expect(err({ sel: { accumulates_into: 'spend', event: 'question' } })).toBe(kindMsg);
  });
  it('refuses window errors with the exact text', () => {
    for (const win of [null, [], 'task']) expect(err({ win })).toBe(`${AT}: win must be an object`);
    expect(err({ win: { kind: 'task', ms: 1 } })).toBe(`${AT}: win {kind: task} has no other member`);
    const sl = `${AT}: win sliding needs a positive ms`;
    for (const win of [{ kind: 'sliding' }, { kind: 'sliding', ms: 0 }, { kind: 'sliding', ms: -5 }, { kind: 'sliding', ms: 1.5 }, { kind: 'sliding', ms: '5' }, { kind: 'sliding', ms: 5, t0: 0 }]) expect(err({ win })).toBe(sl);
    const pe = `${AT}: win period needs a positive ms and t0 >= 0`;
    for (const win of [{ kind: 'period', ms: 10 }, { kind: 'period', ms: 0, t0: 0 }, { kind: 'period', ms: -1, t0: 0 }, { kind: 'period', ms: 1.5, t0: 0 }, { kind: 'period', ms: '10', t0: 0 }, { kind: 'period', ms: 10, t0: -1 }, { kind: 'period', ms: 10, t0: 1.5 }, { kind: 'period', ms: 10, t0: -0 }, { kind: 'period', ms: 10, t0: 0, x: 1 }]) expect(err({ win })).toBe(pe);
    for (const win of [{ kind: 'x' }, {}, { kind: 'Task' }]) expect(err({ win })).toBe(`${AT}: unknown win kind`);
  });
  it('refuses key / domain_max / cap errors with the exact text', () => {
    for (const key of [['action.params.k'], 'k', 'xaction.params.k', undefined, 5, 'action.params.k k']) expect(err({ key })).toBe(`${AT}: key must be null or action.params.<name>`);
    for (const domain_max of [-1, 1.5, -0, '3', null]) expect(err({ domain_max })).toBe(`${AT}: domain_max must be a non-negative safe integer`);
    for (const cap of [-1, 1.5, -0, '3', 2 ** 53]) expect(err({ cap })).toBe(`${AT}: cap must be a non-negative safe integer`);
  });
  it('refuses holder errors with the exact text', () => {
    for (const holder of [null, [], 'site_local']) expect(err({ holder })).toBe(`${AT}: holder must be an object`);
    expect(err({ holder: { kind: 'site_local', x: 1 } })).toBe(`${AT}: holder site_local has no other member`);
    expect(err({ agg: 'count', val: undefined, sel: { event: 'question' }, holder: { kind: 'wallet', uri: 'u' } })).toBe(`${AT}: holder wallet has no other member`);
    expect(err({ holder: { ...SEQ, x: 1 } })).toBe(`${AT}: holder sequenced has unknown member 'x'`);
    for (const uri of [undefined, '', 5, []]) expect(err({ holder: { ...SEQ, uri } })).toBe(`${AT}: holder sequenced needs a uri`);
    for (const root of [undefined, 'abc', b64u(new Uint8Array(31))]) expect(err({ holder: { ...SEQ, root } })).toBe(`${AT}: holder.root is not canonical base64url (32 bytes)`);
    expect(err({ holder: { ...SEQ, root_alg: 'x-suite' } })).toBe(`${AT}: holder.root_alg: unsupported_suite: 'x-suite'`);
    expect(err({ holder: { ...SEQ, root_alg: 5 } })).toBe(`${AT}: holder.root_alg: alg must be a string`);
    for (const root_pq_pk of ['!!', 5, 'a']) expect(err({ holder: { ...SEQ, root_pq_pk } })).toBe(`${AT}: holder.root_pq_pk is not canonical base64url`);
    for (const keys_uri of ['', 5, ['k']]) expect(err({ holder: { ...SEQ, keys_uri } })).toBe(`${AT}: holder.keys_uri must be a non-empty string`);
    for (const holder of [{ kind: 'x' }, {}, { kind: 'Sequenced', uri: 'u', root: R32 }]) expect(err({ holder })).toBe(`${AT}: unknown holder kind`);
  });
  it('wallet events are wallet-held, and only they are', () => {
    const msg = `${AT}: wallet events are wallet-held and only wallet events are`;
    expect(err({ agg: 'count', val: undefined, sel: { event: 'question' } })).toBe(msg);
    expect(err({ agg: 'count', val: undefined, sel: { event: 'question' }, holder: SEQ })).toBe(msg);
    expect(err({ holder: { kind: 'wallet' } })).toBe(msg);
  });
  it('action accumulators need val by agg', () => {
    expect(err({ agg: 'max', val: undefined })).toBe(`${AT}: max needs val (or sel.accumulates_into for a sum)`);
    expect(err({ agg: 'sum', val: undefined })).toBe(`${AT}: sum needs val (or sel.accumulates_into for a sum)`);
    expect(err({ agg: 'distinct', val: undefined })).toBe(`${AT}: distinct needs val (or sel.accumulates_into for a sum)`);
    expect(err({ agg: 'max', val: undefined, sel: { accumulates_into: 'spend' } })).toBe(`${AT}: max needs val`);
    expect(err({ agg: 'distinct', val: undefined, sel: { accumulates_into: 'spend' } })).toBe(`${AT}: distinct needs val`);
    expect(err({ agg: 'count' })).toBe(`${AT}: count takes no val`);
    expect(err({ agg: 'count', holder: SEQ })).toBe(`${AT}: count takes no val`);
  });
});

const MB = (): Record<string, unknown> => ({ id: 'm1', kind: 'never', p: { verb: 'pay' } });
const merr = (o: Record<string, unknown>) => monitorDeclError({ ...MB(), ...o });
const MAT = "monitor 'm1'";

describe('monitorDeclError', () => {
  it('accepts well-formed monitors of every kind', () => {
    expect(monitorDeclError(MB())).toBeNull();
    expect(merr({ kind: 'always' })).toBeNull();
    expect(merr({ kind: 'requires_prior', q: { verb: 'b' } })).toBeNull();
    expect(merr({ kind: 'precedes', q: { verb: ['b', 'c'] } })).toBeNull();
    expect(merr({ kind: 'responds_within', q: { verb: 'b' }, within: 1 })).toBeNull();
    expect(merr({ kind: 'responds_within', q: { verb: 'b' }, within: 64 })).toBeNull();
    expect(merr({ status: 'admitted' })).toBeNull();
    expect(merr({ status: 'committed' })).toBeNull();
    expect(merr({ p: { verb: ['a'] } })).toBeNull();
    expect(merr({ p: Object.assign(Object.create(null), { verb: '*' }) })).toBeNull();
  });
  it('refuses a non-object, unknown members and bad ids', () => {
    for (const x of [null, undefined, [], 'm', Object.create({ id: 'm1' })]) expect(monitorDeclError(x)).toBe('monitor must be an object');
    expect(merr({ extra: 1 })).toBe("monitor: unknown member 'extra'");
    const idMsg = 'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
    for (const id of [123, ['m1'], '', 'a b', 'm'.repeat(65), 'prototype', 'constructor', '__proto__']) expect(merr({ id })).toBe(idMsg);
  });
  it('refuses kind / p / q errors with the exact text', () => {
    expect(merr({ kind: 'x' })).toBe(`${MAT}: unknown kind`);
    for (const p of [null, [], 'pay', {}, { verb: 5 }, { verb: [] }, { verb: ['a', 5] }, Object.create({ verb: 'a' })]) expect(merr({ p })).toBe(`${MAT}: p must be a predicate`);
    const qMsg = `${MAT}: q is required exactly for requires_prior / precedes / responds_within`;
    expect(merr({ kind: 'requires_prior' })).toBe(qMsg);
    expect(merr({ kind: 'precedes' })).toBe(qMsg);
    expect(merr({ kind: 'responds_within', within: 3 })).toBe(qMsg);
    expect(merr({ kind: 'never', q: { verb: 'b' } })).toBe(qMsg);
    expect(merr({ kind: 'always', q: { verb: 'b' } })).toBe(qMsg);
    for (const q of [null, { verb: 5 }, { verb: [] }]) expect(merr({ kind: 'precedes', q })).toBe(`${MAT}: q must be a predicate`);
  });
  it('refuses status / within errors with the exact text', () => {
    for (const status of ['x', '', null, 1]) expect(merr({ status })).toBe(`${MAT}: status must be admitted or committed`);
    const wMsg = `${MAT}: within is required exactly for responds_within`;
    expect(merr({ kind: 'responds_within', q: { verb: 'b' } })).toBe(wMsg);
    expect(merr({ kind: 'never', within: 3 })).toBe(wMsg);
    expect(merr({ kind: 'requires_prior', q: { verb: 'b' }, within: 3 })).toBe(wMsg);
    for (const within of [0, 65, 1.5, '3', -1, null]) expect(merr({ kind: 'responds_within', q: { verb: 'b' }, within })).toBe(`${MAT}: within must be an integer in 1..64`);
  });
});

describe('monitor state sets', () => {
  it('monitorStates per kind', () => {
    expect(monitorStates({ kind: 'requires_prior' })).toEqual(['unmet', 'met']);
    expect(monitorStates({ kind: 'precedes' })).toEqual(['unmet', 'met']);
    expect(monitorStates({ kind: 'never' })).toEqual(['clean', 'seen']);
    expect(monitorStates({ kind: 'always' })).toEqual(['ok', 'broken']);
    expect(monitorStates({ kind: 'responds_within', within: 3 })).toEqual(['idle', 'pending:1', 'pending:2', 'pending:3', 'missed']);
    expect(monitorStates({ kind: 'responds_within', within: 1 })).toEqual(['idle', 'pending:1', 'missed']);
    expect(monitorStates({ kind: 'responds_within' })).toEqual(['idle', 'missed']);
    expect(monitorStates({ kind: 'responds_within', within: 1.5 })).toEqual(['idle', 'missed']);
  });
  it('monitorInitialState per kind', () => {
    expect(monitorInitialState({ kind: 'requires_prior' })).toBe('unmet');
    expect(monitorInitialState({ kind: 'precedes' })).toBe('unmet');
    expect(monitorInitialState({ kind: 'never' })).toBe('clean');
    expect(monitorInitialState({ kind: 'always' })).toBe('ok');
    expect(monitorInitialState({ kind: 'responds_within' })).toBe('idle');
  });
});

const SCHEMA = {
  verbs: [
    { verb: 'pay', params: { 'action.params.fee': { type: 'integer', accumulates_into: ['spend'] }, 'action.params.amt': { type: 'integer', accumulates_into: ['spend', 'other'] }, 'action.params.memo': { type: 'string' }, 'action.params.n': { type: 'integer' } } },
    { verb: 'look', params: { 'action.params.q': { type: 'string' }, 'action.params.k': { type: 'integer', accumulates_into: ['other'] } } },
  ],
} as never;
const acc = (o: Partial<AccumulatorDecl>): AccumulatorDecl => ({ id: 'a1', agg: 'sum', val: 'action.params.total', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' }, ...o });

describe('accSelects', () => {
  it('a listed verb, or a verb with a parameter feeding the unit', () => {
    expect(accSelects(acc({}), 'pay')).toBe(true);
    expect(accSelects(acc({}), 'look')).toBe(false);
    expect(accSelects(acc({}), 'look', SCHEMA)).toBe(false);
    expect(accSelects(acc({ sel: { accumulates_into: 'spend' } }), 'pay', SCHEMA)).toBe(true);
    expect(accSelects(acc({ sel: { accumulates_into: 'spend' } }), 'look', SCHEMA)).toBe(false);
    expect(accSelects(acc({ sel: { accumulates_into: 'spend' } }), 'nope', SCHEMA)).toBe(false);
    expect(accSelects(acc({ sel: { accumulates_into: 'spend' } }), 'pay')).toBe(false);
    expect(accSelects(acc({ sel: { verbs: ['look'], accumulates_into: 'spend' } }), 'pay', SCHEMA)).toBe(true);
    expect(accSelects(acc({ sel: { verbs: ['look'], accumulates_into: 'spend' } }), 'look', SCHEMA)).toBe(true);
    expect(accSelects(acc({ sel: { verbs: ['look'] } }), 'pay', SCHEMA)).toBe(false);
  });
  it('without sel.accumulates_into the schema is never consulted', () => {
    const odd = { verbs: [{ verb: 'pay', params: { 'action.params.x': { type: 'integer', accumulates_into: [undefined] } } }] } as never;
    expect(accSelects(acc({ sel: { verbs: ['look'] } }), 'pay', odd)).toBe(false);
  });
  it('a wallet-event selector never selects an action', () => {
    expect(accSelects(acc({ sel: { verbs: ['pay'], event: 'question' } }), 'pay', SCHEMA)).toBe(false);
    expect(accSelects(acc({ sel: { accumulates_into: 'spend', event: 'question' } }), 'pay', SCHEMA)).toBe(false);
  });
});

describe('distinctKey / accValueOf', () => {
  it('distinctKey: canonical text of a string or a safe integer, else null', () => {
    expect(distinctKey('a')).toBe('"a"');
    expect(distinctKey(5)).toBe('5');
    expect(distinctKey(0)).toBe('0');
    for (const x of [-0, 1.5, 2 ** 53, {}, null, true, undefined, ['a'], '\uD800']) expect(distinctKey(x)).toBeNull();
  });
  it('count is 1', () => {
    expect(accValueOf(acc({ agg: 'count', val: undefined }), 'pay', {})).toEqual({ ok: true, val: 1 });
  });
  it('distinct reads a string or safe integer key', () => {
    const d = acc({ agg: 'distinct', val: 'action.params.to' });
    expect(accValueOf(d, 'pay', { to: 'x' })).toEqual({ ok: true, val: 1, key: '"x"' });
    expect(accValueOf(d, 'pay', { to: 7 })).toEqual({ ok: true, val: 1, key: '7' });
    expect(accValueOf(d, 'pay', { to: 1.5 })).toEqual({ ok: false, reason: 'action.params.to must be a string or a safe integer' });
    expect(accValueOf(d, 'pay', {})).toEqual({ ok: false, reason: 'action.params.to must be a string or a safe integer' });
  });
  it('sum / max with val read a non-negative safe integer (own property only)', () => {
    for (const agg of ['sum', 'max'] as const) {
      const a = acc({ agg });
      expect(accValueOf(a, 'pay', { total: 5 })).toEqual({ ok: true, val: 5 });
      expect(accValueOf(a, 'pay', { total: 0 })).toEqual({ ok: true, val: 0 });
      for (const total of [-1, 1.5, '5', -0]) expect(accValueOf(a, 'pay', { total })).toEqual({ ok: false, reason: 'action.params.total must be a non-negative safe integer' });
      expect(accValueOf(a, 'pay', Object.create({ total: 5 }))).toEqual({ ok: false, reason: 'action.params.total must be a non-negative safe integer' });
    }
  });
  it('sum without val adds every present parameter feeding the unit', () => {
    const a = acc({ val: undefined, sel: { accumulates_into: 'spend' } });
    expect(accValueOf(a, 'pay', { amt: 3, fee: 4, n: 100 }, SCHEMA)).toEqual({ ok: true, val: 7 });
    expect(accValueOf(a, 'pay', { amt: 3 }, SCHEMA)).toEqual({ ok: true, val: 3 });
    expect(accValueOf(a, 'pay', { fee: 2 }, SCHEMA)).toEqual({ ok: true, val: 2 });
    expect(accValueOf(a, 'pay', {}, SCHEMA)).toEqual({ ok: true, val: 0 });
    expect(accValueOf(a, 'pay', { amt: -1, fee: 2 }, SCHEMA)).toEqual({ ok: false, reason: 'action.params.amt must be a non-negative safe integer' });
    expect(accValueOf(a, 'pay', { amt: 1, fee: 'x' }, SCHEMA)).toEqual({ ok: false, reason: 'action.params.fee must be a non-negative safe integer' });
    expect(accValueOf(a, 'pay', { amt: Number.MAX_SAFE_INTEGER, fee: 1 }, SCHEMA)).toEqual({ ok: false, reason: 'accumulated value exceeds 2^53-1' });
    expect(accValueOf(a, 'pay', { amt: Number.MAX_SAFE_INTEGER - 1, fee: 1 }, SCHEMA)).toEqual({ ok: true, val: Number.MAX_SAFE_INTEGER });
    expect(accValueOf(a, 'zzz', { amt: 1 }, SCHEMA)).toEqual({ ok: false, reason: "no schema entry for 'zzz' to read accumulates_into" });
    expect(accValueOf(a, 'pay', { amt: 1 })).toEqual({ ok: false, reason: "no schema entry for 'pay' to read accumulates_into" });
  });
});

describe('preStateError', () => {
  it('accepts the shape of each agg', () => {
    expect(preStateError({ agg: 'sum' }, { sum: 0 })).toBeNull();
    expect(preStateError({ agg: 'count' }, { count: 3 })).toBeNull();
    expect(preStateError({ agg: 'max' }, { max: 9 })).toBeNull();
    expect(preStateError({ agg: 'distinct' }, { values: [] })).toBeNull();
    expect(preStateError({ agg: 'distinct' }, { values: ['"a"', '"b"'] })).toBeNull();
    expect(preStateError({ agg: 'sum' }, Object.assign(Object.create(null), { sum: 1 }))).toBeNull();
  });
  it('refuses with the exact text', () => {
    for (const s of [null, [], 5, Object.create({ sum: 1 })]) expect(preStateError({ agg: 'sum' }, s)).toBe('pre-state must be an object');
    expect(preStateError({ agg: 'sum' }, { count: 1 })).toBe('pre-state of a sum accumulator is {sum}');
    expect(preStateError({ agg: 'sum' }, { sum: 1, x: 1 })).toBe('pre-state of a sum accumulator is {sum}');
    expect(preStateError({ agg: 'count' }, { sum: 1 })).toBe('pre-state of a count accumulator is {count}');
    expect(preStateError({ agg: 'max' }, {})).toBe('pre-state of a max accumulator is {max}');
    expect(preStateError({ agg: 'distinct' }, { sum: 0 })).toBe('pre-state of a distinct accumulator is {values}');
    for (const agg of ['sum', 'count', 'max'] as const) for (const v of [-1, 1.5, '1', -0]) expect(preStateError({ agg }, { [agg]: v })).toBe(`pre-state ${agg} must be a non-negative safe integer`);
    for (const values of ['a', [1], ['a', 1], [1, 'a'], null]) expect(preStateError({ agg: 'distinct' }, { values })).toBe('pre-state values must be strings');
    expect(preStateError({ agg: 'distinct' }, { values: ['a', 'b', 'a'] })).toBe('pre-state values must be distinct');
  });
});

describe('combineAcc / preValue / receiptArithmeticOk / sortedDistinct', () => {
  it('combineAcc per agg, null past 2^53-1', () => {
    expect(combineAcc({ agg: 'sum' }, { sum: 5 }, { val: 3 })).toBe(8);
    expect(combineAcc({ agg: 'sum' }, { sum: Number.MAX_SAFE_INTEGER }, { val: 1 })).toBeNull();
    expect(combineAcc({ agg: 'count' }, { count: 2 }, { val: 9 })).toBe(3);
    expect(combineAcc({ agg: 'max' }, { max: 5 }, { val: 3 })).toBe(5);
    expect(combineAcc({ agg: 'max' }, { max: 5 }, { val: 7 })).toBe(7);
    expect(combineAcc({ agg: 'distinct' }, { values: ['"a"', '"c"'] }, { val: 1, key: '"a"' })).toBe(2);
    expect(combineAcc({ agg: 'distinct' }, { values: ['"a"', '"c"'] }, { val: 1, key: '"b"' })).toBe(3);
  });
  it('preValue per agg', () => {
    expect(preValue({ agg: 'sum' }, { sum: 11 })).toBe(11);
    expect(preValue({ agg: 'count' }, { count: 4 })).toBe(4);
    expect(preValue({ agg: 'max' }, { max: 9 })).toBe(9);
    expect(preValue({ agg: 'distinct' }, { values: ['a', 'b', 'c'] })).toBe(3);
  });
  it('receiptArithmeticOk per agg', () => {
    const ok = (agg: 'sum' | 'count' | 'max' | 'distinct', pre: number, delta: number, post: number, val: number) => receiptArithmeticOk({ agg }, { pre, delta, post }, val);
    expect(ok('sum', 2, 3, 5, 3)).toBe(true);
    expect(ok('sum', 2, 4, 6, 3)).toBe(false);
    expect(ok('sum', 2, 3, 6, 3)).toBe(false);
    expect(ok('count', 4, 1, 5, 99)).toBe(true);
    expect(ok('count', 4, 2, 6, 2)).toBe(false);
    expect(ok('count', 4, 2, 5, 2)).toBe(false);
    expect(ok('count', 4, 1, 4, 1)).toBe(false);
    expect(ok('count', 4, 1, 3, 1)).toBe(false);
    expect(ok('max', 5, 3, 5, 3)).toBe(true);
    expect(ok('max', 2, 3, 3, 3)).toBe(true);
    expect(ok('max', 5, 3, 3, 3)).toBe(false);
    expect(ok('max', 2, 3, 2, 3)).toBe(false);
    expect(ok('max', 5, 4, 5, 3)).toBe(false);
    expect(ok('distinct', 4, 0, 4, 1)).toBe(true);
    expect(ok('distinct', 4, 1, 5, 1)).toBe(true);
    expect(ok('distinct', 4, 2, 6, 1)).toBe(false);
    expect(ok('distinct', 4, 1, 4, 1)).toBe(false);
    expect(ok('distinct', 4, 0, 5, 1)).toBe(false);
    expect(ok('distinct', 4, 1, 3, 1)).toBe(false);
  });
  it('sortedDistinct dedupes and sorts by UTF-8 bytes', () => {
    expect(sortedDistinct(['b', 'a', 'b'])).toEqual(['a', 'b']);
    expect(sortedDistinct(new Set(['\u{1F600}', '｡']))).toEqual(['｡', '\u{1F600}']);
    expect(sortedDistinct([])).toEqual([]);
  });
});

