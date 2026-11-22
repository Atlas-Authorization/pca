import { describe, expect, it } from 'vitest';
import { paramsDigest } from '@atlasauth/pca';
import { ActionKitError, approverRenderCheck, renderApproval, renderDigestForAction, renderersFromDefs, type ActionDef } from '../src';
import { FIXED, TRANSFER } from './vectors-approval';

const err = (f: () => unknown): { code: string; message: string } => {
  try { f(); } catch (e) { return e instanceof ActionKitError ? { code: e.code, message: e.message } : { code: 'other', message: String(e) }; }
  return { code: 'no error', message: '' };
};
const one = (type: string, unit?: unknown): ActionDef => ({ ...TRANSFER, verb: 'test.one.param', params: { p: { type, ...(unit ? { unit } : {}) } } }) as unknown as ActionDef;
const accepts = (type: string, v: unknown): boolean => err(() => renderApproval(one(type), { p: v })).code === 'no error';
const ok = { amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
const LONE = '\ud800';

describe('renderApproval value domain, per declared type', () => {
  it('integer and duration', () => {
    for (const t of ['integer', 'duration']) {
      for (const v of [0, 5, -3, 2 ** 53 - 1]) expect(accepts(t, v), `${t} ${String(v)}`).toBe(true);
      for (const v of ['5', 1.5, -0, null, true, 2 ** 53, NaN, undefined]) expect(accepts(t, v), `${t} ${String(v)}`).toBe(false);
    }
  });
  it('boolean', () => {
    expect(accepts('boolean', true)).toBe(true);
    expect(accepts('boolean', false)).toBe(true);
    for (const v of ['true', 1, 0, null]) expect(accepts('boolean', v)).toBe(false);
  });
  it('string, date, datetime and object_ref', () => {
    for (const t of ['string', 'date', 'datetime', 'object_ref']) {
      for (const v of ['x', '']) expect(accepts(t, v), t).toBe(true);
      for (const v of [5, LONE, null, ['x'], true]) expect(accepts(t, v), t).toBe(false);
    }
  });
  it('set and array', () => {
    for (const t of ['set', 'array']) {
      for (const v of [[], ['a', 1, true, 0, ['b', [2]]], [[]]]) expect(accepts(t, v), t).toBe(true);
      for (const v of ['x', null, 5, true, {}, [LONE], [1.5], [-0], [null], [{}], ['ok', 1.5], [['a', LONE]], ['ok', 'also', null]]) expect(accepts(t, v), `${t} ${JSON.stringify(v)}`).toBe(false);
    }
  });
  it('an unknown declared type accepts nothing', () => {
    for (const v of ['x', 1, true, [], null]) expect(accepts('weird', v)).toBe(false);
  });
  it('the bad-value error names the field and the type', () => {
    expect(err(() => renderApproval(one('integer'), { p: 'x' }))).toEqual({
      code: 'render_bad_value', message: "'p' is not a integer in the canonical domain (no floats, no null, no lone surrogates)",
    });
  });
});

describe('renderApproval params shape and flattening', () => {
  it('refuses a non-object params with the exact message', () => {
    for (const p of [null, 5, 'str', []]) expect(err(() => renderApproval(TRANSFER, p as never)), String(p)).toEqual({ code: 'render_bad_params', message: 'params must be an object' });
  });
  it('refuses a dotted key, top level and nested, with the exact message', () => {
    expect(err(() => renderApproval(FIXED, { 'to.iban': 'x' }))).toEqual({ code: 'render_bad_params', message: "the parameter key 'to.iban' contains a dot" });
    expect(err(() => renderApproval(FIXED, { to: { 'x.y': 1 } }))).toEqual({ code: 'render_bad_params', message: "the parameter key 'x.y' contains a dot" });
  });
  it('reports undeclared and missing parameters with the exact messages', () => {
    expect(err(() => renderApproval(TRANSFER, { ...ok, hidden: 1 }))).toEqual({ code: 'render_undeclared_param', message: "'hidden' is not a parameter of bank.transfer.send" });
    expect(err(() => renderApproval(TRANSFER, { amount: 5, currency: 'EUR' }))).toEqual({ code: 'render_missing_param', message: "required parameter 'payee' of bank.transfer.send is missing" });
  });
  it('flattens exactly MAX_PARAM_PATH_DEPTH segments; deeper objects are leaves', () => {
    const def = { ...TRANSFER, verb: 'test.deep.param', params: { 'a.b.c': { type: 'string' } } } as unknown as ActionDef;
    expect(renderApproval(def, { a: { b: { c: 'x' } } }).fields).toEqual([{ id: 'a.b.c', class: 'param', value: 'x' }]);
    expect(err(() => renderApproval(def, { a: { b: { c: { d: 1 } } } })).code).toBe('render_bad_value');
  });
  it('an empty object is a leaf, not nothing', () => {
    expect(err(() => renderApproval(one('string'), { p: {} })).code).toBe('render_bad_value');
  });
  it('an undefined value is a bad value, not a crash', () => {
    expect(err(() => renderApproval(one('string'), { p: undefined })).code).toBe('render_bad_value');
  });
  it('an empty top-level key does not add a leading dot to nested keys', () => {
    const def = { ...TRANSFER, verb: 'test.empty.key', params: { payee: { type: 'string' } } } as unknown as ActionDef;
    expect(renderApproval(def, { '': { payee: 'x' } }).fields).toEqual([{ id: 'payee', class: 'param', value: 'x' }]);
  });
  it('sorts fields by code unit order', () => {
    const def = { ...TRANSFER, verb: 'test.sort.param', params: { b: { type: 'integer' }, a: { type: 'integer' }, c: { type: 'integer' }, B: { type: 'integer' } } } as unknown as ActionDef;
    expect(renderApproval(def, { c: 3, b: 2, B: 4, a: 1 }).fields.map((f) => f.id)).toEqual(['B', 'a', 'b', 'c']);
  });
});

describe('renderApproval units', () => {
  it('a non-money unit renders as its bare kind', () => {
    expect(renderApproval(one('integer', { kind: 'count' }), { p: 3 }).fields).toEqual([{ id: 'p', class: 'param', value: 3, unit: { kind: 'count' } }]);
  });
  it('an unresolved or empty currency is refused with the exact message', () => {
    const msg = "the currency of 'amount' is not a string";
    expect(err(() => renderApproval(TRANSFER, { amount: 5, currency: 9, payee: 'x' }))).toEqual({ code: 'render_unresolved_currency', message: msg });
    expect(err(() => renderApproval(TRANSFER, { amount: 5, currency: '', payee: 'x' }))).toEqual({ code: 'render_unresolved_currency', message: msg });
  });
});

describe('verifier and approver checks', () => {
  const conf = { attestationVerified: () => true };
  it('exact messages for verb, params and render mismatch', () => {
    const a = { action: { verb: 'bank.transfer.send', params_digest: paramsDigest(ok) } };
    expect(err(() => renderDigestForAction(TRANSFER, ok, { action: { ...a.action, verb: 'bank.transfer.eur' } }, conf))).toEqual({
      code: 'render_verb_mismatch', message: "the PCActn is for 'bank.transfer.eur', the definition for 'bank.transfer.send'",
    });
    expect(err(() => renderDigestForAction(TRANSFER, { ...ok, amount: 1 }, a, conf))).toEqual({
      code: 'render_params_mismatch', message: 'the supplied params are not the params the PCActn signed',
    });
    expect(err(() => approverRenderCheck(TRANSFER, ok, 'AAAA', conf))).toEqual({
      code: 'render_mismatch', message: 'the approval request commits to a render this definition and these params do not produce',
    });
  });
});

describe('renderersFromDefs', () => {
  const B = { ...FIXED, aliases: ['bank.transfer.send', 'pay'] } as ActionDef;
  const fixedParams = { amount: 1, to: { iban: 'DE89370400440532013000' } };
  it('finds a definition by verb or alias, and a real verb is never shadowed by another definition alias', () => {
    const r = renderersFromDefs([TRANSFER, B]);
    expect(r('bank.transfer.send', 'res', ok).verb).toBe('bank.transfer.send');
    expect(r('bank.transfer.eur', 'res', fixedParams).verb).toBe('bank.transfer.eur');
    expect(r('pay', 'res', fixedParams).verb).toBe('bank.transfer.eur');
    expect(renderersFromDefs([B, TRANSFER])('bank.transfer.send', 'res', ok).verb).toBe('bank.transfer.send');
  });
  it('an unknown verb throws render_unknown_verb with the exact message', () => {
    const r = renderersFromDefs([TRANSFER]);
    expect(err(() => r('nope.x.y', 'res', ok))).toEqual({ code: 'render_unknown_verb', message: "no pinned action definition for 'nope.x.y'" });
    expect(err(() => r('Stryker was here', 'res', ok)).code).toBe('render_unknown_verb');
  });
  it('missing params default to an empty object', () => {
    expect(err(() => renderersFromDefs([TRANSFER])('bank.transfer.send', 'res', undefined)).code).toBe('render_missing_param');
  });
});
