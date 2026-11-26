import { describe, expect, it } from 'vitest';
import { validateDef } from '../src';
import { MAX_DESCRIPTION_BYTES } from '../src/def';
import { isFormat, isRole, jsonProfileError, paramNameError } from '../src/validate';

type Json = Record<string, unknown>;

const BASE: Json = {
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
  resource: { type: 'acme.invoice', id: '*', scope: 'tenant' }, params: {}, review: { state: 'authored' },
};
const perr = (decl: unknown): string | null => validateDef({ ...BASE, params: { p: decl, amount: { type: 'integer' } } });
const berr = (b: unknown): string | null => validateDef({ ...BASE, bindings: b });
const strs = (n: number): string[] => Array.from({ length: n }, (_, i) => `v${i}`);
// a key whose value is `undefined` is dropped, since JSON has no undefined
const money = (u: Json): Json => {
  const unit: Json = { kind: 'money', ccy: 'USD', exp: 2, ...u };
  for (const k of Object.keys(unit)) if (unit[k] === undefined) delete unit[k];
  return { type: 'integer', unit };
};

describe('json profile and format guards', () => {
  it('refuses a value that is not JSON with the exact reason', () => {
    expect(jsonProfileError(new Date())).toBe('only JSON values are allowed');
  });
  it('a format must be a string, not something that prints like one', () => {
    expect(isFormat(['id:abc'])).toBe(false);
    expect(isFormat('id:abc')).toBe(true);
    expect(isFormat('email')).toBe(true);
  });
});

const cases: [string, unknown, string | null][] = [
  // values
  ['values not an array', { type: 'string', values: 'abc' }, 'p: values must be 1..256 non-empty strings'],
  ['values empty', { type: 'string', values: [] }, 'p: values must be 1..256 non-empty strings'],
  ['values 257', { type: 'string', values: strs(257) }, 'p: values must be 1..256 non-empty strings'],
  ['values 256', { type: 'string', values: strs(256) }, null],
  ['values with an empty string', { type: 'string', values: ['a', ''] }, 'p: values must be 1..256 non-empty strings'],
  ['values duplicated', { type: 'string', values: ['a', 'a'] }, 'p: values must be distinct'],
  ['values on an integer', { type: 'integer', values: ['a'] }, 'p: values apply to string and set only'],
  ['set with values', { type: 'set', values: ['a'] }, null],
  // min / max
  ['array of integers takes min', { type: 'array', items: 'integer', min: 1 }, null],
  ['array of strings refuses min', { type: 'array', items: 'string', min: 1 }, 'p: min must be a safe integer on an integer parameter'],
  ['a string with integer items refuses min', { type: 'string', items: 'integer', min: 1 }, 'p: min must be a safe integer on an integer parameter'],
  ['array without items refuses max', { type: 'array', max: 1 }, 'p: max must be a safe integer on an integer parameter'],
  ['duration takes max', { type: 'duration', max: 5 }, null],
  ['min not an integer', { type: 'integer', min: 'x' }, 'p: min must be a safe integer on an integer parameter'],
  ['max not an integer', { type: 'integer', max: 'x' }, 'p: max must be a safe integer on an integer parameter'],
  ['min on a string', { type: 'string', min: 1 }, 'p: min must be a safe integer on an integer parameter'],
  ['max on a string', { type: 'string', max: 1 }, 'p: max must be a safe integer on an integer parameter'],
  ['min equals max', { type: 'integer', min: 3, max: 3 }, null],
  ['min above max', { type: 'integer', min: 4, max: 3 }, 'p: min > max'],
  // max_len
  ['max_len not an integer', { type: 'string', max_len: 'x' }, 'p: max_len must be 1..16777216 on a string or array'],
  ['max_len zero', { type: 'string', max_len: 0 }, 'p: max_len must be 1..16777216 on a string or array'],
  ['max_len one', { type: 'string', max_len: 1 }, null],
  ['max_len top', { type: 'string', max_len: 16_777_216 }, null],
  ['max_len above top', { type: 'string', max_len: 16_777_217 }, 'p: max_len must be 1..16777216 on a string or array'],
  ['max_len on an integer', { type: 'integer', max_len: 5 }, 'p: max_len must be 1..16777216 on a string or array'],
  ['max_len on an array', { type: 'array', max_len: 5 }, null],
  ['max_len on an object_ref', { type: 'object_ref', max_len: 5 }, null],
  // items
  ['items on a string', { type: 'string', items: 'string' }, 'p: items applies to array only'],
  ['items not a string', { type: 'array', items: 5 }, 'p: items applies to array only'],
  ['items on an array', { type: 'array', items: 'string' }, null],
  // min_items / max_items
  ['min_items negative', { type: 'array', min_items: -1 }, 'p: min_items must be a non-negative integer on a set or array'],
  ['min_items not a number', { type: 'array', min_items: 'x' }, 'p: min_items must be a non-negative integer on a set or array'],
  ['max_items negative', { type: 'array', max_items: -1 }, 'p: max_items must be a non-negative integer on a set or array'],
  ['min_items zero', { type: 'array', min_items: 0 }, null],
  ['min_items on a set', { type: 'set', values: ['a'], min_items: 1 }, null],
  ['max_items on a set', { type: 'set', values: ['a'], max_items: 1 }, null],
  ['min_items on an array', { type: 'array', min_items: 1 }, null],
  ['min_items on a string', { type: 'string', min_items: 1 }, 'p: min_items must be a non-negative integer on a set or array'],
  ['max_items on an integer', { type: 'integer', max_items: 1 }, 'p: max_items must be a non-negative integer on a set or array'],
  ['min_items equals max_items', { type: 'array', min_items: 2, max_items: 2 }, null],
  ['min_items above max_items', { type: 'array', min_items: 3, max_items: 2 }, 'p: min_items > max_items'],
  // format
  ['known format on a string', { type: 'string', format: 'email' }, null],
  ['known format on an object_ref', { type: 'object_ref', format: 'email' }, null],
  ['known format on an integer', { type: 'integer', format: 'email' }, 'p: format must be a known format on a string parameter'],
  ['unknown format', { type: 'string', format: 'nope' }, 'p: format must be a known format on a string parameter'],
  // unit
  ['unit not an object', { type: 'integer', unit: 'x' }, 'p: unit.kind is not a known kind'],
  ['unit without kind', { type: 'integer', unit: {} }, 'p: unit.kind is not a known kind'],
  ['unit unknown kind', { type: 'integer', unit: { kind: 'bogus' } }, 'p: unit.kind is not a known kind'],
  ['money exact', money({}), null],
  ['money extra member', money({ zzz: 1 }), 'p: unit has unknown members'],
  ['money exp missing', money({ exp: undefined }), 'p: unit.exp must be an integer in 0..18'],
  ['money exp not a number', money({ exp: 'x' }), 'p: unit.exp must be an integer in 0..18'],
  ['money exp negative', money({ exp: -1 }), 'p: unit.exp must be an integer in 0..18'],
  ['money exp zero', money({ exp: 0 }), null],
  ['money exp 18', money({ exp: 18 }), null],
  ['money exp 19', money({ exp: 19 }), 'p: unit.exp must be an integer in 0..18'],
  ['money ccy lowercase', money({ ccy: 'usd' }), 'p: unit.ccy must be an ISO 4217 style code'],
  ['money ccy with a prefix', money({ ccy: 'XUSD' }), 'p: unit.ccy must be an ISO 4217 style code'],
  ['money ccy with a suffix', money({ ccy: 'USDX' }), 'p: unit.ccy must be an ISO 4217 style code'],
  ['money ccy from a parameter', money({ ccy: { from: 'amount' } }), null],
  ['money ccy from an undeclared parameter', money({ ccy: { from: 'nope' } }), 'p: unit.ccy.from must name a declared parameter'],
  ['money ccy from with another member', money({ ccy: { from: 'amount', extra: 1 } }), 'p: unit.ccy.from must name a declared parameter'],
  ['money ccy empty object', money({ ccy: {} }), 'p: unit.ccy.from must name a declared parameter'],
  ['money ccy null', money({ ccy: null }), 'p: unit.ccy.from must name a declared parameter'],
  ['money ccy a number', money({ ccy: 5 }), 'p: unit.ccy.from must name a declared parameter'],
  ['money ccy missing', money({ ccy: undefined }), 'p: unit.ccy.from must name a declared parameter'],
  ['count unit exact', { type: 'integer', unit: { kind: 'count' } }, null],
  ['count unit extra member', { type: 'integer', unit: { kind: 'count', zzz: 1 } }, 'p: unit has unknown members'],
  // tags
  ['tags not an array', { type: 'string', tags: 'abc' }, 'p: tags must be distinct known tags'],
  ['tags duplicated', { type: 'string', tags: ['pii', 'pii'] }, 'p: tags must be distinct known tags'],
  ['tags unknown', { type: 'string', tags: ['nope'] }, 'p: tags must be distinct known tags'],
  ['tags every known one', { type: 'string', tags: ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'] }, null],
];

describe('param declarations: each refusal is exact', () => {
  it.each(cases)('%s', (_label, decl, want) => {
    expect(perr(decl)).toBe(want);
  });
});

describe('bindings: each refusal is exact', () => {
  it('bindings must be an object', () => {
    expect(berr('x')).toBe('bindings must be an object');
  });
  it('a kind takes only its own members', () => {
    for (const k of ['mcp', 'http', 'graphql', 'grpc', 'asyncapi']) {
      expect(berr({ [k]: { 'Stryker was here': 'x' } })).toBe(`bindings.${k}: unknown member 'Stryker was here'`);
    }
    expect(berr({ mcp: { tool: 't', extra: 'x' } })).toBe("bindings.mcp: unknown member 'extra'");
  });
  it('a kind body must be an object', () => {
    expect(berr({ mcp: 'x' })).toBe('bindings.mcp must be an object');
  });
  it('required members are non-empty strings', () => {
    expect(berr({ mcp: {} })).toBe('bindings.mcp.tool must be a non-empty string');
    expect(berr({ http: { method: 'GET', path: '' } })).toBe('bindings.http.path must be a non-empty string');
  });
  it('optional members, when present, are non-empty strings', () => {
    expect(berr({ openapi: { operationId: 'o' } })).toBeNull();
    expect(berr({ openapi: { operationId: 'o', method: 'GET', path: '/x' } })).toBeNull();
    expect(berr({ openapi: { operationId: 'o', method: '' } })).toBe('bindings.openapi.method must be a non-empty string');
    expect(berr({ openapi: { operationId: 'o', path: 5 } })).toBe('bindings.openapi.path must be a non-empty string');
  });
  it('graphql and asyncapi ops are checked', () => {
    for (const op of ['query', 'mutation', 'subscription']) expect(berr({ graphql: { op, field: 'f' } })).toBeNull();
    expect(berr({ graphql: { op: 'bogus', field: 'f' } })).toBe('bindings.graphql.op is not a GraphQL operation kind');
    for (const op of ['send', 'receive']) expect(berr({ asyncapi: { channel: 'c', op } })).toBeNull();
    expect(berr({ asyncapi: { channel: 'c', op: 'bogus' } })).toBe('bindings.asyncapi.op must be send or receive');
  });
});

const ACC = 'p: accumulates must be 1..8 distinct unit ids';
const acc = (a: unknown): Json => ({ type: 'integer', accumulates: a });
const more: [string, unknown, string | null][] = [
  ['unknown member', { type: 'string', zzz: 1 }, "p: unknown member 'zzz'"],
  ['unknown type', { type: 'nope' }, 'p: unknown type'],
  ['required not a boolean', { type: 'string', required: 'x' }, 'p: required must be a boolean'],
  ['required boolean', { type: 'string', required: false }, null],
  ['a set needs values', { type: 'set' }, 'p: a set needs values'],
  ['unknown provenance_min', { type: 'string', provenance_min: 'nope' }, 'p: unknown provenance_min'],
  ['known provenance_min', { type: 'string', provenance_min: 'tool' }, null],
  ['unknown sensitivity', { type: 'string', sensitivity: 'nope' }, 'p: unknown sensitivity'],
  ['known sensitivity', { type: 'string', sensitivity: 'critical' }, null],
  // accumulates
  ['accumulates on a string', { type: 'string', accumulates: ['a'] }, 'p: accumulates applies to integer parameters only'],
  ['accumulates on an integer', acc(['a.b_1', '0']), null],
  ['accumulates 8 ids', acc(strs(8)), null],
  ['accumulates 9 ids', acc(strs(9)), ACC],
  ['accumulates empty', acc([]), ACC],
  ['accumulates a string', acc('abc'), ACC],
  ['accumulates an object', acc({}), ACC],
  ['accumulates a number entry', acc([5]), ACC],
  ['accumulates an array entry', acc([['ab']]), ACC],
  ['accumulates id of 64', acc(['a'.repeat(64)]), null],
  ['accumulates id of 65', acc(['a'.repeat(65)]), ACC],
  ['accumulates uppercase', acc(['A']), ACC],
  ['accumulates hyphen inside', acc(['a-b']), ACC],
  ['accumulates hyphen after', acc(['a-']), ACC],
  ['accumulates hyphen before', acc(['-a']), ACC],
  ['accumulates leading dot', acc(['.a']), ACC],
  ['accumulates trailing dot', acc(['a.']), ACC],
  ['accumulates empty segment', acc(['a..b']), ACC],
  ['accumulates duplicate', acc(['a', 'a']), ACC],
  ['accumulates one bad of two', acc(['a', 'A']), ACC],
  // default
  ['default null', { type: 'string', default: null }, 'p: default must not be null (absent = no default)'],
  ['principal_neutral_default not a boolean', { type: 'string', principal_neutral_default: 'x' }, 'p: principal_neutral_default must be a boolean'],
  ['principal_neutral_default false without a default', { type: 'string', principal_neutral_default: false }, null],
  ['principal_neutral_default true without a default', { type: 'string', principal_neutral_default: true }, 'p: principal_neutral_default needs a default'],
  ['principal_neutral_default true with a default', { type: 'string', principal_neutral_default: true, default: 'a' }, null],
  // description
  ['description empty', { type: 'string', description: '' }, `p: description must be a string up to ${MAX_DESCRIPTION_BYTES} bytes`],
  ['description at the limit', { type: 'string', description: 'x'.repeat(MAX_DESCRIPTION_BYTES) }, null],
  ['description over the limit', { type: 'string', description: 'x'.repeat(MAX_DESCRIPTION_BYTES + 1) }, `p: description must be a string up to ${MAX_DESCRIPTION_BYTES} bytes`],
];

describe('param declarations: the remaining members are exact', () => {
  it.each(more)('%s', (_label, decl, want) => {
    expect(perr(decl)).toBe(want);
  });
  it('a member name that is not NFC or has a lone surrogate is refused', () => {
    expect(jsonProfileError({ 'e\u0301': 1 })).toBe('member name is not NFC / has a lone surrogate');
    expect(jsonProfileError({ '\ud800': 1 })).toBe('member name is not NFC / has a lone surrogate');
    expect(jsonProfileError({ 'caf\u00e9': 1 })).toBeNull();
  });
});

describe('role and param name guards', () => {
  it('a role must be a string, not something that prints like one', () => {
    expect(isRole(['id.abc'])).toBe(false);
    expect(isRole('id.abc')).toBe(true);
    expect(perr({ type: 'string', role: ['id.abc'] })).toBe('p: unknown role');
  });
  it('a dotted name is reserved when any one segment is reserved', () => {
    for (const n of ['a.constructor', 'constructor.a', 'a.__proto__.b', 'prototype.x']) {
      expect(paramNameError(n)).toBe(`param name '${n}' is reserved`);
    }
    expect(paramNameError('a.b.c')).toBeNull();
  });
});
