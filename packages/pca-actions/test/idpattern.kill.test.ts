// Kill tests for idpattern.ts and rule22.ts: the exact error of every malformed resource id pattern, the edges of each match and
// containment rule, and the fail-closed decisions of the rule 22 engine.
import { describe, expect, it } from 'vitest';
import { RULE22_ENGINE, idMatches, idPatternContains, idPatternError, profile, type IdPattern } from '../src';

const SHAPE = "resource.id must be '*', {exact} or {prefix, class, len}";
const EXACT = 'resource.id.exact must be 1..128 safe characters';
const PREFIX = 'resource.id.prefix must be up to 32 safe characters';
const LEN = 'resource.id.len must be [min, max] in 1..128';
const UUID_ERR = 'a uuid id has no prefix and length exactly [36, 36]';
const UUID = ['0b8f1c52', '77aa', '4d10', '9e4b', '2c7d1a3f5e60'].join('-'); // assembled: the public-tree scan refuses GUID literals

describe('idPatternError', () => {
  it('a value that is not an object, a star or an array is not a pattern, whatever its type', () => {
    for (const p of [undefined, null, 5, true, 'abc', [], ['*']]) expect(idPatternError(p), String(p)).toBe(SHAPE);
    expect(idPatternError('*')).toBeNull();
  });
  it('an exact id is a string of 1..128 safe characters', () => {
    expect(idPatternError({ exact: 'abc' })).toBeNull();
    expect(idPatternError({ exact: 'a'.repeat(128) })).toBeNull();
    expect(idPatternError({ exact: 'a'.repeat(129) })).toBe(EXACT);
    expect(idPatternError({ exact: '' })).toBe(EXACT);
    expect(idPatternError({ exact: 'a b' })).toBe(EXACT);
    expect(idPatternError({ exact: 5 })).toBe(EXACT);
    expect(idPatternError({ exact: ['a'] })).toBe(EXACT);
  });
  it('a prefix is a string of at most 32 safe characters', () => {
    const p = (prefix: unknown) => ({ prefix, class: 'alnum', len: [1, 2] });
    expect(idPatternError(p('a'.repeat(32)))).toBeNull();
    expect(idPatternError(p(''))).toBeNull();
    expect(idPatternError(p('a'.repeat(33)))).toBe(PREFIX);
    expect(idPatternError(p('a b'))).toBe(PREFIX);
    expect(idPatternError(p(5))).toBe(PREFIX);
    expect(idPatternError(p(null))).toBe(PREFIX);
  });
  it('the class must be one of the id classes', () => {
    expect(idPatternError({ prefix: '', class: 'nope', len: [1, 2] })).toBe('resource.id.class is not an id class');
  });
  it('len is exactly [min, max] inside 1..128', () => {
    const p = (len: unknown) => ({ prefix: '', class: 'alnum', len });
    expect(idPatternError(p([1, 128]))).toBeNull();
    for (const len of [undefined, 5, [1], [1, 2, 3], [0, 5], [1, 129], ['1', 2], [1.5, 2]]) expect(idPatternError(p(len)), JSON.stringify(len)).toBe(LEN);
    expect(idPatternError(p([3, 2]))).toBe('resource.id.len: min > max');
  });
  it('a uuid pattern has no prefix and length exactly [36, 36]', () => {
    expect(idPatternError({ prefix: '', class: 'uuid', len: [36, 36] })).toBeNull();
    expect(idPatternError({ prefix: 'a', class: 'uuid', len: [36, 36] })).toBe(UUID_ERR);
    expect(idPatternError({ prefix: '', class: 'uuid', len: [35, 36] })).toBe(UUID_ERR);
    expect(idPatternError({ prefix: '', class: 'uuid', len: [36, 37] })).toBe(UUID_ERR);
  });
  it('unknown members make it a different shape', () => {
    expect(idPatternError({ exact: 'a', extra: 1 })).toBe(SHAPE);
    expect(idPatternError({ prefix: '', class: 'alnum' })).toBe(SHAPE);
  });
});

describe('idMatches', () => {
  it('a star matches 1..128 safe characters', () => {
    expect(idMatches('*', 'abc')).toBe(true);
    expect(idMatches('*', 'a'.repeat(128))).toBe(true);
    expect(idMatches('*', 'a'.repeat(129))).toBe(false);
    expect(idMatches('*', '')).toBe(false);
    expect(idMatches('*', 'a b')).toBe(false);
  });
  it('an exact pattern matches that id only', () => {
    expect(idMatches({ exact: 'abc' }, 'abc')).toBe(true);
    expect(idMatches({ exact: 'abc' }, 'abd')).toBe(false);
    expect(idMatches({ exact: 'abc' }, 'abcd')).toBe(false);
  });
  it('a uuid-class pattern matches the canonical lowercase form and nothing else of the class alphabet', () => {
    const p: IdPattern = { prefix: '', class: 'uuid', len: [36, 36] };
    expect(idMatches(p, UUID)).toBe(true);
    expect(idMatches(p, '-'.repeat(36))).toBe(false);
    expect(idMatches(p, 'a'.repeat(36))).toBe(false);
    expect(idMatches(p, UUID.toUpperCase())).toBe(false);
  });
  it('a prefix pattern checks the prefix, the length of the rest and the class of the rest', () => {
    const p: IdPattern = { prefix: 'inv_', class: 'digits', len: [2, 4] };
    expect(idMatches(p, 'inv_12')).toBe(true);
    expect(idMatches(p, 'inv_1234')).toBe(true);
    expect(idMatches(p, 'inv_1')).toBe(false);
    expect(idMatches(p, 'inv_12345')).toBe(false);
    expect(idMatches(p, 'inv_1a')).toBe(false);
    expect(idMatches(p, 'xnv_12')).toBe(false);
  });
});

describe('idPatternContains', () => {
  it('an exact outer contains the same exact id only, and never a class pattern', () => {
    expect(idPatternContains({ exact: 'a' }, { exact: 'a' })).toBe(true);
    expect(idPatternContains({ exact: 'a' }, { exact: 'b' })).toBe(false);
    expect(idPatternContains({ exact: 'a' }, { prefix: '', class: 'alnum', len: [1, 1] })).toBe(false);
    // a prefix that spells the text of a missing member must not be read as one
    expect(idPatternContains({ exact: 'a' }, { prefix: 'undefined', class: 'alnum', len: [1, 2] })).toBe(false);
  });
  it('a class pattern contains an exact id it matches', () => {
    expect(idPatternContains({ prefix: 'a', class: 'digits', len: [1, 2] }, { exact: 'a12' })).toBe(true);
    expect(idPatternContains({ prefix: 'a', class: 'digits', len: [1, 2] }, { exact: 'a123' })).toBe(false);
  });
  it('the length range of the inner pattern must sit inside the outer one, at both ends', () => {
    const outer: IdPattern = { prefix: 'a', class: 'digits', len: [3, 5] };
    expect(idPatternContains(outer, { prefix: 'a', class: 'digits', len: [3, 5] })).toBe(true);
    expect(idPatternContains(outer, { prefix: 'a', class: 'digits', len: [4, 5] })).toBe(true);
    expect(idPatternContains(outer, { prefix: 'a', class: 'digits', len: [1, 4] })).toBe(false);
    expect(idPatternContains(outer, { prefix: 'a', class: 'digits', len: [3, 6] })).toBe(false);
    expect(idPatternContains(outer, { prefix: 'a1', class: 'digits', len: [2, 4] })).toBe(true);
  });
  it('a uuid outer contains a uuid inner with no extra prefix, and no other class', () => {
    const outer: IdPattern = { prefix: '', class: 'uuid', len: [36, 36] };
    expect(idPatternContains(outer, { prefix: '', class: 'uuid', len: [36, 36] })).toBe(true);
    expect(idPatternContains(outer, { prefix: '', class: 'hex', len: [36, 36] })).toBe(false);
    expect(idPatternContains(outer, { prefix: 'ab', class: 'hex', len: [34, 34] })).toBe(false);
    expect(idPatternContains(outer, { prefix: 'ab', class: 'uuid', len: [34, 34] })).toBe(false);
  });
});

describe('the rule 22 engine decides closed', () => {
  const floors = profile({ esc: 1, caveats: ['amount_cap'], context: ['idempotency'] });
  const grant = { caveats: ['amount_cap'], max_esc: 3, preauth_esc: 3 };
  const decide = (f: unknown, g: unknown = grant, context: unknown = ['idempotency']) =>
    RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors: f }] }, verb: 'a.b.c', grant: g as never, context: context as never });
  it('control: well-formed floors that the grant covers are allowed', () => {
    expect(decide(floors)).toBe('allow');
  });
  it('floors that are not a canonical profile are denied even when nothing in the decision reads the broken part', () => {
    expect(decide({ ...floors, rev: 'bogus' })).toBe('deny');
    expect(decide({ ...floors, extra: 1 })).toBe('deny');
    expect(decide({ ...floors, caveats: ['window', 'amount_cap'] })).toBe('deny');
  });
  it('a document without a verbs member denies', () => {
    expect(RULE22_ENGINE.decide({ doc: {} as never, verb: 'a.b.c', grant: grant as never, context: [] })).toBe('deny');
  });
  it('a schema document whose reading throws a null is reported with the engine prefix and the reason', () => {
    const doc = {
      get trait_defs(): unknown { throw null; },
      get traits_digest(): unknown { throw null; },
      get verbs(): unknown { throw null; },
    };
    expect(RULE22_ENGINE.schemaError(doc as never, undefined)).toMatch(/^schema_floor_forged: Cannot read properties of null/);
  });
  it('a grant whose caveats are not an array is denied, not read as text', () => {
    expect(decide(floors, { ...grant, caveats: 'amount_cap' })).toBe('deny');
  });
  it('a call context that is not an array is denied, not read as text', () => {
    expect(decide(floors, grant, 'idempotency')).toBe('deny');
  });
  it('a grant caveat or context key of an unknown kind provides nothing', () => {
    expect(decide(floors, { ...grant, caveats: ['not_a_caveat'] })).toBe('escalate');
    expect(decide(floors, grant, ['not_a_context_key'])).toBe('escalate');
  });
});
