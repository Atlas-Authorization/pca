import { describe, expect, it } from 'vitest';
import { celToCondition, parseCel, type CelSchema } from './index';

const schema: CelSchema = { vars: { s: { path: 'action.params.s', type: 'string' }, n: { path: 'action.params.n', type: 'int' }, b: { path: 'env.b', type: 'bool' }, t: { path: 'env.t', type: 'timestamp_ms' }, o: { path: 'action.params.o', type: 'string', optional: true } } };
const err = (e: string) => { const r = celToCondition(e, schema); if (r.ok) throw new Error(`expected a rejection of ${e}`); return r; };
const ok = (e: string) => { const r = celToCondition(e, schema); if (!r.ok) throw new Error(`${e}: ${r.code} ${r.message}`); return r.condition; };

describe('error offsets and codes are exact', () => {
  it.each([
    ['s == "a" + "b"', 'unsupported', 'arithmetic (+)', 9],
    ['s == "a" ? 1 : 2', 'unsupported', 'the conditional operator', 9],
    ['n > 1.5', 'unsupported', 'double literal', 4],
    ['n > 1u', 'unsupported', 'unsigned integer literal', 4],
    ['n > 0x1', 'unsupported', 'hexadecimal literal', 4],
    ['n > 1e2', 'unsupported', 'double literal', 4],
    ['n > 01', 'unsupported', 'integer literal with a leading zero', 4],
    ['s == "a', 'syntax', 'unterminated string', 5],
    ['s == "a\nb"', 'syntax', 'unterminated string', 5],
    ['s == "\\q"', 'unsupported', 'string escape \\q', 6],
    ['s == "\\', 'unsupported', 'string escape \\', 6],
    ['s ==', 'syntax', 'unexpected end of expression', 4],
    ['s == "a" )', 'syntax', "unexpected ')'", 9],
    ['s == [1', 'syntax', "expected ']'", 7],
    ['has(s', 'syntax', "expected ')'", 5],
    ['s.startsWith("a", "b")', 'syntax', "'startsWith' takes one argument", 2],
    ['s.foo("a")', 'unsupported', "method 'foo'", 2],
    ['s.', 'syntax', "expected a name after '.'", 1],
    ['"a".size', 'unsupported', 'field selection on something that is not a declared variable', 3],
    ['s == $x', 'syntax', "unexpected character '$'", 5],
    ['s == "a" // c', 'unsupported', 'comments', 9],
    ['s[0]', 'unsupported', 'index operator', 1],
    ['null == s', 'unsupported', 'null', 0],
    ['-s == 1', 'unsupported', 'unary minus on a non-literal', 0],
    ['n > -', 'unsupported', 'unary minus on a non-literal', 4],
    ['s in', 'syntax', 'unexpected end of expression', 4],
    ['r"x" == s', 'unsupported', 'raw string literal', 0],
    ['b"x" == s', 'unsupported', 'bytes literal', 0],
    ["s == '''x'''", 'unsupported', 'triple-quoted string', 5],
    ['b @ 1', 'unsupported', '@', 2],
    ['n > 9007199254740992', 'unsupported', 'integer literal outside the safe-integer range', 4],
    ['n > -9007199254740992', 'unsupported', 'integer literal outside the safe-integer range', 4],
    ['unknown_fn(1)', 'unsupported', "unknown function 'unknown_fn'", 0],
    ['size(s) > 1', 'unsupported', "function 'size'", 0],
    ['has(s, s)', 'syntax', 'has() takes one declared variable', 0],
    ['timestamp()', 'unsupported', 'timestamp() of a non-literal', 0],
    ['timestamp("2030-01-01T00:00:00Z", 1) > t', 'unsupported', 'timestamp() of a non-literal', 0],
  ])('%s', (e, code, msg, at) => {
    const r = err(e);
    expect({ code: r.code, message: r.message, at: r.at }).toEqual({ code, message: msg, at });
  });
});

describe('limits are exact', () => {
  it('expression length', () => {
    const pad = (n: number) => `s == "a"${' '.repeat(n)}`;
    expect(celToCondition(pad(4096 - 8), schema).ok).toBe(true);
    expect(celToCondition(pad(4097 - 8), schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'expression longer than 4096 characters', at: 0 });
  });
  it('string literal 256 passes, 257 fails with its offset', () => {
    expect(celToCondition(`s == "${'a'.repeat(256)}"`, schema).ok).toBe(true);
    expect(celToCondition(`s == "${'a'.repeat(257)}"`, schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'string literal longer than 256', at: 5 });
  });
  it('list 64 passes, 65 fails', () => {
    const list = (n: number) => `s in [${Array.from({ length: n }, (_, i) => `"x${i}"`).join(',')}]`;
    expect(celToCondition(list(64), schema).ok).toBe(true);
    expect(celToCondition(list(65), schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'list longer than 64' });
  });
  it('nesting: 32 parentheses pass, 33 fail', () => {
    const nest = (n: number) => `${'('.repeat(n)}n > 1${')'.repeat(n)}`;
    expect(celToCondition(nest(32), schema).ok).toBe(true);
    expect(celToCondition(nest(33), schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'nesting deeper than 32' });
  });
  it('negation depth: 31 pass, 32 fail (the parenthesised operand is one level deeper)', () => {
    expect(celToCondition(`${'!'.repeat(31)}(n > 1)`, schema).ok).toBe(true);
    expect(celToCondition(`${'!'.repeat(32)}(n > 1)`, schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'nesting deeper than 32' });
  });
  it('node count', () => {
    const chain = (k: number) => Array.from({ length: k }, () => 'n > 1').join(' && ');
    expect(celToCondition(chain(60), schema).ok).toBe(true);
    expect(celToCondition(chain(100), schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'more than 256 nodes' });
  });
  it('glob length: contains of 255 plain characters passes, escapes count', () => {
    expect(celToCondition(`s.contains("${'a'.repeat(510)}")`, schema).ok).toBe(false); // string literal limit is 256 first
    expect(celToCondition(`s.contains("${'*'.repeat(256)}")`, schema)).toMatchObject({ ok: false, code: 'too_complex', message: 'literal too long for a glob' });
    expect(celToCondition(`s.contains("${'*'.repeat(255)}")`, schema).ok).toBe(true);
    expect(celToCondition(`s.endsWith("${'*'.repeat(255)}")`, schema).ok).toBe(true);
    expect(celToCondition(`s.endsWith("${'*'.repeat(256)}")`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
  });
});

describe('translation details', () => {
  it('integers: negative literal, zero, the safe-integer edges', () => {
    expect(ok('n == -5')).toEqual({ field: 'action.params.n', op: 'eq', value: -5 });
    expect(ok('n == 0')).toEqual({ field: 'action.params.n', op: 'eq', value: 0 });
    expect(ok('n == -0')).toEqual({ field: 'action.params.n', op: 'eq', value: 0 });
    expect(Object.is((ok('n == -0') as { value: number }).value, 0)).toBe(true);
    expect(ok('n == 9007199254740991')).toEqual({ field: 'action.params.n', op: 'eq', value: 9007199254740991 });
    expect(ok('n == -9007199254740991')).toEqual({ field: 'action.params.n', op: 'eq', value: -9007199254740991 });
  });
  it('strings: every supported escape', () => {
    expect(ok('s == "a\\\\b\\"c\\\'d\\ne\\tf\\rg"')).toEqual({ field: 'action.params.s', op: 'eq', value: 'a\\b"c\'d\ne\tf\rg' });
    expect(ok("s == 'single'")).toEqual({ field: 'action.params.s', op: 'eq', value: 'single' });
    expect(ok("s == 'it\\'s'")).toEqual({ field: 'action.params.s', op: 'eq', value: "it's" });
  });
  it('timestamps: milliseconds, padding and rejection of impossible instants', () => {
    expect(ok('t < timestamp("2030-01-01T00:00:00.5Z")')).toEqual({ field: 'env.t', op: 'lt', value: Date.parse('2030-01-01T00:00:00.500Z') });
    expect(ok('t < timestamp("2030-01-01T00:00:00.05Z")')).toEqual({ field: 'env.t', op: 'lt', value: Date.parse('2030-01-01T00:00:00.050Z') });
    expect(ok('t < timestamp("2030-01-01T00:00:00.123Z")')).toEqual({ field: 'env.t', op: 'lt', value: Date.parse('2030-01-01T00:00:00.123Z') });
    expect(err('t < timestamp("2030-01-01T24:00:00Z")').message).toBe('timestamp() is not a real instant');
    expect(err('t < timestamp("2030-13-01T00:00:00Z")').message).toBe('timestamp() is not a real instant');
    expect(err('t < timestamp("2030-01-01T00:00:00+01:00")').message).toContain('RFC 3339 UTC');
    expect(err('t < timestamp("2030-01-01 00:00:00Z")').message).toContain('RFC 3339 UTC');
  });
  it('relational flipping, var against var, and in-lists of every type', () => {
    expect(ok('1 < n')).toEqual({ field: 'action.params.n', op: 'gt', value: 1 });
    expect(ok('1 <= n')).toEqual({ field: 'action.params.n', op: 'gte', value: 1 });
    expect(ok('1 > n')).toEqual({ field: 'action.params.n', op: 'lt', value: 1 });
    expect(ok('1 >= n')).toEqual({ field: 'action.params.n', op: 'lte', value: 1 });
    expect(ok('1 == n')).toEqual({ field: 'action.params.n', op: 'eq', value: 1 });
    expect(ok('1 != n')).toEqual({ field: 'action.params.n', op: 'ne', value: 1 });
    expect(ok('s != o')).toEqual({ field: 'action.params.s', op: 'ne', ref: 'action.params.o' });
    expect(ok('s < o')).toEqual({ field: 'action.params.s', op: 'lt', ref: 'action.params.o' });
    expect(ok('n in [1, -2, 3]')).toEqual({ field: 'action.params.n', op: 'in', value: [1, -2, 3] });
    expect(ok('b in [true, false]')).toEqual({ field: 'env.b', op: 'in', value: [true, false] });
    expect(ok('b == true')).toEqual({ field: 'env.b', op: 'eq', value: true });
    expect(ok('b != false')).toEqual({ field: 'env.b', op: 'ne', value: false });
    expect(ok('t in [timestamp("2030-01-01T00:00:00Z")]')).toEqual({ field: 'env.t', op: 'in', value: [Date.parse('2030-01-01T00:00:00Z')] });
  });
  it('and / or flatten across nesting but keep grouping across the other operator', () => {
    expect(ok('n > 1 && n > 2 && n > 3')).toEqual({ all_of: [{ field: 'action.params.n', op: 'gt', value: 1 }, { field: 'action.params.n', op: 'gt', value: 2 }, { field: 'action.params.n', op: 'gt', value: 3 }] });
    expect(ok('n > 1 || (n > 2 || n > 3)')).toEqual({ any_of: [{ field: 'action.params.n', op: 'gt', value: 1 }, { field: 'action.params.n', op: 'gt', value: 2 }, { field: 'action.params.n', op: 'gt', value: 3 }] });
    expect(ok('n > 1 && n > 2 || n > 3')).toEqual({ any_of: [{ all_of: [{ field: 'action.params.n', op: 'gt', value: 1 }, { field: 'action.params.n', op: 'gt', value: 2 }] }, { field: 'action.params.n', op: 'gt', value: 3 }] });
    expect(ok('!(n > 1)')).toEqual({ not: { field: 'action.params.n', op: 'gt', value: 1 } });
  });
  it('type errors name both types and the glob escapes', () => {
    expect(err('n == "a"').message).toBe('int against string');
    expect(err('s < true').message).toBe('string against bool');
    expect(err('1 < 2').code).toBe('constant_expression');
    expect(err('"a" in s').code).toBe('constant_expression');
    expect(err('n in [1, "a"]').message).toBe('list items must be int literals');
    expect(err('n in [n]').message).toBe('list items must be int literals');
    expect(err('s.startsWith(1)').message).toBe('startsWith of anything but a non-empty string literal');
    expect(err('n.startsWith("a")').message).toBe('startsWith needs a string variable');
    expect(err('"a".startsWith("a")').message).toBe('startsWith needs a string variable');
    expect(ok('s.contains("a?b\\\\c*")')).toEqual({ field: 'action.params.s', op: 'like', value: '*a\\?b\\\\c\\**' });
    expect(err('s').message).toBe("a bare variable 's' as a condition");
    expect(err('b').message).toBe("a bare variable 'b' as a condition (write b == true)");
    expect(err('has(o) == true').code).toBe('unsupported');
    expect(err('has(s)').code).toBe('has_requires_optional');
    expect(ok('has(o)')).toEqual({ field: 'action.params.o', op: 'exists', value: true });
  });
  it('schema validation messages', () => {
    const bad = (s: unknown) => celToCondition('b == true', s as never);
    expect(bad(null)).toMatchObject({ code: 'bad_schema', message: 'the schema must be an object' });
    expect(bad([])).toMatchObject({ code: 'bad_schema', message: 'the schema must be an object' });
    expect(bad({})).toMatchObject({ message: 'the schema needs a vars object' });
    expect(bad({ vars: [] })).toMatchObject({ message: 'the schema needs a vars object' });
    expect(bad({ vars: { 'a.__proto__': { path: 'env.a', type: 'bool' } } })).toMatchObject({ message: "bad variable name 'a.__proto__'" });
    expect(bad({ vars: { a: null } })).toMatchObject({ message: "variable 'a' needs a path rooted at action, subject or env" });
    expect(bad({ vars: { a: { path: 'env', type: 'bool' } } })).toMatchObject({ message: "variable 'a' needs a path rooted at action, subject or env" });
    expect(bad({ vars: { a: { path: 'env.a', type: 'float' } } })).toMatchObject({ message: "variable 'a' has an unsupported type" });
    expect(bad({ vars: { a: { path: 'env.a', type: 'bool', optional: 1 } } })).toMatchObject({ message: "variable 'a': optional must be a boolean" });
    expect(bad({ vars: { b: { path: 'env.b', type: 'bool', optional: false } } }).ok).toBe(true);
  });
  it('parseCel exposes the tree and positions', () => {
    const p = parseCel('n > 1');
    expect(p).toEqual({ ok: true, ast: { t: 'rel', op: '>', l: { t: 'var', name: 'n', at: 0 }, r: { t: 'int', v: 1, at: 4 }, at: 2 } });
    expect(parseCel('')).toMatchObject({ ok: false, code: 'syntax', message: 'empty expression', at: 0 });
    expect(parseCel(5 as never)).toMatchObject({ ok: false, code: 'syntax' });
  });
});
