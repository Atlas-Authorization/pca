import { describe, expect, it } from 'vitest';
import { evaluateConditionTri, type ActionContext } from '@atlasauth/pca';
import { celConditionsToPca, celToCondition, celToPredicate, parseCel, decide, type CelNode, type CelSchema } from './index';

const schema: CelSchema = {
  vars: {
    'resource.name': { path: 'action.params.name', type: 'string' },
    'object.spec.replicas': { path: 'action.params.count', type: 'int' },
    'request.flag': { path: 'env.flag', type: 'bool' },
    'request.time': { path: 'env.now', type: 'timestamp_ms' },
    'resource.tag': { path: 'action.params.opt', type: 'string', optional: true },
    'principal.org': { path: 'subject.other', type: 'string' },
  },
};
const T = Date.parse('2030-01-01T00:00:00.000Z');

// ---- a reference CEL evaluator over the parsed tree (true | false | 'error'), the oracle of the differential test ----------------
const ERR = Symbol('err');
type V = string | number | boolean | undefined;
type R = true | false | 'error';
function evalCel(n: CelNode, ctx: Record<string, V>): R {
  const val = (x: CelNode): V | typeof ERR => {
    if (x.t === 'var') return Object.prototype.hasOwnProperty.call(ctx, x.name) ? ctx[x.name] : ERR;
    if (x.t === 'int' || x.t === 'str' || x.t === 'bool' || x.t === 'ts') return x.v;
    return ERR;
  };
  switch (n.t) {
    case 'or': { const a = evalCel(n.l, ctx); const b = evalCel(n.r, ctx); return a === true || b === true ? true : a === 'error' || b === 'error' ? 'error' : false; }
    case 'and': { const a = evalCel(n.l, ctx); const b = evalCel(n.r, ctx); return a === false || b === false ? false : a === 'error' || b === 'error' ? 'error' : true; }
    case 'not': { const a = evalCel(n.e, ctx); return a === 'error' ? 'error' : !a; }
    case 'has': return n.e.t === 'var' && Object.prototype.hasOwnProperty.call(ctx, n.e.name);
    case 'method': {
      const t = val(n.target);
      const a = val(n.arg);
      if (typeof t !== 'string' || typeof a !== 'string') return 'error';
      return n.fn === 'startsWith' ? t.startsWith(a) : n.fn === 'endsWith' ? t.endsWith(a) : t.includes(a);
    }
    case 'rel': {
      if (n.op === 'in') {
        const l = val(n.l);
        if (l === ERR || n.r.t !== 'list') return 'error';
        return n.r.items.some((i) => val(i) === l);
      }
      const l = val(n.l);
      const r = val(n.r);
      if (l === ERR || r === ERR) return 'error';
      if (n.op === '==') return l === r;
      if (n.op === '!=') return l !== r;
      if (typeof l !== typeof r || (typeof l !== 'number' && typeof l !== 'string')) return 'error';
      const a = l as number | string;
      const b = r as number | string;
      const c = a < b ? -1 : a > b ? 1 : 0;
      return n.op === '<' ? c < 0 : n.op === '<=' ? c <= 0 : n.op === '>' ? c > 0 : c >= 0;
    }
    default: return 'error';
  }
}

const EXPRS = [
  'resource.name == "abc"', 'resource.name != "abc"', '"abc" == resource.name', 'resource.name == principal.org', 'resource.name != principal.org',
  'object.spec.replicas <= 5', '5 >= object.spec.replicas', 'object.spec.replicas < 5 || object.spec.replicas > 7', '!(object.spec.replicas > 5)', 'object.spec.replicas == -3',
  'request.flag == true', '!(request.flag == true)', 'request.flag != false', 'request.flag == false', '!(request.flag != true)',
  'request.time < timestamp("2030-01-01T00:00:00Z")', 'request.time >= timestamp("2030-01-01T00:00:00.000Z")', 'timestamp("2030-01-01T00:00:00Z") > request.time',
  'resource.name in ["abc", "xyz"]', '!(resource.name in ["abc"])', 'object.spec.replicas in [3, 8]',
  'resource.name.startsWith("a")', 'resource.name.endsWith("c")', 'resource.name.contains("b")', '!resource.name.endsWith("c")', 'resource.name.contains("*")',
  'has(resource.tag)', '!has(resource.tag)', 'has(resource.tag) && resource.tag == "abc"',
  'resource.name == "abc" && object.spec.replicas <= 5 && request.flag == true', 'resource.name == "abc" || object.spec.replicas <= 5', '(resource.name == "abc" || principal.org == "b") && request.flag != true',
  'resource.name < "b"', 'principal.org >= "b"', '!(resource.name.startsWith("a") && request.flag == true) || object.spec.replicas == 3',
];
const choices: Record<string, V[]> = {
  'resource.name': [undefined, 'abc', 'xyz', '', 5, 'a*c'],
  'object.spec.replicas': [undefined, -3, 3, 5, 8, 'x'],
  'request.flag': [undefined, true, false, 'x'],
  'request.time': [undefined, T - 1, T, T + 1, 'x'],
  'resource.tag': [undefined, 'abc'],
  'principal.org': [undefined, 'abc', 'b'],
};
const toCtx = (c: Record<string, V>): ActionContext => {
  const params: Record<string, unknown> = {};
  const env: Record<string, unknown> = {};
  const subject: Record<string, unknown> = {};
  for (const [name, v] of Object.entries(c)) {
    if (v === undefined) continue;
    const path = schema.vars[name]!.path.split('.');
    (path[0] === 'action' ? params : path[0] === 'env' ? env : subject)[path[path.length - 1]!] = v;
  }
  return { action: { verb: 'v', resource: 'r', params }, env, subject };
};
function* grid(): Generator<Record<string, V>> {
  const names = Object.keys(choices);
  const rec = function* (i: number, acc: Record<string, V>): Generator<Record<string, V>> {
    if (i === names.length) { yield { ...acc }; return; }
    for (const v of choices[names[i]!]!) { if (v === undefined) { const { [names[i]!]: _x, ...rest } = acc; yield* rec(i + 1, rest); } else yield* rec(i + 1, { ...acc, [names[i]!]: v }); }
  };
  yield* rec(0, {});
}

describe('celToCondition: exact translation (differential against a reference CEL evaluator)', () => {
  for (const e of EXPRS) {
    it(`${e}`, () => {
      const tr = celToCondition(e, schema);
      expect(tr.ok, JSON.stringify(tr)).toBe(true);
      if (!tr.ok) return;
      const parsed = parseCel(e);
      if (!parsed.ok) throw new Error('parse');
      let trues = 0;
      let n = 0;
      for (const c of grid()) {
        n++;
        const want = evalCel(parsed.ast, c);
        const got = evaluateConditionTri(tr.condition, toCtx(c));
        // exact for true; an error in CEL is never a true here; a CEL false is never a true here
        expect(got === 'true', `${e} ${JSON.stringify(c)} cel=${want} pca=${got}`).toBe(want === true);
        if (want === true) trues++;
      }
      expect(n).toBeGreaterThan(2000);
      expect(trues, `${e} is never true on the grid: the test proves nothing`).toBeGreaterThan(0);
    });
  }
});

describe('celToCondition: exact output shapes', () => {
  it('maps each construct', () => {
    const c = (e: string) => { const r = celToCondition(e, schema); if (!r.ok) throw new Error(r.message); return r.condition; };
    expect(c('resource.name == "abc"')).toEqual({ field: 'action.params.name', op: 'eq', value: 'abc' });
    expect(c('5 >= object.spec.replicas')).toEqual({ field: 'action.params.count', op: 'lte', value: 5 });
    expect(c('resource.name == principal.org')).toEqual({ field: 'action.params.name', op: 'eq', ref: 'subject.other' });
    expect(c('request.flag != true')).toEqual({ field: 'env.flag', op: 'ne', value: true });
    expect(c('request.time < timestamp("2030-01-01T00:00:00Z")')).toEqual({ field: 'env.now', op: 'lt', value: T });
    expect(c('resource.name in ["a", "b"]')).toEqual({ field: 'action.params.name', op: 'in', value: ['a', 'b'] });
    expect(c('resource.name.startsWith("a")')).toEqual({ field: 'action.params.name', op: 'prefix', value: 'a' });
    expect(c('resource.name.endsWith("a*?\\\\")')).toEqual({ field: 'action.params.name', op: 'like', value: '*a\\*\\?\\\\' });
    expect(c('resource.name.contains("x")')).toEqual({ field: 'action.params.name', op: 'like', value: '*x*' });
    expect(c('has(resource.tag)')).toEqual({ field: 'action.params.opt', op: 'exists', value: true });
    expect(c('(resource.name == "a" && request.flag == true) && object.spec.replicas < 2 || principal.org == "b" || principal.org == "c"')).toEqual({
      any_of: [{ all_of: [{ field: 'action.params.name', op: 'eq', value: 'a' }, { field: 'env.flag', op: 'eq', value: true }, { field: 'action.params.count', op: 'lt', value: 2 }] }, { field: 'subject.other', op: 'eq', value: 'b' }, { field: 'subject.other', op: 'eq', value: 'c' }],
    });
    const r = celToCondition('resource.name == "a" && principal.org == "b"', schema);
    expect(r.ok && r.fields).toEqual(['action.params.name', 'subject.other']);
  });
});

describe('celToCondition: anything it cannot translate exactly is rejected, by name', () => {
  const rejected: [string, string, string][] = [
    ['1 + 2 == object.spec.replicas', 'unsupported', 'arithmetic (+)'],
    ['object.spec.replicas * 2 > 3', 'unsupported', 'arithmetic (*)'],
    ['object.spec.replicas % 2 == 0', 'unsupported', 'arithmetic (%)'],
    ['request.flag ? true : false', 'unsupported', 'the conditional operator'],
    ['resource.name.matches("^a")', 'unsupported', "method 'matches'"],
    ['matches(resource.name, "a")', 'unsupported', "function 'matches'"],
    ['size(resource.name) > 3', 'unsupported', "function 'size'"],
    ['resource.name.size() > 3', 'unsupported', "method 'size'"],
    ['[1, 2].exists(x, x > 1)', 'unsupported', "method 'exists'"],
    ['object.spec.replicas > 1.5', 'unsupported', 'double literal'],
    ['object.spec.replicas > 1e3', 'unsupported', 'double literal'],
    ['object.spec.replicas > 1u', 'unsupported', 'unsigned integer literal'],
    ['object.spec.replicas > 0x10', 'unsupported', 'hexadecimal literal'],
    ['object.spec.replicas > 007', 'unsupported', 'integer literal with a leading zero'],
    ['object.spec.replicas > 9007199254740993', 'unsupported', 'integer literal outside the safe-integer range'],
    ['resource.name == b"x"', 'unsupported', 'bytes literal'],
    ['resource.name == r"x"', 'unsupported', 'raw string literal'],
    ['resource.name == """x"""', 'unsupported', 'triple-quoted string'],
    ['resource.name == "\\u0041"', 'unsupported', 'string escape \\u'],
    ['resource.name == null', 'unsupported', 'null'],
    ['int(resource.name) == 1', 'unsupported', "function 'int'"],
    ['duration("1h") > request.time', 'unsupported', "function 'duration'"],
    ['resource.name[0] == "a"', 'unsupported', 'index operator'],
    ['{"a": 1}.a == 1', 'unsupported', 'map or message literal'],
    ['object.spec.replicas > -resource.name', 'unsupported', 'unary minus on a non-literal'],
    ['1 < object.spec.replicas < 5', 'unsupported', 'chained comparison'],
    ['request.time < timestamp("2030-01-01")', 'unsupported', 'RFC 3339 UTC'],
    ['request.time < timestamp("2030-02-30T00:00:00Z")', 'unsupported', 'not a real instant'],
    ['request.time < timestamp("2030-01-01T00:00:00.1234Z")', 'unsupported', 'RFC 3339 UTC'],
    ['request.time < timestamp(resource.name)', 'unsupported', 'timestamp() of a non-literal'],
    ['resource.name.startsWith(principal.org)', 'unsupported', 'startsWith of anything but a non-empty string literal'],
    ['resource.name.startsWith("")', 'unsupported', 'startsWith of anything but a non-empty string literal'],
    ['resource.name in principal.org', 'unsupported', '"in" against anything but a non-empty list literal'],
    ['resource.name in []', 'unsupported', '"in" against anything but a non-empty list literal'],
    ['resource.name in ["a", 1]', 'type_mismatch', 'list items must be string literals'],
    ['unknown.var == 1', 'unknown_identifier', "'unknown.var' is not declared in the schema"],
    ['resource.name == 5', 'type_mismatch', 'string against int'],
    ['resource.name == request.flag', 'type_mismatch', 'string against bool'],
    ['request.flag < true', 'type_mismatch', 'ordering of booleans'],
    ['resource.name', 'unsupported', "a bare variable 'resource.name' as a condition"],
    ['request.flag', 'unsupported', 'write request.flag == true'],
    ['!request.flag', 'unsupported', 'write request.flag == true'],
    ['true', 'constant_expression', 'a bare constant is not a condition'],
    ['1 == 1', 'constant_expression', 'a comparison of two literals'],
    ['true && true', 'constant_expression', 'a bare constant is not a condition'],
    ['has(resource.name)', 'has_requires_optional', 'has(resource.name): mark the variable optional in the schema (its container must always be present)'],
    ['has(resource)', 'unknown_identifier', "'resource' is not declared in the schema"],
    ['has("x")', 'syntax', 'has() takes one declared variable'],
    ['resource.name == ', 'syntax', 'unexpected end of expression'],
    ['(resource.name == "a"', 'syntax', "expected ')'"],
    ['resource.name == "a" resource.name', 'syntax', "unexpected 'resource'"],
    ['resource.name == "a', 'syntax', 'unterminated string'],
    ['', 'syntax', 'empty expression'],
    ['resource.name = "a"', 'unsupported', 'assignment'],
    ['resource.name == "a" // c', 'unsupported', 'comments'],
    ['frobnicate(resource.name)', 'unsupported', "unknown function 'frobnicate'"],
    ['in', 'syntax', "unexpected 'in'"],
  ];
  it.each(rejected)('%s', (e, code, msg) => {
    const r = celToCondition(e, schema);
    expect(r.ok).toBe(false);
    if (!r.ok) { expect(r.code).toBe(code); expect(r.message).toContain(msg); }
  });
  it('limits', () => {
    expect(celToCondition(`resource.name == "${'a'.repeat(257)}"`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition(`${'resource.name == "a" || '.repeat(300)}request.flag == true`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition(`${'('.repeat(40)}request.flag == true${')'.repeat(40)}`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition(`${'!'.repeat(40)}(request.flag == true)`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition(`resource.name in [${Array.from({ length: 65 }, (_, i) => `"a${i}"`).join(',')}]`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition(`resource.name == "${'a'.repeat(250)}" || ${'x'.repeat(4096)}`, schema)).toMatchObject({ ok: false, code: 'too_complex' });
    expect(celToCondition('resource.name.contains("' + 'a'.repeat(256) + '")', schema).ok).toBe(true);
  });
  it('a bad schema is refused', () => {
    expect(celToCondition('request.flag', null as never)).toMatchObject({ code: 'bad_schema' });
    expect(celToCondition('x', { vars: { x: { path: 'bogus.x', type: 'bool' } } })).toMatchObject({ code: 'bad_schema' });
    expect(celToCondition('x', { vars: { x: { path: 'env.__proto__', type: 'bool' } } })).toMatchObject({ code: 'bad_schema' });
    expect(celToCondition('x', { vars: { x: { path: 'env.x', type: 'double' as never } } })).toMatchObject({ code: 'bad_schema' });
    expect(celToCondition('x', { vars: { 'a b': { path: 'env.x', type: 'bool' } } })).toMatchObject({ code: 'bad_schema' });
    expect(celToCondition('toString', schema)).toMatchObject({ code: 'unknown_identifier' });
  });
});

describe('celToPredicate / celConditionsToPca', () => {
  it('wraps the condition in a permit predicate', () => {
    expect(celToPredicate('request.flag == true', schema, { verb: 'read', resource: '/a/*' })).toEqual({ ok: true, predicate: { verb: 'read', resource: '/a/*', where: [{ field: 'env.flag', op: 'eq', value: true }] }, fields: ['env.flag'] });
  });
  it('one rejection makes the whole import deny everything', () => {
    const r = celConditionsToPca([
      { name: 'ok', expression: 'request.flag == true', verb: 'read' },
      { name: 'bad', expression: 'size(resource.name) > 1', verb: 'read' },
    ], schema);
    expect(r.predicates).toHaveLength(1);
    expect(r.report.errors).toEqual(["bad: rejected (unsupported) at 0: function 'size'"]);
    expect(decide(r, { action: { verb: 'read', resource: 'x', params: {} }, env: { flag: true } })).toMatchObject({ allowed: false, reason: 'translation incomplete (fail closed)' });
    const good = celConditionsToPca([{ name: 'ok', expression: 'request.flag == true', verb: 'read' }], schema);
    expect(decide(good, { action: { verb: 'read', resource: 'x', params: {} }, env: { flag: true } }).allowed).toBe(true);
    expect(decide(good, { action: { verb: 'read', resource: 'x', params: {} }, env: {} }).allowed).toBe(false);
  });
});
