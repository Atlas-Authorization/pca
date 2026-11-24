import { describe, expect, it, vi } from 'vitest';
import { celConditionsToPca, celToCondition, celToPredicate, parseCel, type CelSchema } from './cel';

const fail = (src: string) => {
  const r = parseCel(src);
  if (r.ok) throw new Error(`expected a rejection: ${src}`);
  return r;
};
const rejects = (src: string, code: string, message: string, at: number) =>
  expect(fail(src)).toEqual({ ok: false, code, message, at });

const schema: CelSchema = {
  vars: {
    s: { path: 'env.s', type: 'string' },
    n: { path: 'env.n', type: 'int' },
    b: { path: 'env.b', type: 'bool' },
    t: { path: 'env.t', type: 'timestamp_ms' },
    o: { path: 'env.o', type: 'string', optional: true },
    z: { path: 'env.z', type: 'string' },
    a: { path: 'env.a', type: 'string' },
  },
};

describe('lexer', () => {
  it('skips tab, newline and carriage return between tokens', () => {
    for (const ws of ['\t', '\n', '\r']) expect(parseCel(`s${ws}==${ws}'a'`).ok).toBe(true);
  });
  it('rejects comments and keeps a lone slash as arithmetic', () => {
    rejects("s == 'a' // x", 'unsupported', 'comments', 9);
    rejects('s/2', 'unsupported', 'arithmetic (/)', 1);
    rejects('s / 2', 'unsupported', 'arithmetic (/)', 2);
  });
  it('rejects raw and bytes literals of either case and quote, not other identifiers', () => {
    rejects('r"x"', 'unsupported', 'raw string literal', 0);
    rejects("R'x'", 'unsupported', 'raw string literal', 0);
    rejects('b"x"', 'unsupported', 'bytes literal', 0);
    rejects("B'x'", 'unsupported', 'bytes literal', 0);
    rejects('s"x"', 'syntax', "unexpected 'x'", 1);
  });
  it('names each unsupported numeric form', () => {
    rejects('1.5', 'unsupported', 'double literal', 0);
    rejects('1.x', 'unsupported', 'field selection on something that is not a declared variable', 1);
    rejects('1e5', 'unsupported', 'double literal', 0);
    rejects('1E5', 'unsupported', 'double literal', 0);
    rejects('1u', 'unsupported', 'unsigned integer literal', 0);
    rejects('1U', 'unsupported', 'unsigned integer literal', 0);
    rejects('0x1', 'unsupported', 'hexadecimal literal', 0);
    rejects('1X', 'unsupported', 'hexadecimal literal', 0);
    rejects('01', 'unsupported', 'integer literal with a leading zero', 0);
  });
  it('a raw line break inside a string is unterminated', () => {
    rejects("'a\rb'", 'syntax', 'unterminated string', 0);
    rejects("'a\nb'", 'syntax', 'unterminated string', 0);
  });
});

describe('parser', () => {
  it('rejects an empty or non-string expression', () => {
    rejects('', 'syntax', 'empty expression', 0);
    rejects(123 as unknown as string, 'syntax', 'empty expression', 0);
  });
  it('a string token is never punctuation', () => {
    rejects('"a" "."', 'syntax', "unexpected '.'", 4);
    rejects('s foo', 'syntax', "unexpected 'foo'", 2);
    rejects('s "in"', 'syntax', "unexpected 'in'", 2);
    rejects('s "=="', 'syntax', "unexpected '=='", 2);
    rejects("s == 'a' \"==\"", 'syntax', "unexpected '=='", 9);
    rejects("s == 'a' \"in\"", 'syntax', "unexpected 'in'", 9);
    rejects("s == 'a' foo", 'syntax', "unexpected 'foo'", 9);
    rejects('()', 'syntax', "unexpected ')'", 1);
    rejects(')', 'syntax', "unexpected ')'", 0);
  });
  it('rejects chained comparisons', () => {
    rejects("s == 'a' == 'b'", 'unsupported', 'chained comparison', 9);
    rejects("s in ['a'] in ['b']", 'unsupported', 'chained comparison', 11);
    rejects("s == 'a' in ['b']", 'unsupported', 'chained comparison', 9);
  });
  it('bounds nesting at 32 for parentheses, negation, call arguments and lists', () => {
    expect(parseCel('('.repeat(32) + 's' + ')'.repeat(32)).ok).toBe(true);
    rejects('('.repeat(33), 'too_complex', 'nesting deeper than 32', 0);
    rejects('('.repeat(33) + 's' + ')'.repeat(33), 'too_complex', 'nesting deeper than 32', 33);
    expect(parseCel('!'.repeat(32) + 's').ok).toBe(true);
    rejects('!'.repeat(33) + 's', 'too_complex', 'nesting deeper than 32', 32);
    rejects('has('.repeat(33) + 's' + ')'.repeat(33), 'too_complex', 'nesting deeper than 32', 132);
    rejects('['.repeat(33) + "'a'" + ']'.repeat(33), 'too_complex', 'nesting deeper than 32', 33);
  });
  it('bounds the node count at 256 counting every kind of node', () => {
    const pieces: [string, number][] = [
      ["s == 'a'", 3],
      ['n == -1', 3],
      ['n == 2', 3],
      ['b == true', 3],
      ["s.startsWith('a')", 3],
      ['has(o)', 2],
      ["s in ['a', 'b']", 5],
      ["!(s == 'a')", 4],
      ["t == timestamp('2020-01-01T00:00:00Z')", 3],
    ];
    const base = pieces.reduce((a, [, k]) => a + k, 0) + (pieces.length - 1);
    const build = (target: number) => {
      const pad = target - base;
      const units = Math.floor(pad / 4);
      const body = pieces.map(([p], i) => (i === 0 ? '!'.repeat(pad % 4) + p : `${i % 2 === 1 ? '&&' : '||'} ${p}`)).join(' ');
      return body + " || s == 'a'".repeat(units);
    };
    expect(parseCel(build(256)).ok).toBe(true);
    expect(fail(build(257))).toMatchObject({ ok: false, code: 'too_complex', message: 'more than 256 nodes' });
  });
  it('timestamp() must match the whole RFC 3339 form', () => {
    const msg = 'timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision';
    rejects("timestamp('x2020-01-01T00:00:00Z')", 'unsupported', msg, 0);
    rejects("timestamp('2020-01-01T00:00:00Zx')", 'unsupported', msg, 0);
    expect(parseCel("timestamp('2020-01-01T00:00:00.5Z')").ok).toBe(true);
  });
  it('an unexpected exception inside the parser is reported, not thrown', () => {
    const spy = vi.spyOn(String.prototype, 'startsWith').mockImplementation(() => {
      throw new Error('boom');
    });
    let r: ReturnType<typeof parseCel> | undefined;
    try {
      r = parseCel('s == 1');
    } finally {
      spy.mockRestore();
    }
    expect(r).toEqual({ ok: false, code: 'syntax', message: 'internal error', at: 0 });
  });
});

describe('translation', () => {
  const err = (expression: string, sch: CelSchema = schema) => celToCondition(expression, sch);
  it('reports a malformed schema', () => {
    const bad = (s: unknown, message: string) => expect(celToCondition('s == 1', s as CelSchema)).toEqual({ ok: false, code: 'bad_schema', message, at: 0 });
    bad(5, 'the schema must be an object');
    bad(null, 'the schema must be an object');
    bad([], 'the schema must be an object');
    bad({ vars: null }, 'the schema needs a vars object');
    bad({ vars: { s: undefined } }, "variable 's' needs a path rooted at action, subject or env");
    bad({ vars: { s: { path: ['env.x'], type: 'string' } } }, "variable 's' needs a path rooted at action, subject or env");
  });
  it('names the reason for each rejected condition', () => {
    expect(err('b')).toEqual({ ok: false, code: 'unsupported', message: "a bare variable 'b' as a condition (write b == true)", at: 0 });
    expect(err('s')).toEqual({ ok: false, code: 'unsupported', message: "a bare variable 's' as a condition", at: 0 });
    expect(err("s.startsWith('a') == true")).toEqual({ ok: false, code: 'unsupported', message: 'a computed value as a comparison operand', at: 2 });
    expect(err("n.startsWith('a')")).toEqual({ ok: false, code: 'type_mismatch', message: 'startsWith needs a string variable', at: 2 });
    expect(err("'a' in ['b']")).toEqual({ ok: false, code: 'constant_expression', message: 'the left side of "in" must be a declared variable', at: 4 });
  });
  it('lists the variables read in sorted order', () => {
    expect(err("z == 'x' && a == 'y'")).toEqual({
      ok: true,
      condition: { all_of: [{ field: 'env.z', op: 'eq', value: 'x' }, { field: 'env.a', op: 'eq', value: 'y' }] },
      fields: ['env.a', 'env.z'],
    });
  });
  it('an unexpected exception during translation is reported, not thrown', () => {
    let reads = 0;
    const flaky = {
      get vars() {
        if (reads++ > 0) throw new Error('boom');
        return { s: { path: 'env.s', type: 'string' } };
      },
    } as unknown as CelSchema;
    expect(celToCondition("s == 'a'", flaky)).toEqual({ ok: false, code: 'syntax', message: 'internal error', at: 0 });
  });
  it('celToPredicate carries the resource only when given', () => {
    const where = [{ field: 'env.s', op: 'eq', value: 'x' }];
    expect(celToPredicate("s == 'x'", schema, { verb: 'read' })).toStrictEqual({ ok: true, predicate: { verb: 'read', where }, fields: ['env.s'] });
    expect(celToPredicate("s == 'x'", schema, { verb: 'read', resource: 'R::1' })).toStrictEqual({
      ok: true,
      predicate: { verb: 'read', resource: 'R::1', where },
      fields: ['env.s'],
    });
  });
  it('celConditionsToPca reports every item exactly', () => {
    const r = celConditionsToPca(
      [
        { name: 'p1', expression: "s == 'x'", verb: 'read' },
        { name: 'p2', expression: "z == 'x' && a == 'y'", verb: ['a', 'b'], resource: 'R::1' },
        { name: 'bad', expression: 'q == 1', verb: 'read' },
      ],
      schema,
    );
    expect(r).toStrictEqual({
      predicates: [
        { verb: 'read', where: [{ field: 'env.s', op: 'eq', value: 'x' }] },
        {
          verb: ['a', 'b'],
          resource: 'R::1',
          where: [{ all_of: [{ field: 'env.z', op: 'eq', value: 'x' }, { field: 'env.a', op: 'eq', value: 'y' }] }],
        },
      ],
      denies: [],
      caveats: [],
      report: {
        source: 'cel',
        translated: ['p1: translated exactly (reads env.s)', 'p2: translated exactly (reads env.a, env.z)'],
        skipped: [],
        errors: ["bad: rejected (unknown_identifier) at 0: 'q' is not declared in the schema"],
      },
    });
  });
});
