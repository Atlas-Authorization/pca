import { describe, expect, it } from 'vitest';
import { regoToPca } from './rego';

const NODEF = 'no `default allow = false` found; assuming default-deny';
const wrap = (body: string) => `package p\ndefault allow = false\nallow {\n${body}\n}\n`;
const one = (body: string) => regoToPca(wrap(body));
const preds = (body: string) => one(body).predicates;

describe('module-level', () => {
  it('empty module', () => {
    expect(regoToPca('')).toEqual({
      predicates: [],
      denies: [],
      caveats: [],
      report: { source: 'rego', translated: [], skipped: [NODEF], errors: [] },
    });
  });
  it('package names', () => {
    expect(regoToPca('package a.b_c').report.translated).toEqual(['package a.b_c']);
    expect(regoToPca('package 1x').report.translated).toEqual([]);
    expect(regoToPca('mypackage x').report.translated).toEqual([]);
    expect(regoToPca('package   _x9').report.translated).toEqual(['package _x9']);
    expect(regoToPca('x\npackage a\npackage b').report.translated).toEqual(['package a']);
  });
  it('default allow variants', () => {
    expect(regoToPca('default allow = false').report.skipped).toEqual([]);
    expect(regoToPca('default allow := false').report.skipped).toEqual([]);
    expect(regoToPca('default allow=false').report.skipped).toEqual([]);
    expect(regoToPca('default  allow   :=   false').report.skipped).toEqual([]);
    const T = '`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny';
    expect(regoToPca('default allow = true').report.skipped).toEqual([T]);
    expect(regoToPca('default allow := true').report.skipped).toEqual([T]);
    expect(regoToPca('default allow=true').report.skipped).toEqual([T]);
    expect(regoToPca('default allow = truex').report.skipped).toEqual([NODEF]);
    expect(regoToPca('default allow = falsey').report.skipped).toEqual([NODEF]);
    expect(regoToPca('mydefault allow = false').report.skipped).toEqual([NODEF]);
    expect(regoToPca('default allowed = false').report.skipped).toEqual([NODEF]);
    expect(regoToPca('default allow == false').report.skipped).toEqual([NODEF]);
    expect(regoToPca('default allow : = false').report.skipped).toEqual([NODEF]);
  });
  it('comments are stripped', () => {
    const r = regoToPca('# default allow = true\npackage p # trailing\nallow {\n input.a == 1 # c\n}');
    expect(r.report.skipped).toEqual([NODEF]);
    expect(r.report.translated).toEqual(['package p', 'allow → verb "*" (1 condition(s))']);
    // a # inside a string literal truncates it (fails closed)
    const h = regoToPca('allow {\n input.a == "x#y"\n}');
    expect(h.predicates).toEqual([]);
    // the string is cut at '#', so the brace matcher sees an unterminated string and the block never closes
    expect(h.report.skipped).toEqual([NODEF]);
    expect(h.report.errors).toEqual(['unterminated `allow { ... }` block']);
  });
});

describe('rule forms', () => {
  const forms = ['allow {', 'allow = true {', 'allow := true {', 'allow if {', 'allow=true{', 'allow:=true{', 'allow  if  {', 'allow{', 'allow\n{'];
  for (const f of forms) {
    it(`accepts ${JSON.stringify(f)}`, () => {
      const r = regoToPca(`default allow = false\n${f} input.a == 1 }`);
      expect(r.predicates).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', value: 1 }] }]);
    });
  }
  for (const f of ['allow := false {', 'allowed {', 'xallow {', 'allow = trueish {', 'allow if x {', 'allow == true {', 'allow = true if {', 'allow : true {', 'allow = tru {']) {
    it(`ignores ${JSON.stringify(f)}`, () => {
      expect(regoToPca(`default allow = false\n${f} input.a == 1 }`).predicates).toEqual([]);
    });
  }
  it('multiple rules are independent predicates', () => {
    const r = regoToPca(
      'default allow = false\nallow {\n input.action == "r"\n}\nallow {\n input.action == "w"\n input.resource == "/x"\n}\n',
    );
    expect(r.predicates).toEqual([{ verb: 'r' }, { verb: 'w', resource: '/x' }]);
    expect(r.report.translated).toEqual(['allow → verb "r" (0 condition(s))', 'allow → verb "w" on /x (0 condition(s))']);
  });
  it('unterminated block is an error and stops scanning', () => {
    const r = regoToPca('default allow = false\nallow {\n input.a == 1\n}\nallow {\n input.b == 2\n');
    expect(r.report.errors).toEqual(['unterminated `allow { ... }` block']);
    expect(r.predicates).toHaveLength(1);
    const r2 = regoToPca('default allow = false\nallow {\n input.a == 1\nallow {\n input.b == 2\n}\n');
    expect(r2.report.errors).toEqual(['unterminated `allow { ... }` block']);
    expect(r2.predicates).toEqual([]);
  });
  it('braces in set literals and strings do not end the body', () => {
    const r = preds('input.a in {"x", "y"}\ninput.action == "}"');
    expect(r).toEqual([{ verb: '}', where: [{ field: 'env.a', op: 'in', value: ['x', 'y'] }] }]);
  });
  it('semicolon separates statements; blank statements ignored', () => {
    expect(preds('input.action == "a"; input.b == 1;;\n\n  ; input.c == 2')).toEqual([
      { verb: 'a', where: [{ field: 'env.b', op: 'eq', value: 1 }, { field: 'env.c', op: 'eq', value: 2 }] },
    ]);
  });
  it('empty body is a wildcard predicate with no where/resource', () => {
    const r = one('');
    expect(r.predicates).toEqual([{ verb: '*' }]);
    expect(Object.keys(r.predicates[0]!)).toEqual(['verb']);
    expect(r.report.translated).toEqual(['package p', 'allow → verb "*" (0 condition(s))']);
  });
  it('translated message formats', () => {
    expect(one('input.action in {"a","b"}\ninput.resource == "/r"\ninput.x == 1').report.translated).toEqual([
      'package p',
      'allow → verb ["a","b"] on /r (1 condition(s))',
    ]);
    // empty-string resource is set on the predicate but omitted from the message
    const e = one('input.resource == ""');
    expect(e.predicates).toEqual([{ verb: '*', resource: '' }]);
    expect(e.report.translated).toEqual(['package p', 'allow → verb "*" (0 condition(s))']);
  });
  it('later verb / resource statements override earlier ones', () => {
    expect(preds('input.action == "a"\ninput.action == "b"\ninput.resource == "x"\ninput.resource == "y"')).toEqual([{ verb: 'b', resource: 'y' }]);
    expect(preds('input.action == "a"\ninput.action in {"c"}')).toEqual([{ verb: ['c'] }]);
  });
});

describe('statements', () => {
  const cond = (s: string) => preds(s)[0]?.where;
  it('comparison operators', () => {
    expect(cond('input.a == 1')).toEqual([{ field: 'env.a', op: 'eq', value: 1 }]);
    expect(cond('input.a != 1')).toEqual([{ field: 'env.a', op: 'ne', value: 1 }]);
    expect(cond('input.a < 1')).toEqual([{ field: 'env.a', op: 'lt', value: 1 }]);
    expect(cond('input.a <= 1')).toEqual([{ field: 'env.a', op: 'lte', value: 1 }]);
    expect(cond('input.a > 1')).toEqual([{ field: 'env.a', op: 'gt', value: 1 }]);
    expect(cond('input.a >= 1')).toEqual([{ field: 'env.a', op: 'gte', value: 1 }]);
    expect(cond('input.a>=1')).toEqual([{ field: 'env.a', op: 'gte', value: 1 }]);
    expect(cond('input.a.b.c == "s"')).toEqual([{ field: 'env.a.b.c', op: 'eq', value: 's' }]);
  });
  it('literals', () => {
    expect(cond('input.a == true')).toEqual([{ field: 'env.a', op: 'eq', value: true }]);
    expect(cond('input.a == false')).toEqual([{ field: 'env.a', op: 'eq', value: false }]);
    expect(cond('input.a == -5')).toEqual([{ field: 'env.a', op: 'eq', value: -5 }]);
    expect(cond('input.a == 1.25')).toEqual([{ field: 'env.a', op: 'eq', value: 1.25 }]);
    expect(cond('input.a == ""')).toEqual([{ field: 'env.a', op: 'eq', value: '' }]);
    expect(cond('input.a != "x y"')).toEqual([{ field: 'env.a', op: 'ne', value: 'x y' }]);
    expect(cond('input.a != true')).toEqual([{ field: 'env.a', op: 'ne', value: true }]);
    for (const bad of ['1e3', '.5', '+5', '5.', '"a\\"b"', 'null', 'foo', '--1', '1.2.3', 'True', '"a"b"']) {
      expect(preds(`input.a == ${bad}`)).toEqual([]);
    }
  });
  it('action / resource special fields', () => {
    expect(preds('input.action == "go"')).toEqual([{ verb: 'go' }]);
    expect(preds('input.resource == "/p"')).toEqual([{ verb: '*', resource: '/p' }]);
    // non-string => ordinary condition on env.action / env.resource
    expect(cond('input.action == 5')).toEqual([{ field: 'env.action', op: 'eq', value: 5 }]);
    expect(cond('input.resource == true')).toEqual([{ field: 'env.resource', op: 'eq', value: true }]);
    // != and ordering are ordinary conditions
    expect(cond('input.action != "x"')).toEqual([{ field: 'env.action', op: 'ne', value: 'x' }]);
    expect(cond('input.resource != "x"')).toEqual([{ field: 'env.resource', op: 'ne', value: 'x' }]);
    expect(cond('input.action < 3')).toEqual([{ field: 'env.action', op: 'lt', value: 3 }]);
    expect(cond('input.actions == "x"')).toEqual([{ field: 'env.actions', op: 'eq', value: 'x' }]);
    expect(cond('input.resource.id == "x"')).toEqual([{ field: 'env.resource.id', op: 'eq', value: 'x' }]);
  });
  it('ordering ops require numbers', () => {
    for (const op of ['<', '<=', '>', '>=']) {
      expect(preds(`input.a ${op} "x"`)).toEqual([]);
      expect(preds(`input.a ${op} true`)).toEqual([]);
    }
  });
  it('in: sets and arrays', () => {
    expect(cond('input.a in {"x", 1, true}')).toEqual([{ field: 'env.a', op: 'in', value: ['x', 1, true] }]);
    expect(cond('input.a in ["x","y"]')).toEqual([{ field: 'env.a', op: 'in', value: ['x', 'y'] }]);
    expect(cond('input.a in {}')).toEqual([{ field: 'env.a', op: 'in', value: [] }]);
    expect(cond('input.a in [ ]')).toEqual([{ field: 'env.a', op: 'in', value: [] }]);
    expect(cond('input.a in {"x,y", "z"}')).toEqual([{ field: 'env.a', op: 'in', value: ['x,y', 'z'] }]);
    expect(cond('input.a in {"x",}')).toEqual([{ field: 'env.a', op: 'in', value: ['x'] }]);
    expect(cond('input.a  in   {"x"}')).toEqual([{ field: 'env.a', op: 'in', value: ['x'] }]);
    for (const bad of ['"x"', '{"x"', '"x"}', '[1}', '{1]', '{foo}', '{"a", b}', 'input.b', '(1,2)']) {
      expect(preds(`input.a in ${bad}`)).toEqual([]);
    }
    expect(preds('input.action in {"a","b"}')).toEqual([{ verb: ['a', 'b'] }]);
    expect(preds('input.action in ["a"]')).toEqual([{ verb: ['a'] }]);
    expect(preds('input.action in {}')).toEqual([{ verb: [] }]);
    expect(preds('input.action in {"a", 1}')).toEqual([]);
    expect(preds('input.resource in {"a"}')[0]?.where).toEqual([{ field: 'env.resource', op: 'in', value: ['a'] }]);
  });
  it('refs', () => {
    expect(cond('input.a == input.b')).toEqual([{ field: 'env.a', op: 'eq', ref: 'env.b' }]);
    expect(cond('input.a != input.b.c')).toEqual([{ field: 'env.a', op: 'ne', ref: 'env.b.c' }]);
    expect(preds('input.action == input.b')).toEqual([{ verb: '*', where: [{ field: 'env.action', op: 'eq', ref: 'env.b' }] }]);
    for (const op of ['<', '<=', '>', '>=']) expect(preds(`input.a ${op} input.b`)).toEqual([]);
    expect(preds('input.a == input.')).toEqual([]);
  });
  it('not', () => {
    expect(cond('not input.a == 1')).toEqual([{ not: { field: 'env.a', op: 'eq', value: 1 } }]);
    expect(cond('not   input.a > 2')).toEqual([{ not: { field: 'env.a', op: 'gt', value: 2 } }]);
    expect(cond('not not input.a == 1')).toEqual([{ not: { not: { field: 'env.a', op: 'eq', value: 1 } } }]);
    expect(cond('not startswith(input.a, "p")')).toEqual([{ not: { field: 'env.a', op: 'prefix', value: 'p' } }]);
    expect(preds('not input.action == "x"')).toEqual([]);
    expect(preds('not input.resource == "x"')).toEqual([]);
    expect(preds('not input.action in {"x"}')).toEqual([]);
    expect(preds('not input.xs[_]')).toEqual([]);
    expect(cond('not input.a in {1}')).toEqual([{ not: { field: 'env.a', op: 'in', value: [1] } }]);
    // `not` must be followed by whitespace
    expect(preds('notinput.a == 1')).toEqual([]);
    expect(preds('not')).toEqual([]);
  });
  it('startswith', () => {
    expect(cond('startswith(input.a, "pre")')).toEqual([{ field: 'env.a', op: 'prefix', value: 'pre' }]);
    expect(cond('startswith( input.a.b ,  "" )')).toEqual([{ field: 'env.a.b', op: 'prefix', value: '' }]);
    for (const bad of ['startswith(input.a, pre)', 'startswith("x", "p")', 'startswith(input.a, "p", 1)', 'xstartswith(input.a, "p")', 'startswith(input.a, "p") == true', 'startswith(input.a "p")', ' endswith(input.a, "p")']) {
      if (bad.startsWith(' ')) continue;
      expect(preds(bad)).toEqual([]);
    }
    expect(preds('endswith(input.a, "p")')).toEqual([]);
  });
  it('glob.match', () => {
    expect(cond('glob.match("a*", [], input.p)')).toEqual([{ field: 'env.p', op: 'like', value: 'a*' }]);
    expect(cond('glob.match("a?b", null, input.p.q)')).toEqual([{ field: 'env.p.q', op: 'like', value: 'a?b' }]);
    expect(cond('glob.match( "" , [ ] , input.p )')).toEqual([{ field: 'env.p', op: 'like', value: '' }]);
    expect(cond('glob.match("a\\*", [], input.p)')).toEqual([{ field: 'env.p', op: 'like', value: 'a\\*' }]);
    for (const ch of ['[', ']', '{', '}']) expect(preds(`glob.match("a${ch}b", [], input.p)`)).toEqual([]);
    for (const bad of ['glob.match("a", ["/"], input.p)', 'glob.match("a", [], "x")', 'glob.match(a, [], input.p)', 'glob.match("a", input.p)', 'glob.match("a", [], input.p) == true', 'glob.match("a", nil, input.p)']) {
      expect(preds(bad)).toEqual([]);
    }
    const r = one('glob.match("a[x]", [], input.p)');
    expect(r.report.skipped).toEqual(['unmodeled statement "glob.match("a[x]", [], input.p)" — rule dropped (fail closed)']);
  });
  it('unmodeled constructs drop the whole rule with a truncated message', () => {
    const bad = ['x := 1', 'some i', 'every x in input.xs { x }', 'input.a == [x | x := 1]', 'count(input.a) > 1', 'input.xs[_] == 1', 'input.xs[0] == 1', 'input.flag', 'input.some == 1', 'input.every == 1', '"x" in input.coll', 'data.foo == 1', 'input == 1', 'input.a in [1, "x|y"]', 'input.a'];
    for (const b of bad) {
      const r = regoToPca(`default allow = false\nallow {\n input.ok == 1\n ${b}\n}\nallow {\n input.fine == 2\n}`);
      expect(r.predicates).toEqual([{ verb: '*', where: [{ field: 'env.fine', op: 'eq', value: 2 }] }]);
      expect(r.report.skipped).toEqual([`unmodeled statement "${b}" — rule dropped (fail closed)`]);
    }
    expect(preds('input.something == 1')).toEqual([{ verb: '*', where: [{ field: 'env.something', op: 'eq', value: 1 }] }]);
    expect(preds('input.xs.every == 1')).toEqual([]);
    expect(preds('input.a in [1,2]')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'in', value: [1, 2] }] }]);
  });
  it('truncation at 80 chars with whitespace collapse', () => {
    const long = 'input.' + 'a'.repeat(74); // 80 chars exactly -> unmodeled (no operator)
    expect(long.length).toBe(80);
    expect(one(long).report.skipped).toEqual([`unmodeled statement "${long}" — rule dropped (fail closed)`]);
    const long81 = long + 'b';
    expect(one(long81).report.skipped).toEqual([`unmodeled statement "${long81.slice(0, 77)}..." — rule dropped (fail closed)`]);
    expect(one('some   thing   here').report.skipped).toEqual(['unmodeled statement "some thing here" — rule dropped (fail closed)']);
  });
  it('dropped rule leaves no translated entry for it', () => {
    expect(one('x := 1').report.translated).toEqual(['package p']);
  });
  it('conditions keep statement order', () => {
    expect(cond('input.a == 1\ninput.b == 2\nnot input.c == 3')).toEqual([
      { field: 'env.a', op: 'eq', value: 1 },
      { field: 'env.b', op: 'eq', value: 2 },
      { not: { field: 'env.c', op: 'eq', value: 3 } },
    ]);
  });
  it('multi-line rhs is not joined (regex s-flag guard)', () => {
    expect(preds('input.a ==\n1')).toEqual([]);
  });
});
