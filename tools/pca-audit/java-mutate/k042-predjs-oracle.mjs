// Oracle for the Java 0.4.2 mutation kill tests of Predicates.java + IntentJs.java (K042PredJs*Test): runs the TS
// reference (packages/pca/src/predicates.ts + hash.ts + JS number semantics) on targeted inputs and writes the golden.
//   PCA_SRC=<dir with packages/pca/src and its node_modules> tsx tools/pca-audit/java-mutate/k042-predjs-oracle.mjs \
//       sdks/java-pca/test-data/k042-predjs.json
// Every input is carried as JSON TEXT (ctx / cond / preds) so both sides parse the identical lexemes (1e400, -0, \ud800).
import fs from 'node:fs';

const SRC = process.env.PCA_SRC ?? new URL('../../../packages/pca/src/', import.meta.url).pathname;
const P = await import(`${SRC.replace(/\/$/, '')}/predicates.ts`);
const H = await import(`${SRC.replace(/\/$/, '')}/hash.ts`);

const out = { tri: [], preds: [], eq: [], nums: [], u8: [], cmp: [] };
const names = new Set();
const uniq = (n) => {
  if (names.has(n)) throw new Error(`duplicate case ${n}`);
  names.add(n);
  return n;
};
const text = (x) => JSON.stringify(x);

// ---- contexts ----
const A = (n) => 'a'.repeat(n);
const CTX = {
  main:
    '{"action":{"verb":"air.book","resource":"skyair.example/bookings/7","params":{"total":38900,"name":"Ana","tags":["a","b"],' +
    '"nested":{"x":1},"astral":"\\ud83d\\ude00","f":1.5,"neg":-3,"z":0,"nz":-0,"inf":1e400,"ninf":-1e400,"lone":"\\ud800",' +
    '"lone2":"a\\udc00","t":true,"fl":false,"nul":null,"arr2":[1,2],"empty":"","constructor":"x","":"emptykey",' +
    '"el":[],"em":{},"glob":"A*a","banana":"banana","xs":"' + 'x'.repeat(198) + 'yz",' +
    '"s512":"' + A(512) + '","s513":"' + A(513) + '",' +
    '"obj":{"type":"Doc::7","tags":["pii","red"]},"objt":{"type":5,"tags":"x"},"objtags":{"tags":["pii"]},' +
    '"objtype":{"type":"Doc"},"objn":{"tag":"x"},"obj2":{"type":"Other","tags":["Doc"]},"objtn":{"type":5,"tags":["Doc"]},' +
    '"objts":{"type":"Doc","tags":"x"},"objtype2":{"type":"Other"},"ts":"Doc::9","ts2":"Docs","ts3":"Doc","ts4":"Doc:9","ctl":"\\u0002x"}},' +
    '"subject":{"id":"ana","pp":"__proto__","x":"x","groups":{"ana":"staff","staff":["emp",5],"emp":"all","__proto__":["root"],"x":7},' +
    '"glist":["a"]},"env":{"cur":"dev1","n":5,"arr":[[1]],"s":"Ana","a":1}}',
  noparams: '{"action":{"verb":"air.book","resource":"r"},"env":{"a":1}}',
  paramsStr: '{"action":{"verb":"air.book","resource":"r","params":"x"},"env":{"a":1}}',
  paramsArr: '{"action":{"verb":"air.book","resource":"r","params":[7,8]},"env":{"a":1}}',
  paramsNull: '{"action":{"verb":"air.book","resource":"r","params":null},"env":{"a":1}}',
  noaction: '{"env":{"a":1}}',
  actionArr: '{"action":[1],"env":{"a":1}}',
  nullctx: 'null',
  subjNull: '{"action":{"verb":"v","resource":"r","params":{}},"subject":null}',
};

const tri = (name, ctx, cond) => {
  const c = text(cond);
  const v = P.evaluateConditionTri(JSON.parse(c), JSON.parse(CTX[ctx]));
  out.tri.push({ name: uniq(name), ctx, cond: c, tri: v });
};
const L = (field, op, value) => ({ field, op, value });
const R = (field, op, ref) => ({ field, op, ref });
const pp = (k) => `action.params.${k}`;

// ---- leaf structure ----
tri('nofield', 'main', { op: 'eq', value: 1 });
tri('emptyfield', 'main', { field: '', op: 'exists' });
tri('numfield', 'main', { field: 5, op: 'exists' });
tri('noop', 'main', { field: pp('name'), value: 'Ana' });
tri('numop', 'main', { field: pp('name'), op: 5, value: 'Ana' });
tri('unknownop', 'main', L(pp('name'), 'nope', 'Ana'));
tri('novalue', 'main', { field: pp('name'), op: 'eq' });
tri('nullvalue', 'main', L(pp('nul'), 'eq', null));
tri('nullvalue-ne', 'main', L(pp('nul'), 'ne', null));
tri('nullvalue-vs-str', 'main', L(pp('name'), 'eq', null));
tri('null-vs-0', 'main', L(pp('nul'), 'eq', 0));
tri('ref-num', 'main', { field: pp('name'), op: 'eq', ref: 5 });
tri('ref-null', 'main', { field: pp('name'), op: 'eq', ref: null });
tri('ref-missing', 'main', R(pp('name'), 'eq', 'env.nope'));
tri('ref-ok', 'main', R('env.s', 'eq', pp('name')));
tri('ref-ok-ne', 'main', R('env.s', 'ne', pp('name')));
tri('ref-beats-value', 'main', { field: 'env.s', op: 'eq', ref: pp('name'), value: 'zzz' });
tri('missing-field-eq', 'main', L(pp('missing'), 'eq', 'x'));
// ---- eq / ne ----
for (const [n, f, v] of [
  ['total=38900', 'total', 38900], ['total=38900.5', 'total', 38900.5], ['total="38900"', 'total', '38900'],
  ['total=true', 'total', true], ['total=[38900]', 'total', [38900]], ['total={}', 'total', {}],
  ['t=true', 't', true], ['t=false', 't', false], ['t="true"', 't', 'true'], ['t=1', 't', 1], ['fl=false', 'fl', false],
  ['tags=ab', 'tags', ['a', 'b']], ['tags=a', 'tags', ['a']], ['tags=ba', 'tags', ['b', 'a']], ['tags=ac', 'tags', ['a', 'c']],
  ['tags={}', 'tags', {}], ['tags=abc', 'tags', ['a', 'b', 'c']],
  ['nested=x1', 'nested', { x: 1 }], ['nested=x2', 'nested', { x: 2 }], ['nested=y1', 'nested', { y: 1 }],
  ['nested=x1y2', 'nested', { x: 1, y: 2 }], ['nested=[1]', 'nested', [1]], ['nested={}', 'nested', {}], ['nested=x', 'nested', 'x'],
  ['arr2=12', 'arr2', [1, 2]], ['arr2=13', 'arr2', [1, 3]], ['el=[]', 'el', []], ['el={}', 'el', {}], ['em={}', 'em', {}],
  ['em=[]', 'em', []], ['em=null', 'em', null], ['name=5', 'name', 5], ['name=Ana', 'name', 'Ana'], ['name=ana', 'name', 'ana'],
  ['f=1.5', 'f', 1.5], ['f=1.25', 'f', 1.25], ['z=0', 'z', 0], ['obj=deep', 'obj', { tags: ['pii', 'red'], type: 'Doc::7' }],
  ['obj=deep2', 'obj', { tags: ['pii', 'red'], type: 'Doc::8' }], ['lone=lone', 'lone', '\ud800'], ['lone=fffd', 'lone', '�'],
  ['astral', 'astral', '😀'],
]) {
  tri(`eq ${n}`, 'main', L(pp(f), 'eq', v));
  tri(`ne ${n}`, 'main', L(pp(f), 'ne', v));
}
tri('eq z=nz', 'main', R(pp('z'), 'eq', pp('nz')));
tri('eq nz=z', 'main', R(pp('nz'), 'eq', pp('z')));
tri('eq inf=inf', 'main', R(pp('inf'), 'eq', pp('inf')));
tri('ne inf=inf', 'main', R(pp('inf'), 'ne', pp('inf')));
tri('eq total=inf', 'main', R(pp('total'), 'eq', pp('inf')));
tri('eq inf=total', 'main', R(pp('inf'), 'eq', pp('total')));
tri('eq ninf=inf', 'main', R(pp('ninf'), 'eq', pp('inf')));
tri('eq env.arr', 'main', L('env.arr', 'eq', [[1]]));
tri('eq env.arr2', 'main', L('env.arr', 'eq', [[2]]));
tri('eq params-whole', 'paramsArr', L('action.params', 'eq', [7, 8]));
// ---- in / nin ----
for (const [n, f, v] of [
  ['name in xAna', 'name', ['x', 'Ana']], ['name in x', 'name', ['x']], ['name in str', 'name', 'Ana'], ['name in []', 'name', []],
  ['total in', 'total', [1, 38900]], ['total in str', 'total', ['38900']], ['tags in', 'tags', [['a', 'b']]], ['name in obj', 'name', { a: 'Ana' }],
]) {
  tri(`in ${n}`, 'main', L(pp(f), 'in', v));
  tri(`nin ${n}`, 'main', L(pp(f), 'nin', v));
}
// ---- ordering ----
const ORD = ['lt', 'lte', 'gt', 'gte'];
for (const op of ORD) {
  for (const [n, f, v] of [
    ['total 38899', 'total', 38899], ['total 38900', 'total', 38900], ['total 38901', 'total', 38901], ['neg 0', 'neg', 0],
    ['f 1', 'f', 1], ['f 2', 'f', 2], ['name Bob', 'name', 'Bob'], ['name Ana', 'name', 'Ana'], ['name An', 'name', 'An'],
    ['name Ab', 'name', 'Ab'], ['astral uffff', 'astral', '￿'], ['lone a', 'lone', 'a'], ['lone2 a', 'lone2', 'a'],
    ['name 5', 'name', 5], ['total x', 'total', 'x'], ['t true', 't', true], ['tags []', 'tags', []], ['nul null', 'nul', null],
    ['z 0', 'z', 0], ['empty ""', 'empty', ''], ['empty a', 'empty', 'a'],
  ]) tri(`${op} ${n}`, 'main', L(pp(f), op, v));
  tri(`${op} inf 1`, 'main', L(pp('inf'), op, 1));
  tri(`${op} total inf`, 'main', R(pp('total'), op, pp('inf')));
  tri(`${op} ninf total`, 'main', R(pp('ninf'), op, pp('total')));
  tri(`${op} name lone`, 'main', R(pp('name'), op, pp('lone')));
  tri(`${op} nz z`, 'main', R(pp('nz'), op, pp('z')));
}
// ---- prefix ----
for (const [n, f, v] of [['An', 'name', 'An'], ['Ana', 'name', 'Ana'], ['Anab', 'name', 'Anab'], ['empty', 'name', ''],
  ['num', 'total', '3'], ['opnum', 'name', 5], ['an', 'name', 'an']]) tri(`prefix ${n}`, 'main', L(pp(f), 'prefix', v));
// ---- like ----
for (const [f, g] of [
  ['name', 'A*'], ['name', 'a*'], ['name', '?na'], ['name', '??'], ['name', 'A?a'], ['name', '*'], ['name', ''], ['empty', ''],
  ['empty', '*'], ['empty', '?'], ['empty', '**'], ['name', 'A**a'], ['name', '*n*'], ['name', '*x*'], ['glob', 'A\\*a'], ['name', 'A\\*a'],
  ['name', 'A\\'], ['name', '\\A\\n\\a'], ['name', '*a'], ['name', '*b'], ['name', 'A*a*'], ['name', '**'], ['banana', '*ana'],
  ['banana', 'b*n*a'], ['banana', 'b*x'], ['banana', '*an'], ['banana', '?*'], ['banana', '*?'], ['banana', 'b?n*'],
  ['banana', 'ban'], ['banana', 'bananas'], ['banana', 'banana'], ['banana', 'banan?'], ['banana', '*n?n?'], ['name', 'Ana'],
  ['name', 'na'], ['name', 'nA'], ['name', 'xAna'], ['name', 'Ana*'], ['name', 'Ana**'], ['name', 'Ana?'], ['name', 'A'],
  ['name', '?'], ['name', '???'], ['name', '????'], ['name', 'A*?'], ['name', 'A*??'], ['name', 'A*???'], ['glob', 'A?a'],
  ['glob', 'A\\?a'], ['name', '\\?na'], ['banana', '*a*a*a'], ['banana', '*a*a*a*a'], ['name', '*\\'], ['empty', '\\'],
]) tri(`like ${f} ${g}`, 'main', L(pp(f), 'like', g));
tri('like num', 'main', L(pp('total'), 'like', '*'));
tri('like opnum', 'main', L(pp('name'), 'like', 5));
tri('like pat512', 'main', L(pp('s512'), 'like', 'a'.repeat(511) + '*'));
tri('like pat513', 'main', L(pp('s512'), 'like', 'a'.repeat(512) + '*'));
tri('like s512', 'main', L(pp('s512'), 'like', '*'));
tri('like s513', 'main', L(pp('s513'), 'like', '*'));
tri('like s512 nomatch', 'main', L(pp('s512'), 'like', 'b*'));
tri('like pat512 nomatch', 'main', L(pp('name'), 'like', 'x'.repeat(512)));
tri('like pat513 nomatch', 'main', L(pp('name'), 'like', 'x'.repeat(513)));
// ---- matches ----
for (const [f, re] of [['name', 'A.a'], ['name', 'a.a'], ['name', 'An'], ['name', '(a'], ['name', '(a+)+'], ['name', 'a*a*a*'],
  ['name', '[A-Z]na'], ['banana', '(?:an)*'], ['banana', 'b(?:an)*a'], ['name', '\\1'], ['empty', ''], ['empty', 'a?']])
  tri(`matches ${f} ${re}`, 'main', L(pp(f), 'matches', re));
tri('matches num', 'main', L(pp('total'), 'matches', '.*'));
tri('matches opnum', 'main', L(pp('name'), 'matches', 5));
tri('matches pat200', 'main', L(pp('xs'), 'matches', 'x'.repeat(198) + '.*'));
tri('matches pat201', 'main', L(pp('xs'), 'matches', 'x'.repeat(199) + '.*'));
tri('matches s512', 'main', L(pp('s512'), 'matches', '.*'));
tri('matches s513', 'main', L(pp('s513'), 'matches', '.*'));
// budget: ~55 heavy evaluations of a 192-char regex over a 512-char subject overrun the per-document step budget
const heavy = A(190) + '.*';
tri('matches budget all_of', 'main', { all_of: Array.from({ length: 55 }, () => L(pp('s512'), 'matches', heavy)) });
tri('matches budget all_of short', 'main', { all_of: Array.from({ length: 40 }, () => L(pp('s512'), 'matches', heavy)) });
tri('matches eval cap', 'main', { all_of: Array.from({ length: 65 }, () => L(pp('name'), 'matches', 'A.a')) });
tri('matches eval cap 64', 'main', { all_of: Array.from({ length: 64 }, () => L(pp('name'), 'matches', 'A.a')) });
// ---- is_a ----
for (const [f, t] of [['ts', 'Doc'], ['ts2', 'Doc'], ['ts3', 'Doc'], ['ts4', 'Doc'], ['obj', 'Doc'], ['obj', 'pii'], ['obj', 'red'],
  ['obj', 'x'], ['obj', 'Doc::7'], ['objt', 'Doc'], ['objt', 'x'], ['objtags', 'pii'], ['objtags', 'zz'], ['objtype', 'Doc'],
  ['objtype', 'Do'], ['objn', 'x'], ['total', 'x'], ['tags', 'a'], ['obj2', 'Doc'], ['obj2', 'Other'], ['objtn', 'Doc'],
  ['objtn', 'zz'], ['objts', 'Doc'], ['objts', 'zz'], ['objtype2', 'Doc'], ['nul', 'x'], ['ts', 'Doc::9'], ['ts', 'Do']])
  tri(`is_a ${f} ${t}`, 'main', L(pp(f), 'is_a', t));
tri('is_a empty', 'main', L(pp('ts'), 'is_a', ''));
tri('is_a opnum', 'main', L(pp('ts'), 'is_a', 5));
// ---- exists ----
for (const [n, ctx, f, v] of [
  ['name', 'main', pp('name'), true], ['missing', 'main', pp('missing'), true], ['missing false', 'main', pp('missing'), false],
  ['name false', 'main', pp('name'), false], ['nul', 'main', pp('nul'), true], ['name str-false', 'main', pp('name'), 'false'],
  ['missing str-false', 'main', pp('missing'), 'false'], ['missing 0', 'main', pp('missing'), 0], ['name null', 'main', pp('name'), null],
  ['np x', 'noparams', pp('x'), true], ['np x false', 'noparams', pp('x'), false], ['np paramsX false', 'noparams', 'action.paramsX', false],
  ['np paramsX', 'noparams', 'action.paramsX', true], ['np params', 'noparams', 'action.params', true],
  ['np params false', 'noparams', 'action.params', false], ['ps params', 'paramsStr', 'action.params', true],
  ['ps x', 'paramsStr', pp('x'), false], ['pa 0', 'paramsArr', pp('0'), true], ['pa 2', 'paramsArr', pp('2'), true],
  ['pn x', 'paramsNull', pp('x'), false], ['noaction x', 'noaction', pp('x'), false], ['noaction env', 'noaction', 'env.a', true],
  ['actionArr x', 'actionArr', pp('x'), false], ['actionArr verb', 'actionArr', 'action.0', true], ['nullctx', 'nullctx', 'env.a', true],
  ['nullctx false', 'nullctx', 'env.a', false], ['nullctx params', 'nullctx', pp('x'), false], ['np env', 'noparams', 'env.a', true],
  ['subjNull', 'subjNull', 'subject', true], ['subjNull x', 'subjNull', 'subject.x', false], ['nosubj', 'noparams', 'subject', true],
]) {
  tri(`exists ${n}`, ctx, L(f, 'exists', v));
}
tri('exists novalue', 'main', { field: pp('name'), op: 'exists' });
tri('exists novalue missing', 'main', { field: pp('missing'), op: 'exists' });
tri('np ref params', 'noparams', R('env.a', 'eq', pp('x')));
tri('np ref params exact', 'noparams', R('env.a', 'eq', 'action.params'));
tri('np ref paramsX', 'noparams', R('env.a', 'eq', 'action.paramsX'));
tri('np ref env', 'noparams', R('env.a', 'eq', 'env.a'));
tri('np ref num', 'noparams', { field: 'env.a', op: 'eq', ref: 5 });
tri('np value', 'noparams', L('env.a', 'eq', 1));
tri('pa value', 'paramsArr', L(pp('1'), 'eq', 8));
tri('ps ref', 'paramsStr', R('env.a', 'eq', pp('x')));
tri('ps ref params exact', 'paramsStr', R('env.a', 'eq', 'action.params'));
tri('pn ref params exact', 'paramsNull', R('env.a', 'ne', 'action.params'));
tri('ps field params exact', 'paramsStr', L('action.params', 'eq', 'x'));
// a literal U+0002 before '*' (U+0002 == the STAR token kind) must not swallow the star
tri('like ctl2 star', 'main', L(pp('ctl'), 'like', '\u0002*'));
tri('like ctl2 star x', 'main', L(pp('ctl'), 'like', '\u0002*x'));
// budget by STEPS (not source chars): 8 x a{64} is 40 chars but ~512 NFA states; ~19 runs over a 512-char subject
const rep64 = 'a{64}'.repeat(8);
tri('matches budget rep64', 'main', { all_of: Array.from({ length: 25 }, () => L(pp('s512'), 'matches', rep64)) });
tri('matches budget rep64 short', 'main', { all_of: Array.from({ length: 15 }, () => L(pp('s512'), 'matches', rep64)) });
// ---- path resolution ----
for (const [n, f, op, v] of [
  ['tags.0', pp('tags.0'), 'eq', 'a'], ['tags.1', pp('tags.1'), 'eq', 'b'], ['tags.2', pp('tags.2'), 'exists', true],
  ['tags.01', pp('tags.01'), 'exists', true], ['tags.-1', pp('tags.-1'), 'exists', true], ['tags.x', pp('tags.x'), 'exists', true],
  ['tags.1.0', pp('tags.1.0'), 'exists', true], ['tags.length', pp('tags.length'), 'exists', true],
  ['constructor', pp('constructor'), 'exists', true], ['__proto__', 'subject.groups.__proto__', 'exists', true],
  ['prototype', pp('prototype'), 'exists', true], ['trailing dot', 'action.params.', 'eq', 'emptykey'],
  ['double dot', 'action..params', 'exists', true], ['empty seg', 'action.params..name', 'exists', true],
  ['subject.id', 'subject.id', 'eq', 'ana'], ['nope.x', 'nope.x', 'exists', true], ['env', 'env', 'exists', true],
  ['name.x', pp('name.x'), 'exists', true], ['nul.x', pp('nul.x'), 'exists', true], ['env.arr.0.0', 'env.arr.0.0', 'eq', 1],
  ['env.arr.0.1', 'env.arr.0.1', 'exists', true], ['env.arr.1', 'env.arr.1', 'exists', true], ['action', 'action', 'exists', true],
  ['action.verb', 'action.verb', 'eq', 'air.book'], ['tags.1e0', pp('tags.1e0'), 'exists', true], ['tags. 1', pp('tags. 1'), 'exists', true],
  ['dot only', '.', 'exists', true], ['nested.x', pp('nested.x'), 'eq', 1], ['nested.y', pp('nested.y'), 'exists', true],
]) tri(`path ${n}`, 'main', L(f, op, v));
// ---- member_of ----
const MO = (field, extra) => ({ field, op: 'member_of', collection: 'subject.groups', ...extra });
for (const [n, c] of [
  ['emp', MO('subject.id', { value: 'emp' })], ['all', MO('subject.id', { value: 'all' })], ['root', MO('subject.id', { value: 'root' })],
  ['list', MO('subject.id', { value: ['zz', 'all'] })], ['list miss', MO('subject.id', { value: ['zz', 'yy'] })],
  ['list nonstr', MO('subject.id', { value: [5] })], ['list mixed', MO('subject.id', { value: [5, 'staff'] })],
  ['list empty', MO('subject.id', { value: [] })], ['value num', MO('subject.id', { value: 5 })], ['value obj', MO('subject.id', { value: { a: 'staff' } })],
  ['novalue', MO('subject.id', {})], ['value null', MO('subject.id', { value: null })],
  ['ref glist', MO('subject.id', { ref: 'subject.glist' })], ['ref str', MO('subject.id', { ref: 'subject.x' })],
  ['ref missing', MO('subject.id', { ref: 'subject.missing' })], ['ref with value', MO('subject.id', { ref: 'subject.missing', value: 'emp' })],
  ['self', MO('subject.id', { value: 'ana' })], ['proto start', MO('subject.pp', { value: 'root' })], ['proto self', MO('subject.pp', { value: '__proto__' })],
  ['num node', MO('subject.x', { value: '7' })], ['num node self', MO('subject.x', { value: 'x' })], ['field num', MO(pp('total'), { value: 'emp' })],
  ['field missing', MO('subject.missing', { value: 'emp' })], ['staff', MO('subject.id', { value: 'staff' })],
  ['coll empty', { field: 'subject.id', op: 'member_of', collection: '', value: 'emp' }],
  ['coll missing', { field: 'subject.id', op: 'member_of', value: 'emp' }],
  ['coll num', { field: 'subject.id', op: 'member_of', collection: 5, value: 'emp' }],
  ['coll arr', { field: 'subject.id', op: 'member_of', collection: 'subject.glist', value: 'emp' }],
  ['coll str', { field: 'subject.id', op: 'member_of', collection: 'subject.x', value: 'emp' }],
  ['coll nope', { field: 'subject.id', op: 'member_of', collection: 'subject.nope', value: 'emp' }],
]) tri(`member_of ${n}`, 'main', c);
// ---- grouping ----
const T = L(pp('name'), 'eq', 'Ana'), F = L(pp('name'), 'eq', 'x'), U = L(pp('missing'), 'eq', 'x');
for (const [n, c] of [
  ['all []', { all_of: [] }], ['all str', { all_of: 'x' }], ['all null', { all_of: null }], ['all TT', { all_of: [T, T] }],
  ['all TF', { all_of: [T, F] }], ['all TU', { all_of: [T, U] }], ['all UF', { all_of: [U, F] }], ['all FU', { all_of: [F, U] }],
  ['all T', { all_of: [T] }], ['all U', { all_of: [U] }], ['any []', { any_of: [] }], ['any str', { any_of: 'x' }],
  ['any FT', { any_of: [F, T] }], ['any FF', { any_of: [F, F] }], ['any FU', { any_of: [F, U] }], ['any UT', { any_of: [U, T] }],
  ['any TU', { any_of: [T, U] }], ['any F', { any_of: [F] }], ['any U', { any_of: [U] }], ['any T', { any_of: [T] }],
  ['not T', { not: T }], ['not F', { not: F }], ['not U', { not: U }], ['not null', { not: null }], ['not str', { not: 'x' }],
  ['all+any', { all_of: [T], any_of: [F] }], ['any+not', { any_of: [F], not: F }], ['all+not', { all_of: [F], not: F }],
  ['nested', { all_of: [{ any_of: [F, { not: F }] }, { not: { all_of: [T, F] } }] }], ['array cond', [T]], ['empty array cond', []],
  ['string cond', 'x'], ['num cond', 5], ['null cond', null], ['bool cond', true], ['all with str child', { all_of: [T, 'x'] }],
  ['any with num child', { any_of: [5, T] }], ['all_of with field', { all_of: [T], field: pp('name'), op: 'eq', value: 'x' }],
  ['not with field', { not: T, field: pp('name'), op: 'eq', value: 'Ana' }],
]) tri(`group ${n}`, 'main', c);

// ---- predicates ----
const predCase = (name, ctx, preds) => {
  const t = text(preds);
  const c = JSON.parse(CTX[ctx]);
  const parsed = JSON.parse(t);
  const r = P.evaluatePredicates(parsed, c);
  const each = Array.isArray(parsed) ? parsed.map((p) => P.predicateMatches(p, JSON.parse(CTX[ctx]))) : [];
  out.preds.push({ name: uniq(`pred ${name}`), ctx, preds: t, allowed: r.allowed, each });
};
const V = (verb, resource, where) => {
  const p = { verb };
  if (resource !== undefined) p.resource = resource;
  if (where !== undefined) p.where = where;
  return p;
};
for (const [n, ctx, preds] of [
  ['empty', 'main', []], ['notlist', 'main', { verb: '*' }], ['null', 'main', null], ['str', 'main', 'x'],
  ['star', 'main', [V('*')]], ['exact', 'main', [V('air.book')]], ['other', 'main', [V('air.cancel')]],
  ['list', 'main', [V(['air.cancel', 'air.book'])]], ['list star', 'main', [V(['x', '*'])]], ['list miss', 'main', [V(['x', 'y'])]],
  ['list nonstr', 'main', [V([5, null, 'air.book'])]], ['list null first', 'main', [V([null, 'air.book'])]], ['list num only', 'main', [V([5])]],
  ['list empty', 'main', [V([])]], ['verb num', 'main', [V(5)]], ['verb obj', 'main', [V({ a: 'air.book' })]], ['verb missing', 'main', [{}]],
  ['verb null', 'main', [V(null)]], ['star upper', 'main', [V('AIR.BOOK')]],
  ['pred str', 'main', ['x', V('*')]], ['pred arr', 'main', [[V('*')]]], ['pred null', 'main', [null, V('air.cancel')]],
  ['pred num', 'main', [5]], ['second', 'main', [V('x'), V('air.book')]],
  ['res star', 'main', [V('*', '*')]], ['res exact', 'main', [V('*', 'skyair.example/bookings/7')]],
  ['res exact miss', 'main', [V('*', 'skyair.example/bookings/8')]], ['res prefix', 'main', [V('*', 'skyair.example/*')]],
  ['res prefix miss', 'main', [V('*', 'skyair.example/x*')]], ['res prefix exact', 'main', [V('*', 'skyair.example/bookings/7*')]],
  ['res prefix longer', 'main', [V('*', 'skyair.example/bookings/77*')]], ['res abc', 'main', [V('*', 'skyair.example/bookings/')]],
  ['res num', 'main', [V('*', 5)]], ['res null', 'main', [{ verb: '*', resource: null }]], ['res empty', 'main', [V('*', '')]],
  ['res re', 'main', [V('*', 're:skyair\\.example/bookings/[0-9]+')]], ['res re miss', 'main', [V('*', 're:skyair\\.example/bookings/[a-z]+')]],
  ['res re partial', 'main', [V('*', 're:skyair')]], ['res re unsafe', 'main', [V('*', 're:(a+)+')]],
  ['res re cost', 'main', [V('*', 're:s.*s.*k.*y.*')]], ['res re bad', 'main', [V('*', 're:(')]], ['res re empty', 'main', [V('*', 're:')]],
  ['res re star', 'main', [V('*', 're:.*')]], ['res re prefix*', 'main', [V('*', 're:sky*')]],
  ['where empty', 'main', [V('*', undefined, [])]], ['where T', 'main', [V('*', undefined, [T])]], ['where F', 'main', [V('*', undefined, [F])]],
  ['where U', 'main', [V('*', undefined, [U])]], ['where TF', 'main', [V('*', undefined, [T, F])]], ['where obj', 'main', [V('*', undefined, T)]],
  ['where null', 'main', [{ verb: '*', where: null }]], ['where str', 'main', [V('*', undefined, 'x')]],
  ['where then second', 'main', [V('*', undefined, [F]), V('air.book', '*', [T])]],
  ['noaction', 'noaction', [V('*')]], ['actionArr', 'actionArr', [V('*')]], ['nullctx', 'nullctx', [V('*')]],
  ['noverb', 'main', [V('*')]],
]) predCase(n, ctx, preds);
CTX.noverb = '{"action":{"resource":"r"}}';
CTX.noresource = '{"action":{"verb":"v"}}';
CTX.numverb = '{"action":{"verb":5,"resource":"r"}}';
CTX.numres = '{"action":{"verb":"v","resource":5}}';
CTX.long512 = `{"action":{"verb":"v","resource":"${A(512)}"}}`;
CTX.long513 = `{"action":{"verb":"v","resource":"${A(513)}"}}`;
CTX.long300 = `{"action":{"verb":"v","resource":"${A(300)}"}}`;
for (const [n, ctx, preds] of [
  ['noverb star', 'noverb', [V('*')]], ['noverb nores', 'noverb', [{ verb: '*' }]], ['noresource star', 'noresource', [V('*')]],
  ['noresource v', 'noresource', [V('v')]], ['numverb', 'numverb', [V('*')]], ['numres', 'numres', [V('*')]],
  ['re src200', 'long300', [V('*', 're:' + A(198) + '.*')]], ['re src201', 'long300', [V('*', 're:' + A(199) + '.*')]],
  ['re res512', 'long512', [V('*', 're:.*')]], ['re res513', 'long513', [V('*', 're:.*')]], ['prefix res513', 'long513', [V('*', 'a*')]],
  ['re budget', 'long512', [...Array.from({ length: 54 }, () => V('*', 're:' + A(189) + 'b.*')), V('*', 're:' + A(190) + '.*')]],
  ['re budget short', 'long512', [...Array.from({ length: 30 }, () => V('*', 're:' + A(189) + 'b.*')), V('*', 're:' + A(190) + '.*')]],
  ['re budget rep64', 'long512', [...Array.from({ length: 24 }, () => V('*', 're:' + 'a{64}'.repeat(7) + 'a{63}b')), V('*', 're:' + rep64)]],
  ['re budget rep64 short', 'long512', [...Array.from({ length: 14 }, () => V('*', 're:' + 'a{64}'.repeat(7) + 'a{63}b')), V('*', 're:' + rep64)]],
  ['re cost bits', 'long300', [V('*', 're:a*a*a*')]], ['re cost bits ok', 'long300', [V('*', 're:a*a*')]],
]) predCase(n, ctx, preds);

// ---- deepEq (lenient canonical text equality) ----
const deepEq = (a, b) => {
  try {
    return H.canonicalize(a) === H.canonicalize(b);
  } catch {
    return false;
  }
};
for (const [a, b] of [
  ['null', 'null'], ['null', '0'], ['0', 'null'], ['null', '"null"'], ['"a"', '"a"'], ['"a"', '"b"'], ['"1"', '1'], ['1', '"1"'],
  ['true', 'true'], ['true', 'false'], ['true', '1'], ['1', 'true'], ['false', '0'], ['"true"', 'true'], ['1', '1.0'], ['1', '1e0'],
  ['0', '-0'], ['-0', '0'], ['1e400', '1e400'], ['1e400', '1'], ['1', '1e400'], ['-1e400', '1e400'], ['0.1', '0.10'], ['0.1', '0.2'],
  ['[]', '[]'], ['[]', '{}'], ['{}', '[]'], ['{}', '{}'], ['[1]', '[1]'], ['[1]', '[2]'], ['[1]', '[1,1]'], ['[1,1]', '[1]'],
  ['[1,2]', '[2,1]'], ['{"a":1}', '{"a":1}'], ['{"a":1}', '{"a":2}'], ['{"a":1}', '{"b":1}'], ['{"a":1}', '{"a":1,"b":2}'],
  ['{"a":1,"b":2}', '{"a":1}'], ['{"a":1,"b":2}', '{"b":2,"a":1}'], ['{"a":null}', '{}'], ['{}', '{"a":null}'],
  ['{"a":null}', '{"b":null}'], ['[null]', '[null]'], ['[1e400]', '[1e400]'], ['{"a":1e400}', '{"a":1e400}'], ['1', '[1]'],
  ['[1]', '1'], ['{"a":[1,{"b":"c"}]}', '{"a":[1,{"b":"c"}]}'], ['{"a":[1,{"b":"c"}]}', '{"a":[1,{"b":"d"}]}'],
  ['"\\ud800"', '"\\ud800"'], ['"\\ud800"', '"\\ud801"'], ['"\\ud800"', '"\\ufffd"'], ['9007199254740993', '9007199254740992'],
  ['0.30000000000000004', '0.3'], ['1.5', '15e-1'], ['"a"', '["a"]'], ['{"a":1}', '1'], ['1', '{"a":1}'], ['"x"', 'null'],
]) out.eq.push({ a, b, eq: deepEq(JSON.parse(a), JSON.parse(b)) });

// ---- numbers (JSON.parse value, String(n), Number.isSafeInteger / isFinite) ----
for (const raw of ['0', '-0', '1', '-1', '1.0', '1e3', '950000.0', '0.1', '-0.1', '0.30000000000000004', '1.5e-3', '123.456e1',
  '9007199254740991', '9007199254740992', '-9007199254740991', '-9007199254740992', '1152921504606846976', '-1152921504606846976',
  '1e21', '1e22', '1e23', '1e20', '999999999999999999999', '123456789012345678', '1e-6', '1e-7', '5e-324', '1.7976931348623157e308',
  '1e400', '-1e400', '0.5', '2.5', '1.05', '100', '1e2', '12.34', '3.14159', '1e-5', '0.000001', '0.0000001', '4.35', '0.1e1',
  '1.23e-10', '123e-2', '-1.5', '-2.0', '17', '1e15', '1e16', '1e17', '4503599627370496.5', '4503599627370497', '-1e23', '-1e21', '-999999999999999999999', '-123456789012345678']) {
  const n = JSON.parse(raw);
  out.nums.push({ raw, js: Object.is(n, -0) ? '-0' : String(n), safe: Number.isSafeInteger(n), finite: Number.isFinite(n),
    plain: !/e/i.test(String(n)) });
}

// ---- UTF-8 lengths (TextEncoder) ----
const enc = new TextEncoder();
for (const s of ['', 'a', '\u007f', '\u0080', '߿', 'ࠀ', '￿', '😀', '\ud83d', '\ude00', 'a\ud83d', '\ud83da',
  '\ud83d😀', '\ude00\ud83d', 'a\u0080ࠀ😀', '😀\ud83d', 'été', '𐀀\udc00'])
  out.u8.push({ s, n: enc.encode(s).length, lone: H.hasLoneSurrogate(s) });

// ---- compareUtf8 sign ----
for (const [a, b] of [['a', 'b'], ['b', 'a'], ['a', 'a'], ['a', 'ab'], ['ab', 'a'], ['￿', '😀'], ['😀', '￿'],
  ['', ''], ['', 'a'], ['Z', 'a'], ['é', 'z']])
  out.cmp.push({ a, b, sign: Math.sign(H.compareUtf8(a, b)) });

// ---- member closure caps (rebuilt by the Java test from the same recipe) ----
const chainCtx = (n) => {
  const g = {};
  for (let i = 0; i < n; i++) g[`n${i}`] = `n${i + 1}`;
  return { action: { verb: 'v', resource: 'r' }, subject: { id: 'n0', g } };
};
const fanCtx = () => {
  const g = { s: [] };
  const cs = Array.from({ length: 100 }, (_, j) => `c${j}`);
  for (let i = 0; i < 100; i++) {
    g.s.push(`a${i}`);
    g[`a${i}`] = cs;
  }
  g.c0 = 'e';
  g.e = 't';
  return { action: { verb: 'v', resource: 'r' }, subject: { id: 's', g } };
};
const mo = (v) => ({ field: 'subject.id', op: 'member_of', collection: 'subject.g', value: v });
out.chain = {};
for (const v of ['n9999', 'n10000', 'n10001', 'n10002']) out.chain[v] = P.evaluateConditionTri(mo(v), chainCtx(10005));
out.fan = {};
for (const v of ['e', 't', 'c99', 'a99']) out.fan[v] = P.evaluateConditionTri(mo(v), fanCtx());

out.ctx = CTX;
fs.writeFileSync(process.argv[2], JSON.stringify(out, null, 0) + '\n');
console.log(`tri ${out.tri.length} preds ${out.preds.length} eq ${out.eq.length} nums ${out.nums.length} u8 ${out.u8.length}`);
